"""Command handler for the firehose protocol.

Handles PUBLISH_RECORD, EVENT_HEAD, EVENT_RANGE, EVENT_GET, and projection
read commands (BOARD_LIST, ARTICLE_GET/LIST/SEARCH/BODY, USER_GET/LIST,
BAN_STATUS, EVENT_BODY).

Each request is a binary body starting with one opcode byte. Responses begin
with status:u8 (0=success, 1=error).
"""

from __future__ import annotations

import struct
import threading
import time

from bonnet.core.acl import ACLEvaluator, AuthContext
from bonnet.core.board_projection import BoardProjection, board_db_path
from bonnet.core.bodies import BodyStore
from bonnet.core.crypto import Identity
from bonnet.core.firehose import (
    KIND_ARTICLE,
    FirehoseError,
    FirehoseStore,
)
from bonnet.core.global_projections import NavProjection, PolicyProjection, UserProjection
from bonnet.core.kind_validator import KindValidator, ValidationError
from bonnet.core.kinds import ALL_KNOWN_KINDS
from bonnet.core.logging import log_msg
from bonnet.core.record import (
    SIG_SIZE,
    ZERO_ID,
    compute_body_hash,
    compute_event_hash,
    decode_intent,
    encode_head,
    encode_record,
    encode_witness,
    make_origin_witness,
)
from bonnet.core.search import SearchService
from bonnet.net.firehose_wire import (
    OP_ARTICLE_BODY,
    OP_ARTICLE_GET,
    OP_ARTICLE_LIST,
    OP_ARTICLE_QUERY,
    OP_ARTICLE_SEARCH,
    OP_BAN_STATUS,
    OP_BOARD_LIST,
    OP_EVENT_BODY,
    OP_EVENT_GET,
    OP_EVENT_HEAD,
    OP_EVENT_RANGE,
    OP_KEY_EPOCHS,
    OP_PERMISSIONS,
    OP_PUBLISH_RECORD,
    OP_REPORT_LIST,
    OP_USER_GET,
    OP_USER_LIST,
    _enc_text16,
    _read_bytes,
    _read_id32,
    _read_text16,
    _read_u8,
    _read_u16,
    _read_u32,
    _read_u64,
)

KIND_ARTICLE_CANCEL = "bonnet.article.cancel"
KIND_ARTICLE_RESTORE = "bonnet.article.restore"
KIND_ARTICLE_PURGE = "bonnet.article.purge"
KIND_ARTICLE_PIN = "bonnet.article.pin"
KIND_ARTICLE_UNPIN = "bonnet.article.unpin"
KIND_THREAD_CLOSE = "bonnet.thread.close"
KIND_THREAD_REOPEN = "bonnet.thread.reopen"
KIND_PUNISHMENT_ACK = "bonnet.punishment.ack"

# Punishment type codes used by the BAN_STATUS response.
PUNISHMENT_TYPE_CODES = {"warning": 1, "ban": 2, "permaban": 3}


# ---------------------------------------------------------------------------
# Opcodes and the wire codec — defined once in firehose_wire.py, imported above.
#
# The request decoders are the same functions the client uses on responses:
# one bounds-checked copy for both directions. ProtocolError subclasses
# ValueError, so a malformed request still lands in handle()'s `except
# ValueError` and comes back as a 0x0006 error frame.
# ---------------------------------------------------------------------------

CMD_NAMES = {
    OP_PUBLISH_RECORD: "PUBLISH_RECORD",
    OP_EVENT_HEAD: "EVENT_HEAD",
    OP_EVENT_RANGE: "EVENT_RANGE",
    OP_EVENT_GET: "EVENT_GET",
    OP_KEY_EPOCHS: "KEY_EPOCHS",
    OP_PERMISSIONS: "PERMISSIONS",
    OP_BOARD_LIST: "BOARD_LIST",
    OP_ARTICLE_GET: "ARTICLE_GET",
    OP_ARTICLE_LIST: "ARTICLE_LIST",
    OP_ARTICLE_SEARCH: "ARTICLE_SEARCH",
    OP_ARTICLE_QUERY: "ARTICLE_QUERY",
    OP_ARTICLE_BODY: "ARTICLE_BODY",
    OP_USER_GET: "USER_GET",
    OP_USER_LIST: "USER_LIST",
    OP_BAN_STATUS: "BAN_STATUS",
    OP_REPORT_LIST: "REPORT_LIST",
    OP_EVENT_BODY: "EVENT_BODY",
}

WRITE_OPS = frozenset({OP_PUBLISH_RECORD})
READ_OPS = frozenset(
    {
        OP_EVENT_HEAD,
        OP_EVENT_RANGE,
        OP_PERMISSIONS,
        OP_REPORT_LIST,
        OP_EVENT_GET,
        OP_KEY_EPOCHS,
        OP_BOARD_LIST,
        OP_ARTICLE_GET,
        OP_ARTICLE_LIST,
        OP_ARTICLE_SEARCH,
        OP_ARTICLE_QUERY,
        OP_ARTICLE_BODY,
        OP_USER_GET,
        OP_USER_LIST,
        OP_BAN_STATUS,
        OP_EVENT_BODY,
    }
)

# Opcodes whose handler consults the ACL 'board' dimension: PUBLISH_RECORD
# via the board on the intent, the rest via `_board_read_allowed`.
#
# Everything not listed here is board-agnostic *by construction*, not by
# omission. The substrate reads — EVENT_HEAD, EVENT_RANGE, EVENT_GET,
# EVENT_BODY, KEY_EPOCHS — are how a peer replicates this origin's log, and
# the log is a hash chain: each record commits to its predecessor's hash, and
# ingest raises ChainBreak on the first gap (`core/firehose.py`, the
# `previous_event_hash != expected_prev` check). Filtering records out of a
# range by board would hand every peer a broken chain. So these opcodes
# cannot be board-scoped, and granting one is granting the whole log:
# every record's board, author, metadata (an article's subject and tags
# included), body hash and size, plus the body bytes of every non-article
# kind. Article bodies are the exception — they live in the per-board store,
# so ARTICLE_BODY's check is the only door to those.
#
# Grant the substrate opcodes to a principal you would grant `boards = ["*"]`.
BOARD_SCOPED_OPS = frozenset(
    {
        OP_PUBLISH_RECORD,
        OP_REPORT_LIST,
        OP_BOARD_LIST,
        OP_ARTICLE_GET,
        OP_ARTICLE_LIST,
        OP_ARTICLE_SEARCH,
        OP_ARTICLE_QUERY,
        OP_ARTICLE_BODY,
    }
)


# ---------------------------------------------------------------------------
# Response builder helpers
# ---------------------------------------------------------------------------


def _success(payload: bytes = b"") -> bytes:
    return b"\x00" + payload


def _error(code: int, message: str) -> bytes:
    msg_bytes = message.encode("utf-8")
    return b"\x01" + struct.pack(">H", code) + struct.pack(">H", len(msg_bytes)) + msg_bytes


def _pad32(value: bytes) -> bytes:
    """Exactly 32 bytes: truncated, or zero-padded if short.

    The wire format is fixed-width, and a key read back off a record can be
    absent if the record has since been purged from this origin. Built without
    a NUL escape on purpose — heredoc-written escapes have twice put literal
    NUL bytes into source files in this repo.
    """
    return (value + bytes(32))[:32]


# ---------------------------------------------------------------------------
# Command context
# ---------------------------------------------------------------------------


class FirehoseContext:
    """Request context passed to each command handler."""

    def __init__(
        self,
        peer_pubkey: bytes = b"",
        is_anonymous: bool = False,
        is_unknown: bool = False,
        is_registered: bool = False,
        role: str = "",
        origin: str = "",
        remote_addr: str = "",
    ):
        self.peer_pubkey = peer_pubkey
        self.is_anonymous = is_anonymous
        self.is_unknown = is_unknown
        self.is_registered = is_registered
        self.role = role
        self.origin = origin
        self.remote_addr = remote_addr

    def to_auth_context(self) -> AuthContext:
        return AuthContext(
            pubkey=self.peer_pubkey,
            role=self.role,
            origin=self.origin,
            is_anonymous=self.is_anonymous,
            is_unknown=self.is_unknown,
            is_registered=self.is_registered,
        )


# ---------------------------------------------------------------------------
# Firehose command handler
# ---------------------------------------------------------------------------


class FirehoseCommandHandler:
    """Dispatches firehose protocol commands."""

    def __init__(
        self,
        firehose: FirehoseStore,
        server_identity: Identity,
        config_origin: str,
        nav: NavProjection,
        users: UserProjection,
        policy: PolicyProjection,
        body_store: BodyStore,
        boards_dir: str,
        acl: ACLEvaluator,
        validator: KindValidator,
        search: SearchService,
        hostname: str = "",
        dispatcher=None,
        sync_manager=None,
        peer_map: dict = None,
        allowed_origins: set = None,
        max_body_size: int = 1024 * 1024,
    ):
        self._firehose = firehose
        self._identity = server_identity
        self._origin = config_origin
        self._nav = nav
        self._users = users
        self._policy = policy
        self._body_store = body_store
        self._boards_dir = boards_dir
        self._acl = acl
        self._validator = validator
        self._search = search
        self._hostname = hostname or config_origin
        self._dispatcher = dispatcher
        self._sync_manager = sync_manager
        self._peer_map = peer_map or {}
        self._allowed_origins = allowed_origins or set()
        self._board_projections: dict[tuple[str, str], BoardProjection] = {}
        self._boards_lock = threading.Lock()
        self._max_body_size = max_body_size

    def close(self) -> None:
        with self._boards_lock:
            for bp in self._board_projections.values():
                bp.close()
            self._board_projections.clear()

    def set_server_identity(self, identity: Identity) -> None:
        """Hot-swap the identity used to sign future local publishes and
        witness lookups (see core.record.Record vs Event: the origin
        signature over any record appended after this call must come from
        whichever key the key-epoch table now considers current). Used by
        BonnetServer.apply_key_rotation — every call site here reads
        self._identity fresh, so this is the only update this class needs."""
        self._identity = identity

    def _get_board_projection(self, origin: str, board: str) -> BoardProjection:
        key = (origin, board)
        with self._boards_lock:
            bp = self._board_projections.get(key)
            if bp is None:
                bp = BoardProjection(board_db_path(self._boards_dir, origin, board))
                self._board_projections[key] = bp
            return bp

    def _maybe_queue_remote_sync(self, origin: str) -> None:
        """Queue an on-demand sync if the origin is a remote peer."""
        if origin == self._origin:
            return
        if self._sync_manager is not None:
            self._sync_manager.queue_sync_threadsafe(origin)

    def _board_read_allowed(self, ctx: FirehoseContext, cmd_name: str, board: str) -> bool:
        """Enforce the ACL 'board' dimension for a board-scoped read.

        The top-level dispatch in `handle()` only checks the 'command'
        dimension before board is known. Every handler that reads a
        specific board (including each board named in an aggregate,
        cross-origin listing) must call this before touching that board's
        data, or an ACL rule scoped to `boards = [...]` becomes a no-op and
        a caller can reach boards on peered origins through the local
        aggregate index regardless of what they were actually granted.
        """
        return self._acl.check(ctx.to_auth_context(), "read", command=cmd_name, board=board)

    # ------------------------------------------------------------------
    # Punishment write gate
    # ------------------------------------------------------------------

    def _policy_current(self) -> bool:
        """True when the policy projection has caught up with the firehose."""
        for origin in self._allowed_origins or {self._origin}:
            try:
                if self._firehose.get_highest_seq(origin) > self._policy.get_checkpoint(origin):
                    return False
            except Exception:
                return False
        return True

    def _punishment_gate_response(self, actor_pubkey: bytes) -> bytes | None:
        """Return an error response if this user's writes are gated.

        Fails open when the policy projection is unavailable or behind the
        firehose — an outage must not block all publication.
        """
        if not self._policy_current():
            return None
        try:
            pending = self._policy.list_pending_for_pubkey(
                actor_pubkey,
                allowed_origins=self._allowed_origins or None,
            )
        except Exception as e:
            log_msg(f"PUNISHMENT_GATE: fail-open: {type(e).__name__}: {e}")
            return None
        if not pending:
            return None
        p = pending[0]
        expires = p["expires_at"] if p["type"] == "ban" else 0
        msg = (
            f"Write blocked by {p['type']}: "
            f"event={p['event_id'].hex()} origin={p['origin']} expires={expires}"
        )
        return _error(0x000A, msg)

    def handle(self, body: bytes, ctx: FirehoseContext) -> bytes:
        if not body:
            return _error(0x0005, "Empty request")

        opcode = body[0]
        data = body[1:]
        cmd_name = CMD_NAMES.get(opcode, f"UNKNOWN_{opcode:02x}")

        if opcode not in CMD_NAMES:
            return _error(0x0005, f"Unknown opcode 0x{opcode:02x}")

        action = "write" if opcode in WRITE_OPS else "read"

        if action == "read":
            if not self._acl.check(ctx.to_auth_context(), action, command=cmd_name):
                return _error(0x0004, "Command not permitted")

        try:
            if opcode == OP_PUBLISH_RECORD:
                return self._cmd_publish(data, ctx)
            elif opcode == OP_EVENT_HEAD:
                return self._cmd_event_head(data, ctx)
            elif opcode == OP_EVENT_RANGE:
                return self._cmd_event_range(data, ctx)
            elif opcode == OP_EVENT_GET:
                return self._cmd_event_get(data, ctx)
            elif opcode == OP_REPORT_LIST:
                return self._cmd_report_list(data, ctx)
            elif opcode == OP_PERMISSIONS:
                return self._cmd_permissions(data, ctx)
            elif opcode == OP_KEY_EPOCHS:
                return self._cmd_key_epochs(data, ctx)
            elif opcode == OP_BOARD_LIST:
                return self._cmd_board_list(data, ctx)
            elif opcode == OP_ARTICLE_GET:
                return self._cmd_article_get(data, ctx)
            elif opcode == OP_ARTICLE_LIST:
                return self._cmd_article_list(data, ctx)
            elif opcode == OP_ARTICLE_SEARCH:
                return self._cmd_article_search(data, ctx)
            elif opcode == OP_ARTICLE_QUERY:
                return self._cmd_article_query(data, ctx)
            elif opcode == OP_ARTICLE_BODY:
                return self._cmd_article_body(data, ctx)
            elif opcode == OP_USER_GET:
                return self._cmd_user_get(data, ctx)
            elif opcode == OP_USER_LIST:
                return self._cmd_user_list(data, ctx)
            elif opcode == OP_BAN_STATUS:
                return self._cmd_ban_status(data, ctx)
            elif opcode == OP_EVENT_BODY:
                return self._cmd_event_body(data, ctx)
            else:
                return _error(0x0005, f"Unhandled opcode 0x{opcode:02x}")
        except ValueError as e:
            return _error(0x0006, str(e))
        except (FirehoseError, ValidationError) as e:
            return _error(0x0006, str(e))
        except Exception as e:
            log_msg(f"COMMAND: {cmd_name} failed unexpectedly: {e}")
            return _error(0x0000, "Internal error")

    # ------------------------------------------------------------------
    # PUBLISH_RECORD
    # ------------------------------------------------------------------

    def _cmd_publish(self, data: bytes, ctx: FirehoseContext) -> bytes:
        now = int(time.time())
        offset = 0
        intent_len, offset = _read_u32(data, offset)
        if offset + intent_len > len(data):
            return _error(0x0006, "Truncated intent")
        encoded_intent = data[offset : offset + intent_len]
        offset += intent_len

        if offset + SIG_SIZE > len(data):
            return _error(0x0006, "Missing actor signature")
        actor_sig = data[offset : offset + SIG_SIZE]
        offset += SIG_SIZE

        body_len, offset = _read_u32(data, offset)
        if offset + body_len > len(data):
            return _error(0x0006, "Truncated body")
        body = data[offset : offset + body_len]
        offset += body_len

        intent = decode_intent(encoded_intent)

        if intent.origin != self._origin:
            return _error(0x0004, "Origin mismatch")

        if intent.actor_pubkey != ctx.peer_pubkey:
            return _error(0x0004, "Actor pubkey does not match authenticated key")

        try:
            self._validator.validate(intent)
        except ValidationError as e:
            return _error(0x0006, f"Validation error: {e}")

        kind = intent.kind
        board = intent.board
        if not self._acl.check(
            ctx.to_auth_context(), "write", command="PUBLISH_RECORD", kind=kind, board=board or None
        ):
            return _error(0x0004, "Not permitted")

        # Write gate: administrators bypass; ack must pass so a
        # punished user can acknowledge their warning.
        if kind != KIND_PUNISHMENT_ACK and ctx.role != "administrator":
            gate_error = self._punishment_gate_response(intent.actor_pubkey)
            if gate_error is not None:
                return gate_error

        if kind in (
            KIND_ARTICLE_CANCEL,
            KIND_ARTICLE_RESTORE,
            KIND_ARTICLE_PURGE,
            KIND_ARTICLE_PIN,
            KIND_ARTICLE_UNPIN,
            KIND_THREAD_CLOSE,
            KIND_THREAD_REOPEN,
        ):
            if (
                intent.target_article_id == ZERO_ID
                or not intent.target_origin
                or not intent.target_board
            ):
                return _error(0x0006, "Control event requires complete target tuple")

            bp = self._get_board_projection(intent.target_origin, intent.target_board)
            target = bp.get_article_by_id(
                intent.target_origin,
                intent.target_board,
                intent.target_article_id,
            )

            if target is None:
                return _error(0x0003, "Target article not found")

            if kind == KIND_ARTICLE_CANCEL:
                if target.author_pubkey != intent.actor_pubkey:
                    if ctx.role != "administrator" and ctx.role != "moderator":
                        return _error(
                            0x0004, "Only the author or a moderator may cancel this article"
                        )
                if target.visibility == "cancelled":
                    return _error(0x0009, "Article is already cancelled")
                if target.visibility == "superseded":
                    return _error(0x0009, "Cannot cancel a superseded article")
            elif kind == KIND_ARTICLE_RESTORE:
                if target.author_pubkey != intent.actor_pubkey:
                    if ctx.role != "administrator" and ctx.role != "moderator":
                        return _error(
                            0x0004, "Only the author or a moderator may restore this article"
                        )
                if target.visibility != "cancelled":
                    return _error(0x0009, "Article is not cancelled")
                if target.body_state == "purged":
                    return _error(0x0009, "Cannot restore a purged article")
            elif kind == KIND_ARTICLE_PURGE:
                if target.author_pubkey != intent.actor_pubkey:
                    if ctx.role != "administrator" and ctx.role != "moderator":
                        return _error(
                            0x0004, "Only the author or a moderator may purge this article"
                        )
                if target.body_state == "purged":
                    return _error(0x0009, "Article is already purged")
            elif kind == KIND_ARTICLE_PIN:
                if target.pin_state != "unpinned":
                    return _error(0x0009, "Article is already pinned")
            elif kind == KIND_ARTICLE_UNPIN:
                if target.pin_state == "unpinned":
                    return _error(0x0009, "Article is not pinned")
            elif kind == KIND_THREAD_CLOSE:
                if target.thread_state == "closed":
                    return _error(0x0009, "Thread is already closed")
            elif kind == KIND_THREAD_REOPEN:
                if target.thread_state == "open":
                    return _error(0x0009, "Thread is not closed")

        if kind == KIND_ARTICLE:
            supersedes_id = intent.metadata.get_bytes(7)
            if supersedes_id and supersedes_id != ZERO_ID:
                bp = self._get_board_projection(intent.origin, intent.board)
                target = bp.get_article_by_id(intent.origin, intent.board, supersedes_id)
                if target is None:
                    return _error(0x0003, "Supersede target article not found")
                if target.author_pubkey != intent.actor_pubkey:
                    if ctx.role != "administrator" and ctx.role != "moderator":
                        return _error(0x0004, "Only the original author may supersede an article")

        if intent.body_size > 0:
            if intent.body_size > self._max_body_size:
                return _error(
                    0x0006, f"Body size {intent.body_size} exceeds maximum {self._max_body_size}"
                )
            if len(body) != intent.body_size:
                return _error(0x0006, "Body length mismatch")
            actual_hash = compute_body_hash(body)
            if actual_hash != intent.body_hash:
                return _error(0x0006, "Body hash mismatch")

        if intent.kind == KIND_ARTICLE and intent.body_size > 0:
            self._body_store.stage_article_body(
                intent.origin,
                intent.board,
                intent.event_id,
                body,
                intent.body_hash,
                intent.body_size,
            )
        elif intent.body_size > 0:
            self._body_store.write_event_body(
                intent.origin,
                intent.event_id,
                body,
                intent.body_hash,
                intent.body_size,
            )

        try:
            rec = self._firehose.append_record(
                self._identity, intent, actor_sig, body, created_at=now
            )
        except Exception:
            if intent.kind == KIND_ARTICLE and intent.body_size > 0:
                self._body_store.delete_staged_article_body(
                    intent.origin, intent.board, intent.event_id
                )
            elif intent.body_size > 0:
                self._body_store.delete_event_body(intent.origin, intent.event_id)
            raise

        if intent.kind == KIND_ARTICLE and intent.body_size > 0:
            self._body_store.finalize_article_body(
                intent.origin,
                intent.board,
                intent.event_id,
                rec.article_num,
            )

        if self._dispatcher:
            self._dispatcher.dispatch_origin(self._origin)

        encoded_rec = encode_record(rec)
        event_hash = compute_event_hash(encoded_rec)

        witness = make_origin_witness(
            origin=self._origin,
            event_id=rec.event_id,
            event_hash=event_hash,
            origin_identity=self._identity,
            hostname=self._hostname,
            seen_at=now,
        )
        self._firehose.store_witness(witness)
        encoded_witness = encode_witness(witness)

        return _success(
            struct.pack(">I", len(encoded_rec))
            + encoded_rec
            + struct.pack(">H", len(encoded_witness))
            + encoded_witness
        )

    # ------------------------------------------------------------------
    # EVENT_HEAD
    # ------------------------------------------------------------------

    def _cmd_event_head(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        self._maybe_queue_remote_sync(origin)

        head = self._firehose.get_head(origin)
        if head is None:
            return _error(0x0002, "No head for origin")

        encoded = encode_head(head)
        return _success(struct.pack(">H", len(encoded)) + encoded)

    # ------------------------------------------------------------------
    # KEY_EPOCHS
    # ------------------------------------------------------------------

    def _cmd_key_epochs(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        self._maybe_queue_remote_sync(origin)

        epochs = self._firehose.get_key_epochs(origin)
        if not epochs:
            return _error(0x0002, "No key epochs for origin")

        payload = struct.pack(">H", len(epochs))
        for start_seq, end_seq, pubkey in epochs:
            payload += struct.pack(">Q", start_seq)
            payload += struct.pack(">Q", end_seq if end_seq is not None else 0)
            payload += pubkey
        return _success(payload)

    # ------------------------------------------------------------------
    # REPORT_LIST
    # ------------------------------------------------------------------

    def _cmd_report_list(self, data: bytes, ctx: FirehoseContext) -> bytes:
        """The moderation queue, filtered where the ACL can reach it.

        Reports name people and point at boards, which is exactly why this is
        a command and not something a client assembles for itself. Two
        enforcement points exist here and neither is available to a client
        scanning the event log:

        The reporter is read back off each record rather than stored again in
        the projection. Projections are derived views over records and keep
        (origin, event_id) precisely so the record can be consulted; the
        signed field there is the authoritative one.

        1. `REPORT_LIST` is its own ACL command, so an operator can grant the
           queue to moderators and to nobody else.
        2. A report carrying an article target is filtered through
           `_board_read_allowed` for *that* board. Without it, an ACL rule
           scoped to `boards = [...]` would be a no-op here — a caller barred
           from a board could still enumerate every accusation made in it,
           which is the failure `_board_read_allowed` exists to prevent.

        Reports with an event target or no target carry no board to check and
        are governed by the command grant alone.
        """
        offset = 0
        key_len, offset = _read_u8(data, offset)
        culprit, offset = _read_bytes(data, offset, key_len, "culprit pubkey")
        culprit = culprit or None
        limit, offset = _read_u16(data, offset)
        page_offset, offset = _read_u16(data, offset)

        rows = self._policy.list_reports(
            culprit_pubkey=culprit, limit=limit or 100, offset=page_offset
        )

        visible = [
            r
            for r in rows
            if not r["target_board"]
            or self._board_read_allowed(ctx, "REPORT_LIST", r["target_board"])
        ]

        payload = struct.pack(">H", len(visible))
        for r in visible:
            # Who filed it comes from the record, not from this projection.
            # The record is the authoritative artifact: actor_pubkey there is
            # covered by the actor signature, the origin countersignature and
            # the hash chain. A copy denormalized into a projection column
            # would be unsigned derived state saying the same thing less
            # credibly — and the row already carries the (origin, event_id)
            # needed to go ask.
            rec = self._firehose.get_event_by_id(r["origin"], r["event_id"])
            reporter = rec.actor_pubkey if rec else b""
            reporter_name = rec.actor_username if rec else ""

            payload += r["event_id"]
            payload += _enc_text16(r["origin"])
            payload += struct.pack(">Q", r["origin_seq"])
            payload += _pad32(reporter)
            payload += _enc_text16(reporter_name)
            payload += r["culprit_pubkey"]
            payload += _enc_text16(r["target_origin"])
            payload += _enc_text16(r["target_board"])
            payload += r["target_article_id"]
            payload += r["target_event_id"]
            payload += r["body_hash"]
            payload += struct.pack(">I", r["body_size"])
            payload += struct.pack(">Q", max(0, r["created_at"]))
        return _success(payload)

    # ------------------------------------------------------------------
    # PERMISSIONS
    # ------------------------------------------------------------------

    def _cmd_permissions(self, data: bytes, ctx: FirehoseContext) -> bytes:
        """Report what this principal may do, as the ACL evaluates it now.

        Enumerates rather than guesses: every command name and every known
        kind is put through the same ACLEvaluator the enforcing paths use, so
        the answer cannot drift from what a real request would get. That is
        the whole point — a client that infers permissions from anything else
        is maintaining a second, divergent copy of this policy.

        Scoped to the board in the request when one is given — but only for
        the opcodes that actually consult the board dimension (see
        BOARD_SCOPED_OPS). ACL rules carry a board dimension, so the same
        principal may publish to one board and not another, and a
        board-independent answer cannot express that.

        Scoping the board-agnostic opcodes too would break the promise above.
        A board-scoped deny would drop EVENT_GET from this list while a real
        EVENT_GET still succeeded, because `handle()` gates it without a
        board and no handler re-checks. Reporting them unscoped is the
        honest answer: the substrate reads are not board-restrictable, and a
        caller reading this list needs to see that rather than a denial the
        relay will not enforce.

        This is deliberately an ordinary ACL-gated read: an operator who does
        not want policy shape enumerated can deny it like anything else, and
        the shipped default grants it to every principal class so the answer
        is available exactly when a caller most needs it — before it knows
        what else it can do.
        """
        board, _ = _read_text16(data, 0)
        auth = ctx.to_auth_context()
        scope = board or None

        principal = "registered" if ctx.is_registered else "unknown"
        if ctx.is_anonymous:
            principal = "anonymous"

        commands = [
            name
            for opcode, name in sorted(CMD_NAMES.items())
            if self._acl.check(
                auth,
                "write" if opcode in WRITE_OPS else "read",
                command=name,
                board=scope if opcode in BOARD_SCOPED_OPS else None,
            )
        ]

        kinds = []
        if "PUBLISH_RECORD" in commands:
            kinds = [
                kind
                for kind in sorted(ALL_KNOWN_KINDS)
                if self._acl.check(auth, "write", command="PUBLISH_RECORD", kind=kind, board=scope)
            ]

        payload = _enc_text16(principal) + _enc_text16(ctx.role or "") + _enc_text16(board)
        payload += struct.pack(">H", len(commands))
        for name in commands:
            payload += _enc_text16(name)
        payload += struct.pack(">H", len(kinds))
        for kind in kinds:
            payload += _enc_text16(kind)
        return _success(payload)

    # ------------------------------------------------------------------
    # EVENT_RANGE
    # ------------------------------------------------------------------

    def _cmd_event_range(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        self._maybe_queue_remote_sync(origin)
        start_seq, offset = _read_u64(data, offset)
        max_count, offset = _read_u16(data, offset)
        max_bytes, offset = _read_u32(data, offset)

        records = self._firehose.get_events_range(origin, start_seq, max_count)

        out = struct.pack(">H", len(records))
        total_bytes = 0
        for rec in records:
            encoded_rec = encode_record(rec)
            if max_bytes > 0 and total_bytes + len(encoded_rec) > max_bytes:
                break
            event_hash = compute_event_hash(encoded_rec)

            witness = self._firehose.get_witness(origin, rec.event_id, self._identity.public_key)
            if witness is None:
                witness = make_origin_witness(
                    origin=origin,
                    event_id=rec.event_id,
                    event_hash=event_hash,
                    origin_identity=self._identity,
                    hostname=self._hostname,
                    seen_at=rec.created_at,
                )
                self._firehose.store_witness(witness)
            encoded_witness = encode_witness(witness)

            out += struct.pack(">I", len(encoded_rec)) + encoded_rec
            out += struct.pack(">H", len(encoded_witness)) + encoded_witness
            total_bytes += len(encoded_rec)

        return _success(out)

    # ------------------------------------------------------------------
    # EVENT_GET
    # ------------------------------------------------------------------

    def _cmd_event_get(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        self._maybe_queue_remote_sync(origin)
        event_id, offset = _read_id32(data, offset)

        rec = self._firehose.get_event_by_id(origin, event_id)
        if rec is None:
            return _error(0x0003, "Event not found")

        encoded_rec = encode_record(rec)
        event_hash = compute_event_hash(encoded_rec)

        witness = self._firehose.get_witness(origin, rec.event_id, self._identity.public_key)
        if witness is None:
            witness = make_origin_witness(
                origin=origin,
                event_id=rec.event_id,
                event_hash=event_hash,
                origin_identity=self._identity,
                hostname=self._hostname,
                seen_at=rec.created_at,
            )
            self._firehose.store_witness(witness)
        encoded_witness = encode_witness(witness)

        return _success(
            struct.pack(">I", len(encoded_rec))
            + encoded_rec
            + struct.pack(">H", len(encoded_witness))
            + encoded_witness
        )

    # ------------------------------------------------------------------
    # BOARD_LIST
    # ------------------------------------------------------------------

    def _cmd_board_list(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)

        if origin == "":
            boards = self._nav.list_boards()
            if self._allowed_origins:
                boards = [b for b in boards if b["origin"] in self._allowed_origins]
            boards = [b for b in boards if self._board_read_allowed(ctx, "BOARD_LIST", b["board"])]
            out = struct.pack(">H", len(boards))
            for b in boards:
                out += _enc_text16(b["origin"])
                name_bytes = b["board"].encode("utf-8")
                out += struct.pack(">H", len(name_bytes)) + name_bytes
                out += struct.pack(">B", 1 if b["closed"] else 0)
                owner = b["owner_pubkey"]
                out += struct.pack(">B", len(owner)) + owner
                display = b["display_name"].encode("utf-8")
                out += struct.pack(">H", len(display)) + display
            return _success(out)

        self._maybe_queue_remote_sync(origin)
        if origin and self._allowed_origins and origin not in self._allowed_origins:
            return _success(struct.pack(">H", 0))
        boards = self._nav.list_boards(origin)
        boards = [b for b in boards if self._board_read_allowed(ctx, "BOARD_LIST", b["board"])]
        out = struct.pack(">H", len(boards))
        for b in boards:
            name_bytes = b["board"].encode("utf-8")
            out += struct.pack(">H", len(name_bytes)) + name_bytes
            out += struct.pack(">B", 1 if b["closed"] else 0)
            owner = b["owner_pubkey"]
            out += struct.pack(">B", len(owner)) + owner
            display = b["display_name"].encode("utf-8")
            out += struct.pack(">H", len(display)) + display
        return _success(out)

    # ------------------------------------------------------------------
    # ARTICLE_GET
    # ------------------------------------------------------------------

    def _cmd_article_get(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        if not origin:
            return _error(0x0003, "Article not found")
        self._maybe_queue_remote_sync(origin)
        if origin and self._allowed_origins and origin not in self._allowed_origins:
            return _error(0x0003, "Article not found")
        board, offset = _read_text16(data, offset)
        if not self._board_read_allowed(ctx, "ARTICLE_GET", board):
            return _error(0x0003, "Article not found")
        selector_type, offset = _read_u8(data, offset)

        if selector_type == 0x01:
            article_num, offset = _read_u64(data, offset)
            article_id = None
        elif selector_type == 0x02:
            article_id, offset = _read_id32(data, offset)
            article_num = None
        else:
            return _error(0x0005, "Invalid selector type")

        include_body, offset = _read_u8(data, offset)

        bp = self._get_board_projection(origin, board)
        if article_num is not None:
            art = bp.get_article_by_num(origin, board, article_num)
        else:
            assert article_id is not None  # the only other selector_type branch sets it
            art = bp.get_article_by_id(origin, board, article_id)

        if art is None:
            return _error(0x0003, "Article not found")

        return _success(self._encode_article_view(art, include_body=bool(include_body)))

    def _encode_article_view(self, art, include_body: bool = False) -> bytes:
        from bonnet.core.record import ZERO_ID

        out = struct.pack(">Q", art.article_num)
        out += struct.pack(">B", len(art.article_id)) + art.article_id
        out += struct.pack(">B", len(art.event_id)) + art.event_id

        vis_map = {"active": 0, "cancelled": 1, "superseded": 2}
        out += struct.pack(">B", vis_map.get(art.visibility, 0))

        body_map = {"available": 0, "unavailable": 1, "purged": 2}
        out += struct.pack(">B", body_map.get(art.body_state, 1))

        out += struct.pack(">B", len(art.body_hash)) + art.body_hash
        out += struct.pack(">Q", art.body_size)
        out += struct.pack(">q", art.created_at)
        out += struct.pack(">B", len(art.author_pubkey)) + art.author_pubkey

        author_username = getattr(art, "author_username", "") or ""
        au_bytes = author_username.encode("utf-8")
        out += struct.pack(">H", len(au_bytes)) + au_bytes

        author_registrar = getattr(art, "author_registrar", "") or ""
        ar_bytes = author_registrar.encode("utf-8")
        out += struct.pack(">H", len(ar_bytes)) + ar_bytes

        subject_bytes = art.subject.encode("utf-8")
        out += struct.pack(">H", len(subject_bytes)) + subject_bytes

        tags_bytes = art.tags.encode("utf-8")
        out += struct.pack(">H", len(tags_bytes)) + tags_bytes

        ct_bytes = art.content_type.encode("utf-8")
        out += struct.pack(">H", len(ct_bytes)) + ct_bytes

        root_id = getattr(art, "root_article_id", ZERO_ID) or ZERO_ID
        out += struct.pack(">B", len(root_id)) + root_id

        reply_id = getattr(art, "reply_to_article_id", ZERO_ID) or ZERO_ID
        out += struct.pack(">B", len(reply_id)) + reply_id

        replacement_id = getattr(art, "replacement_article_id", None)
        if replacement_id and len(replacement_id) == 32:
            out += struct.pack(">B", 1) + replacement_id
        else:
            out += struct.pack(">B", 0)

        pin_state = getattr(art, "pin_state", "unpinned") or "unpinned"
        pin_bytes = pin_state.encode("utf-8")
        out += struct.pack(">H", len(pin_bytes)) + pin_bytes

        thread_state = getattr(art, "thread_state", "open") or "open"
        thread_bytes = thread_state.encode("utf-8")
        out += struct.pack(">H", len(thread_bytes)) + thread_bytes

        body_bytes = b""
        if include_body and art.body_state == "available" and art.body_size > 0:
            body_bytes = (
                self._body_store.get_article_body(
                    art.origin,
                    art.board,
                    art.article_num,
                    art.body_hash,
                    art.body_size,
                )
                or b""
            )

        out += struct.pack(">I", len(body_bytes)) + body_bytes
        return out

    # ------------------------------------------------------------------
    # ARTICLE_LIST
    # ------------------------------------------------------------------

    def _cmd_article_list(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        board, offset = _read_text16(data, offset)
        if not self._board_read_allowed(ctx, "ARTICLE_LIST", board):
            return _success(struct.pack(">H", 0))
        list_offset, offset = _read_u32(data, offset)
        limit, offset = _read_u16(data, offset)
        flags, offset = _read_u8(data, offset)

        include_cancelled = bool(flags & 0x01)
        include_superseded = bool(flags & 0x02)
        include_purged = bool(flags & 0x04)

        if origin == "":
            all_boards = self._nav.list_boards()
            origins_with_board = [
                b["origin"]
                for b in all_boards
                if b["board"] == board
                and (not self._allowed_origins or b["origin"] in self._allowed_origins)
            ]

            all_articles = []
            for orig in origins_with_board:
                bp = self._get_board_projection(orig, board)
                articles = bp.list_articles(
                    orig,
                    board,
                    offset=0,
                    limit=list_offset + limit,
                    include_cancelled=include_cancelled,
                    include_superseded=include_superseded,
                    include_purged=include_purged,
                )
                for art in articles:
                    all_articles.append((art, orig))

            all_articles.sort(key=lambda x: (-x[0].created_at, x[1], x[0].article_num))
            page = all_articles[list_offset : list_offset + limit]

            out = struct.pack(">H", len(page))
            for art, orig in page:
                out += _enc_text16(orig)
                out += self._encode_article_view(art, include_body=False)
            return _success(out)

        self._maybe_queue_remote_sync(origin)
        if origin and self._allowed_origins and origin not in self._allowed_origins:
            return _success(struct.pack(">H", 0))
        bp = self._get_board_projection(origin, board)
        articles = bp.list_articles(
            origin,
            board,
            offset=list_offset,
            limit=limit,
            include_cancelled=include_cancelled,
            include_superseded=include_superseded,
            include_purged=include_purged,
        )

        out = struct.pack(">H", len(articles))
        for art in articles:
            out += self._encode_article_view(art, include_body=False)
        return _success(out)

    # ------------------------------------------------------------------
    # ARTICLE_SEARCH
    # ------------------------------------------------------------------

    def _cmd_article_search(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        board, offset = _read_text16(data, offset)
        if not self._board_read_allowed(ctx, "ARTICLE_SEARCH", board):
            out = struct.pack(">H", 0) + struct.pack(">I", 0) + struct.pack(">B", 0)
            return _success(out)
        meta_query, offset = _read_text16(data, offset)
        body_query, offset = _read_text16(data, offset)
        list_offset, offset = _read_u32(data, offset)
        limit, offset = _read_u16(data, offset)
        flags, offset = _read_u8(data, offset)

        include_cancelled = bool(flags & 0x01)
        include_superseded = bool(flags & 0x02)

        if origin == "":
            all_boards = self._nav.list_boards()
            origins_with_board = [
                b["origin"]
                for b in all_boards
                if b["board"] == board
                and (not self._allowed_origins or b["origin"] in self._allowed_origins)
            ]

            all_results = []
            total = 0
            truncated = False
            for orig in origins_with_board:
                bp = self._get_board_projection(orig, board)
                if body_query:
                    results = self._search.search_bodies(
                        bp,
                        orig,
                        board,
                        body_query,
                        offset=0,
                        limit=list_offset + limit,
                        include_cancelled=include_cancelled,
                        include_superseded=include_superseded,
                    )
                else:
                    results = self._search.search_metadata(
                        bp,
                        orig,
                        board,
                        text_query=meta_query,
                        offset=0,
                        limit=list_offset + limit,
                        include_cancelled=include_cancelled,
                        include_superseded=include_superseded,
                    )
                for r in results.results:
                    all_results.append((r, orig))
                total += results.total
                if results.truncated:
                    truncated = True

            all_results.sort(key=lambda x: (-x[0].created_at, x[1], x[0].article_num))
            page = all_results[list_offset : list_offset + limit]

            out = struct.pack(">H", len(page))
            out += struct.pack(">I", total)
            out += struct.pack(">B", 1 if truncated else 0)
            for r, orig in page:
                out += _enc_text16(orig)
                out += struct.pack(">Q", r.article_num)
                out += struct.pack(">B", len(r.article_id)) + r.article_id
                subj_bytes = r.subject.encode("utf-8")
                out += struct.pack(">B", len(subj_bytes)) + subj_bytes
                out += struct.pack(">B", len(r.author_pubkey)) + r.author_pubkey
                out += struct.pack(">q", r.created_at)
                out += struct.pack(">B", 1 if r.body_available else 0)
                excerpt = r.excerpt.encode("utf-8") if r.excerpt else b""
                out += struct.pack(">H", len(excerpt)) + excerpt
            return _success(out)

        self._maybe_queue_remote_sync(origin)
        if origin and self._allowed_origins and origin not in self._allowed_origins:
            out = struct.pack(">H", 0) + struct.pack(">I", 0) + struct.pack(">B", 0)
            return _success(out)
        bp = self._get_board_projection(origin, board)

        if body_query:
            results = self._search.search_bodies(
                bp,
                origin,
                board,
                body_query,
                offset=list_offset,
                limit=limit,
                include_cancelled=include_cancelled,
                include_superseded=include_superseded,
            )
        else:
            results = self._search.search_metadata(
                bp,
                origin,
                board,
                text_query=meta_query,
                offset=list_offset,
                limit=limit,
                include_cancelled=include_cancelled,
                include_superseded=include_superseded,
            )

        out = struct.pack(">H", len(results.results))
        out += struct.pack(">I", results.total)
        out += struct.pack(">B", 1 if results.truncated else 0)
        for r in results.results:
            out += struct.pack(">Q", r.article_num)
            out += struct.pack(">B", len(r.article_id)) + r.article_id
            subj_bytes = r.subject.encode("utf-8")
            out += struct.pack(">B", len(subj_bytes)) + subj_bytes
            out += struct.pack(">B", len(r.author_pubkey)) + r.author_pubkey
            out += struct.pack(">q", r.created_at)
            out += struct.pack(">B", 1 if r.body_available else 0)
            excerpt = r.excerpt.encode("utf-8") if r.excerpt else b""
            out += struct.pack(">H", len(excerpt)) + excerpt
        return _success(out)

    # ------------------------------------------------------------------
    # ARTICLE_QUERY
    # ------------------------------------------------------------------

    def _cmd_article_query(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        if not origin:
            return _success(struct.pack(">H", 0))
        self._maybe_queue_remote_sync(origin)
        if origin and self._allowed_origins and origin not in self._allowed_origins:
            return _success(struct.pack(">H", 0))
        board, offset = _read_text16(data, offset)
        if not self._board_read_allowed(ctx, "ARTICLE_QUERY", board):
            return _success(struct.pack(">H", 0))
        filter_count, offset = _read_u8(data, offset)

        filters = []
        for _ in range(filter_count):
            field_id, offset = _read_u8(data, offset)
            operator, offset = _read_u8(data, offset)
            value_type, offset = _read_u8(data, offset)
            value_len, offset = _read_u16(data, offset)
            raw_value, offset = _read_bytes(data, offset, value_len, "filter value")

            value: bytes | str | int | bool
            if value_type == 0x01:
                value = raw_value
            elif value_type == 0x02:
                value = raw_value.decode("utf-8")
            elif value_type == 0x03:
                value = struct.unpack(">q", raw_value)[0]
            elif value_type == 0x04:
                value = raw_value[0] != 0
            else:
                return _error(0x0006, f"Invalid value type 0x{value_type:02x}")

            filters.append((field_id, operator, value))

        list_offset, offset = _read_u32(data, offset)
        limit, offset = _read_u16(data, offset)

        bp = self._get_board_projection(origin, board)
        articles = bp.query_articles(
            origin,
            board,
            filters,
            offset=list_offset,
            limit=limit,
        )

        out = struct.pack(">H", len(articles))
        for art in articles:
            out += self._encode_article_view(art, include_body=False)
        return _success(out)

    # ------------------------------------------------------------------
    # ARTICLE_BODY
    # ------------------------------------------------------------------

    def _cmd_article_body(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        if not origin:
            return _error(0x0003, "Article body unavailable")
        self._maybe_queue_remote_sync(origin)
        if origin and self._allowed_origins and origin not in self._allowed_origins:
            return _error(0x0003, "Article body unavailable")
        board, offset = _read_text16(data, offset)
        if not self._board_read_allowed(ctx, "ARTICLE_BODY", board):
            return _error(0x0003, "Article body unavailable")
        article_num, offset = _read_u64(data, offset)

        bp = self._get_board_projection(origin, board)
        art = bp.get_article_by_num(origin, board, article_num)
        if art is None:
            return _error(0x0003, "Article not found")

        if art.body_state == "purged":
            return _error(0x0008, "Article body purged")

        if art.body_size == 0:
            return _success(struct.pack(">I", 0))

        body = self._body_store.get_article_body(
            origin,
            board,
            article_num,
            art.body_hash,
            art.body_size,
        )
        if body is None:
            if origin != self._origin:
                peer = self._peer_map.get(origin)
                if peer:
                    out = _enc_text16(origin)
                    out += _enc_text16(peer.hostname)
                    out += struct.pack(">H", peer.port)
                    out += struct.pack(">B", 1 if peer.verify_tls else 0)
                    return b"\x02" + out
            return _error(0x0003, "Body unavailable")

        return _success(struct.pack(">I", len(body)) + body)

    # ------------------------------------------------------------------
    # USER_GET
    # ------------------------------------------------------------------

    def _cmd_user_get(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        if not origin:
            return _error(0x0001, "User not found")
        self._maybe_queue_remote_sync(origin)
        if origin and self._allowed_origins and origin not in self._allowed_origins:
            return _error(0x0001, "User not found")
        pubkey_len, offset = _read_u8(data, offset)
        pubkey, offset = _read_bytes(data, offset, pubkey_len, "pubkey")

        user = self._users.get_user_by_pubkey(origin, pubkey)
        if user is None:
            return _error(0x0001, "User not found")

        out = struct.pack(">B", len(user["user_pubkey"])) + user["user_pubkey"]
        username = user["username"].encode("utf-8")
        out += struct.pack(">H", len(username)) + username
        out += struct.pack(">Q", user["flags"])
        out += struct.pack(">Q", user["reg_seq"])
        out += struct.pack(">q", user["created_at"])
        out += struct.pack(">B", 1 if user["revoked"] else 0)
        revoked_seq = user.get("revoked_seq") or 0
        out += struct.pack(">Q", revoked_seq)
        return _success(out)

    # ------------------------------------------------------------------
    # USER_LIST
    # ------------------------------------------------------------------

    def _cmd_user_list(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        if not origin:
            return _success(struct.pack(">H", 0))
        self._maybe_queue_remote_sync(origin)
        if origin and self._allowed_origins and origin not in self._allowed_origins:
            return _success(struct.pack(">H", 0))
        flags, offset = _read_u8(data, offset)

        include_revoked = bool(flags & 0x01)
        users = self._users.list_users(origin, include_revoked=include_revoked)

        out = struct.pack(">H", len(users))
        for u in users:
            origin_bytes = u["origin"].encode("utf-8")
            out += struct.pack(">H", len(origin_bytes)) + origin_bytes
            out += struct.pack(">B", len(u["user_pubkey"])) + u["user_pubkey"]
            username = u["username"].encode("utf-8")
            out += struct.pack(">H", len(username)) + username
            out += struct.pack(">Q", u["flags"])
            out += struct.pack(">Q", u["reg_seq"])
            out += struct.pack(">q", u["created_at"])
            out += struct.pack(">B", 1 if u["revoked"] else 0)
        return _success(out)

    # ------------------------------------------------------------------
    # BAN_STATUS
    # ------------------------------------------------------------------

    def _cmd_ban_status(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        pubkey_len, offset = _read_u8(data, offset)
        pubkey, offset = _read_bytes(data, offset, pubkey_len, "pubkey")

        try:
            punishments = self._policy.list_pending_for_pubkey(
                pubkey,
                allowed_origins=self._allowed_origins or None,
            )
        except Exception as e:
            log_msg(f"BAN_STATUS: policy read failed: {type(e).__name__}: {e}")
            return _error(0x0000, "Internal error")

        out = struct.pack(">B", len(punishments))
        for p in punishments:
            out += struct.pack(">B", PUNISHMENT_TYPE_CODES.get(p["type"], 0))
            out += struct.pack(">q", p["expires_at"])
            out += struct.pack(">I", p["body_size"])
            out += p["body_hash"]
            out += p["event_id"]
            origin_bytes = p["origin"].encode("utf-8")
            out += struct.pack(">H", len(origin_bytes)) + origin_bytes

        return _success(out)

    # ------------------------------------------------------------------
    # EVENT_BODY
    # ------------------------------------------------------------------

    def _cmd_event_body(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        self._maybe_queue_remote_sync(origin)
        event_id, offset = _read_id32(data, offset)

        rec = self._firehose.get_event_by_id(origin, event_id)
        if rec is None:
            return _error(0x0003, "Event not found")

        if rec.body_size == 0:
            return _success(struct.pack(">I", 0))

        body = self._body_store.get_event_body(
            origin,
            event_id,
            rec.body_hash,
            rec.body_size,
        )
        if body is None:
            return _error(0x0003, "Event body unavailable")

        return _success(struct.pack(">I", len(body)) + body)
