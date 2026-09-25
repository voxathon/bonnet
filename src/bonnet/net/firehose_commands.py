# Copyright 2026 The Bonnet Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Command handler for the firehose protocol.

Handles PUBLISH_RECORD, EVENT_HEAD, EVENT_RANGE, EVENT_GET, and projection
read commands (BOARD_LIST, ARTICLE_GET/LIST/SEARCH/BODY, USER_GET/LIST,
BAN_STATUS, EVENT_BODY).

Each request is a binary body starting with one opcode byte. Responses begin
with status:u8 (0=success, 1=error).
"""

from __future__ import annotations

import heapq
import struct
import threading
import time
from contextlib import nullcontext
from typing import Any

from bonnet.core.acl import ACLEvaluator, AuthContext
from bonnet.core.board_projection import (
    ARTICLE_ID_IN,
    QUERY_FIELD_IDS,
    BoardProjection,
    board_db_path,
)
from bonnet.core.bodies import BodyStore
from bonnet.core.crypto import Identity
from bonnet.core.firehose import (
    KIND_ARTICLE,
    FirehoseError,
    FirehoseStore,
)
from bonnet.core.global_projections import NavProjection, PolicyProjection, UserProjection
from bonnet.core.kind_validator import KindValidator, ValidationError
from bonnet.core.kinds import (
    ALL_KNOWN_KINDS,
    ARTICLE_CONTROL_KINDS,
    BOARD_LIFECYCLE_KINDS,
    KIND_ARTICLE_CANCEL,
    KIND_ARTICLE_PIN,
    KIND_ARTICLE_PURGE,
    KIND_ARTICLE_RESTORE,
    KIND_ARTICLE_UNPIN,
    KIND_BOARD_CLOSE,
    KIND_BOARD_CREATE,
    KIND_BOARD_PURGE,
    KIND_BOARD_REOPEN,
    KIND_PUNISHMENT_ACK,
    KIND_PUNISHMENT_BAN,
    KIND_PUNISHMENT_PERMABAN,
    KIND_THREAD_CLOSE,
    KIND_THREAD_REOPEN,
    KIND_USER_KEY_ROTATE,
    KIND_USER_REGISTER,
)
from bonnet.core.logging import log_debug, log_info, log_msg, log_warning
from bonnet.core.record import (
    SIG_SIZE,
    ZERO_ID,
    CodecError,
    Intent,
    compute_body_hash,
    compute_event_hash,
    decode_intent,
    encode_head,
    encode_record,
    encode_witness,
    make_origin_witness,
    normalize_origin,
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
    QUERY_NEWEST_FIRST,
    _enc_text16,
    _read_bytes,
    _read_id32,
    _read_text16,
    _read_u8,
    _read_u16,
    _read_u32,
    _read_u64,
)

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


def _require_request_end(data: bytes, offset: int, what: str) -> None:
    """Reject a request with bytes left over after its declared fields.

    Raises ValueError so handle() turns it into a 0x0006 frame. Extra bytes
    are never padding — they mean the peer encoded a different layout than
    this handler decoded, and silently ignoring them lets two sides disagree
    about what was asked.
    """
    if offset != len(data):
        raise ValueError(f"trailing bytes after {what}: {len(data) - offset} extra")


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
        via_bridge_runtime: bool = False,
    ):
        self.peer_pubkey = peer_pubkey
        self.is_anonymous = is_anonymous
        self.is_unknown = is_unknown
        self.is_registered = is_registered
        self.role = role
        self.origin = origin
        self.remote_addr = remote_addr
        # Set only by the bridge runtime's in-process publisher
        # (bonnet.bridges.local_publish), never by derive_context, so no
        # network request can claim it.
        self.via_bridge_runtime = via_bridge_runtime

    def to_auth_context(self) -> AuthContext:
        return AuthContext(
            pubkey=self.peer_pubkey,
            role=self.role,
            origin=self.origin,
            is_anonymous=self.is_anonymous,
            is_unknown=self.is_unknown,
            is_registered=self.is_registered,
        )


def derive_context(
    users: UserProjection | None,
    origin: str,
    peer_pubkey: bytes,
    remote_addr: str,
    anonymous_pubkey: bytes,
) -> FirehoseContext:
    """The request context for an authenticated key, as the HTTP server sees it.

    The single definition of how a key maps to a principal: anonymous, a
    registered user (with role from its flags), or unknown. Registered means
    registered here, not revoked, and not superseded. A rotated key stops
    authenticating as registered the moment the rotation dispatches, which
    is the point of rotating after a compromise.

    Shared by the HTTP server and the bridge runtime's in-process publisher
    so the two can't drift; never hand-set `role` anywhere else.
    """
    is_anonymous = peer_pubkey == anonymous_pubkey
    role = ""
    is_registered = False
    is_unknown = False

    if not is_anonymous:
        if users is not None:
            user = users.get_user_by_pubkey(origin, peer_pubkey)
            successor = user.get("superseded_by") if user else None
            if successor is not None:
                # Logged with the successor so a client still holding the
                # retired key gets a diagnosable failure instead of an
                # unexplained demotion to unknown.
                log_msg(
                    f"AUTH: origin='{origin}' key "
                    f"{peer_pubkey.hex()[:16]} was superseded by "
                    f"{successor.hex()[:16]}; treating as unknown"
                )
                is_unknown = True
            elif user is not None and not user.get("revoked", False):
                is_registered = True
                flags = user.get("flags", 0)
                if flags & 0x01:
                    role = "administrator"
                elif flags & 0x02:
                    role = "moderator"
            else:
                is_unknown = True
        else:
            is_unknown = True

    return FirehoseContext(
        peer_pubkey=peer_pubkey,
        is_anonymous=is_anonymous,
        is_unknown=is_unknown,
        is_registered=is_registered,
        role=role,
        origin=origin,
        remote_addr=remote_addr,
    )


# ARTICLE_QUERY filter fields answered from bridges.db (design doc §9.5).
BRIDGE_QUERY_FIELD_IDS = frozenset({0x0B, 0x0C})


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
        wire_max: int = 32,
        bridge_policy=None,
        bridge_projection=None,
        recognized_bridges: dict | None = None,
        bridge_venue_types: dict | None = None,
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
        self._wire_max = max(1, min(32, wire_max))
        # bonnet.bridges.model.BridgePolicy on a bridge origin, else None.
        self._bridge_policy = bridge_policy
        # bonnet.core.bridge_projection.BridgeProjection (bridges.db), and the
        # venue -> recognized bridge origins map ([[recognize]] + own runtime).
        self._bridges = bridge_projection
        self._recognized_bridges = dict(recognized_bridges or {})
        self._bridge_venue_types = dict(bridge_venue_types or {})
        # bonnet.bridges.admission.Admission on a bridge origin with
        # bridges.toml [admission] enabled, else None (set by BonnetServer).
        self._admission: Any = None
        # Venues whose runtime is running in this process right now; the
        # bridge runtime adds and removes itself (manifest `local`).
        self.live_bridge_venues: set[str] = set()
        # Serializes the check-then-append span for bonnet.user.register,
        # bonnet.board.create and bonnet.user.key.rotate: without it, two
        # concurrent registrations for the same name can both read "no holder
        # yet" before either appends, so both get appended as distinct signed
        # records even though the projection later resolves only one of them
        # as the winner (and likewise two concurrent rotates onto one key).
        # Held across the dispatcher call too (dispatch_origin runs
        # synchronously here), so a blocked second registration re-checks
        # against a projection that has already caught up with the first.
        self._identity_lock = threading.Lock()
        # Per-board striped locks for the closed-board write gate. Article
        # publishes are high-volume, so a single global lock would serialize
        # every board behind one mutex; stripes keep the check-then-append
        # race (article vs close racing on the SAME board) serialized while
        # letting different boards proceed in parallel. RLock: the publish
        # path re-reads the same board twice (no-board check, then supersede
        # / control-target lookup). Fixed order everywhere: stripe ->>
        # _identity_lock -> FirehoseStore -> Dispatcher -> projections, and
        # the stripe is never taken from inside dispatch/rebuild/sync.
        self._board_write_stripes: list[threading.RLock] = [threading.RLock() for _ in range(256)]

    def _board_stripe(self, origin: str, board: str) -> threading.RLock:
        return self._board_write_stripes[hash((origin, board)) % len(self._board_write_stripes)]

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

    @staticmethod
    def _effective_board(intent) -> tuple[str, str | None]:
        """Board a publish acts on, for ACL and closed-gate purposes.

        Articles and board-lifecycle records carry it in `intent.board`;
        article controls (cancel/restore/purge/pin/unpin/thread.close/reopen)
        force `board == ""` and carry it in the target tuple instead. Using
        the target here is what lets `boards = [...]` ACL rules actually
        scope controls, and what lets the closed gate see which board a
        control would mutate. Returns (origin, board); board is None for
        board-agnostic kinds (register, ack, revokes, key rotation).
        """
        if intent.kind == KIND_ARTICLE or intent.kind in BOARD_LIFECYCLE_KINDS:
            return (intent.origin, intent.board or None)
        if intent.kind in ARTICLE_CONTROL_KINDS:
            if intent.target_origin and intent.target_board:
                return (intent.target_origin, intent.target_board)
            return (intent.origin, None)
        return (intent.origin, None)

    def _closed_board_denial(
        self, intent, ctx: FirehoseContext
    ) -> tuple[bytes | None, tuple[str, str | None]]:
        """Refuse article writes into a closed board, with owner/admin bypass.

        Returns (error_response_or_None, (eff_origin, eff_board)). `reopen`
        is never gated (else a close deadlocks); federated records never
        reach this path — dispatch still projects/relays them verbatim.
        """
        eff_origin, eff_board = self._effective_board(intent)
        if eff_board is None:
            return None, (eff_origin, eff_board)
        if intent.kind != KIND_ARTICLE and intent.kind not in ARTICLE_CONTROL_KINDS:
            return None, (eff_origin, eff_board)
        # Only a board on this origin can gate a local publish; a control
        # naming a foreign board is some other origin's business (and its
        # own origin will enforce it there).
        if eff_origin != self._origin:
            return None, (eff_origin, eff_board)
        try:
            board = self._nav.get_board(eff_origin, eff_board)
        except Exception:
            return None, (eff_origin, eff_board)
        if board is None or not board.get("closed"):
            return None, (eff_origin, eff_board)
        try:
            is_owner = bytes(board.get("owner_pubkey") or b"") == bytes(
                intent.actor_pubkey or b""
            ) and bool(intent.actor_pubkey)
        except Exception:
            is_owner = False
        if is_owner or ctx.role in ("administrator", "moderator"):
            return None, (eff_origin, eff_board)
        log_warning("PUBLISH deny reason=board-closed", board=eff_board)
        return _error(0x0004, f"Board '{eff_board}' is closed"), (eff_origin, eff_board)

    @staticmethod
    def _register_subject_suffix(intent) -> str:
        """Subject hint for the EVENT log line on user.register records.

        Best-effort: malformed federated metadata must not break logging.
        """
        try:
            if intent.kind != KIND_USER_REGISTER:
                return ""
            username = intent.metadata.get_text(1) or ""
            subject = intent.metadata.get_bytes(2)
            flags = intent.metadata.get_u64(3)
            if not username and not subject:
                return ""
            short = subject.hex()[:16] if subject else "?"
            return f" subject={username!r}/{short} flags={flags if flags is not None else 0}"
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # Punishment write gate
    # ------------------------------------------------------------------

    def _policy_current(self) -> bool:
        """True when the policy projection has caught up with the firehose."""
        # Snapshot: the sync manager adds and removes learned origins from
        # this set on the event loop while this runs in a worker thread.
        for origin in list(self._allowed_origins or {self._origin}):
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

    def _log_write_denial(self, cmd_name: str, ctx: FirehoseContext, result: bytes) -> None:
        """Log a write rejected by the ACL, a validator, or a domain rule.

        A headless server otherwise records nothing past startup — every
        acceptance already lands in events.db, but a denial never does, so
        without this an operator has no way to see one happen at all.
        """
        if not result or result[0:1] != b"\x01":
            return
        code = struct.unpack(">H", result[1:3])[0]
        msg_len = struct.unpack(">H", result[3:5])[0]
        reason = result[5 : 5 + msg_len].decode("utf-8", errors="replace")
        actor = ctx.peer_pubkey.hex() if ctx.peer_pubkey else "-"
        log_msg(f"DENIED: {cmd_name} actor={actor} code=0x{code:04x} reason={reason}")

    def handle(self, body: bytes, ctx: FirehoseContext) -> bytes:
        if not body:
            return _error(0x0006, "Empty request")

        opcode = body[0]
        data = body[1:]
        cmd_name = CMD_NAMES.get(opcode, f"UNKNOWN_{opcode:02x}")

        if opcode not in CMD_NAMES:
            log_warning("COMMAND deny reason=unknown-opcode", opcode=f"0x{opcode:02x}")
            return _error(0x0005, f"Unknown opcode 0x{opcode:02x}")

        action = "write" if opcode in WRITE_OPS else "read"

        if action == "read":
            if not self._acl.check(ctx.to_auth_context(), action, command=cmd_name):
                log_warning(
                    "COMMAND deny",
                    cmd=cmd_name,
                    actor=ctx.peer_pubkey.hex()[:16] if ctx.peer_pubkey else "-",
                )
                return _error(0x0004, "Command not permitted")

        try:
            if opcode == OP_PUBLISH_RECORD:
                result = self._cmd_publish(data, ctx)
                self._log_write_denial(cmd_name, ctx, result)
                if result and result[0:1] == b"\x00":
                    log_info(
                        "PUBLISH ok",
                        actor=ctx.peer_pubkey.hex()[:16] if ctx.peer_pubkey else "-",
                    )
                return result
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
        except (FirehoseError, ValidationError, CodecError) as e:
            return _error(0x0006, str(e))
        except Exception as e:
            log_msg(f"COMMAND: {cmd_name} failed unexpectedly: {e}")
            return _error(0x0000, "Internal error")

    # ------------------------------------------------------------------
    # Bridge reads (docs/bonnet-bridges-design.md §9.4, §9.5, §10.1)
    # ------------------------------------------------------------------

    def _dedups(self, board: str) -> bool:
        """Aggregate reads of `~` boards show one canonical copy per foreign post."""
        return board.startswith("~") and self._bridges is not None

    def _bridge_view(self):
        from bonnet.core.bridge_projection import BridgeView

        return BridgeView(self._bridges, self._recognized_bridges)

    def _canonical_article_page(
        self, board: str, origins: list[str], list_offset: int, limit: int, **flags
    ) -> list:
        """A lazy k-way merge over each origin's rows in aggregate order.

        Each origin's rows come in (created_at DESC, article_num) order, so
        merging on (-created_at, origin, article_num) yields the aggregate
        order. Non-canonical copies are skipped as they stream past, and
        batches are pulled until the page is full or every origin runs out.
        """
        view = self._bridge_view()
        batch = max(limit, 50)

        def stream(orig: str):
            bp = self._get_board_projection(orig, board)
            pos = 0
            while True:
                rows = bp.list_articles(orig, board, offset=pos, limit=batch, **flags)
                for art in rows:
                    yield (-art.created_at, orig, art.article_num), art, orig
                if len(rows) < batch:
                    return
                pos += batch

        page: list = []
        skipped = 0
        merged = heapq.merge(*(stream(o) for o in origins), key=lambda t: t[0])
        for _, art, orig in merged:
            if not view.visible_event(orig, art.event_id):
                continue
            if skipped < list_offset:
                skipped += 1
                continue
            page.append((art, orig))
            if len(page) >= limit:
                break
        return page

    def _canonical_search_page(
        self, board: str, origins: list[str], run_search, list_offset: int, limit: int
    ) -> tuple[list, int, bool]:
        """Search rows with non-canonical copies removed; `total` counts survivors.

        Per-origin search results aren't in aggregate order, so there's no
        merge to stream: the window per origin grows until every origin has
        returned all its matches (or the search cap is reached, which marks
        the response truncated), then survivors are sorted and paged.
        """
        view = self._bridge_view()
        cap = max(getattr(self._search, "_max_count", 1000), list_offset + limit)
        window = list_offset + limit
        while True:
            rows: list = []
            exhausted = True
            truncated = False
            for orig in origins:
                results = run_search(orig, window)
                if len(results.results) >= window:
                    exhausted = False
                elif results.truncated:
                    truncated = True
                rows.extend((r, orig) for r in results.results)
            if exhausted or window >= cap:
                truncated = truncated or not exhausted
                break
            window = min(window * 2, cap)
        survivors = [(r, o) for r, o in rows if view.visible_article(o, board, r.article_id)]
        survivors.sort(key=lambda x: (-x[0].created_at, x[1], x[0].article_num))
        return survivors[list_offset : list_offset + limit], len(survivors), truncated

    def _bridge_filter_article_ids(
        self, origin: str, board: str, field_id: int, operator: int, value
    ) -> list[bytes] | bytes:
        """Article ids on (origin, board) matching a bridge filter, or an error frame."""
        from bonnet.core.bridge_projection import src_from_filter

        if not isinstance(value, str):
            return _error(0x0006, f"filter field 0x{field_id:02x} takes text")
        if field_id == 0x0B and operator in (0x01, 0x06):
            parts = value.split(",") if operator == 0x06 else [value]
            srcs = [src_from_filter(p.strip()) for p in parts if p.strip()]
            if any(src is None for src in srcs):
                return _error(0x0006, "src filter must be venue#channel#foreign_id")
            return self._bridges.article_ids_for_src(origin, board, srcs)
        if field_id == 0x0C and operator == 0x01:
            root = src_from_filter(value)
            if root is None:
                return _error(0x0006, "foreign_root filter must be venue#channel#root_foreign_id")
            return self._bridges.article_ids_for_root(origin, board, root)
        return _error(0x0006, f"unsupported operator 0x{operator:02x} for field 0x{field_id:02x}")

    def recognized_origins(self, venue: str) -> list[str]:
        return list(self._recognized_bridges.get(venue, []))

    def recognize_bridge_origin(self, venue: str, origin: str, venue_type: str = "") -> None:
        """Adopt `origin` for `venue`, after every origin already recognized (M3)."""
        order = self._recognized_bridges.setdefault(venue, [])
        if origin not in order:
            # Replace rather than append in place: a BridgeView built from
            # the old list mid-request keeps a consistent snapshot.
            self._recognized_bridges[venue] = [*order, origin]
        if venue_type:
            self._bridge_venue_types.setdefault(venue, venue_type)

    def bridges_manifest(self) -> list[dict]:
        """The discovery document's `bridges` list (§10.1), computed per request.

        One entry per recognized venue and bound channel. `status` says
        whether this server holds the binding records behind it:

          bound     one entry per bound (venue, channel): the recognized
                    origins whose binding records for it are synced and
                    active, in preference order, with the board they bind
          unsynced  recognized, but no binding for the venue has arrived
                    (the origin isn't a sync peer yet, hasn't synced, or
                    never bound it): every recognized origin, and no board

        An entry this server binds itself also says whether it admits
        crossposters (`admission`); a server can't know that of another.
        """
        if self._bridges is None:
            return []
        bindings = self._bridges.active_bindings()
        out = []
        for venue, order in self._recognized_bridges.items():
            venue_type = self._bridge_venue_types.get(venue, venue.partition("@")[0])
            channels: dict[str, dict[str, dict]] = {}
            for b in bindings:
                if b["venue"] == venue and b["origin"] in order:
                    channels.setdefault(b["channel"], {})[b["origin"]] = b
            if not channels:
                out.append(
                    {
                        "type": venue_type,
                        "venue": venue,
                        "status": "unsynced",
                        "board": None,
                        "origins": list(order),
                        "local": False,
                    }
                )
                continue
            for channel, by_origin in sorted(channels.items()):
                origins = [o for o in order if o in by_origin]
                first = (
                    by_origin[self._origin] if self._origin in by_origin else by_origin[origins[0]]
                )
                cap = first.get("max_body_bytes") or self._max_body_size
                entry = {
                    "type": venue_type,
                    "venue": venue,
                    "status": "bound",
                    "board": first["board"],
                    "origins": origins,
                    "local": venue in self.live_bridge_venues and self._origin in by_origin,
                    "max_body_bytes": min(cap, self._max_body_size),
                }
                if self._origin in by_origin:
                    entry["admission"] = self._admission is not None
                if channel:
                    entry["channel"] = channel
                out.append(entry)
        return out

    # ------------------------------------------------------------------
    # Bridge reservations (docs/bonnet-bridges-design.md §8)
    # ------------------------------------------------------------------

    def _bridge_reservation_denial(self, intent: Intent, ctx: FirehoseContext) -> bytes | None:
        """Refuse local publishes that would squat on bridge namespaces.

        Every origin reserves boards starting with `~` for its own bridge
        runtime, and bridge records and roles for the runtime alone. A bridge origin also closes registration: only the runtime
        (its daemon, and puppets named `<handle>~<type>` for a type it runs)
        and administrators may register. Crossposters are admitted by
        appending straight to the firehose, so they never reach this check,
        and neither do federated records.
        """
        if (
            intent.kind == KIND_BOARD_CREATE
            and intent.board.startswith("~")
            and not ctx.via_bridge_runtime
        ):
            return _error(0x0004, "Boards starting with '~' are reserved for this origin's bridge")
        if not ctx.via_bridge_runtime:
            # Bridge facts (bindings, links, observations, mirrors) are the
            # runtime's to state; readers dedup and thread on them. The ACL
            # grants these kinds to the daemon alone, but an operator's broad
            # allow rule mustn't be able to widen that. A crosspost is the one
            # role a user may claim, and it counts for nothing until the
            # bridge observes it at the venue.
            from bonnet.bridges.model import ROLE_CROSSPOST, BridgeMetadata

            if intent.kind.startswith("bonnet.bridge."):
                return _error(0x0004, "Bridge records are published by the bridge runtime only")
            if intent.kind == KIND_ARTICLE:
                role = BridgeMetadata.from_metadata(intent.metadata).bridge_role
                if role is not None and role != ROLE_CROSSPOST:
                    return _error(
                        0x0004, "Only the bridge runtime may publish mirrors of foreign posts"
                    )
        policy = self._bridge_policy
        if policy is None or intent.kind != KIND_USER_REGISTER or ctx.role == "administrator":
            return None
        if ctx.via_bridge_runtime:
            name = intent.metadata.get_text(1) or ""
            if intent.actor_pubkey == policy.daemon_pubkey and "~" not in name:
                return None
            if policy.is_puppet_name(name):
                return None
            return _error(0x0004, "The bridge runtime may only register puppets as <handle>~<type>")
        return _error(
            0x0004,
            "Registration on this bridge origin is closed; crossposters are admitted "
            "through their home origin",
        )

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
        _require_request_end(data, offset, "publish request")

        intent = decode_intent(encoded_intent)

        if intent.origin != self._origin:
            log_warning("PUBLISH deny reason=origin-mismatch", kind=intent.kind)
            return _error(0x0004, "Origin mismatch")

        if intent.actor_pubkey != ctx.peer_pubkey:
            log_warning(
                "PUBLISH deny reason=actor-mismatch",
                kind=intent.kind,
                actor=intent.actor_pubkey.hex()[:16],
            )
            return _error(0x0004, "Actor pubkey does not match authenticated key")

        try:
            self._validator.validate(intent)
        except ValidationError as e:
            log_warning("PUBLISH deny reason=validation", kind=intent.kind, err=str(e)[:120])
            return _error(0x0006, f"Validation error: {e}")

        # Bridge admission (docs/bonnet-bridges-design.md §6): a crossposter's
        # home key is checked against its home origin, and admitted on first
        # contact. Before the ACL check and outside every lock: it may wait on
        # the network. An admitted key continues as a registered principal.
        if self._admission is not None:
            from bonnet.bridges.admission import AdmissionRefused

            try:
                admitted = self._admission.check(intent, ctx)
            except AdmissionRefused as e:
                log_warning("PUBLISH deny reason=admission", err=str(e)[:120])
                return _error(0x0004, f"Admission refused: {e}")
            if admitted is not None:
                ctx = admitted

        kind = intent.kind
        board = intent.board
        eff_origin, eff_board = self._effective_board(intent)
        if not self._acl.check(
            ctx.to_auth_context(),
            "write",
            command="PUBLISH_RECORD",
            kind=kind,
            board=eff_board,
        ):
            log_warning(
                "PUBLISH deny reason=acl",
                kind=kind,
                board=eff_board or board or "-",
                actor=ctx.peer_pubkey.hex()[:16] if ctx.peer_pubkey else "-",
            )
            return _error(0x0004, "Not permitted")

        # An article needs a real board to land in - see
        # Dispatcher._dispatch_article for why a bare publish is no longer
        # allowed to silently mint one. Refused here, before append, so the
        # caller gets a clean error instead of a "successful" publish that
        # then never surfaces as a queryable article.
        if kind == KIND_ARTICLE and self._nav.get_board(intent.origin, board) is None:
            log_warning("PUBLISH deny reason=no-board", board=board)
            return _error(0x0003, f"Board '{board}' does not exist - create it first")

        # Closed boards refuse new articles and article controls. Owner and
        # admin/moderator bypass; reopen is never gated; federated records
        # never reach this handler so they still project/relay verbatim.
        closed_denial, _ = self._closed_board_denial(intent, ctx)
        if closed_denial is not None:
            return closed_denial

        # Registration gates: privilege, and subject.
        #
        # The actor binding above fixes *who signed*, but a registration also
        # carries the key it is about (field 2) and the flags that
        # firehose_http_server reads back as `role` (field 3). Neither was
        # constrained, and the shipped ACL grants unknown principals
        # bonnet.user.register so the first-run flow works — which made
        # administrator self-service on first contact, and let anyone bind a
        # username onto a key they do not hold.
        #
        # Administrators are exempt on both counts, because provisioning is a
        # genuine operator task: `console.grant-role` registers another party's
        # key with a role over the local connection, which authenticates as
        # administrator (app/cli.py FirehoseLocalConnection). Note that on the
        # shipped config no principal can reach that exemption — the register
        # kind is granted to `unknown` alone and the matchers are mutually
        # exclusive — so an operator who wants it has to grant it explicitly.
        #
        # Nothing else legitimate is blocked: the gateway's register tool
        # publishes flags=0 for its own key, and the server's own root
        # registration (BonnetServer._ensure_root_registered) is appended
        # directly to the firehose without passing through this handler.
        if kind == KIND_USER_REGISTER and ctx.role != "administrator":
            if (intent.metadata.get_u64(3) or 0) != 0:
                return _error(0x0004, "Only an administrator may register privileged flags")
            if intent.metadata.get_bytes(2) != intent.actor_pubkey:
                return _error(
                    0x0004, "Only an administrator may register a username for another key"
                )

        reserved = self._bridge_reservation_denial(intent, ctx)
        if reserved is not None:
            return reserved

        identity_guard = (
            self._identity_lock
            if kind in (KIND_USER_REGISTER, KIND_BOARD_CREATE, KIND_USER_KEY_ROTATE)
            else nullcontext()
        )
        # Stripe key: the board this publish would mutate, so a close racing
        # an article on the SAME board serializes while different boards run
        # in parallel. Board-agnostic kinds stripe by kind to avoid collapsing
        # onto one lock. Fixed order: stripe -> _identity_lock -> store ->
        # dispatcher -> projections; never taken from inside dispatch/sync.
        stripe_key = (eff_origin, eff_board) if eff_board else (self._origin, f"kind:{kind}")
        with self._board_stripe(*stripe_key), identity_guard:
            # Re-check under the stripe: a close may have landed between the
            # fast-path check above and lock acquisition.
            locked_denial, _ = self._closed_board_denial(intent, ctx)
            if locked_denial is not None:
                return locked_denial
            # First writer wins on a username, within this origin. UserProjection
            # enforces this too and has to, since federated registrations never
            # reach this handler — but refusing here is what lets a local caller
            # see why, which is the behaviour the gateway's register tool already
            # documents ("the server rejects the registration and this reports the
            # failure — pick another name").
            if kind == KIND_USER_REGISTER:
                requested = intent.metadata.get_text(1) or ""
                subject = intent.metadata.get_bytes(2) or intent.actor_pubkey
                holder = self._users.username_holder(intent.origin, requested)
                if holder is not None and holder != subject:
                    return _error(0x0009, f"Username '{requested}' is already registered")
                if holder is not None and holder == subject:
                    # Exact duplicate re-registration: same key, same name,
                    # same flags. Refuse so repeat connect+register loops and
                    # no-op grant-role calls don't spam the append-only log.
                    # A changed-flags grant (role update) still passes — the
                    # admin privilege checks above already ran — as does a
                    # rename (different name = holder is None above).
                    requested_flags = intent.metadata.get_u64(3) or 0
                    try:
                        existing = self._users.get_user_by_pubkey(intent.origin, subject)
                    except Exception:
                        existing = None
                    if (
                        existing is not None
                        and not existing.get("revoked")
                        and existing.get("username") == requested
                        and (existing.get("flags") or 0) == requested_flags
                    ):
                        return _error(
                            0x0009,
                            f"Username '{requested}' is already registered to this key",
                        )

            # A key is single-use per origin: rotating onto a key this origin
            # has ever registered — a previous key of this user, another
            # user's key, a revoked key — would either cycle the succession
            # (both keys reading superseded, nobody able to authenticate) or
            # silently merge two identities. UserProjection enforces this too
            # and has to, since federated rotates never reach this handler —
            # but refusing here is what lets a local caller see why.
            if kind == KIND_USER_KEY_ROTATE:
                new_pubkey = intent.metadata.get_bytes(1)
                if new_pubkey is not None:
                    try:
                        prior = self._users.get_user_by_pubkey(intent.origin, new_pubkey)
                    except Exception:
                        prior = None
                    if prior is not None:
                        return _error(
                            0x0009,
                            "New key is already registered at this origin; rotate onto a fresh key",
                        )

            # Same rule, same reason, for board names: first writer wins.
            # NavProjection.apply_board_create enforces this too and has to,
            # since a federated board.create never reaches this handler either —
            # but refusing here is what lets a local caller see why, instead of
            # a signed record that's silently accepted and then just never takes
            # ownership.
            #
            # Refused even when the *same* owner re-creates their own board:
            # a second bonnet.board.create for a name that already exists is
            # a spurious "I created this" claim minted into the append-only
            # log for no effect (the projection dedupes it away silently, but
            # the log itself now carries two creation claims with nothing to
            # say either was a no-op). Same for user.register: an exact
            # duplicate (same key, same name, same flags) is refused above,
            # which is what lets the gateway map it to already_registered
            # instead of appending a new seq. Changed flags (a role update by
            # an admin) still pass.
            if kind == KIND_BOARD_CREATE:
                claimed_owner = intent.metadata.get_bytes(1) or intent.actor_pubkey
                existing_board = self._nav.get_board(intent.origin, board)
                if existing_board is not None:
                    if existing_board["owner_pubkey"] != claimed_owner:
                        return _error(0x0009, f"Board '{board}' is already owned by someone else")
                    return _error(0x0009, f"Board '{board}' already exists")

            # Board close/reopen name a real board and a real state change:
            # a close for a name nobody created (or one already purged, whose
            # nav row is gone) and a duplicate close / reopen of an already-
            # open board would otherwise append a signed no-effect record —
            # the same "spurious claim minted into the append-only log" the
            # board.create block above refuses. Purge is the deliberate
            # exception (second/absent purge stays a success *without
            # append* — see the noop block below — so names remain
            # reclaimable without spamming the append-only log). Checked
            # under the stripe so concurrent close/reopen/article on the
            # same board serialize.
            if kind in (KIND_BOARD_CLOSE, KIND_BOARD_REOPEN):
                target_board = self._nav.get_board(intent.origin, board)
                if target_board is None:
                    return _error(0x0003, f"Board '{board}' does not exist")
                if kind == KIND_BOARD_CLOSE:
                    if target_board.get("closed"):
                        return _error(0x0009, f"Board '{board}' is already closed")
                elif not target_board.get("closed"):
                    return _error(0x0009, f"Board '{board}' is not closed")

            # The identity a record is published under is the registrar's to state,
            # not the caller's to choose. Until now `actor_username` and
            # `actor_registrar` were free text on every record: the actor binding
            # above fixes the *key*, and the two fields a reader actually reads went
            # unchecked, so any authenticated key could publish as anyone.
            #
            # Refusal rather than substitution, deliberately. Both fields sit inside
            # the bytes the actor signed, so rewriting them server-side would
            # invalidate the intent signature. Refusing keeps two properties at
            # once: the author signed the name they published under, and the name is
            # one this origin issued to that key.
            #
            # Empty stays legal — claiming nothing is honest. bonnet.user.register
            # is exempt because it is the record that establishes the name; there is
            # nothing to check it against yet.
            if kind != KIND_USER_REGISTER:
                if intent.actor_registrar and intent.actor_registrar != self._origin:
                    return _error(
                        0x0004,
                        f"actor_registrar must be '{self._origin}' on a record published here",
                    )
                if intent.actor_username:
                    registered = self._users.get_user_by_pubkey(self._origin, intent.actor_pubkey)
                    if registered is None or registered["username"] != intent.actor_username:
                        return _error(
                            0x0004,
                            "actor_username is not the name this origin issued to that key",
                        )
                    # A retired key may no longer publish under its old name:
                    # the rotation carried the identity to its successor.
                    # Best-effort — authentication ran before this handler,
                    # so a write already past auth can still land after a
                    # racing rotation; the dispatch-time `retired` verdict
                    # in Dispatcher._resolve_author_check is authoritative.
                    if registered.get("superseded_by") is not None:
                        return _error(
                            0x0004,
                            "actor key has been rotated; publish with its successor",
                        )

            # An ack must name a real punishment that actually targets the
            # acker — otherwise this signs a forged "acknowledged" record
            # against another user's warning, a nonexistent event ID, or
            # something that isn't a punishment at all.
            # PolicyProjection.apply_punishment_ack enforces this too and has
            # to, since a federated ack never reaches this handler either —
            # but refusing here is what lets a local caller see why.
            if kind == KIND_PUNISHMENT_ACK:
                target_id = intent.metadata.get_bytes(1) or ZERO_ID
                punishment = self._policy.get_punishment(target_id)
                if punishment is None:
                    return _error(0x0003, "No such punishment")
                if punishment["punished_pubkey"] != intent.actor_pubkey:
                    return _error(0x0004, "Cannot acknowledge a punishment issued to someone else")

            # A moderator who bans themself is locked out of every write —
            # including the punish_revoke needed to undo it — by the same
            # gate a few lines down (only an administrator bypasses it). A
            # temporary ban expires eventually; a permaban does not, so a
            # self-permaban would be permanently unrecoverable. Refused
            # outright rather than trusted to a confirm prompt: nothing
            # legitimate ever needs to target one's own key with either kind.
            if kind in (KIND_PUNISHMENT_BAN, KIND_PUNISHMENT_PERMABAN):
                target_pubkey = intent.metadata.get_bytes(1)
                if target_pubkey == intent.actor_pubkey:
                    return _error(0x0004, "Cannot ban your own identity")

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

                if kind in (
                    KIND_ARTICLE_PIN,
                    KIND_ARTICLE_UNPIN,
                    KIND_THREAD_CLOSE,
                    KIND_THREAD_REOPEN,
                ):
                    # These controls chase supersede chains to the live head:
                    # validating the named (possibly superseded) row would
                    # approve state that lands nowhere visible, while the
                    # projection applies to the head. The walk is unbounded
                    # (same helper the projection uses): supersede links only
                    # ever point forward in time, so a cap would validate a
                    # superseded row on a long-but-legitimate edit chain.
                    target_id = bp.resolve_head_id(
                        intent.target_origin, intent.target_board, intent.target_article_id
                    )
                    head = bp.get_article_by_id(
                        intent.target_origin, intent.target_board, target_id
                    )
                    if head is not None:
                        target = head

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
                            return _error(
                                0x0004, "Only the original author may supersede an article"
                            )
                    # A supersede is a move of live state: the target must
                    # still be live. Superseding a superseded row would fork
                    # the chain (replies/pins already moved to the first
                    # replacement), and superseding a cancelled or purged row
                    # would silently undo moderation. Same 0x0009 state
                    # conflict cancel already uses for superseded rows.
                    if target.visibility != "active":
                        return _error(0x0009, "Cannot supersede a non-active article")
                    if target.body_state == "purged":
                        return _error(0x0009, "Cannot supersede a purged article")

            if intent.body_size > 0:
                if intent.body_size > self._max_body_size:
                    return _error(
                        0x0006,
                        f"Body size {intent.body_size} exceeds maximum {self._max_body_size}",
                    )
                if len(body) != intent.body_size:
                    return _error(0x0006, "Body length mismatch")
                actual_hash = compute_body_hash(body)
                if actual_hash != intent.body_hash:
                    return _error(0x0006, "Body hash mismatch")

            # Purge of an absent board is success without append: the
            # projection would be a no-op anyway (nav row already gone),
            # so skip the body write, append_record, dispatch and witness
            # mint, and return the current head record + own witness to
            # keep the publish response shape. The caller detects the
            # noop by returned event_id != requested event_id. Falls
            # through to the legacy append path only when there is no
            # head yet (fresh origin, test-only in practice). All
            # authorization above (ACL, actor binding, punishment gate)
            # already ran, so this is not a free success probe.
            if kind == KIND_BOARD_PURGE:
                if self._nav.get_board(intent.origin, board) is None:
                    head_seq = self._firehose.get_highest_seq(self._origin)
                    head_recs = (
                        self._firehose.get_events_range(self._origin, head_seq, 1)
                        if head_seq > 0
                        else []
                    )
                    if head_recs:
                        head_rec = head_recs[0]
                        encoded_head = encode_record(head_rec)
                        head_hash = compute_event_hash(encoded_head)
                        own = self._firehose.get_witness(
                            self._origin, head_rec.event_id, self._identity.public_key
                        )
                        if own is None:
                            own = make_origin_witness(
                                origin=self._origin,
                                event_id=head_rec.event_id,
                                event_hash=head_hash,
                                event_origin_seq=head_rec.origin_seq,
                                origin_identity=self._identity,
                                hostname=self._hostname,
                                relay_origin=self._origin,
                                seen_at=now,
                            )
                            self._firehose.store_witness(
                                own, keep_pubkeys={self._identity.public_key}
                            )
                        encoded_own = encode_witness(own)
                        log_debug(
                            "PUBLISH purge noop",
                            board=board or "-",
                            head_seq=head_rec.origin_seq,
                        )
                        return _success(
                            struct.pack(">I", len(encoded_head))
                            + encoded_head
                            + struct.pack(">H", len(encoded_own))
                            + encoded_own
                        )

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
                event_origin_seq=rec.origin_seq,
                origin_identity=self._identity,
                hostname=self._hostname,
                relay_origin=self._origin,
                seen_at=now,
            )
            self._firehose.store_witness(witness, keep_pubkeys={self._identity.public_key})
            encoded_witness = encode_witness(witness)

            log_msg(
                f"EVENT: seq={rec.origin_seq} kind={intent.kind} "
                f"actor={intent.actor_pubkey.hex()[:16]} board={intent.board or '-'}"
                f"{self._register_subject_suffix(intent)}"
            )
            log_debug(
                "PUBLISH stored",
                seq=rec.origin_seq,
                kind=intent.kind,
                board=intent.board or "-",
                article=rec.article_num,
                event=rec.event_id.hex()[:16],
            )

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
        _require_request_end(data, offset, "event head request")
        origin = normalize_origin(origin)
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
        _require_request_end(data, offset, "key epochs request")
        origin = normalize_origin(origin)
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
        culprit_raw, offset = _read_bytes(data, offset, key_len, "culprit pubkey")
        culprit = culprit_raw or None
        limit, offset = _read_u16(data, offset)
        page_offset, offset = _read_u16(data, offset)
        _require_request_end(data, offset, "report list request")

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
        board, offset = _read_text16(data, 0)
        _require_request_end(data, offset, "permissions request")
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

    def _witness_set(self, origin: str, rec, event_hash: bytes) -> bytes:
        """Encode the provenance chain held for one event.

        The local relay's own witness always leads; upstream ones retained from
        peers follow. Each is a signed statement by the relay it names, so the
        chain stays readable after any of those relays goes offline - which is
        the whole reason it travels with the record instead of being fetched
        from the relays themselves when someone asks.

        Serving only our own link, as this did before, meant the chain died at
        every hop: each relay downstream saw one entry and had no way to learn
        the rest.

        The terminating origin link is only ever minted for this relay's own
        origin. Minting one for another origin's event would put a witness
        shaped exactly like an origin attestation (zero upstream key) under
        this relay's key — and trace_event seeds its traversal from
        origin-shaped links, so it would display as the chain's terminus,
        `is_origin=True`, for an origin that never signed it. Carrying such
        an event with no statement of our own, the honest answer is the
        retained upstream chain as-is, even if that is empty.

        Truncation to wire_max is deterministic (own, origin witnesses, then
        newest upstream) and storage is untouched.
        """
        from bonnet.core.record import is_origin_witness as _is_origin

        own = self._firehose.get_witness(origin, rec.event_id, self._identity.public_key)
        if own is None and origin == self._origin:
            own = make_origin_witness(
                origin=origin,
                event_id=rec.event_id,
                event_hash=event_hash,
                event_origin_seq=rec.origin_seq,
                origin_identity=self._identity,
                hostname=self._hostname,
                relay_origin=self._origin,
                seen_at=rec.created_at,
            )
            self._firehose.store_witness(own, keep_pubkeys={self._identity.public_key})

        lead = [own] if own is not None else []
        rest = [
            w
            for w in self._firehose.get_witnesses(origin, rec.event_id, limit=10_000)
            if w.relay_pubkey != self._identity.public_key
        ]
        rest.sort(key=lambda w: (not _is_origin(w), -w.seen_at, w.relay_pubkey))
        chain = lead + rest[: max(0, self._wire_max - len(lead))]
        out = struct.pack(">H", len(chain))
        for w in chain:
            encoded = encode_witness(w)
            out += struct.pack(">H", len(encoded)) + encoded
        return out

    # ------------------------------------------------------------------
    # EVENT_RANGE
    # ------------------------------------------------------------------

    def _cmd_event_range(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        origin = normalize_origin(origin)
        self._maybe_queue_remote_sync(origin)
        start_seq, offset = _read_u64(data, offset)
        max_count, offset = _read_u16(data, offset)
        max_bytes, offset = _read_u32(data, offset)
        _require_request_end(data, offset, "event range request")

        records = self._firehose.get_events_range(origin, start_seq, max_count)

        body = b""
        served = 0
        total_bytes = 0
        for rec in records:
            encoded_rec = encode_record(rec)
            event_hash = compute_event_hash(encoded_rec)
            witnesses = self._witness_set(origin, rec, event_hash)
            # Budget covers record + witness bytes (spec: count rec+wit).
            row_cost = len(encoded_rec) + len(witnesses)
            if max_bytes > 0 and total_bytes + row_cost > max_bytes:
                break
            body += struct.pack(">I", len(encoded_rec)) + encoded_rec
            body += witnesses
            total_bytes += row_cost
            served += 1

        return _success(struct.pack(">H", served) + body)

    # ------------------------------------------------------------------
    # EVENT_GET
    # ------------------------------------------------------------------

    def _cmd_event_get(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        origin = normalize_origin(origin)
        self._maybe_queue_remote_sync(origin)
        event_id, offset = _read_id32(data, offset)
        _require_request_end(data, offset, "event get request")

        rec = self._firehose.get_event_by_id(origin, event_id)
        if rec is None:
            return _error(0x0003, "Event not found")

        encoded_rec = encode_record(rec)
        event_hash = compute_event_hash(encoded_rec)

        return _success(
            struct.pack(">I", len(encoded_rec))
            + encoded_rec
            + self._witness_set(origin, rec, event_hash)
        )

    # ------------------------------------------------------------------
    # BOARD_LIST
    # ------------------------------------------------------------------

    def _cmd_board_list(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        _require_request_end(data, offset, "board list request")
        origin = normalize_origin(origin)

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
        origin = normalize_origin(origin)
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
        _require_request_end(data, offset, "article get request")

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

        author_check = getattr(art, "author_check", "unchecked") or "unchecked"
        ac_bytes = author_check.encode("utf-8")
        out += struct.pack(">H", len(ac_bytes)) + ac_bytes

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
        origin = normalize_origin(origin)
        board, offset = _read_text16(data, offset)
        if not self._board_read_allowed(ctx, "ARTICLE_LIST", board):
            return _success(struct.pack(">H", 0))
        list_offset, offset = _read_u32(data, offset)
        limit, offset = _read_u16(data, offset)
        limit = max(1, min(limit, 65535))
        flags, offset = _read_u8(data, offset)
        _require_request_end(data, offset, "article list request")

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

            if self._dedups(board):
                page = self._canonical_article_page(
                    board,
                    origins_with_board,
                    list_offset,
                    limit,
                    include_cancelled=include_cancelled,
                    include_superseded=include_superseded,
                    include_purged=include_purged,
                )
            else:
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
        origin = normalize_origin(origin)
        board, offset = _read_text16(data, offset)
        if not self._board_read_allowed(ctx, "ARTICLE_SEARCH", board):
            out = struct.pack(">H", 0) + struct.pack(">I", 0) + struct.pack(">B", 0)
            return _success(out)
        meta_query, offset = _read_text16(data, offset)
        body_query, offset = _read_text16(data, offset)
        list_offset, offset = _read_u32(data, offset)
        limit, offset = _read_u16(data, offset)
        limit = max(1, min(limit, 65535))
        flags, offset = _read_u8(data, offset)
        _require_request_end(data, offset, "article search request")

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

            def run_search(orig: str, window: int):
                bp = self._get_board_projection(orig, board)
                if body_query:
                    return self._search.search_bodies(
                        bp,
                        orig,
                        board,
                        body_query,
                        offset=0,
                        limit=window,
                        include_cancelled=include_cancelled,
                        include_superseded=include_superseded,
                    )
                return self._search.search_metadata(
                    bp,
                    orig,
                    board,
                    text_query=meta_query,
                    offset=0,
                    limit=window,
                    include_cancelled=include_cancelled,
                    include_superseded=include_superseded,
                )

            if self._dedups(board):
                page, total, truncated = self._canonical_search_page(
                    board, origins_with_board, run_search, list_offset, limit
                )
            else:
                all_results = []
                total = 0
                truncated = False
                for orig in origins_with_board:
                    results = run_search(orig, list_offset + limit)
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
                out += _enc_text16(r.subject)
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
            out += _enc_text16(r.subject)
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
        origin = normalize_origin(origin)
        if origin:
            self._maybe_queue_remote_sync(origin)
            if self._allowed_origins and origin not in self._allowed_origins:
                return _success(struct.pack(">H", 0))
        board, offset = _read_text16(data, offset)
        if not self._board_read_allowed(ctx, "ARTICLE_QUERY", board):
            return _success(struct.pack(">H", 0))
        filter_count, offset = _read_u8(data, offset)

        # Bridge filters resolve to article ids per origin, so they're kept
        # aside and resolved once the origins being queried are known.
        filters: list[tuple[int, int, object]] = []
        bridge_filters: list[tuple[int, int, object]] = []
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
                try:
                    value = raw_value.decode("utf-8")
                except UnicodeDecodeError as e:
                    return _error(0x0006, f"Bad filter text: {e}")
            elif value_type == 0x03:
                if len(raw_value) != 8:
                    return _error(0x0006, "Bad filter i64 length")
                value = struct.unpack(">q", raw_value)[0]
            elif value_type == 0x04:
                if len(raw_value) != 1:
                    return _error(0x0006, "Bad filter bool length")
                value = raw_value[0] != 0
            else:
                return _error(0x0006, f"Invalid value type 0x{value_type:02x}")

            if field_id in BRIDGE_QUERY_FIELD_IDS and self._bridges is not None:
                bridge_filters.append((field_id, operator, value))
                continue
            if field_id not in QUERY_FIELD_IDS:
                return _error(0x0006, f"unknown filter field 0x{field_id:02x}")
            filters.append((field_id, operator, value))

        list_offset, offset = _read_u32(data, offset)
        limit, offset = _read_u16(data, offset)
        limit = max(1, min(limit, 65535))
        flags, offset = _read_u8(data, offset)
        _require_request_end(data, offset, "article query request")
        newest_first = bool(flags & QUERY_NEWEST_FIRST)

        def filters_for(orig: str) -> list | bytes:
            out = list(filters)
            for field_id, operator, value in bridge_filters:
                ids = self._bridge_filter_article_ids(orig, board, field_id, operator, value)
                if isinstance(ids, bytes):
                    return ids  # an error frame
                out.append((ARTICLE_ID_IN, 0x06, ids))
            return out

        if origin:
            resolved = filters_for(origin)
            if isinstance(resolved, bytes):
                return resolved
            bp = self._get_board_projection(origin, board)
            articles = bp.query_articles(
                origin, board, resolved, offset=list_offset, limit=limit, newest_first=newest_first
            )
            out = struct.pack(">H", len(articles))
            for art in articles:
                out += self._encode_article_view(art, include_body=False)
            return _success(out)

        origins_with_board = sorted(
            {
                b["origin"]
                for b in self._nav.list_boards()
                if b["board"] == board
                and (not self._allowed_origins or b["origin"] in self._allowed_origins)
            }
        )
        per_origin: dict[str, list] = {}
        for orig in origins_with_board:
            resolved = filters_for(orig)
            if isinstance(resolved, bytes):
                return resolved
            per_origin[orig] = resolved
        page = self._aggregate_query_page(board, per_origin, list_offset, limit, newest_first)
        out = struct.pack(">H", len(page))
        for art, orig in page:
            out += _enc_text16(orig)
            out += self._encode_article_view(art, include_body=False)
        return _success(out)

    def _aggregate_query_page(
        self,
        board: str,
        per_origin: dict[str, list],
        list_offset: int,
        limit: int,
        newest_first: bool,
    ) -> list:
        """One page of ARTICLE_QUERY across origins: (article, origin) pairs.

        A lazy k-way merge, as `_canonical_article_page` does for lists, on
        (created_at, origin, article_num): each origin's rows already arrive
        in that order (origin being constant), ascending or, newest first,
        descending, so one merge in the same direction gives one order across
        origins, and newest first is exactly oldest first reversed. On a `~`
        board, non-canonical copies are skipped as they stream past.
        """
        view = self._bridge_view() if self._dedups(board) else None
        batch = max(limit, 50)

        def stream(orig: str, orig_filters: list):
            bp = self._get_board_projection(orig, board)
            pos = 0
            while True:
                rows = bp.query_articles(
                    orig, board, orig_filters, offset=pos, limit=batch, newest_first=newest_first
                )
                for art in rows:
                    yield (art.created_at, orig, art.article_num), art, orig
                if len(rows) < batch:
                    return
                pos += batch

        merged = heapq.merge(
            *(stream(o, f) for o, f in per_origin.items()),
            key=lambda t: t[0],
            reverse=newest_first,
        )
        page: list = []
        skipped = 0
        for _, art, orig in merged:
            if view is not None and not view.visible_event(orig, art.event_id):
                continue
            if skipped < list_offset:
                skipped += 1
                continue
            page.append((art, orig))
            if len(page) >= limit:
                break
        return page

    # ------------------------------------------------------------------
    # ARTICLE_BODY
    # ------------------------------------------------------------------

    def _cmd_article_body(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        origin = normalize_origin(origin)
        if not origin:
            return _error(0x0003, "Article body unavailable")
        self._maybe_queue_remote_sync(origin)
        if origin and self._allowed_origins and origin not in self._allowed_origins:
            return _error(0x0003, "Article body unavailable")
        board, offset = _read_text16(data, offset)
        if not self._board_read_allowed(ctx, "ARTICLE_BODY", board):
            return _error(0x0003, "Article body unavailable")
        article_num, offset = _read_u64(data, offset)
        _require_request_end(data, offset, "article body request")

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
            # A file that exists but fails size/hash verification is a
            # distinct outcome from one that was never stored: the former is
            # an integrity failure worth surfacing as such, not silently
            # folded into the generic "unavailable" case below.
            if self._body_store.article_body_exists(origin, board, article_num):
                log_msg(
                    f"INTEGRITY: body failed size/hash check "
                    f"origin={origin} board={board} article_num={article_num}"
                )
                return _error(0x0007, "Body failed integrity check")
            if origin != self._origin:
                peer = self._peer_map.get(origin)
                if peer:
                    # A location hint: where this origin can be reached, so the
                    # caller can ask the party that actually holds the body.
                    #
                    # It no longer carries a TLS setting. That was this relay
                    # telling a client how carefully to check someone else's
                    # certificate — a decision that belongs to the client, sent
                    # by the one party a client should not take it from, since
                    # the same message chooses the destination. The client
                    # applies its own policy to the hop.
                    out = _enc_text16(origin)
                    out += _enc_text16(peer.hostname)
                    out += struct.pack(">H", peer.port)
                    return b"\x02" + out
            return _error(0x0003, "Body unavailable")

        return _success(struct.pack(">I", len(body)) + body)

    # ------------------------------------------------------------------
    # USER_GET
    # ------------------------------------------------------------------

    def _cmd_user_get(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        origin = normalize_origin(origin)
        if not origin:
            return _error(0x0001, "User not found")
        self._maybe_queue_remote_sync(origin)
        if origin and self._allowed_origins and origin not in self._allowed_origins:
            return _error(0x0001, "User not found")
        pubkey_len, offset = _read_u8(data, offset)
        pubkey, offset = _read_bytes(data, offset, pubkey_len, "pubkey")
        _require_request_end(data, offset, "user get request")

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
        superseded_by = user.get("superseded_by")
        if superseded_by is not None:
            out += struct.pack(">B", 1) + bytes(superseded_by)
        else:
            out += struct.pack(">B", 0)
        return _success(out)

    # ------------------------------------------------------------------
    # USER_LIST
    # ------------------------------------------------------------------

    def _cmd_user_list(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        origin = normalize_origin(origin)
        if not origin:
            return _success(struct.pack(">H", 0))
        self._maybe_queue_remote_sync(origin)
        if origin and self._allowed_origins and origin not in self._allowed_origins:
            return _success(struct.pack(">H", 0))
        flags, offset = _read_u8(data, offset)
        _require_request_end(data, offset, "user list request")

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
            out += struct.pack(">Q", u.get("revoked_seq") or 0)
        return _success(out)

    # ------------------------------------------------------------------
    # BAN_STATUS
    # ------------------------------------------------------------------

    def _cmd_ban_status(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        pubkey_len, offset = _read_u8(data, offset)
        pubkey, offset = _read_bytes(data, offset, pubkey_len, "pubkey")
        _require_request_end(data, offset, "ban status request")

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
        origin = normalize_origin(origin)
        self._maybe_queue_remote_sync(origin)
        event_id, offset = _read_id32(data, offset)
        _require_request_end(data, offset, "event body request")

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
