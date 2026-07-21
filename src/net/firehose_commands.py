"""Firehose command handler for the Bonnet Firehose Protocol (PROTOCOL.md §19).

Handles PUBLISH_RECORD, EVENT_HEAD, EVENT_RANGE, EVENT_GET, and projection
read commands (BOARD_LIST, ARTICLE_GET/LIST/SEARCH/BODY, USER_GET/LIST,
BAN_STATUS, EVENT_BODY).

Each request is a binary body starting with one opcode byte. Responses begin
with status:u8 (0=success, 1=error).
"""

from __future__ import annotations

import struct
import time
from typing import Optional

from core.crypto import Identity
from core.record import (
    Intent, Record, Head, Witness, MetadataMap,
    encode_record, decode_record, encode_intent, decode_intent,
    encode_head, decode_head, encode_unsigned_head,
    encode_witness, decode_witness, encode_unsigned_witness,
    compute_event_hash, compute_head_hash, compute_body_hash,
    sign_intent, verify_intent_signature,
    sign_record, verify_record_signature,
    sign_head, verify_head_signature,
    sign_witness, verify_witness_signature,
    reconstruct_intent_from_record,
    make_origin_witness, is_origin_witness,
    ZERO_ID, ZERO_HASH, ID_SIZE, SIG_SIZE,
    enc_text16, enc_u8, enc_u16, enc_u32, enc_u64, enc_i64,
)
from core.firehose import (
    FirehoseStore, FirehoseError, EventIdCollision, ArticleIdCollision,
    KIND_ARTICLE,
)
from core.acl import ACLEvaluator, AuthContext
from core.kind_validator import KindValidator, ValidationError
from core.board_projection import BoardProjection, board_db_path
from core.global_projections import NavProjection, UserProjection, PolicyProjection
from core.bodies import BodyStore
from core.search import SearchService


# ---------------------------------------------------------------------------
# Opcodes (§19)
# ---------------------------------------------------------------------------

OP_PUBLISH_RECORD = 0x01
OP_EVENT_HEAD = 0x02
OP_EVENT_RANGE = 0x03
OP_EVENT_GET = 0x04
OP_BOARD_LIST = 0x10
OP_ARTICLE_GET = 0x11
OP_ARTICLE_LIST = 0x12
OP_ARTICLE_SEARCH = 0x13
OP_ARTICLE_BODY = 0x14
OP_USER_GET = 0x20
OP_USER_LIST = 0x21
OP_BAN_STATUS = 0x22
OP_EVENT_BODY = 0x30

CMD_NAMES = {
    OP_PUBLISH_RECORD: "PUBLISH_RECORD",
    OP_EVENT_HEAD: "EVENT_HEAD",
    OP_EVENT_RANGE: "EVENT_RANGE",
    OP_EVENT_GET: "EVENT_GET",
    OP_BOARD_LIST: "BOARD_LIST",
    OP_ARTICLE_GET: "ARTICLE_GET",
    OP_ARTICLE_LIST: "ARTICLE_LIST",
    OP_ARTICLE_SEARCH: "ARTICLE_SEARCH",
    OP_ARTICLE_BODY: "ARTICLE_BODY",
    OP_USER_GET: "USER_GET",
    OP_USER_LIST: "USER_LIST",
    OP_BAN_STATUS: "BAN_STATUS",
    OP_EVENT_BODY: "EVENT_BODY",
}

WRITE_OPS = frozenset({OP_PUBLISH_RECORD})
READ_OPS = frozenset({
    OP_EVENT_HEAD, OP_EVENT_RANGE, OP_EVENT_GET,
    OP_BOARD_LIST, OP_ARTICLE_GET, OP_ARTICLE_LIST, OP_ARTICLE_SEARCH,
    OP_ARTICLE_BODY, OP_USER_GET, OP_USER_LIST, OP_BAN_STATUS, OP_EVENT_BODY,
})


# ---------------------------------------------------------------------------
# Response builder helpers
# ---------------------------------------------------------------------------

def _success(payload: bytes = b"") -> bytes:
    return b"\x00" + payload


def _error(code: int, message: str) -> bytes:
    msg_bytes = message.encode("utf-8")
    return b"\x01" + struct.pack(">H", code) + struct.pack(">H", len(msg_bytes)) + msg_bytes


def _read_text16(data: bytes, offset: int) -> tuple[str, int]:
    if offset + 2 > len(data):
        raise ValueError("truncated text16")
    n = struct.unpack(">H", data[offset:offset + 2])[0]
    offset += 2
    if offset + n > len(data):
        raise ValueError("truncated text16 content")
    s = data[offset:offset + n].decode("utf-8")
    return s, offset + n


def _read_u64(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 8 > len(data):
        raise ValueError("truncated u64")
    return struct.unpack(">Q", data[offset:offset + 8])[0], offset + 8


def _read_u16(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(data):
        raise ValueError("truncated u16")
    return struct.unpack(">H", data[offset:offset + 2])[0], offset + 2


def _read_u32(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 4 > len(data):
        raise ValueError("truncated u32")
    return struct.unpack(">I", data[offset:offset + 4])[0], offset + 4


def _read_u8(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 1 > len(data):
        raise ValueError("truncated u8")
    return data[offset], offset + 1


def _read_id32(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 32 > len(data):
        raise ValueError("truncated id32")
    return data[offset:offset + 32], offset + 32


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
    """Dispatches firehose protocol commands (§19)."""

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
        self._board_projections: dict[tuple[str, str], BoardProjection] = {}

    def close(self) -> None:
        for bp in self._board_projections.values():
            bp.close()
        self._board_projections.clear()

    def _get_board_projection(self, origin: str, board: str) -> BoardProjection:
        key = (origin, board)
        if key not in self._board_projections:
            self._board_projections[key] = BoardProjection(
                board_db_path(self._boards_dir, origin, board)
            )
        return self._board_projections[key]

    def handle(self, body: bytes, ctx: FirehoseContext) -> bytes:
        if not body:
            return _error(0x0005, "Empty request")

        opcode = body[0]
        data = body[1:]
        cmd_name = CMD_NAMES.get(opcode, f"UNKNOWN_{opcode:02x}")

        if opcode not in CMD_NAMES:
            return _error(0x0005, f"Unknown opcode 0x{opcode:02x}")

        action = "write" if opcode in WRITE_OPS else "read"

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
            elif opcode == OP_BOARD_LIST:
                return self._cmd_board_list(data, ctx)
            elif opcode == OP_ARTICLE_GET:
                return self._cmd_article_get(data, ctx)
            elif opcode == OP_ARTICLE_LIST:
                return self._cmd_article_list(data, ctx)
            elif opcode == OP_ARTICLE_SEARCH:
                return self._cmd_article_search(data, ctx)
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
            return _error(0x0000, str(e))

    # ------------------------------------------------------------------
    # PUBLISH_RECORD (§19.1)
    # ------------------------------------------------------------------

    def _cmd_publish(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        intent_len, offset = _read_u32(data, offset)
        if offset + intent_len > len(data):
            return _error(0x0006, "Truncated intent")
        encoded_intent = data[offset:offset + intent_len]
        offset += intent_len

        if offset + SIG_SIZE > len(data):
            return _error(0x0006, "Missing actor signature")
        actor_sig = data[offset:offset + SIG_SIZE]
        offset += SIG_SIZE

        body_len, offset = _read_u32(data, offset)
        if offset + body_len > len(data):
            return _error(0x0006, "Truncated body")
        body = data[offset:offset + body_len]
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
        if not self._acl.check(ctx.to_auth_context(), "write", kind=kind, board=board or None):
            return _error(0x0004, "Kind or board not permitted")

        if intent.body_size > 0:
            if len(body) != intent.body_size:
                return _error(0x0006, "Body length mismatch")
            actual_hash = compute_body_hash(body)
            if actual_hash != intent.body_hash:
                return _error(0x0006, "Body hash mismatch")

        if intent.kind == KIND_ARTICLE and intent.body_size > 0:
            self._body_store.stage_article_body(
                intent.origin, intent.board, intent.event_id,
                body, intent.body_hash, intent.body_size,
            )

        rec = self._firehose.append_record(self._identity, intent, actor_sig, body)

        if intent.kind == KIND_ARTICLE and intent.body_size > 0:
            self._body_store.finalize_article_body(
                intent.origin, intent.board, intent.event_id, rec.article_num,
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
            seen_at=int(time.time()),
        )
        encoded_witness = encode_witness(witness)

        return _success(
            struct.pack(">I", len(encoded_rec)) + encoded_rec +
            struct.pack(">H", len(encoded_witness)) + encoded_witness
        )

    # ------------------------------------------------------------------
    # EVENT_HEAD (§19.2)
    # ------------------------------------------------------------------

    def _cmd_event_head(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)

        head = self._firehose.get_head(origin)
        if head is None:
            return _error(0x0002, "No head for origin")

        encoded = encode_head(head)
        return _success(struct.pack(">H", len(encoded)) + encoded)

    # ------------------------------------------------------------------
    # EVENT_RANGE (§19.3)
    # ------------------------------------------------------------------

    def _cmd_event_range(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
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

            witness = make_origin_witness(
                origin=origin,
                event_id=rec.event_id,
                event_hash=event_hash,
                origin_identity=self._identity,
                hostname=self._hostname,
                seen_at=int(time.time()),
            )
            encoded_witness = encode_witness(witness)

            out += struct.pack(">I", len(encoded_rec)) + encoded_rec
            out += struct.pack(">H", len(encoded_witness)) + encoded_witness
            total_bytes += len(encoded_rec)

        return _success(out)

    # ------------------------------------------------------------------
    # EVENT_GET (§19.4)
    # ------------------------------------------------------------------

    def _cmd_event_get(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        event_id, offset = _read_id32(data, offset)

        rec = self._firehose.get_event_by_id(origin, event_id)
        if rec is None:
            return _error(0x0003, "Event not found")

        encoded_rec = encode_record(rec)
        event_hash = compute_event_hash(encoded_rec)

        witness = make_origin_witness(
            origin=origin,
            event_id=rec.event_id,
            event_hash=event_hash,
            origin_identity=self._identity,
            hostname=self._hostname,
            seen_at=int(time.time()),
        )
        encoded_witness = encode_witness(witness)

        return _success(
            struct.pack(">I", len(encoded_rec)) + encoded_rec +
            struct.pack(">H", len(encoded_witness)) + encoded_witness
        )

    # ------------------------------------------------------------------
    # BOARD_LIST (§19.5)
    # ------------------------------------------------------------------

    def _cmd_board_list(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)

        boards = self._nav.list_boards(origin)
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
    # ARTICLE_GET (§19.5)
    # ------------------------------------------------------------------

    def _cmd_article_get(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        board, offset = _read_text16(data, offset)
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
            art = bp.get_article_by_id(origin, board, article_id)

        if art is None:
            return _error(0x0003, "Article not found")

        return _success(self._encode_article_view(art, include_body=bool(include_body)))

    def _encode_article_view(self, art, include_body: bool = False) -> bytes:
        from core.record import ZERO_ID

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

        subject_bytes = art.subject.encode("utf-8")
        out += struct.pack(">H", len(subject_bytes)) + subject_bytes

        tags_bytes = art.tags.encode("utf-8")
        out += struct.pack(">H", len(tags_bytes)) + tags_bytes

        ct_bytes = art.content_type.encode("utf-8")
        out += struct.pack(">H", len(ct_bytes)) + ct_bytes

        root_id = getattr(art, 'root_article_id', ZERO_ID) or ZERO_ID
        out += struct.pack(">B", len(root_id)) + root_id

        reply_id = getattr(art, 'reply_to_article_id', ZERO_ID) or ZERO_ID
        out += struct.pack(">B", len(reply_id)) + reply_id

        replacement_id = getattr(art, 'replacement_article_id', None)
        if replacement_id and len(replacement_id) == 32:
            out += struct.pack(">B", 1) + replacement_id
        else:
            out += struct.pack(">B", 0)

        pin_state = getattr(art, 'pin_state', 'unpinned') or 'unpinned'
        pin_bytes = pin_state.encode("utf-8")
        out += struct.pack(">H", len(pin_bytes)) + pin_bytes

        thread_state = getattr(art, 'thread_state', 'open') or 'open'
        thread_bytes = thread_state.encode("utf-8")
        out += struct.pack(">H", len(thread_bytes)) + thread_bytes

        body_bytes = b""
        if include_body and art.body_state == "available" and art.body_size > 0:
            body_bytes = self._body_store.get_article_body(
                art.origin, art.board, art.article_num,
                art.body_hash, art.body_size,
            ) or b""

        out += struct.pack(">I", len(body_bytes)) + body_bytes
        return out

    # ------------------------------------------------------------------
    # ARTICLE_LIST (§19.5)
    # ------------------------------------------------------------------

    def _cmd_article_list(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        board, offset = _read_text16(data, offset)
        list_offset, offset = _read_u32(data, offset)
        limit, offset = _read_u16(data, offset)
        flags, offset = _read_u8(data, offset)

        include_cancelled = bool(flags & 0x01)
        include_superseded = bool(flags & 0x02)
        include_purged = bool(flags & 0x04)

        bp = self._get_board_projection(origin, board)
        articles = bp.list_articles(
            origin, board, offset=list_offset, limit=limit,
            include_cancelled=include_cancelled,
            include_superseded=include_superseded,
        )

        out = struct.pack(">H", len(articles))
        for art in articles:
            out += self._encode_article_view(art, include_body=False)
        return _success(out)

    # ------------------------------------------------------------------
    # ARTICLE_SEARCH (§19.5)
    # ------------------------------------------------------------------

    def _cmd_article_search(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        board, offset = _read_text16(data, offset)
        meta_query, offset = _read_text16(data, offset)
        body_query, offset = _read_text16(data, offset)
        list_offset, offset = _read_u32(data, offset)
        limit, offset = _read_u16(data, offset)
        flags, offset = _read_u8(data, offset)

        include_cancelled = bool(flags & 0x01)
        include_superseded = bool(flags & 0x02)

        bp = self._get_board_projection(origin, board)

        if body_query:
            results = self._search.search_bodies(
                bp, origin, board, body_query,
                offset=list_offset, limit=limit,
                include_cancelled=include_cancelled,
                include_superseded=include_superseded,
            )
        else:
            results = self._search.search_metadata(
                bp, origin, board, text_query=meta_query,
                offset=list_offset, limit=limit,
                include_cancelled=include_cancelled,
                include_superseded=include_superseded,
            )

        out = struct.pack(">H", len(results.results))
        out += struct.pack(">I", results.total)
        out += struct.pack(">B", 1 if results.truncated else 0)
        for r in results.results:
            out += struct.pack(">Q", r.article_num)
            out += struct.pack(">B", len(r.article_id)) + r.article_id
            out += struct.pack(">B", len(r.subject.encode("utf-8"))) + r.subject.encode("utf-8")
            out += struct.pack(">B", len(r.author_pubkey)) + r.author_pubkey
            out += struct.pack(">q", r.created_at)
            out += struct.pack(">B", 1 if r.body_available else 0)
            excerpt = r.excerpt.encode("utf-8") if r.excerpt else b""
            out += struct.pack(">H", len(excerpt)) + excerpt
        return _success(out)

    # ------------------------------------------------------------------
    # ARTICLE_BODY (§19.5)
    # ------------------------------------------------------------------

    def _cmd_article_body(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        board, offset = _read_text16(data, offset)
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
            origin, board, article_num, art.body_hash, art.body_size,
        )
        if body is None:
            return _error(0x0003, "Body unavailable")

        return _success(struct.pack(">I", len(body)) + body)

    # ------------------------------------------------------------------
    # USER_GET (§19.5)
    # ------------------------------------------------------------------

    def _cmd_user_get(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        pubkey_len, offset = _read_u8(data, offset)
        pubkey = data[offset:offset + pubkey_len]
        offset += pubkey_len

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
        return _success(out)

    # ------------------------------------------------------------------
    # USER_LIST (§19.5)
    # ------------------------------------------------------------------

    def _cmd_user_list(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        flags, offset = _read_u8(data, offset)

        include_revoked = bool(flags & 0x01)
        users = self._users.list_users(origin, include_revoked=include_revoked)

        out = struct.pack(">H", len(users))
        for u in users:
            out += struct.pack(">B", len(u["user_pubkey"])) + u["user_pubkey"]
            username = u["username"].encode("utf-8")
            out += struct.pack(">H", len(username)) + username
            out += struct.pack(">Q", u["flags"])
            out += struct.pack(">B", 1 if u["revoked"] else 0)
        return _success(out)

    # ------------------------------------------------------------------
    # BAN_STATUS (§19.5)
    # ------------------------------------------------------------------

    def _cmd_ban_status(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        pubkey_len, offset = _read_u8(data, offset)
        pubkey = data[offset:offset + pubkey_len]
        offset += pubkey_len

        punishments = self._policy.list_punishments_for_pubkey(pubkey, include_revoked=False)

        now = int(time.time())
        active_ban = None
        for p in punishments:
            expires = p["expires_at"]
            if expires == 0:
                continue
            if expires < 0 or expires > now:
                active_ban = p
                break

        if active_ban:
            out = struct.pack(">B", 1)
            out += struct.pack(">B", len(active_ban["event_id"])) + active_ban["event_id"]
            origin = active_ban["origin"].encode("utf-8")
            out += struct.pack(">H", len(origin)) + origin
            out += struct.pack(">q", active_ban["expires_at"])
        else:
            out = struct.pack(">B", 0)

        return _success(out)

    # ------------------------------------------------------------------
    # EVENT_BODY (§19.5)
    # ------------------------------------------------------------------

    def _cmd_event_body(self, data: bytes, ctx: FirehoseContext) -> bytes:
        offset = 0
        origin, offset = _read_text16(data, offset)
        event_id, offset = _read_id32(data, offset)

        rec = self._firehose.get_event_by_id(origin, event_id)
        if rec is None:
            return _error(0x0003, "Event not found")

        if rec.body_size == 0:
            return _success(struct.pack(">I", 0))

        body = self._body_store.get_event_body(
            origin, event_id, rec.body_hash, rec.body_size,
        )
        if body is None:
            return _error(0x0003, "Event body unavailable")

        return _success(struct.pack(">I", len(body)) + body)
