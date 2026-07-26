"""Firehose client wire protocol for the Bonnet Firehose Protocol (PROTOCOL.md §19).

Binary builders and parsers for all 13 command requests and responses.
These are pure functions with no networking dependencies.
"""

from __future__ import annotations

import struct

from client.firehose_models import (
    ArticleListItem,
    ArticleView,
    BanStatus,
    BoardInfo,
    HeadInfo,
    PublishResult,
    QueryResponse,
    SearchResponse,
    SearchResult,
    UserInfo,
)
from core.record import (
    ZERO_ID,
    Head,
    Intent,
    Record,
    Witness,
    decode_head,
    decode_record,
    decode_witness,
    encode_intent,
)

# ---------------------------------------------------------------------------
# Opcodes
# ---------------------------------------------------------------------------

OP_PUBLISH_RECORD = 0x01
OP_EVENT_HEAD = 0x02
OP_EVENT_RANGE = 0x03
OP_EVENT_GET = 0x04
OP_BOARD_LIST = 0x10
OP_ARTICLE_GET = 0x11
OP_ARTICLE_LIST = 0x12
OP_ARTICLE_SEARCH = 0x13
OP_ARTICLE_QUERY = 0x15
OP_ARTICLE_BODY = 0x14
OP_USER_GET = 0x20
OP_USER_LIST = 0x21
OP_BAN_STATUS = 0x22
OP_EVENT_BODY = 0x30


# ---------------------------------------------------------------------------
# Response status
# ---------------------------------------------------------------------------

STATUS_SUCCESS = 0x00
STATUS_ERROR = 0x01


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _enc_text16(s: str) -> bytes:
    encoded = s.encode("utf-8")
    return struct.pack(">H", len(encoded)) + encoded


def _read_text16(data: bytes, offset: int) -> tuple[str, int]:
    n = struct.unpack(">H", data[offset:offset + 2])[0]
    offset += 2
    s = data[offset:offset + n].decode("utf-8")
    return s, offset + n


def _read_u8(data: bytes, offset: int) -> tuple[int, int]:
    return data[offset], offset + 1


def _read_u16(data: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack(">H", data[offset:offset + 2])[0], offset + 2


def _read_u32(data: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack(">I", data[offset:offset + 4])[0], offset + 4


def _read_u64(data: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack(">Q", data[offset:offset + 8])[0], offset + 8


def _read_i64(data: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack(">q", data[offset:offset + 8])[0], offset + 8


def _read_id32(data: bytes, offset: int) -> tuple[bytes, int]:
    return data[offset:offset + 32], offset + 32


def _read_blob32(data: bytes, offset: int) -> tuple[bytes, int]:
    n = struct.unpack(">I", data[offset:offset + 4])[0]
    offset += 4
    return data[offset:offset + n], offset + n


def _read_sig64(data: bytes, offset: int) -> tuple[bytes, int]:
    return data[offset:offset + 64], offset + 64


class ProtocolError(Exception):
    pass


class BodyRedirectError(Exception):
    def __init__(self, origin: str, hostname: str, port: int, verify_tls: bool):
        self.origin = origin
        self.hostname = hostname
        self.port = port
        self.verify_tls = verify_tls
        super().__init__(f"body redirect: origin='{origin}' hostname='{hostname}' port={port}")


# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------

def parse_response(resp: bytes) -> tuple[int, bytes]:
    """Parse a response into (status, payload). Status 0=success, 1=error."""
    if not resp:
        raise ProtocolError("empty response")
    status = resp[0]
    payload = resp[1:]
    if status == STATUS_ERROR:
        if len(payload) < 2:
            raise ProtocolError("truncated error response")
        code = struct.unpack(">H", payload[:2])[0]
        msg_len = struct.unpack(">H", payload[2:4])[0]
        msg = payload[4:4 + msg_len].decode("utf-8", errors="replace")
        raise ProtocolError(f"error {code}: {msg}")
    return status, payload


# ---------------------------------------------------------------------------
# PUBLISH_RECORD
# ---------------------------------------------------------------------------

def build_publish_record(intent: Intent, actor_sig: bytes, body: bytes) -> bytes:
    encoded_intent = encode_intent(intent)
    out = struct.pack(">B", OP_PUBLISH_RECORD)
    out += struct.pack(">I", len(encoded_intent)) + encoded_intent
    out += actor_sig
    out += struct.pack(">I", len(body)) + body
    return out


def parse_publish_response(resp: bytes) -> PublishResult:
    status, payload = parse_response(resp)
    offset = 0
    rec_len, offset = _read_u32(payload, offset)
    rec = decode_record(payload[offset:offset + rec_len])
    offset += rec_len
    witness_len, offset = _read_u16(payload, offset)
    witness = decode_witness(payload[offset:offset + witness_len])
    return PublishResult(
        origin_seq=rec.origin_seq,
        event_id=rec.event_id.hex(),
        kind=rec.kind,
        article_num=rec.article_num,
        origin=rec.origin,
        board=rec.board,
        witness_pubkey=witness.relay_pubkey.hex(),
        witness_hostname=witness.relay_hostname,
    )


def parse_publish_response_raw(resp: bytes) -> tuple[Record, Witness]:
    """Parse publish response, returning raw record and witness objects."""
    status, payload = parse_response(resp)
    offset = 0
    rec_len, offset = _read_u32(payload, offset)
    rec = decode_record(payload[offset:offset + rec_len])
    offset += rec_len
    witness_len, offset = _read_u16(payload, offset)
    witness = decode_witness(payload[offset:offset + witness_len])
    return rec, witness


# ---------------------------------------------------------------------------
# EVENT_HEAD
# ---------------------------------------------------------------------------

def build_event_head(origin: str) -> bytes:
    return struct.pack(">B", OP_EVENT_HEAD) + _enc_text16(origin)


def parse_event_head_response(resp: bytes) -> HeadInfo:
    status, payload = parse_response(resp)
    head_len, offset = _read_u16(payload, 0)
    head = decode_head(payload[2:2 + head_len])
    return HeadInfo(
        origin=head.origin,
        latest_origin_seq=head.latest_origin_seq,
        latest_event_hash=head.latest_event_hash.hex(),
        event_count=head.event_count,
        generated_at=head.generated_at,
        origin_pubkey=head.origin_pubkey.hex(),
    )


def parse_event_head_response_raw(resp: bytes) -> Head:
    status, payload = parse_response(resp)
    head_len, offset = _read_u16(payload, 0)
    return decode_head(payload[2:2 + head_len])


# ---------------------------------------------------------------------------
# EVENT_RANGE
# ---------------------------------------------------------------------------

def build_event_range(origin: str, start_seq: int, max_count: int = 100, max_bytes: int = 0) -> bytes:
    out = struct.pack(">B", OP_EVENT_RANGE)
    out += _enc_text16(origin)
    out += struct.pack(">Q", start_seq)
    out += struct.pack(">H", max_count)
    out += struct.pack(">I", max_bytes)
    return out


def parse_event_range_response(resp: bytes) -> list[tuple[Record, Witness]]:
    status, payload = parse_response(resp)
    count, offset = _read_u16(payload, 0)
    results = []
    for _ in range(count):
        rec_len, offset = _read_u32(payload, offset)
        rec = decode_record(payload[offset:offset + rec_len])
        offset += rec_len
        w_len, offset = _read_u16(payload, offset)
        witness = decode_witness(payload[offset:offset + w_len])
        offset += w_len
        results.append((rec, witness))
    return results


# ---------------------------------------------------------------------------
# EVENT_GET
# ---------------------------------------------------------------------------

def build_event_get(origin: str, event_id: bytes) -> bytes:
    out = struct.pack(">B", OP_EVENT_GET)
    out += _enc_text16(origin)
    out += event_id
    return out


def parse_event_get_response(resp: bytes) -> tuple[Record, Witness]:
    status, payload = parse_response(resp)
    offset = 0
    rec_len, offset = _read_u32(payload, offset)
    rec = decode_record(payload[offset:offset + rec_len])
    offset += rec_len
    w_len, offset = _read_u16(payload, offset)
    witness = decode_witness(payload[offset:offset + w_len])
    return rec, witness


# ---------------------------------------------------------------------------
# BOARD_LIST
# ---------------------------------------------------------------------------

def build_board_list(origin: str) -> bytes:
    return struct.pack(">B", OP_BOARD_LIST) + _enc_text16(origin)


def parse_board_list_response(resp: bytes, aggregate: bool = False) -> list[BoardInfo]:
    status, payload = parse_response(resp)
    count, offset = _read_u16(payload, 0)
    boards = []
    for _ in range(count):
        board_origin = ""
        if aggregate:
            board_origin, offset = _read_text16(payload, offset)
        name, offset = _read_text16(payload, offset)
        closed, offset = _read_u8(payload, offset)
        owner_len, offset = _read_u8(payload, offset)
        owner = payload[offset:offset + owner_len].hex()
        offset += owner_len
        display, offset = _read_text16(payload, offset)
        boards.append(BoardInfo(
            name=name,
            closed=bool(closed),
            owner_pubkey=owner,
            display_name=display,
            origin=board_origin,
        ))
    return boards


# ---------------------------------------------------------------------------
# ARTICLE_GET
# ---------------------------------------------------------------------------

SELECTOR_BY_NUM = 0x01
SELECTOR_BY_ID = 0x02


def build_article_get(origin: str, board: str, selector_type: int, selector: bytes | int, include_body: bool = False) -> bytes:
    out = struct.pack(">B", OP_ARTICLE_GET)
    out += _enc_text16(origin)
    out += _enc_text16(board)
    out += struct.pack(">B", selector_type)
    if selector_type == SELECTOR_BY_NUM:
        out += struct.pack(">Q", selector)
    elif selector_type == SELECTOR_BY_ID:
        out += selector
    else:
        raise ProtocolError(f"invalid selector type {selector_type}")
    out += struct.pack(">B", 1 if include_body else 0)
    return out


def parse_article_get_response(resp: bytes) -> ArticleView:
    status, payload = parse_response(resp)
    return _decode_article_view(payload)


def _decode_article_view(data: bytes) -> ArticleView:
    offset = 0
    article_num, offset = _read_u64(data, offset)
    aid_len, offset = _read_u8(data, offset)
    article_id = data[offset:offset + aid_len]
    offset += aid_len
    eid_len, offset = _read_u8(data, offset)
    event_id = data[offset:offset + eid_len]
    offset += eid_len
    visibility_code, offset = _read_u8(data, offset)
    body_code, offset = _read_u8(data, offset)
    bh_len, offset = _read_u8(data, offset)
    body_hash = data[offset:offset + bh_len]
    offset += bh_len
    body_size, offset = _read_u64(data, offset)
    created_at, offset = _read_i64(data, offset)
    ap_len, offset = _read_u8(data, offset)
    author_pubkey = data[offset:offset + ap_len]
    offset += ap_len
    author_username, offset = _read_text16(data, offset)
    author_registrar, offset = _read_text16(data, offset)
    subject, offset = _read_text16(data, offset)
    tags, offset = _read_text16(data, offset)
    content_type, offset = _read_text16(data, offset)

    root_len, offset = _read_u8(data, offset)
    root_raw = data[offset:offset + root_len] if root_len else b""
    root_id = root_raw.hex() if root_raw and root_raw != ZERO_ID else ""
    offset += root_len

    reply_len, offset = _read_u8(data, offset)
    reply_raw = data[offset:offset + reply_len] if reply_len else b""
    reply_id = reply_raw.hex() if reply_raw and reply_raw != ZERO_ID else ""
    offset += reply_len

    has_replacement, offset = _read_u8(data, offset)
    replacement_id = ""
    if has_replacement:
        replacement_id = data[offset:offset + 32].hex()
        offset += 32

    pin_state, offset = _read_text16(data, offset)
    thread_state, offset = _read_text16(data, offset)

    body_bytes, offset = _read_blob32(data, offset)

    vis_map = {0: "active", 1: "cancelled", 2: "superseded"}
    body_map = {0: "available", 1: "unavailable", 2: "purged"}

    return ArticleView(
        article_num=article_num,
        article_id=article_id.hex(),
        event_id=event_id.hex(),
        visibility=vis_map.get(visibility_code, "active"),
        body_state=body_map.get(body_code, "unavailable"),
        body_hash=body_hash.hex(),
        body_size=body_size,
        created_at=created_at,
        author_pubkey=author_pubkey.hex(),
        author_username=author_username,
        author_registrar=author_registrar,
        subject=subject,
        tags=tags,
        content_type=content_type,
        root_article_id=root_id,
        reply_to_article_id=reply_id,
        replacement_article_id=replacement_id,
        pin_state=pin_state,
        thread_state=thread_state,
        body=body_bytes if body_bytes else None,
    )


# ---------------------------------------------------------------------------
# ARTICLE_LIST
# ---------------------------------------------------------------------------

def build_article_list(origin: str, board: str, offset: int = 0, limit: int = 100,
                        include_cancelled: bool = False, include_superseded: bool = False) -> bytes:
    flags = 0
    if include_cancelled:
        flags |= 0x01
    if include_superseded:
        flags |= 0x02
    limit = max(1, min(limit, 65535))
    out = struct.pack(">B", OP_ARTICLE_LIST)
    out += _enc_text16(origin)
    out += _enc_text16(board)
    out += struct.pack(">I", offset)
    out += struct.pack(">H", limit)
    out += struct.pack(">B", flags)
    return out


def parse_article_list_response(resp: bytes, aggregate: bool = False) -> QueryResponse:
    status, payload = parse_response(resp)
    count, offset = _read_u16(payload, 0)
    items = []
    for _ in range(count):
        item_origin = ""
        if aggregate:
            item_origin, offset = _read_text16(payload, offset)
        item, offset = _decode_article_list_item(payload, offset)
        item.origin = item_origin
        items.append(item)
    return QueryResponse(results=items)


def _decode_article_list_item(data: bytes, offset: int) -> tuple[ArticleListItem, int]:
    article_num, offset = _read_u64(data, offset)
    aid_len, offset = _read_u8(data, offset)
    article_id = data[offset:offset + aid_len]
    offset += aid_len
    eid_len, offset = _read_u8(data, offset)
    event_id = data[offset:offset + eid_len]
    offset += eid_len
    visibility_code, offset = _read_u8(data, offset)
    body_code, offset = _read_u8(data, offset)
    bh_len, offset = _read_u8(data, offset)
    body_hash = data[offset:offset + bh_len]
    offset += bh_len
    body_size, offset = _read_u64(data, offset)
    created_at, offset = _read_i64(data, offset)
    ap_len, offset = _read_u8(data, offset)
    author_pubkey = data[offset:offset + ap_len]
    offset += ap_len
    author_username, offset = _read_text16(data, offset)
    author_registrar, offset = _read_text16(data, offset)
    subject, offset = _read_text16(data, offset)
    tags, offset = _read_text16(data, offset)
    content_type, offset = _read_text16(data, offset)

    root_len, offset = _read_u8(data, offset)
    root_raw = data[offset:offset + root_len] if root_len else b""
    root_id = root_raw.hex() if root_raw and root_raw != ZERO_ID else ""
    offset += root_len

    reply_len, offset = _read_u8(data, offset)
    reply_raw = data[offset:offset + reply_len] if reply_len else b""
    reply_id = reply_raw.hex() if reply_raw and reply_raw != ZERO_ID else ""
    offset += reply_len

    has_replacement, offset = _read_u8(data, offset)
    replacement_id = ""
    if has_replacement:
        replacement_id = data[offset:offset + 32].hex()
        offset += 32

    pin_state, offset = _read_text16(data, offset)
    thread_state, offset = _read_text16(data, offset)

    _, offset = _read_blob32(data, offset)

    vis_map = {0: "active", 1: "cancelled", 2: "superseded"}
    body_map = {0: "available", 1: "unavailable", 2: "purged"}

    return ArticleListItem(
        article_num=article_num,
        article_id=article_id.hex(),
        event_id=event_id.hex(),
        visibility=vis_map.get(visibility_code, "active"),
        body_state=body_map.get(body_code, "unavailable"),
        body_hash=body_hash.hex(),
        body_size=body_size,
        created_at=created_at,
        author_pubkey=author_pubkey.hex(),
        author_username=author_username,
        author_registrar=author_registrar,
        subject=subject,
        tags=tags,
        content_type=content_type,
        root_article_id=root_id,
        reply_to_article_id=reply_id,
        replacement_article_id=replacement_id,
        pin_state=pin_state,
        thread_state=thread_state,
    ), offset


# ---------------------------------------------------------------------------
# ARTICLE_SEARCH
# ---------------------------------------------------------------------------

def build_article_search(origin: str, board: str, meta_query: str = "", body_query: str = "",
                         offset: int = 0, limit: int = 100,
                         include_cancelled: bool = False, include_superseded: bool = False) -> bytes:
    flags = 0
    if include_cancelled:
        flags |= 0x01
    if include_superseded:
        flags |= 0x02
    limit = max(1, min(limit, 65535))
    out = struct.pack(">B", OP_ARTICLE_SEARCH)
    out += _enc_text16(origin)
    out += _enc_text16(board)
    out += _enc_text16(meta_query)
    out += _enc_text16(body_query)
    out += struct.pack(">I", offset)
    out += struct.pack(">H", limit)
    out += struct.pack(">B", flags)
    return out


def parse_article_search_response(resp: bytes, aggregate: bool = False) -> SearchResponse:
    status, payload = parse_response(resp)
    count, offset = _read_u16(payload, 0)
    total, offset = _read_u32(payload, offset)
    truncated, offset = _read_u8(payload, offset)
    results = []
    for _ in range(count):
        result_origin = ""
        if aggregate:
            result_origin, offset = _read_text16(payload, offset)
        article_num, offset = _read_u64(payload, offset)
        aid_len, offset = _read_u8(payload, offset)
        article_id = payload[offset:offset + aid_len]
        offset += aid_len
        subj_len, offset = _read_u8(payload, offset)
        subject = payload[offset:offset + subj_len].decode("utf-8")
        offset += subj_len
        ap_len, offset = _read_u8(payload, offset)
        author_pubkey = payload[offset:offset + ap_len]
        offset += ap_len
        created_at, offset = _read_i64(payload, offset)
        body_avail, offset = _read_u8(payload, offset)
        excerpt, offset = _read_text16(payload, offset)
        results.append(SearchResult(
            article_num=article_num,
            article_id=article_id.hex(),
            subject=subject,
            author_pubkey=author_pubkey.hex(),
            created_at=created_at,
            body_available=bool(body_avail),
            excerpt=excerpt,
            origin=result_origin,
        ))
    return SearchResponse(results=results, total=total, truncated=bool(truncated))


# ---------------------------------------------------------------------------
# ARTICLE_QUERY
# ---------------------------------------------------------------------------

def build_article_query(
    origin: str, board: str, filters: list, offset: int = 0, limit: int = 100,
) -> bytes:
    """Build an ARTICLE_QUERY request.

    filters: list of (field_id, operator, value_type, value_bytes) tuples.
        value_type: 0x01=BYTES, 0x02=TEXT, 0x03=I64, 0x04=BOOL
    """
    out = struct.pack(">B", OP_ARTICLE_QUERY)
    out += _enc_text16(origin)
    out += _enc_text16(board)
    out += struct.pack(">B", len(filters))
    for field_id, operator, value_type, value in filters:
        if isinstance(value, str):
            value = value.encode("utf-8")
        out += struct.pack(">B", field_id)
        out += struct.pack(">B", operator)
        out += struct.pack(">B", value_type)
        out += struct.pack(">H", len(value)) + value
    limit = max(1, min(limit, 65535))
    out += struct.pack(">I", offset)
    out += struct.pack(">H", limit)
    return out


def parse_article_query_response(resp: bytes) -> QueryResponse:
    """Parse an ARTICLE_QUERY response. Returns QueryResponse."""
    status, payload = parse_response(resp)
    count, offset = _read_u16(payload, 0)
    items = []
    for _ in range(count):
        item, offset = _decode_article_list_item(payload, offset)
        items.append(item)
    return QueryResponse(results=items)


# ---------------------------------------------------------------------------
# ARTICLE_BODY
# ---------------------------------------------------------------------------

def build_article_body(origin: str, board: str, article_num: int) -> bytes:
    out = struct.pack(">B", OP_ARTICLE_BODY)
    out += _enc_text16(origin)
    out += _enc_text16(board)
    out += struct.pack(">Q", article_num)
    return out


def parse_article_body_response(resp: bytes) -> bytes:
    if not resp:
        raise ProtocolError("empty response")
    status = resp[0]
    payload = resp[1:]
    if status == 0x02:
        origin, offset = _read_text16(payload, 0)
        hostname, offset = _read_text16(payload, offset)
        port, offset = _read_u16(payload, offset)
        verify_tls = payload[offset]
        raise BodyRedirectError(origin, hostname, port, bool(verify_tls))
    if status == STATUS_ERROR:
        parse_response(resp)
    body_len, offset = _read_u32(payload, 0)
    return payload[4:4 + body_len]


# ---------------------------------------------------------------------------
# USER_GET
# ---------------------------------------------------------------------------

def build_user_get(origin: str, pubkey: bytes) -> bytes:
    out = struct.pack(">B", OP_USER_GET)
    out += _enc_text16(origin)
    out += struct.pack(">B", len(pubkey)) + pubkey
    return out


def parse_user_get_response(resp: bytes) -> UserInfo:
    status, payload = parse_response(resp)
    offset = 0
    pk_len, offset = _read_u8(payload, offset)
    pubkey = payload[offset:offset + pk_len]
    offset += pk_len
    username, offset = _read_text16(payload, offset)
    flags, offset = _read_u64(payload, offset)
    reg_seq, offset = _read_u64(payload, offset)
    created_at, offset = _read_i64(payload, offset)
    revoked, offset = _read_u8(payload, offset)
    revoked_seq, offset = _read_u64(payload, offset)
    return UserInfo(
        pubkey=pubkey.hex(),
        username=username,
        flags=flags,
        reg_seq=reg_seq,
        created_at=created_at,
        revoked=bool(revoked),
        revoked_seq=revoked_seq,
    )


# ---------------------------------------------------------------------------
# USER_LIST
# ---------------------------------------------------------------------------

def build_user_list(origin: str, include_revoked: bool = False) -> bytes:
    flags = 0x01 if include_revoked else 0
    out = struct.pack(">B", OP_USER_LIST)
    out += _enc_text16(origin)
    out += struct.pack(">B", flags)
    return out


def parse_user_list_response(resp: bytes) -> list[UserInfo]:
    status, payload = parse_response(resp)
    count, offset = _read_u16(payload, 0)
    users = []
    for _ in range(count):
        origin, offset = _read_text16(payload, offset)
        pk_len, offset = _read_u8(payload, offset)
        pubkey = payload[offset:offset + pk_len]
        offset += pk_len
        username, offset = _read_text16(payload, offset)
        flags, offset = _read_u64(payload, offset)
        reg_seq, offset = _read_u64(payload, offset)
        created_at, offset = _read_i64(payload, offset)
        revoked, offset = _read_u8(payload, offset)
        users.append(UserInfo(
            pubkey=pubkey.hex(),
            username=username,
            flags=flags,
            reg_seq=reg_seq,
            created_at=created_at,
            revoked=bool(revoked),
            origin=origin,
        ))
    return users


# ---------------------------------------------------------------------------
# BAN_STATUS
# ---------------------------------------------------------------------------

def build_ban_status(pubkey: bytes) -> bytes:
    return struct.pack(">B", OP_BAN_STATUS) + struct.pack(">B", len(pubkey)) + pubkey


def parse_ban_status_response(resp: bytes) -> BanStatus:
    status, payload = parse_response(resp)
    banned, offset = _read_u8(payload, 0)
    if not banned:
        return BanStatus(banned=False)
    eid_len, offset = _read_u8(payload, offset)
    event_id = payload[offset:offset + eid_len]
    offset += eid_len
    origin, offset = _read_text16(payload, offset)
    expires_at, offset = _read_i64(payload, offset)
    return BanStatus(
        banned=True,
        punishment_event_id=event_id.hex(),
        source_origin=origin,
        expires_at=expires_at,
    )


# ---------------------------------------------------------------------------
# EVENT_BODY
# ---------------------------------------------------------------------------

def build_event_body(origin: str, event_id: bytes) -> bytes:
    out = struct.pack(">B", OP_EVENT_BODY)
    out += _enc_text16(origin)
    out += event_id
    return out


def parse_event_body_response(resp: bytes) -> bytes:
    status, payload = parse_response(resp)
    body_len, offset = _read_u32(payload, 0)
    return payload[4:4 + body_len]
