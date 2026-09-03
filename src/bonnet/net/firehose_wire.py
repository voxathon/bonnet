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

"""Command and response wire codec for the firehose protocol.

Binary builders and parsers for all 13 command requests and responses.
Shared by the server's federation sync and the client library.
These are pure functions with no networking dependencies.
"""

from __future__ import annotations

import struct

from bonnet.core.record import (
    MAX_WITNESS_SET,
    ZERO_ID,
    CodecError,
    Head,
    Intent,
    Record,
    Witness,
    decode_head,
    decode_record,
    decode_witness,
    encode_intent,
)
from bonnet.net.firehose_models import (
    ArticleListItem,
    ArticleView,
    BanStatus,
    BoardInfo,
    HeadInfo,
    PendingPunishment,
    Permissions,
    PublishResult,
    QueryResponse,
    ReportInfo,
    SearchResponse,
    SearchResult,
    UserInfo,
)

# ---------------------------------------------------------------------------
# Opcodes
# ---------------------------------------------------------------------------

OP_PUBLISH_RECORD = 0x01
OP_EVENT_HEAD = 0x02
OP_EVENT_RANGE = 0x03
OP_EVENT_GET = 0x04
OP_KEY_EPOCHS = 0x05
# Authorization introspection: what may *this* principal do. Substrate
# range because it describes the caller's relationship to the relay, not
# bulletin-board semantics, and must be able to report on substrate
# opcodes as well as application ones.
OP_PERMISSIONS = 0x06
OP_BOARD_LIST = 0x10
OP_ARTICLE_GET = 0x11
OP_ARTICLE_LIST = 0x12
OP_ARTICLE_SEARCH = 0x13
OP_ARTICLE_QUERY = 0x15
OP_ARTICLE_BODY = 0x14
OP_USER_GET = 0x20
OP_USER_LIST = 0x21
OP_BAN_STATUS = 0x22
# The moderation queue. Its own opcode rather than a client-side filter
# over EVENT_RANGE, because a selector is where the ACL runs: reports name
# people and point at boards, so both the command and each report's target
# board have to be checkable. A client-side scan is enforceable nowhere.
OP_REPORT_LIST = 0x23
OP_EVENT_BODY = 0x30


# ---------------------------------------------------------------------------
# Response status
# ---------------------------------------------------------------------------

STATUS_SUCCESS = 0x00
STATUS_ERROR = 0x01


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class ProtocolError(ValueError):
    """A frame from the far end is malformed, or is an error frame.

    Subclasses ValueError so that the server handler's `except ValueError` in
    `firehose_commands.handle()` keeps turning a malformed *request* into a
    0x0006 error frame — the same decoders serve both directions.

    `code` and `detail` carry the status code and the far end's own message
    when this came from an error frame; both are None when the bytes
    themselves were unparseable. Callers that need to branch on the code, or
    to render it their own way, have them here rather than by matching on
    str(self).
    """

    def __init__(self, message: str, code: int | None = None, detail: str | None = None):
        super().__init__(message)
        self.code = code
        self.detail = detail


def _guard(fn, *args):
    """Run a `core.record` decoder, restating its CodecError as ProtocolError.

    CodecError does not descend from ValueError or ProtocolError, so without
    this every caller of this module would need a second except clause for
    bytes that arrived over the same socket.
    """
    try:
        return fn(*args)
    except CodecError as e:
        raise ProtocolError(f"{fn.__name__}: {e}") from e


def _enc_text16(s: str) -> bytes:
    encoded = s.encode("utf-8")
    if len(encoded) > 0xFFFF:
        raise ProtocolError(f"text16 encoded length {len(encoded)} exceeds {0xFFFF}")
    return struct.pack(">H", len(encoded)) + encoded


def _enc_u64(v: int, what: str) -> bytes:
    """Pack an unsigned 64-bit request field, rejecting what struct.pack won't.

    Sibling to _read_u64, on the encode side: request builders take these
    values from tool callers, not from an already-validated Record, so the
    range/type checks core.record's decoders get for free have to happen
    here instead of surfacing as a raw struct.error.
    """
    if isinstance(v, bool) or not isinstance(v, int):
        raise ProtocolError(f"{what} must be an integer, got {type(v).__name__}")
    if not 0 <= v <= 0xFFFFFFFFFFFFFFFF:
        raise ProtocolError(f"{what} must be between 0 and 2**64-1, got {v}")
    return struct.pack(">Q", v)


def _enc_u32(v: int, what: str) -> bytes:
    if isinstance(v, bool) or not isinstance(v, int):
        raise ProtocolError(f"{what} must be an integer, got {type(v).__name__}")
    if not 0 <= v <= 0xFFFFFFFF:
        raise ProtocolError(f"{what} must be between 0 and 2**32-1, got {v}")
    return struct.pack(">I", v)


def _enc_u16(v: int, what: str) -> bytes:
    if isinstance(v, bool) or not isinstance(v, int):
        raise ProtocolError(f"{what} must be an integer, got {type(v).__name__}")
    if not 0 <= v <= 0xFFFF:
        raise ProtocolError(f"{what} must be between 0 and 2**16-1, got {v}")
    return struct.pack(">H", v)


def _read_bytes(data: bytes, offset: int, n: int, what: str) -> tuple[bytes, int]:
    """Slice exactly n bytes, or raise.

    Every fixed-width and length-prefixed read below goes through here.
    Python slicing silently returns short — a truncated frame otherwise
    yields a short event_id, pubkey, or body rather than an error.
    """
    end = offset + n
    if offset < 0 or n < 0 or end > len(data):
        raise ProtocolError(
            f"truncated {what}: want {n} bytes at {offset}, have {len(data) - offset}"
        )
    return data[offset:end], end


def _read_text16(data: bytes, offset: int) -> tuple[str, int]:
    raw, offset = _read_bytes(data, offset, 2, "text16 length")
    n = struct.unpack(">H", raw)[0]
    raw, offset = _read_bytes(data, offset, n, "text16 content")
    try:
        return raw.decode("utf-8"), offset
    except UnicodeDecodeError as e:
        raise ProtocolError(f"text16 is not valid utf-8: {e}") from e


def _read_u8(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _read_bytes(data, offset, 1, "u8")
    return raw[0], offset


def _read_u16(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _read_bytes(data, offset, 2, "u16")
    return struct.unpack(">H", raw)[0], offset


def _read_u32(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _read_bytes(data, offset, 4, "u32")
    return struct.unpack(">I", raw)[0], offset


def _read_u64(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _read_bytes(data, offset, 8, "u64")
    return struct.unpack(">Q", raw)[0], offset


def _read_i64(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _read_bytes(data, offset, 8, "i64")
    return struct.unpack(">q", raw)[0], offset


def _read_id32(data: bytes, offset: int) -> tuple[bytes, int]:
    return _read_bytes(data, offset, 32, "id32")


def _read_blob16(data: bytes, offset: int) -> tuple[bytes, int]:
    """A u16-length-prefixed blob."""
    n, offset = _read_u16(data, offset)
    return _read_bytes(data, offset, n, "blob16 content")


def _read_blob32(data: bytes, offset: int) -> tuple[bytes, int]:
    """A u32-length-prefixed blob."""
    n, offset = _read_u32(data, offset)
    return _read_bytes(data, offset, n, "blob32 content")


class BodyRedirectError(Exception):
    """Where a body lives, when the relay asked for it does not hold it.

    A hint about the origin's location, and nothing more. It deliberately does
    not carry a TLS setting: how carefully to verify the far end's certificate
    is the client's policy, and taking it from the relay that also chose the
    destination would let one party pick both the host and the scrutiny.
    """

    def __init__(self, origin: str, hostname: str, port: int):
        self.origin = origin
        self.hostname = hostname
        self.port = port
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
        code, offset = _read_u16(payload, 0)
        raw, _ = _read_blob16(payload, offset)
        msg = raw.decode("utf-8", errors="replace")
        raise ProtocolError(f"error {code}: {msg}", code=code, detail=msg)
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
    raw, offset = _read_blob32(payload, offset)
    rec = _guard(decode_record, raw)
    raw, offset = _read_blob16(payload, offset)
    witness = _guard(decode_witness, raw)
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
    raw, offset = _read_blob32(payload, offset)
    rec = _guard(decode_record, raw)
    raw, offset = _read_blob16(payload, offset)
    witness = _guard(decode_witness, raw)
    return rec, witness


# ---------------------------------------------------------------------------
# EVENT_HEAD
# ---------------------------------------------------------------------------


def build_event_head(origin: str) -> bytes:
    return struct.pack(">B", OP_EVENT_HEAD) + _enc_text16(origin)


def parse_event_head_response(resp: bytes) -> HeadInfo:
    status, payload = parse_response(resp)
    raw, offset = _read_blob16(payload, 0)
    head = _guard(decode_head, raw)
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
    raw, _ = _read_blob16(payload, 0)
    return _guard(decode_head, raw)


# ---------------------------------------------------------------------------
# EVENT_RANGE
# ---------------------------------------------------------------------------


def build_event_range(
    origin: str, start_seq: int, max_count: int = 100, max_bytes: int = 0
) -> bytes:
    out = struct.pack(">B", OP_EVENT_RANGE)
    out += _enc_text16(origin)
    out += _enc_u64(start_seq, "start_seq")
    out += _enc_u16(max_count, "max_count")
    out += _enc_u32(max_bytes, "max_bytes")
    return out


def build_key_epochs(origin: str) -> bytes:
    """Build a KEY_EPOCHS request: origin only."""
    out = struct.pack(">B", OP_KEY_EPOCHS)
    out += _enc_text16(origin)
    return out


def parse_key_epochs_response(resp: bytes) -> list[tuple[int, int | None, bytes]]:
    """Parse a KEY_EPOCHS response into [(start_seq, end_seq_or_None, pubkey)]."""
    status, payload = parse_response(resp)
    if status != 0x00:
        raise ProtocolError("key epochs response not a success frame")
    count, offset = _read_u16(payload, 0)
    epochs = []
    for _ in range(count):
        start, offset = _read_u64(payload, offset)
        end_raw, offset = _read_u64(payload, offset)
        pubkey, offset = _read_id32(payload, offset)
        epochs.append((start, None if end_raw == 0 else end_raw, pubkey))
    return epochs


def build_report_list(culprit_pubkey: bytes = b"", limit: int = 100, offset: int = 0) -> bytes:
    """Build a REPORT_LIST request. Empty culprit means every report."""
    out = struct.pack(">B", OP_REPORT_LIST)
    out += struct.pack(">B", len(culprit_pubkey)) + culprit_pubkey
    out += _enc_u16(limit, "limit") + _enc_u16(offset, "offset")
    return out


def parse_report_list_response(resp: bytes) -> list[ReportInfo]:
    """Parse a REPORT_LIST response."""
    status, payload = parse_response(resp)
    if status != 0x00:
        raise ProtocolError("report list response not a success frame")
    count, offset = _read_u16(payload, 0)
    reports = []
    for _ in range(count):
        event_id, offset = _read_id32(payload, offset)
        origin, offset = _read_text16(payload, offset)
        origin_seq, offset = _read_u64(payload, offset)
        reporter, offset = _read_id32(payload, offset)
        reporter_username, offset = _read_text16(payload, offset)
        culprit, offset = _read_id32(payload, offset)
        target_origin, offset = _read_text16(payload, offset)
        target_board, offset = _read_text16(payload, offset)
        target_article_id, offset = _read_id32(payload, offset)
        target_event_id, offset = _read_id32(payload, offset)
        body_hash, offset = _read_id32(payload, offset)
        body_size, offset = _read_u32(payload, offset)
        created_at, offset = _read_u64(payload, offset)

        if target_article_id != ZERO_ID:
            target_kind = "article"
        elif target_event_id != ZERO_ID:
            target_kind = "event"
        else:
            target_kind = "none"

        reports.append(
            ReportInfo(
                event_id=event_id.hex(),
                origin=origin,
                origin_seq=origin_seq,
                reporter_pubkey=reporter.hex(),
                reporter_username=reporter_username,
                culprit_pubkey=culprit.hex(),
                target_kind=target_kind,
                target_origin=target_origin,
                target_board=target_board,
                target_article_id=target_article_id.hex(),
                target_event_id=target_event_id.hex(),
                body_hash=body_hash.hex(),
                body_size=body_size,
                created_at=created_at,
            )
        )
    return reports


def build_permissions(board: str = "") -> bytes:
    """Build a PERMISSIONS request, optionally scoped to one board.

    An empty board asks only about what does not depend on one; ACL rules
    carry a board dimension, so a principal may publish to `general` and not
    to `staff`, and a board-independent answer cannot express that.
    """
    return struct.pack(">B", OP_PERMISSIONS) + _enc_text16(board)


def parse_permissions_response(resp: bytes) -> Permissions:
    """Parse a PERMISSIONS response."""
    status, payload = parse_response(resp)
    if status != 0x00:
        raise ProtocolError("permissions response not a success frame")
    principal, offset = _read_text16(payload, 0)
    role, offset = _read_text16(payload, offset)
    board, offset = _read_text16(payload, offset)
    count, offset = _read_u16(payload, offset)
    commands = []
    for _ in range(count):
        name, offset = _read_text16(payload, offset)
        commands.append(name)
    count, offset = _read_u16(payload, offset)
    kinds = []
    for _ in range(count):
        name, offset = _read_text16(payload, offset)
        kinds.append(name)
    return Permissions(principal=principal, role=role, board=board, commands=commands, kinds=kinds)


def _read_witness_set(payload: bytes, offset: int) -> tuple[list[Witness], int]:
    """A count-prefixed provenance chain: one witness per relay the event crossed.

    Every entry is a signed statement by the relay it names, so the chain is
    readable without contacting any of them - which is the point, since a relay
    that has gone offline or stopped answering would otherwise erase the trail
    through it. The set is unordered on purpose: reassemble it by matching
    relay_pubkey against received_from_pubkey, and treat a broken or forked
    edge as a finding rather than something a sort order should smooth over.

    Nothing here is trusted. Signatures are checked where the witnesses are
    stored (FirehoseStore.store_witness); this only frames the bytes.
    """
    count, offset = _read_u16(payload, offset)
    if count > MAX_WITNESS_SET:
        raise ProtocolError(f"witness set of {count} exceeds maximum {MAX_WITNESS_SET}")
    witnesses = []
    for _ in range(count):
        raw, offset = _read_blob16(payload, offset)
        witnesses.append(_guard(decode_witness, raw))
    return witnesses, offset


def parse_event_range_response(resp: bytes) -> list[tuple[Record, list[Witness]]]:
    status, payload = parse_response(resp)
    count, offset = _read_u16(payload, 0)
    results = []
    for _ in range(count):
        raw, offset = _read_blob32(payload, offset)
        rec = _guard(decode_record, raw)
        witnesses, offset = _read_witness_set(payload, offset)
        results.append((rec, witnesses))
    return results


# ---------------------------------------------------------------------------
# EVENT_GET
# ---------------------------------------------------------------------------


def build_event_get(origin: str, event_id: bytes) -> bytes:
    out = struct.pack(">B", OP_EVENT_GET)
    out += _enc_text16(origin)
    out += event_id
    return out


def parse_event_get_response(resp: bytes) -> tuple[Record, list[Witness]]:
    status, payload = parse_response(resp)
    offset = 0
    raw, offset = _read_blob32(payload, offset)
    rec = _guard(decode_record, raw)
    witnesses, offset = _read_witness_set(payload, offset)
    return rec, witnesses


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
        _raw, offset = _read_bytes(payload, offset, owner_len, "owner")
        owner = _raw.hex()
        display, offset = _read_text16(payload, offset)
        boards.append(
            BoardInfo(
                name=name,
                closed=bool(closed),
                owner_pubkey=owner,
                display_name=display,
                origin=board_origin,
            )
        )
    return boards


# ---------------------------------------------------------------------------
# ARTICLE_GET
# ---------------------------------------------------------------------------

SELECTOR_BY_NUM = 0x01
SELECTOR_BY_ID = 0x02


def build_article_get(
    origin: str, board: str, selector_type: int, selector: bytes | int, include_body: bool = False
) -> bytes:
    out = struct.pack(">B", OP_ARTICLE_GET)
    out += _enc_text16(origin)
    out += _enc_text16(board)
    out += struct.pack(">B", selector_type)
    if selector_type == SELECTOR_BY_NUM:
        out += _enc_u64(selector, "article_num")  # type: ignore[arg-type]
    elif selector_type == SELECTOR_BY_ID:
        if not isinstance(selector, bytes):
            raise ProtocolError("by-ID selector must be bytes")
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
    article_id, offset = _read_bytes(data, offset, aid_len, "article_id")
    eid_len, offset = _read_u8(data, offset)
    event_id, offset = _read_bytes(data, offset, eid_len, "event_id")
    visibility_code, offset = _read_u8(data, offset)
    body_code, offset = _read_u8(data, offset)
    bh_len, offset = _read_u8(data, offset)
    body_hash, offset = _read_bytes(data, offset, bh_len, "body_hash")
    body_size, offset = _read_u64(data, offset)
    created_at, offset = _read_i64(data, offset)
    ap_len, offset = _read_u8(data, offset)
    author_pubkey, offset = _read_bytes(data, offset, ap_len, "author_pubkey")
    author_username, offset = _read_text16(data, offset)
    author_registrar, offset = _read_text16(data, offset)
    subject, offset = _read_text16(data, offset)
    tags, offset = _read_text16(data, offset)
    content_type, offset = _read_text16(data, offset)

    root_len, offset = _read_u8(data, offset)
    root_raw, offset = _read_bytes(data, offset, root_len, "root_raw")
    root_id = root_raw.hex() if root_raw and root_raw != ZERO_ID else ""

    reply_len, offset = _read_u8(data, offset)
    reply_raw, offset = _read_bytes(data, offset, reply_len, "reply_raw")
    reply_id = reply_raw.hex() if reply_raw and reply_raw != ZERO_ID else ""

    has_replacement, offset = _read_u8(data, offset)
    replacement_id = ""
    if has_replacement:
        _raw, offset = _read_id32(data, offset)
        replacement_id = _raw.hex()

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


def build_article_list(
    origin: str,
    board: str,
    offset: int = 0,
    limit: int = 100,
    include_cancelled: bool = False,
    include_superseded: bool = False,
    include_purged: bool = False,
) -> bytes:
    flags = 0
    if include_cancelled:
        flags |= 0x01
    if include_superseded:
        flags |= 0x02
    if include_purged:
        flags |= 0x04
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ProtocolError(f"limit must be an integer, got {type(limit).__name__}")
    limit = max(1, min(limit, 65535))
    out = struct.pack(">B", OP_ARTICLE_LIST)
    out += _enc_text16(origin)
    out += _enc_text16(board)
    out += _enc_u32(offset, "offset")
    out += _enc_u16(limit, "limit")
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
    article_id, offset = _read_bytes(data, offset, aid_len, "article_id")
    eid_len, offset = _read_u8(data, offset)
    event_id, offset = _read_bytes(data, offset, eid_len, "event_id")
    visibility_code, offset = _read_u8(data, offset)
    body_code, offset = _read_u8(data, offset)
    bh_len, offset = _read_u8(data, offset)
    body_hash, offset = _read_bytes(data, offset, bh_len, "body_hash")
    body_size, offset = _read_u64(data, offset)
    created_at, offset = _read_i64(data, offset)
    ap_len, offset = _read_u8(data, offset)
    author_pubkey, offset = _read_bytes(data, offset, ap_len, "author_pubkey")
    author_username, offset = _read_text16(data, offset)
    author_registrar, offset = _read_text16(data, offset)
    subject, offset = _read_text16(data, offset)
    tags, offset = _read_text16(data, offset)
    content_type, offset = _read_text16(data, offset)

    root_len, offset = _read_u8(data, offset)
    root_raw, offset = _read_bytes(data, offset, root_len, "root_raw")
    root_id = root_raw.hex() if root_raw and root_raw != ZERO_ID else ""

    reply_len, offset = _read_u8(data, offset)
    reply_raw, offset = _read_bytes(data, offset, reply_len, "reply_raw")
    reply_id = reply_raw.hex() if reply_raw and reply_raw != ZERO_ID else ""

    has_replacement, offset = _read_u8(data, offset)
    replacement_id = ""
    if has_replacement:
        _raw, offset = _read_id32(data, offset)
        replacement_id = _raw.hex()

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


def build_article_search(
    origin: str,
    board: str,
    meta_query: str = "",
    body_query: str = "",
    offset: int = 0,
    limit: int = 100,
    include_cancelled: bool = False,
    include_superseded: bool = False,
) -> bytes:
    flags = 0
    if include_cancelled:
        flags |= 0x01
    if include_superseded:
        flags |= 0x02
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ProtocolError(f"limit must be an integer, got {type(limit).__name__}")
    limit = max(1, min(limit, 65535))
    out = struct.pack(">B", OP_ARTICLE_SEARCH)
    out += _enc_text16(origin)
    out += _enc_text16(board)
    out += _enc_text16(meta_query)
    out += _enc_text16(body_query)
    out += _enc_u32(offset, "offset")
    out += _enc_u16(limit, "limit")
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
        article_id, offset = _read_bytes(payload, offset, aid_len, "article_id")
        subj_len, offset = _read_u8(payload, offset)
        _raw, offset = _read_bytes(payload, offset, subj_len, "subject")
        subject = _raw.decode("utf-8")
        ap_len, offset = _read_u8(payload, offset)
        author_pubkey, offset = _read_bytes(payload, offset, ap_len, "author_pubkey")
        created_at, offset = _read_i64(payload, offset)
        body_avail, offset = _read_u8(payload, offset)
        excerpt, offset = _read_text16(payload, offset)
        results.append(
            SearchResult(
                article_num=article_num,
                article_id=article_id.hex(),
                subject=subject,
                author_pubkey=author_pubkey.hex(),
                created_at=created_at,
                body_available=bool(body_avail),
                excerpt=excerpt,
                origin=result_origin,
            )
        )
    return SearchResponse(results=results, total=total, truncated=bool(truncated))


# ---------------------------------------------------------------------------
# ARTICLE_QUERY
# ---------------------------------------------------------------------------


def build_article_query(
    origin: str,
    board: str,
    filters: list,
    offset: int = 0,
    limit: int = 100,
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
        out += _enc_u16(len(value), "filter value length") + value
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ProtocolError(f"limit must be an integer, got {type(limit).__name__}")
    limit = max(1, min(limit, 65535))
    out += _enc_u32(offset, "offset")
    out += _enc_u16(limit, "limit")
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
    out += _enc_u64(article_num, "article_num")
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
        raise BodyRedirectError(origin, hostname, port)
    if status == STATUS_ERROR:
        parse_response(resp)
    body, _ = _read_blob32(payload, 0)
    return body


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
    pubkey, offset = _read_bytes(payload, offset, pk_len, "pubkey")
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
        pubkey, offset = _read_bytes(payload, offset, pk_len, "pubkey")
        username, offset = _read_text16(payload, offset)
        flags, offset = _read_u64(payload, offset)
        reg_seq, offset = _read_u64(payload, offset)
        created_at, offset = _read_i64(payload, offset)
        revoked, offset = _read_u8(payload, offset)
        users.append(
            UserInfo(
                pubkey=pubkey.hex(),
                username=username,
                flags=flags,
                reg_seq=reg_seq,
                created_at=created_at,
                revoked=bool(revoked),
                origin=origin,
            )
        )
    return users


# ---------------------------------------------------------------------------
# BAN_STATUS
# ---------------------------------------------------------------------------


def build_ban_status(pubkey: bytes) -> bytes:
    return struct.pack(">B", OP_BAN_STATUS) + struct.pack(">B", len(pubkey)) + pubkey


def parse_ban_status_response(resp: bytes) -> BanStatus:
    status, payload = parse_response(resp)
    type_names = {1: "warning", 2: "ban", 3: "permaban"}
    count, offset = _read_u8(payload, 0)
    punishments = []
    for _ in range(count):
        type_code, offset = _read_u8(payload, offset)
        expires_at, offset = _read_i64(payload, offset)
        body_size, offset = _read_u32(payload, offset)
        body_hash, offset = _read_id32(payload, offset)
        event_id, offset = _read_id32(payload, offset)
        origin, offset = _read_text16(payload, offset)
        punishments.append(
            PendingPunishment(
                type=type_names.get(type_code, f"unknown({type_code})"),
                event_id=event_id.hex(),
                origin=origin,
                expires_at=expires_at,
                body_hash=body_hash.hex(),
                body_size=body_size,
            )
        )
    return BanStatus(punishments=punishments)


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
    body, _ = _read_blob32(payload, 0)
    return body
