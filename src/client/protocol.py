import struct
from typing import Optional

from .models import (
    User,
    Board,
    Post,
    PostSummary,
    PostCreateResult,
    Rule,
    Report,
    Punishment,
    BannedStatus,
    Peer,
    Article,
    ArticleEvent,
    FeedHeadInfo,
)


class ProtocolError(Exception):
    pass


class ResponseStatus:
    SUCCESS = 0x00
    ERROR = 0x01
    REDIRECT = 0x02


class ErrorCode:
    UNKNOWN = 0x0000
    USER_NOT_FOUND = 0x0001
    BOARD_NOT_FOUND = 0x0002
    POST_NOT_FOUND = 0x0003
    PERMISSION_DENIED = 0x0004
    INVALID_COMMAND = 0x0005
    INVALID_DATA = 0x0006
    ALREADY_EXISTS = 0x0007
    BOARD_CLOSED = 0x0008
    NOT_REGISTERED = 0x0009


def encode_frame(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


def decode_frame(data: bytes) -> tuple[int, bytes]:
    if len(data) < 4:
        raise ProtocolError("Frame too short")
    length = struct.unpack(">I", data[:4])[0]
    if len(data) < 4 + length:
        raise ProtocolError(f"Incomplete frame: expected {4 + length}, got {len(data)}")
    return length, data[4 : 4 + length]


def encode_string(s: str) -> bytes:
    encoded = s.encode("utf-8")
    if len(encoded) > 255:
        raise ProtocolError(f"String too long: {len(encoded)} bytes")
    return struct.pack(">B", len(encoded)) + encoded


def encode_bytes(data: bytes) -> bytes:
    if len(data) > 255:
        raise ProtocolError(f"Bytes too long: {len(data)} bytes")
    return struct.pack(">B", len(data)) + data


def encode_long_string(s: str) -> bytes:
    encoded = s.encode("utf-8")
    return struct.pack(">I", len(encoded)) + encoded


def decode_string(data: bytes, offset: int) -> tuple[str, int]:
    if offset >= len(data):
        raise ProtocolError("String length byte missing")
    length = data[offset]
    start = offset + 1
    end = start + length
    if end > len(data):
        raise ProtocolError(f"String data incomplete: expected {length} bytes")
    return data[start:end].decode("utf-8"), end


def decode_long_string(data: bytes, offset: int) -> tuple[str, int]:
    if offset + 4 > len(data):
        raise ProtocolError("Long string length bytes missing")
    length = struct.unpack(">I", data[offset : offset + 4])[0]
    start = offset + 4
    end = start + length
    if end > len(data):
        raise ProtocolError(f"Long string data incomplete: expected {length} bytes")
    return data[start:end].decode("utf-8"), end


def decode_bytes(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset >= len(data):
        raise ProtocolError("Bytes length byte missing")
    length = data[offset]
    start = offset + 1
    end = start + length
    if end > len(data):
        raise ProtocolError(f"Bytes data incomplete: expected {length} bytes")
    return data[start:end], end


def parse_response(data: bytes) -> tuple[int, bytes]:
    if not data:
        raise ProtocolError("Empty response")
    status = data[0]
    return status, data[1:]


def parse_error_response(payload: bytes) -> str:
    if len(payload) < 3:
        return "Unknown error"
    code = struct.unpack(">H", payload[:2])[0]
    msg_len = payload[2]
    if len(payload) < 3 + msg_len:
        return f"Error code {code:#06x}"
    msg = payload[3 : 3 + msg_len].decode("utf-8", errors="replace")
    return f"Error {code:#06x}: {msg}"


def decode_redirect(payload: bytes) -> str:
    origin, _ = decode_string(payload, 0)
    return origin


COMMANDS = {
    "REGISTER": 0x01,
    "GET_USER": 0x02,
    "LIST_USERS": 0x03,
    "LIST_PEERS": 0x04,
    "USER_REGISTRY_HEAD": 0x05,
    "USER_REGISTRY_NODES": 0x06,
    "USER_REGISTRY_RECORDS": 0x07,
    "USER_REGISTRY_HEADS": 0x08,
    "USER_REGISTRY_HEAD_CHAIN": 0x09,
    "BOARD_CREATE": 0x10,
    "BOARD_LIST": 0x11,
    "POST_CREATE": 0x12,
    "POST_GET": 0x13,
    "POST_LIST": 0x14,
    "POST_UPDATE": 0x15,
    "POST_DELETE": 0x16,
    "BOARD_CLOSE": 0x17,
    "BOARD_DELETE": 0x18,
    "QUERY_POSTS": 0x19,
    "POST_CONTENT_SEARCH": 0x1A,
    "USER_PROMOTE": 0x20,
    "USER_DEMOTE": 0x21,
    "POST_SIGN": 0x22,
    "GET_PUBKEY": 0x30,
    "RULE_CREATE": 0x40,
    "RULE_GET": 0x41,
    "RULE_GET_BY_NAME": 0x42,
    "RULE_LIST": 0x43,
    "RULE_UPDATE": 0x44,
    "REPORT_CREATE": 0x50,
    "REPORT_GET": 0x51,
    "REPORT_LIST_BY_CULPRIT": 0x52,
    "REPORT_SIGN": 0x53,
    "REPORT_LIST_SINCE": 0x54,
    "PUNISHMENT_CREATE": 0x60,
    "PUNISHMENT_GET": 0x61,
    "PUNISHMENT_LIST_ACTIVE": 0x62,
    "IS_BANNED": 0x63,
    "PUNISHMENT_LIST_BY_PUBKEY": 0x64,
    "REPORT_REGISTRY_HEAD": 0x55,
    "REPORT_REGISTRY_NODES": 0x56,
    "REPORT_REGISTRY_RECORDS": 0x57,
    "REPORT_REGISTRY_HEADS": 0x58,
    "REPORT_REGISTRY_HEAD_CHAIN": 0x59,
    "PUNISHMENT_REGISTRY_HEAD": 0x65,
    "PUNISHMENT_REGISTRY_NODES": 0x66,
    "PUNISHMENT_REGISTRY_RECORDS": 0x67,
    "PUNISHMENT_REGISTRY_HEADS": 0x68,
    "PUNISHMENT_REGISTRY_HEAD_CHAIN": 0x69,
}


def build_register(username: str, registrar: str) -> bytes:
    return (
        struct.pack(">B", COMMANDS["REGISTER"])
        + encode_string(username)
        + encode_string(registrar)
    )


def build_get_user(pubkey: bytes) -> bytes:
    if len(pubkey) != 32:
        raise ProtocolError(f"Invalid pubkey length: {len(pubkey)}")
    return struct.pack(">B", COMMANDS["GET_USER"]) + pubkey


def build_list_users(offset: int, limit: int) -> bytes:
    return struct.pack(">BII", COMMANDS["LIST_USERS"], offset, limit)


def build_list_peers() -> bytes:
    return struct.pack(">B", COMMANDS["LIST_PEERS"])


def build_board_create(name: str) -> bytes:
    return struct.pack(">B", COMMANDS["BOARD_CREATE"]) + encode_string(name)


def build_board_list() -> bytes:
    return struct.pack(">B", COMMANDS["BOARD_LIST"])


def build_board_close(name: str) -> bytes:
    return struct.pack(">B", COMMANDS["BOARD_CLOSE"]) + encode_string(name)


def build_board_delete(name: str) -> bytes:
    return struct.pack(">B", COMMANDS["BOARD_DELETE"]) + encode_string(name)


def build_post_create(
    board: str, root: int, subject: str, tags: str, options: str, content: str
) -> bytes:
    return (
        struct.pack(">B", COMMANDS["POST_CREATE"])
        + encode_string(board)
        + struct.pack(">Q", root)
        + encode_string(subject)
        + encode_string(tags)
        + encode_string(options)
        + encode_long_string(content)
    )


def build_post_get(board: str, post_num: int) -> bytes:
    return (
        struct.pack(">B", COMMANDS["POST_GET"])
        + encode_string(board)
        + struct.pack(">Q", post_num)
    )


def build_post_list(board: str, offset: int, limit: int) -> bytes:
    return (
        struct.pack(">B", COMMANDS["POST_LIST"])
        + encode_string(board)
        + struct.pack(">II", offset, limit)
    )


TLV_CONTENT = 0x01
TLV_SUBJECT = 0x02
TLV_OPTIONS = 0x03
TLV_TAGS = 0x04
TLV_STICKY = 0x05
TLV_CLOSED = 0x06


def encode_tlv_str(field_type: int, value: str) -> bytes:
    return struct.pack(">B", field_type) + encode_string(value)


def encode_tlv_long_str(field_type: int, value: str) -> bytes:
    return struct.pack(">B", field_type) + encode_long_string(value)


def encode_tlv_i32(field_type: int, value: int) -> bytes:
    return struct.pack(">Bi", field_type, value)


def encode_tlv_u8(field_type: int, value: int) -> bytes:
    return struct.pack(">BB", field_type, value)


def build_post_update(
    board: str, post_num: int, fields: list[tuple[str, bytes]]
) -> bytes:
    field_map = {
        "content": TLV_CONTENT,
        "subject": TLV_SUBJECT,
        "options": TLV_OPTIONS,
        "tags": TLV_TAGS,
        "sticky": TLV_STICKY,
        "closed": TLV_CLOSED,
    }
    tlv_data = b""
    for name, value in fields:
        if name not in field_map:
            raise ProtocolError(f"Unknown field: {name}")
        tlv_data += value

    return (
        struct.pack(">B", COMMANDS["POST_UPDATE"])
        + encode_string(board)
        + struct.pack(">Q", post_num)
        + struct.pack(">B", len(fields))
        + tlv_data
    )


def build_post_delete(board: str, post_num: int) -> bytes:
    return (
        struct.pack(">B", COMMANDS["POST_DELETE"])
        + encode_string(board)
        + struct.pack(">Q", post_num)
    )


def build_query_posts(
    board: str, where: str, values: list[tuple[int, bytes]], orderby: str, limit: int
) -> bytes:
    where_encoded = where.encode("utf-8") if where else b""
    where_bytes = struct.pack(">H", len(where_encoded)) + where_encoded

    values_data = struct.pack(">B", len(values))
    for vtype, vdata in values:
        values_data += struct.pack(">B", vtype) + vdata

    orderby_encoded = orderby.encode("utf-8") if orderby else b""
    orderby_bytes = struct.pack(">H", len(orderby_encoded)) + orderby_encoded

    return (
        struct.pack(">B", COMMANDS["QUERY_POSTS"])
        + encode_string(board)
        + where_bytes
        + values_data
        + orderby_bytes
        + struct.pack(">I", limit)
    )


def build_post_content_search(board: str, pattern: str, limit: int = 100) -> bytes:
    return (
        struct.pack(">B", COMMANDS["POST_CONTENT_SEARCH"])
        + encode_string(board)
        + encode_long_string(pattern)
        + struct.pack(">I", limit)
    )


def build_post_sign(board: str, post_num: int, signature: str) -> bytes:
    sig_bytes = bytes.fromhex(signature) if signature else b""
    return (
        struct.pack(">B", COMMANDS["POST_SIGN"])
        + encode_string(board)
        + struct.pack(">Q", post_num)
        + encode_string(signature)
    )


def build_user_promote(username: str) -> bytes:
    return struct.pack(">B", COMMANDS["USER_PROMOTE"]) + encode_string(username)


def build_user_demote(username: str) -> bytes:
    return struct.pack(">B", COMMANDS["USER_DEMOTE"]) + encode_string(username)


def build_get_pubkey() -> bytes:
    return struct.pack(">B", COMMANDS["GET_PUBKEY"])


def build_rule_create(name: str, description: str) -> bytes:
    return (
        struct.pack(">B", COMMANDS["RULE_CREATE"])
        + encode_string(name)
        + encode_string(description)
    )


def build_rule_get(rule_num: int) -> bytes:
    return struct.pack(">BQ", COMMANDS["RULE_GET"], rule_num)


def build_rule_get_by_name(name: str) -> bytes:
    return struct.pack(">B", COMMANDS["RULE_GET_BY_NAME"]) + encode_string(name)


def build_rule_list() -> bytes:
    return struct.pack(">B", COMMANDS["RULE_LIST"])


def build_rule_update(rule_num: int, fields: list[tuple[str, bytes]]) -> bytes:
    RULE_TLV_NAME = 0x01
    RULE_TLV_DESC = 0x02

    tlv_data = b""
    for name, value in fields:
        if name == "name":
            tlv_data += struct.pack(">B", RULE_TLV_NAME) + value
        elif name == "description":
            tlv_data += struct.pack(">B", RULE_TLV_DESC) + value

    return (
        struct.pack(">B", COMMANDS["RULE_UPDATE"])
        + struct.pack(">Q", rule_num)
        + struct.pack(">B", len(fields))
        + tlv_data
    )


def build_report_create(
    rule_num: int,
    culprit_pubkey: bytes,
    reporter_pubkey: bytes,
    description: str,
    board: Optional[str] = None,
    post_num: Optional[int] = None,
    origin: Optional[str] = None,
    relay: Optional[str] = None,
) -> bytes:
    return (
        struct.pack(">B", COMMANDS["REPORT_CREATE"])
        + struct.pack(">Q", rule_num)
        + encode_bytes(culprit_pubkey)
        + encode_bytes(reporter_pubkey)
        + encode_string(description)
        + encode_string(board or "")
        + struct.pack(">Q", post_num or 0)
        + encode_string(origin or "")
        + encode_string(relay or "")
    )


def build_report_get(origin: str, report_num: int) -> bytes:
    return (
        struct.pack(">B", COMMANDS["REPORT_GET"])
        + encode_string(origin)
        + struct.pack(">Q", report_num)
    )


def build_report_list_by_culprit(pubkey: bytes) -> bytes:
    return struct.pack(">B", COMMANDS["REPORT_LIST_BY_CULPRIT"]) + encode_string(
        pubkey.hex()
    )


def build_report_sign(origin: str, report_num: int, signature: str) -> bytes:
    return (
        struct.pack(">B", COMMANDS["REPORT_SIGN"])
        + encode_string(origin)
        + struct.pack(">Q", report_num)
        + encode_string(signature)
    )


def build_report_list_since(since: int) -> bytes:
    return struct.pack(">Bq", COMMANDS["REPORT_LIST_SINCE"], since)


def build_punishment_create(
    pubkey: bytes, report_ids: list[int], expires_at: int, notes: str
) -> bytes:
    ids_data = struct.pack(">B", len(report_ids))
    for rid in report_ids:
        ids_data += struct.pack(">Q", rid)

    return (
        struct.pack(">B", COMMANDS["PUNISHMENT_CREATE"])
        + encode_bytes(pubkey)
        + ids_data
        + struct.pack(">q", expires_at)
        + encode_string(notes)
    )


def build_punishment_get(origin: str, punishment_id: int) -> bytes:
    """§12.4: PUNISHMENT_GET takes (origin: u8-length UTF-8, punishment_id: u64be)."""
    origin_b = origin.encode("utf-8")
    return (
        struct.pack(">B", COMMANDS["PUNISHMENT_GET"])
        + struct.pack(">B", len(origin_b)) + origin_b
        + struct.pack(">Q", punishment_id)
    )


def build_punishment_list_active() -> bytes:
    return struct.pack(">B", COMMANDS["PUNISHMENT_LIST_ACTIVE"])


def build_punishment_list_by_pubkey(pubkey: bytes) -> bytes:
    return struct.pack(">B", COMMANDS["PUNISHMENT_LIST_BY_PUBKEY"]) + encode_bytes(pubkey)


def build_is_banned(pubkey: bytes) -> bytes:
    return struct.pack(">B", COMMANDS["IS_BANNED"]) + encode_bytes(pubkey)


def parse_register_resp(payload: bytes) -> str:
    username, _ = decode_string(payload, 0)
    return username


def parse_list_users_resp(payload: bytes) -> list[User]:
    offset = 0
    count = struct.unpack(">H", payload[offset : offset + 2])[0]
    offset += 2

    users = []
    for _ in range(count):
        username, offset = decode_string(payload, offset)
        registrar, offset = decode_string(payload, offset)
        record_origin, offset = decode_string(payload, offset)
        relay, offset = decode_string(payload, offset)
        pubkey, offset = decode_bytes(payload, offset)

        users.append(
            User(
                username=username,
                registrar=registrar,
                record_origin=record_origin,
                relay=relay,
                public_key=pubkey.hex(),
            )
        )

    return users


def parse_list_peers_resp(payload: bytes) -> list[Peer]:
    offset = 0
    count = struct.unpack(">H", payload[offset : offset + 2])[0]
    offset += 2

    peers = []
    for _ in range(count):
        origin, offset = decode_string(payload, offset)
        peers.append(Peer(origin=origin))

    return peers


def parse_board_list_resp(payload: bytes) -> list[Board]:
    offset = 0
    count = struct.unpack(">H", payload[offset : offset + 2])[0]
    offset += 2

    boards = []
    for _ in range(count):
        name, offset = decode_string(payload, offset)
        origin, offset = decode_string(payload, offset)
        sig, offset = decode_bytes(payload, offset)
        closed = payload[offset]
        offset += 1

        boards.append(
            Board(
                name=name,
                origin=origin,
                signature=sig.hex(),
                closed=bool(closed),
                owner_pubkey=None,
            )
        )

    return boards


def parse_post_create_resp(payload: bytes) -> PostCreateResult:
    offset = 0
    post_num = struct.unpack(">Q", payload[offset : offset + 8])[0]
    offset += 8
    creation_date = struct.unpack(">q", payload[offset : offset + 8])[0]
    offset += 8
    last_modified = struct.unpack(">q", payload[offset : offset + 8])[0]
    offset += 8
    author, offset = decode_string(payload, offset)
    author_registrar, offset = decode_string(payload, offset)
    tags, offset = decode_string(payload, offset)
    subject, offset = decode_string(payload, offset)
    options, offset = decode_string(payload, offset)

    return PostCreateResult(
        post_num=post_num,
        creation_date=creation_date,
        last_modified=last_modified,
        author=author,
        author_registrar=author_registrar,
        tags=tags,
        subject=subject,
        options=options,
    )


def parse_post_get_resp(payload: bytes) -> Post:
    offset = 0
    post_num = struct.unpack(">Q", payload[offset : offset + 8])[0]
    offset += 8
    last_modified = struct.unpack(">q", payload[offset : offset + 8])[0]
    offset += 8
    creation_date = struct.unpack(">q", payload[offset : offset + 8])[0]
    offset += 8
    last_bumped = struct.unpack(">q", payload[offset : offset + 8])[0]
    offset += 8
    closed = payload[offset]
    offset += 1
    sticky = struct.unpack(">i", payload[offset : offset + 4])[0]
    offset += 4
    tags, offset = decode_string(payload, offset)
    subject, offset = decode_string(payload, offset)
    options, offset = decode_string(payload, offset)
    root = struct.unpack(">Q", payload[offset : offset + 8])[0]
    offset += 8
    author, offset = decode_string(payload, offset)
    author_registrar, offset = decode_string(payload, offset)
    signature, offset = decode_string(payload, offset)
    content, offset = decode_long_string(payload, offset)

    return Post(
        post_num=post_num,
        last_modified=last_modified,
        creation_date=creation_date,
        last_bumped=last_bumped,
        closed=bool(closed),
        sticky=sticky,
        tags=[t for t in tags.split(",") if t],
        subject=subject,
        options=options,
        root=root,
        author=author,
        author_registrar=author_registrar,
        signature=signature,
        content=content,
    )


def parse_post_list_resp(payload: bytes) -> list[PostSummary]:
    posts = []
    offset = 0

    while offset < len(payload):
        post_num = struct.unpack(">Q", payload[offset : offset + 8])[0]
        offset += 8
        creation_date = struct.unpack(">q", payload[offset : offset + 8])[0]
        offset += 8
        subject, offset = decode_string(payload, offset)
        author, offset = decode_string(payload, offset)
        root = struct.unpack(">Q", payload[offset : offset + 8])[0]
        offset += 8

        posts.append(
            PostSummary(
                post_num=post_num,
                creation_date=creation_date,
                subject=subject,
                author=author,
                root=root,
            )
        )

    return posts


def parse_query_posts_resp(payload: bytes) -> list[PostSummary]:
    posts = []
    offset = 0

    while offset < len(payload):
        post_num = struct.unpack(">Q", payload[offset : offset + 8])[0]
        offset += 8
        last_modified = struct.unpack(">q", payload[offset : offset + 8])[0]
        offset += 8
        creation_date = struct.unpack(">q", payload[offset : offset + 8])[0]
        offset += 8
        last_bumped = struct.unpack(">q", payload[offset : offset + 8])[0]
        offset += 8
        closed = payload[offset]
        offset += 1
        sticky = struct.unpack(">i", payload[offset : offset + 4])[0]
        offset += 4
        tags, offset = decode_string(payload, offset)
        subject, offset = decode_string(payload, offset)
        options, offset = decode_string(payload, offset)
        root = struct.unpack(">Q", payload[offset : offset + 8])[0]
        offset += 8
        author, offset = decode_string(payload, offset)
        author_registrar, offset = decode_string(payload, offset)
        signature, offset = decode_string(payload, offset)

        posts.append(
            PostSummary(
                post_num=post_num,
                creation_date=creation_date,
                subject=subject,
                author=author,
                root=root,
            )
        )

    return posts


def parse_post_content_search_resp(payload: bytes) -> list[PostSummary]:
    # The server serializes content-search results with the same per-post
    # encoding as QUERY_POSTS, so reuse that decoder.
    return parse_query_posts_resp(payload)


def parse_get_pubkey_resp(payload: bytes) -> str:
    return payload[:32].hex()


def parse_rule_resp(payload: bytes) -> Rule:
    offset = 0
    rule_num = struct.unpack(">Q", payload[offset : offset + 8])[0]
    offset += 8
    name, offset = decode_string(payload, offset)
    description, offset = decode_string(payload, offset)

    return Rule(rule_num=rule_num, name=name, description=description)


def parse_rule_list_resp(payload: bytes) -> list[Rule]:
    offset = 0
    count = struct.unpack(">H", payload[offset : offset + 2])[0]
    offset += 2

    rules = []
    for _ in range(count):
        rule_num = struct.unpack(">Q", payload[offset : offset + 8])[0]
        offset += 8
        name, offset = decode_string(payload, offset)
        description, offset = decode_string(payload, offset)
        rules.append(Rule(rule_num=rule_num, name=name, description=description))

    return rules


def parse_report_resp(payload: bytes) -> Report:
    offset = 0
    report_num = struct.unpack(">Q", payload[offset : offset + 8])[0]
    offset += 8
    rule_num = struct.unpack(">Q", payload[offset : offset + 8])[0]
    offset += 8
    culprit, offset = decode_bytes(payload, offset)
    board, offset = decode_string(payload, offset)
    post_num = struct.unpack(">Q", payload[offset : offset + 8])[0]
    offset += 8
    reporter, offset = decode_bytes(payload, offset)
    report_time = struct.unpack(">q", payload[offset : offset + 8])[0]
    offset += 8
    origin, offset = decode_string(payload, offset)
    relay, offset = decode_string(payload, offset)
    description, offset = decode_string(payload, offset)
    origin_sig, offset = decode_string(payload, offset)
    reporter_sig, offset = decode_string(payload, offset)

    return Report(
        report_num=report_num,
        rule_num=rule_num,
        culprit_pubkey=culprit.hex(),
        board=board if board else None,
        post_num=post_num if post_num else None,
        reporter_pubkey=reporter.hex(),
        report_time=report_time,
        origin=origin,
        relay=relay,
        description=description,
        origin_sig=origin_sig,
        reporter_sig=reporter_sig if reporter_sig else None,
    )


def parse_report_list_resp(payload: bytes) -> list[Report]:
    offset = 0
    count = struct.unpack(">H", payload[offset : offset + 2])[0]
    offset += 2

    reports = []
    for _ in range(count):
        report_num = struct.unpack(">Q", payload[offset : offset + 8])[0]
        offset += 8
        rule_num = struct.unpack(">Q", payload[offset : offset + 8])[0]
        offset += 8
        culprit, offset = decode_bytes(payload, offset)
        board, offset = decode_string(payload, offset)
        post_num = struct.unpack(">Q", payload[offset : offset + 8])[0]
        offset += 8
        reporter, offset = decode_bytes(payload, offset)
        report_time = struct.unpack(">q", payload[offset : offset + 8])[0]
        offset += 8
        origin, offset = decode_string(payload, offset)
        relay, offset = decode_string(payload, offset)
        description, offset = decode_string(payload, offset)
        origin_sig, offset = decode_string(payload, offset)
        reporter_sig, offset = decode_string(payload, offset)

        reports.append(
            Report(
                report_num=report_num,
                rule_num=rule_num,
                culprit_pubkey=culprit.hex(),
                board=board if board else None,
                post_num=post_num if post_num else None,
                reporter_pubkey=reporter.hex(),
                report_time=report_time,
                origin=origin,
                relay=relay,
                description=description,
                origin_sig=origin_sig,
                reporter_sig=reporter_sig if reporter_sig else None,
            )
        )

    return reports


def parse_punishment_resp(payload: bytes) -> Punishment:
    offset = 0
    punishment_id = struct.unpack(">Q", payload[offset : offset + 8])[0]
    offset += 8
    origin, offset = decode_string(payload, offset)
    rollover = struct.unpack(">Q", payload[offset : offset + 8])[0]
    offset += 8
    pubkey, offset = decode_bytes(payload, offset)
    id_count = payload[offset]
    offset += 1

    report_ids = []
    for _ in range(id_count):
        rid = struct.unpack(">Q", payload[offset : offset + 8])[0]
        offset += 8
        report_ids.append(rid)

    expires_at = struct.unpack(">q", payload[offset : offset + 8])[0]
    offset += 8
    notes, offset = decode_string(payload, offset)
    issued_by, offset = decode_bytes(payload, offset)
    created_at = struct.unpack(">q", payload[offset : offset + 8])[0]
    offset += 8
    origin_sig, offset = decode_string(payload, offset)

    return Punishment(
        punishment_id=punishment_id,
        origin=origin,
        rollover=rollover,
        pubkey=pubkey.hex(),
        report_ids=report_ids,
        expires_at=expires_at,
        notes=notes,
        issued_by=issued_by.hex() if issued_by else None,
        created_at=created_at,
        origin_sig=origin_sig if origin_sig else None,
    )


def parse_punishment_list_resp(payload: bytes) -> list[Punishment]:
    offset = 0
    count = struct.unpack(">H", payload[offset : offset + 2])[0]
    offset += 2

    punishments = []
    for _ in range(count):
        punishment_id = struct.unpack(">Q", payload[offset : offset + 8])[0]
        offset += 8
        origin, offset = decode_string(payload, offset)
        rollover = struct.unpack(">Q", payload[offset : offset + 8])[0]
        offset += 8
        pubkey, offset = decode_bytes(payload, offset)
        id_count = payload[offset]
        offset += 1

        report_ids = []
        for _ in range(id_count):
            rid = struct.unpack(">Q", payload[offset : offset + 8])[0]
            offset += 8
            report_ids.append(rid)

        expires_at = struct.unpack(">q", payload[offset : offset + 8])[0]
        offset += 8
        notes, offset = decode_string(payload, offset)
        issued_by, offset = decode_bytes(payload, offset)
        created_at = struct.unpack(">q", payload[offset : offset + 8])[0]
        offset += 8
        origin_sig, offset = decode_string(payload, offset)

        punishments.append(
            Punishment(
                punishment_id=punishment_id,
                origin=origin,
                rollover=rollover,
                pubkey=pubkey.hex(),
                report_ids=report_ids,
                expires_at=expires_at,
                notes=notes,
                issued_by=issued_by.hex() if issued_by else None,
                created_at=created_at,
                origin_sig=origin_sig if origin_sig else None,
            )
        )

    return punishments


def parse_is_banned_resp(payload: bytes) -> BannedStatus:
    offset = 0
    banned = payload[offset]
    offset += 1
    reason, offset = decode_string(payload, offset)

    return BannedStatus(banned=bool(banned), reason=reason)


# ---------------------------------------------------------------------------
# Registry protocol builders and parsers (opcodes 0x05–0x09)
# ---------------------------------------------------------------------------

_MAX_ORIGIN_LEN = 255
_MAX_PREFIX_BITS = 256
_MAX_NODES_PER_REQUEST = 256
_MAX_RECORDS_PER_REQUEST = 64
_MAX_HEADS_PER_RESPONSE = 100
_REGISTRY_HEAD_FIXED_SIZE = 22 + 32 + 32 + 64  # domain(22) + fields + root + prev + sig


def build_user_registry_head(origin: str, requested_seq: int = 0) -> bytes:
    origin_b = origin.encode("utf-8")
    if len(origin_b) > _MAX_ORIGIN_LEN:
        raise ProtocolError(f"Origin too long: {len(origin_b)} bytes")
    return (
        struct.pack(">B", COMMANDS["USER_REGISTRY_HEAD"])
        + struct.pack(">H", len(origin_b)) + origin_b
        + struct.pack(">Q", requested_seq)
    )


def parse_user_registry_head_resp(payload: bytes) -> bytes:
    if len(payload) < 3:
        raise ProtocolError("Response too short for registry head")
    head_len = struct.unpack(">H", payload[:2])[0]
    if len(payload) != 2 + head_len:
        raise ProtocolError(f"Trailing/truncated head: expected {2 + head_len}, got {len(payload)}")
    return payload[2:2 + head_len]


def build_user_registry_nodes(origin: str, registry_seq: int,
                              prefixes: list[tuple[int, bytes]]) -> bytes:
    origin_b = origin.encode("utf-8")
    if len(origin_b) > _MAX_ORIGIN_LEN:
        raise ProtocolError(f"Origin too long: {len(origin_b)} bytes")
    if len(prefixes) > _MAX_NODES_PER_REQUEST:
        raise ProtocolError(f"Too many prefixes: {len(prefixes)} > {_MAX_NODES_PER_REQUEST}")
    data = (
        struct.pack(">B", COMMANDS["USER_REGISTRY_NODES"])
        + struct.pack(">H", len(origin_b)) + origin_b
        + struct.pack(">Q", registry_seq)
        + struct.pack(">H", len(prefixes))
    )
    for bit_len, prefix_bytes in prefixes:
        if bit_len > _MAX_PREFIX_BITS:
            raise ProtocolError(f"Prefix bit length {bit_len} exceeds {_MAX_PREFIX_BITS}")
        byte_len = (bit_len + 7) // 8
        if len(prefix_bytes) != byte_len:
            raise ProtocolError(f"Prefix byte length mismatch: {len(prefix_bytes)} != {byte_len}")
        data += struct.pack(">H", bit_len) + struct.pack(">B", byte_len) + prefix_bytes
    return data


def parse_user_registry_nodes_resp(payload: bytes) -> list[dict]:
    offset = 0
    if len(payload) < 2:
        raise ProtocolError("Response too short for registry nodes")
    node_count = struct.unpack(">H", payload[offset:offset + 2])[0]
    offset += 2
    if node_count > _MAX_NODES_PER_REQUEST:
        raise ProtocolError(f"Node count {node_count} exceeds limit")
    nodes = []
    for _ in range(node_count):
        if offset + 3 > len(payload):
            raise ProtocolError("Truncated node header")
        bit_len = struct.unpack(">H", payload[offset:offset + 2])[0]
        offset += 2
        byte_len = payload[offset]
        offset += 1
        if offset + byte_len > len(payload):
            raise ProtocolError("Truncated prefix bytes")
        prefix = payload[offset:offset + byte_len]
        offset += byte_len
        if offset + 1 > len(payload):
            raise ProtocolError("Truncated node kind")
        node_kind = payload[offset]
        offset += 1
        if offset + 32 > len(payload):
            raise ProtocolError("Truncated node hash")
        node_hash = payload[offset:offset + 32]
        offset += 32
        entry = {
            "prefix_bit_length": bit_len,
            "prefix": prefix,
            "node_kind": node_kind,
            "node_hash": node_hash,
        }
        if node_kind == 1:  # branch
            if offset + 64 > len(payload):
                raise ProtocolError("Truncated branch children")
            entry["left_hash"] = payload[offset:offset + 32]
            offset += 32
            entry["right_hash"] = payload[offset:offset + 32]
            offset += 32
        elif node_kind == 2:  # leaf
            if offset + 64 > len(payload):
                raise ProtocolError("Truncated leaf data")
            entry["registry_key"] = payload[offset:offset + 32]
            offset += 32
            entry["value_hash"] = payload[offset:offset + 32]
            offset += 32
        nodes.append(entry)
    if offset != len(payload):
        raise ProtocolError(f"Trailing data in nodes response: {len(payload) - offset} bytes")
    return nodes


def build_user_registry_records(origin: str, registry_seq: int,
                                keys: list[bytes],
                                include_proofs: bool = False) -> bytes:
    origin_b = origin.encode("utf-8")
    if len(origin_b) > _MAX_ORIGIN_LEN:
        raise ProtocolError(f"Origin too long: {len(origin_b)} bytes")
    if len(keys) > _MAX_RECORDS_PER_REQUEST:
        raise ProtocolError(f"Too many keys: {len(keys)} > {_MAX_RECORDS_PER_REQUEST}")
    data = (
        struct.pack(">B", COMMANDS["USER_REGISTRY_RECORDS"])
        + struct.pack(">H", len(origin_b)) + origin_b
        + struct.pack(">Q", registry_seq)
        + struct.pack(">H", len(keys))
        + struct.pack(">B", 1 if include_proofs else 0)
    )
    for key in keys:
        if len(key) != 32:
            raise ProtocolError(f"Registry key must be 32 bytes, got {len(key)}")
        data += key
    return data


def parse_user_registry_records_resp(payload: bytes) -> list[dict]:
    offset = 0
    if len(payload) < 2:
        raise ProtocolError("Response too short for registry records")
    record_count = struct.unpack(">H", payload[offset:offset + 2])[0]
    offset += 2
    if record_count > _MAX_RECORDS_PER_REQUEST:
        raise ProtocolError(f"Record count {record_count} exceeds limit")
    records = []
    for _ in range(record_count):
        if offset + 33 > len(payload):
            raise ProtocolError("Truncated record header")
        key = payload[offset:offset + 32]
        offset += 32
        present = payload[offset]
        offset += 1
        entry = {"registry_key": key, "present": present}
        if present:
            if offset + 2 > len(payload):
                raise ProtocolError("Truncated record length")
            rec_len = struct.unpack(">H", payload[offset:offset + 2])[0]
            offset += 2
            if offset + rec_len > len(payload):
                raise ProtocolError("Truncated record bytes")
            entry["raw_record"] = payload[offset:offset + rec_len]
            offset += rec_len
            if offset + 2 > len(payload):
                raise ProtocolError("Truncated proof length")
            proof_len = struct.unpack(">H", payload[offset:offset + 2])[0]
            offset += 2
            if proof_len > 0:
                if offset + proof_len > len(payload):
                    raise ProtocolError("Truncated proof bytes")
                entry["proof"] = payload[offset:offset + proof_len]
                offset += proof_len
            else:
                entry["proof"] = None
        records.append(entry)
    if offset != len(payload):
        raise ProtocolError(f"Trailing data in records response: {len(payload) - offset} bytes")
    return records


def build_user_registry_heads(offset: int = 0, limit: int = 100) -> bytes:
    if limit > _MAX_HEADS_PER_RESPONSE:
        limit = _MAX_HEADS_PER_RESPONSE
    return (
        struct.pack(">B", COMMANDS["USER_REGISTRY_HEADS"])
        + struct.pack(">I", offset)
        + struct.pack(">H", limit)
    )


def parse_user_registry_heads_resp(payload: bytes) -> list[bytes]:
    offset = 0
    if len(payload) < 2:
        raise ProtocolError("Response too short for registry heads list")
    head_count = struct.unpack(">H", payload[offset:offset + 2])[0]
    offset += 2
    if head_count > _MAX_HEADS_PER_RESPONSE:
        raise ProtocolError(f"Head count {head_count} exceeds limit")
    heads = []
    for _ in range(head_count):
        if offset + 2 > len(payload):
            raise ProtocolError("Truncated head length")
        head_len = struct.unpack(">H", payload[offset:offset + 2])[0]
        offset += 2
        if offset + head_len > len(payload):
            raise ProtocolError("Truncated head bytes")
        heads.append(payload[offset:offset + head_len])
        offset += head_len
    if offset != len(payload):
        raise ProtocolError(f"Trailing data in heads response: {len(payload) - offset} bytes")
    return heads


def build_user_registry_head_chain(origin: str, start_seq: int,
                                   max_count: int = 10) -> bytes:
    origin_b = origin.encode("utf-8")
    if len(origin_b) > _MAX_ORIGIN_LEN:
        raise ProtocolError(f"Origin too long: {len(origin_b)} bytes")
    if max_count > _MAX_HEADS_PER_RESPONSE:
        max_count = _MAX_HEADS_PER_RESPONSE
    return (
        struct.pack(">B", COMMANDS["USER_REGISTRY_HEAD_CHAIN"])
        + struct.pack(">H", len(origin_b)) + origin_b
        + struct.pack(">Q", start_seq)
        + struct.pack(">H", max_count)
    )


# ---------------------------------------------------------------------------
# Report registry protocol commands (opcodes 0x55–0x59)
# Mirrors the user registry protocol but with report registry opcodes.
# ---------------------------------------------------------------------------

def build_report_registry_head(origin: str, requested_seq: int = 0) -> bytes:
    origin_b = origin.encode("utf-8")
    if len(origin_b) > _MAX_ORIGIN_LEN:
        raise ProtocolError(f"Origin too long: {len(origin_b)} bytes")
    return (
        struct.pack(">B", COMMANDS["REPORT_REGISTRY_HEAD"])
        + struct.pack(">H", len(origin_b)) + origin_b
        + struct.pack(">Q", requested_seq)
    )


def parse_report_registry_head_resp(payload: bytes) -> bytes:
    if len(payload) < 3:
        raise ProtocolError("Response too short for registry head")
    head_len = struct.unpack(">H", payload[:2])[0]
    if len(payload) != 2 + head_len:
        raise ProtocolError(f"Trailing/truncated head: expected {2 + head_len}, got {len(payload)}")
    return payload[2:2 + head_len]


def build_report_registry_nodes(origin: str, registry_seq: int,
                                prefixes: list[tuple[int, bytes]]) -> bytes:
    origin_b = origin.encode("utf-8")
    if len(origin_b) > _MAX_ORIGIN_LEN:
        raise ProtocolError(f"Origin too long: {len(origin_b)} bytes")
    if len(prefixes) > _MAX_NODES_PER_REQUEST:
        raise ProtocolError(f"Too many prefixes: {len(prefixes)} > {_MAX_NODES_PER_REQUEST}")
    data = (
        struct.pack(">B", COMMANDS["REPORT_REGISTRY_NODES"])
        + struct.pack(">H", len(origin_b)) + origin_b
        + struct.pack(">Q", registry_seq)
        + struct.pack(">H", len(prefixes))
    )
    for bit_len, prefix_bytes in prefixes:
        if bit_len > _MAX_PREFIX_BITS:
            raise ProtocolError(f"Prefix bit length {bit_len} exceeds {_MAX_PREFIX_BITS}")
        byte_len = (bit_len + 7) // 8
        if len(prefix_bytes) != byte_len:
            raise ProtocolError(f"Prefix byte length mismatch: {len(prefix_bytes)} != {byte_len}")
        data += struct.pack(">H", bit_len) + struct.pack(">B", byte_len) + prefix_bytes
    return data


def parse_report_registry_nodes_resp(payload: bytes) -> list[dict]:
    return parse_user_registry_nodes_resp(payload)


def build_report_registry_records(origin: str, registry_seq: int,
                                  keys: list[bytes],
                                  include_proofs: bool = False) -> bytes:
    origin_b = origin.encode("utf-8")
    if len(origin_b) > _MAX_ORIGIN_LEN:
        raise ProtocolError(f"Origin too long: {len(origin_b)} bytes")
    if len(keys) > _MAX_RECORDS_PER_REQUEST:
        raise ProtocolError(f"Too many keys: {len(keys)} > {_MAX_RECORDS_PER_REQUEST}")
    data = (
        struct.pack(">B", COMMANDS["REPORT_REGISTRY_RECORDS"])
        + struct.pack(">H", len(origin_b)) + origin_b
        + struct.pack(">Q", registry_seq)
        + struct.pack(">H", len(keys))
        + struct.pack(">B", 1 if include_proofs else 0)
    )
    for key in keys:
        if len(key) != 32:
            raise ProtocolError(f"Registry key must be 32 bytes, got {len(key)}")
        data += key
    return data


def parse_report_registry_records_resp(payload: bytes) -> list[dict]:
    return parse_user_registry_records_resp(payload)


def build_report_registry_heads(offset: int = 0, limit: int = 100) -> bytes:
    if limit > _MAX_HEADS_PER_RESPONSE:
        limit = _MAX_HEADS_PER_RESPONSE
    return (
        struct.pack(">B", COMMANDS["REPORT_REGISTRY_HEADS"])
        + struct.pack(">I", offset)
        + struct.pack(">H", limit)
    )


def parse_report_registry_heads_resp(payload: bytes) -> list[bytes]:
    return parse_user_registry_heads_resp(payload)


def build_report_registry_head_chain(origin: str, start_seq: int,
                                     max_count: int = 10) -> bytes:
    origin_b = origin.encode("utf-8")
    if len(origin_b) > _MAX_ORIGIN_LEN:
        raise ProtocolError(f"Origin too long: {len(origin_b)} bytes")
    if max_count > _MAX_HEADS_PER_RESPONSE:
        max_count = _MAX_HEADS_PER_RESPONSE
    return (
        struct.pack(">B", COMMANDS["REPORT_REGISTRY_HEAD_CHAIN"])
        + struct.pack(">H", len(origin_b)) + origin_b
        + struct.pack(">Q", start_seq)
        + struct.pack(">H", max_count)
    )


# ---------------------------------------------------------------------------
# Punishment registry protocol commands (opcodes 0x65–0x69)
# Mirrors the report registry protocol but with punishment registry opcodes.
# ---------------------------------------------------------------------------

def build_punishment_registry_head(origin: str, requested_seq: int = 0) -> bytes:
    origin_b = origin.encode("utf-8")
    if len(origin_b) > _MAX_ORIGIN_LEN:
        raise ProtocolError(f"Origin too long: {len(origin_b)} bytes")
    return (
        struct.pack(">B", COMMANDS["PUNISHMENT_REGISTRY_HEAD"])
        + struct.pack(">H", len(origin_b)) + origin_b
        + struct.pack(">Q", requested_seq)
    )


def parse_punishment_registry_head_resp(payload: bytes) -> bytes:
    return parse_report_registry_head_resp(payload)


def build_punishment_registry_nodes(origin: str, registry_seq: int,
                                    prefixes: list[tuple[int, bytes]]) -> bytes:
    origin_b = origin.encode("utf-8")
    if len(origin_b) > _MAX_ORIGIN_LEN:
        raise ProtocolError(f"Origin too long: {len(origin_b)} bytes")
    if len(prefixes) > _MAX_NODES_PER_REQUEST:
        raise ProtocolError(f"Too many prefixes: {len(prefixes)} > {_MAX_NODES_PER_REQUEST}")
    data = (
        struct.pack(">B", COMMANDS["PUNISHMENT_REGISTRY_NODES"])
        + struct.pack(">H", len(origin_b)) + origin_b
        + struct.pack(">Q", registry_seq)
        + struct.pack(">H", len(prefixes))
    )
    for bit_len, prefix_bytes in prefixes:
        if bit_len > _MAX_PREFIX_BITS:
            raise ProtocolError(f"Prefix bit length {bit_len} exceeds {_MAX_PREFIX_BITS}")
        byte_len = (bit_len + 7) // 8
        if len(prefix_bytes) != byte_len:
            raise ProtocolError(f"Prefix byte length mismatch: {len(prefix_bytes)} != {byte_len}")
        data += struct.pack(">H", bit_len) + struct.pack(">B", byte_len) + prefix_bytes
    return data


def parse_punishment_registry_nodes_resp(payload: bytes) -> list[dict]:
    return parse_user_registry_nodes_resp(payload)


def build_punishment_registry_records(origin: str, registry_seq: int,
                                      keys: list[bytes],
                                      include_proofs: bool = False) -> bytes:
    origin_b = origin.encode("utf-8")
    if len(origin_b) > _MAX_ORIGIN_LEN:
        raise ProtocolError(f"Origin too long: {len(origin_b)} bytes")
    if len(keys) > _MAX_RECORDS_PER_REQUEST:
        raise ProtocolError(f"Too many keys: {len(keys)} > {_MAX_RECORDS_PER_REQUEST}")
    data = (
        struct.pack(">B", COMMANDS["PUNISHMENT_REGISTRY_RECORDS"])
        + struct.pack(">H", len(origin_b)) + origin_b
        + struct.pack(">Q", registry_seq)
        + struct.pack(">H", len(keys))
        + struct.pack(">B", 1 if include_proofs else 0)
    )
    for key in keys:
        if len(key) != 32:
            raise ProtocolError(f"Registry key must be 32 bytes, got {len(key)}")
        data += key
    return data


def parse_punishment_registry_records_resp(payload: bytes) -> list[dict]:
    return parse_user_registry_records_resp(payload)


def build_punishment_registry_heads(offset: int = 0, limit: int = 100) -> bytes:
    if limit > _MAX_HEADS_PER_RESPONSE:
        limit = _MAX_HEADS_PER_RESPONSE
    return (
        struct.pack(">B", COMMANDS["PUNISHMENT_REGISTRY_HEADS"])
        + struct.pack(">I", offset)
        + struct.pack(">H", limit)
    )


def parse_punishment_registry_heads_resp(payload: bytes) -> list[bytes]:
    return parse_user_registry_heads_resp(payload)


def build_punishment_registry_head_chain(origin: str, start_seq: int,
                                         max_count: int = 10) -> bytes:
    origin_b = origin.encode("utf-8")
    if len(origin_b) > _MAX_ORIGIN_LEN:
        raise ProtocolError(f"Origin too long: {len(origin_b)} bytes")
    if max_count > _MAX_HEADS_PER_RESPONSE:
        max_count = _MAX_HEADS_PER_RESPONSE
    return (
        struct.pack(">B", COMMANDS["PUNISHMENT_REGISTRY_HEAD_CHAIN"])
        + struct.pack(">H", len(origin_b)) + origin_b
        + struct.pack(">Q", start_seq)
        + struct.pack(">H", max_count)
    )


# ===========================================================================
# Protocol v3 article feed builders and parsers (§13.4)
# ===========================================================================

V3_COMMANDS = {
    "ARTICLE_PUBLISH": 0x12,
    "ARTICLE_GET": 0x13,
    "ARTICLE_LIST": 0x14,
    "FEED_HEAD": 0x15,
    "FEED_EVENTS": 0x16,
    "ARTICLE_BODY": 0x17,
    "FEED_HEADS": 0x18,
    "ARTICLE_SEARCH": 0x19,
    "BOARD_SET_STATE": 0x1A,
    "BAN_STATUS": 0x1B,
}


def _encode_v3_str(s: str) -> bytes:
    """u16 length + UTF-8 bytes (§13.4: stop using u8 string lengths)."""
    b = s.encode("utf-8")
    return struct.pack(">H", len(b)) + b


def _decode_v3_str(data: bytes, offset: int) -> tuple[str, int]:
    length = struct.unpack(">H", data[offset:offset + 2])[0]
    offset += 2
    s = data[offset:offset + length].decode("utf-8")
    return s, offset + length


def _decode_v3_bytes_u16(data: bytes, offset: int) -> tuple[bytes, int]:
    length = struct.unpack(">H", data[offset:offset + 2])[0]
    offset += 2
    b = data[offset:offset + length]
    return b, offset + length


def _decode_v3_bytes_u32(data: bytes, offset: int) -> tuple[bytes, int]:
    length = struct.unpack(">I", data[offset:offset + 4])[0]
    offset += 4
    b = data[offset:offset + length]
    return b, offset + length


# --- ARTICLE_PUBLISH (§13.4) ---

def build_article_publish(encoded_submission: bytes, body: bytes,
                          author_signature_scheme: int,
                          author_signature: bytes) -> bytes:
    """Build an ARTICLE_PUBLISH request.

    Wire format:
      opcode:u8 + submission_len:u32 + encoded_submission +
      body_len:u32 + body + author_signature_scheme:u8 +
      author_signature_len:u16 + author_signature
    """
    return (
        struct.pack(">B", V3_COMMANDS["ARTICLE_PUBLISH"])
        + struct.pack(">I", len(encoded_submission)) + encoded_submission
        + struct.pack(">I", len(body)) + body
        + struct.pack(">B", author_signature_scheme)
        + struct.pack(">H", len(author_signature)) + author_signature
    )


def parse_article_publish_resp(payload: bytes) -> dict:
    """Parse ARTICLE_PUBLISH success response.

    Format: event_len:u32 + encoded_event + head_len:u16 + encoded_head
    Returns dict with 'event_bytes' and 'head_bytes'.
    """
    offset = 0
    event_len = struct.unpack(">I", payload[offset:offset + 4])[0]
    offset += 4
    event_bytes = payload[offset:offset + event_len]
    offset += event_len
    head_len = struct.unpack(">H", payload[offset:offset + 2])[0]
    offset += 2
    head_bytes = payload[offset:offset + head_len]
    return {"event_bytes": event_bytes, "head_bytes": head_bytes}


# --- ARTICLE_GET (§13.4) ---

def build_article_get(board: str, selector_type: int,
                      selector: bytes | int, include_body: bool = True) -> bytes:
    """Build an ARTICLE_GET request.

    selector_type: 0x01 (article_num, selector is int) or
                   0x02 (message_id, selector is 32-byte bytes)
    """
    out = struct.pack(">B", V3_COMMANDS["ARTICLE_GET"]) + _encode_v3_str(board)
    out += struct.pack(">B", selector_type)
    if selector_type == 0x01:
        out += struct.pack(">Q", selector)
    elif selector_type == 0x02:
        out += selector  # 32 bytes raw
    else:
        raise ProtocolError(f"invalid selector_type {selector_type}")
    out += struct.pack(">B", 1 if include_body else 0)
    return out


def parse_article_get_resp(payload: bytes) -> dict:
    """Parse ARTICLE_GET success response.

    Format: event_len:u32 + encoded_event + projected_state:u8 +
    control_count:u16 + control_message_ids:(32*count) +
    body_status:u8 + body_len:u32 + body_bytes
    """
    offset = 0
    event_len = struct.unpack(">I", payload[offset:offset + 4])[0]
    offset += 4
    event_bytes = payload[offset:offset + event_len]
    offset += event_len
    projected_state = payload[offset]
    offset += 1
    control_count = struct.unpack(">H", payload[offset:offset + 2])[0]
    offset += 2
    control_ids = []
    for _ in range(control_count):
        control_ids.append(payload[offset:offset + 32].hex())
        offset += 32
    body_status = payload[offset]
    offset += 1
    body_len = struct.unpack(">I", payload[offset:offset + 4])[0]
    offset += 4
    body = payload[offset:offset + body_len] if body_len > 0 else b""
    return {
        "event_bytes": event_bytes,
        "projected_state": projected_state,
        "control_event_ids": control_ids,
        "body_status": body_status,
        "body": body,
    }


# --- ARTICLE_LIST (§13.4) ---

def build_article_list(board: str, offset: int = 0, limit: int = 50,
                       flags: int = 0) -> bytes:
    """Build an ARTICLE_LIST request."""
    return (
        struct.pack(">B", V3_COMMANDS["ARTICLE_LIST"])
        + _encode_v3_str(board)
        + struct.pack(">I", offset)
        + struct.pack(">H", limit)
        + struct.pack(">H", flags)
    )


def parse_article_list_resp(payload: bytes) -> list[dict]:
    """Parse ARTICLE_LIST success response.

    Format: count:u16 + repeated { event_len:u32 + encoded_event +
    projected_state:u8 + control_count:u16 + control_ids + body_status:u8 +
    body_len:u32 + optional_body }
    """
    offset = 0
    count = struct.unpack(">H", payload[offset:offset + 2])[0]
    offset += 2
    results = []
    for _ in range(count):
        event_len = struct.unpack(">I", payload[offset:offset + 4])[0]
        offset += 4
        event_bytes = payload[offset:offset + event_len]
        offset += event_len
        projected_state = payload[offset]
        offset += 1
        control_count = struct.unpack(">H", payload[offset:offset + 2])[0]
        offset += 2
        control_ids = []
        for _ in range(control_count):
            control_ids.append(payload[offset:offset + 32].hex())
            offset += 32
        body_status = payload[offset]
        offset += 1
        body_len = struct.unpack(">I", payload[offset:offset + 4])[0]
        offset += 4
        body = payload[offset:offset + body_len] if body_len > 0 else b""
        offset += body_len
        results.append({
            "event_bytes": event_bytes,
            "projected_state": projected_state,
            "control_event_ids": control_ids,
            "body_status": body_status,
            "body": body,
        })
    return results


# --- FEED_HEAD (§13.4) ---

def build_feed_head(board: str) -> bytes:
    """Build a FEED_HEAD request. Format: origin + board (u16 strings)."""
    return (
        struct.pack(">B", V3_COMMANDS["FEED_HEAD"])
        + _encode_v3_str("")  # origin omitted for local; server fills
        + _encode_v3_str(board)
    )


def parse_feed_head_resp(payload: bytes) -> bytes:
    """Parse FEED_HEAD success response. Returns encoded head bytes."""
    head_len = struct.unpack(">H", payload[0:2])[0]
    return payload[2:2 + head_len]


# --- FEED_EVENTS (§13.4) ---

def build_feed_events(board: str, start_seq: int, max_count: int = 100) -> bytes:
    """Build a FEED_EVENTS request."""
    return (
        struct.pack(">B", V3_COMMANDS["FEED_EVENTS"])
        + _encode_v3_str("")  # origin omitted for local
        + _encode_v3_str(board)
        + struct.pack(">Q", start_seq)
        + struct.pack(">H", max_count)
    )


def parse_feed_events_resp(payload: bytes) -> list[bytes]:
    """Parse FEED_EVENTS success response. Returns list of encoded event bytes."""
    offset = 0
    count = struct.unpack(">H", payload[offset:offset + 2])[0]
    offset += 2
    events = []
    for _ in range(count):
        event_len = struct.unpack(">I", payload[offset:offset + 4])[0]
        offset += 4
        events.append(payload[offset:offset + event_len])
        offset += event_len
    return events


# --- ARTICLE_BODY (§13.4) ---

def build_article_body(board: str, message_id: bytes, body_hash: bytes) -> bytes:
    """Build an ARTICLE_BODY request."""
    return (
        struct.pack(">B", V3_COMMANDS["ARTICLE_BODY"])
        + _encode_v3_str("")  # origin
        + _encode_v3_str(board)
        + message_id  # 32 bytes
        + body_hash   # 32 bytes
    )


def parse_article_body_resp(payload: bytes) -> bytes:
    """Parse ARTICLE_BODY success response. Returns body bytes."""
    body_len = struct.unpack(">I", payload[0:4])[0]
    return payload[4:4 + body_len]


# --- FEED_HEADS (§13.4) ---

def build_feed_heads(offset: int = 0, limit: int = 100) -> bytes:
    """Build a FEED_HEADS request."""
    return (
        struct.pack(">B", V3_COMMANDS["FEED_HEADS"])
        + struct.pack(">I", offset)
        + struct.pack(">H", limit)
    )


def parse_feed_heads_resp(payload: bytes) -> list[dict]:
    """Parse FEED_HEADS success response.

    Format: count:u16 + repeated { origin:u16 + board:u16 + head_len:u16 + head }
    """
    offset = 0
    count = struct.unpack(">H", payload[offset:offset + 2])[0]
    offset += 2
    results = []
    for _ in range(count):
        origin, offset = _decode_v3_str(payload, offset)
        board, offset = _decode_v3_str(payload, offset)
        head_len = struct.unpack(">H", payload[offset:offset + 2])[0]
        offset += 2
        head_bytes = payload[offset:offset + head_len]
        offset += head_len
        results.append({"origin": origin, "board": board, "head_bytes": head_bytes})
    return results


# --- ARTICLE_SEARCH (§13.4) ---

def build_article_search(board: str, text_query: str = "",
                         offset: int = 0, limit: int = 50,
                         flags: int = 0,
                         actor_pubkey: bytes = None,
                         created_after: int = 0,
                         created_before: int = 0) -> bytes:
    """Build an ARTICLE_SEARCH request with structured filters."""
    out = struct.pack(">B", V3_COMMANDS["ARTICLE_SEARCH"])
    out += _encode_v3_str("")  # origin
    out += _encode_v3_str(board)
    out += struct.pack(">I", 0)  # event_type_mask (not used in Phase 3)
    out += (actor_pubkey if actor_pubkey else b"\x00" * 32)  # actor_pubkey_or_zero
    out += b"\x00" * 32  # subject_pubkey_or_zero
    out += b"\x00" * 32  # target_message_id_or_zero
    out += struct.pack(">q", created_after)
    out += struct.pack(">q", created_before)
    out += _encode_v3_str(text_query)
    out += struct.pack(">I", offset)
    out += struct.pack(">H", limit)
    out += struct.pack(">H", flags)
    return out


def parse_article_search_resp(payload: bytes) -> dict:
    """Parse ARTICLE_SEARCH success response.

    Format: body_search_complete:u8 + same entry list as ARTICLE_LIST
    """
    body_search_complete = payload[0]
    entries = parse_article_list_resp(payload[1:])
    return {"body_search_complete": body_search_complete, "entries": entries}


# --- BAN_STATUS (§13.4) ---

def build_ban_status(pubkey: bytes) -> bytes:
    """Build a BAN_STATUS request. Format: opcode + 32-byte pubkey."""
    return struct.pack(">B", V3_COMMANDS["BAN_STATUS"]) + pubkey


def parse_ban_status_resp(payload: bytes) -> dict:
    """Parse BAN_STATUS success response.

    Format: banned:u8 + reason:u16 + punishment_message_id:32 +
    source_origin:u16 + source_board:u16 + expires_at:i64
    """
    offset = 0
    banned = payload[offset]
    offset += 1
    reason, offset = _decode_v3_str(payload, offset)
    punishment_message_id = payload[offset:offset + 32].hex()
    offset += 32
    source_origin, offset = _decode_v3_str(payload, offset)
    source_board, offset = _decode_v3_str(payload, offset)
    expires_at = struct.unpack(">q", payload[offset:offset + 8])[0]
    return {
        "banned": bool(banned),
        "reason": reason,
        "punishment_message_id": punishment_message_id,
        "source_origin": source_origin,
        "source_board": source_board,
        "expires_at": expires_at,
    }


# --- Event decoding helper for client-side consumption ---

def decode_v3_event(event_bytes: bytes) -> dict:
    """Decode a v3 encoded event into a dict of fields.

    Uses core.article_feed.decode_event and converts to client-friendly dict.
    """
    import sys
    import os
    src_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "src")
    if src_path not in sys.path:
        sys.path.insert(0, src_path)
    from core.article_feed import (
        decode_event, EVENT_ARTICLE, EVENT_CANCEL, EVENT_RESTORE, EVENT_PURGE,
        ArticleHeaders, ReportHeaders, PunishmentHeaders, RuleHeaders, PinHeaders,
    )

    ev = decode_event(event_bytes)
    event_type_names = {
        0x01: "ARTICLE", 0x02: "CANCEL", 0x03: "RESTORE", 0x04: "PURGE",
        0x05: "RULE", 0x06: "RULE_REVOKE", 0x07: "REPORT", 0x08: "PUNISHMENT",
        0x09: "PUNISHMENT_REVOKE", 0x0A: "BOARD_CLOSE", 0x0B: "BOARD_REOPEN",
        0x0C: "ARTICLE_PIN", 0x0D: "ARTICLE_UNPIN", 0x0E: "THREAD_CLOSE",
        0x0F: "THREAD_REOPEN",
    }
    result = {
        "feed_seq": ev.feed_seq,
        "article_num": ev.article_num,
        "message_id": ev.message_id.hex(),
        "event_type": ev.event_type,
        "event_type_name": event_type_names.get(ev.event_type, "UNKNOWN"),
        "origin": ev.origin,
        "board": ev.board,
        "created_at": ev.created_at,
        "actor_pubkey": ev.actor_pubkey.hex(),
        "actor_username": ev.actor_username,
        "actor_registrar": ev.actor_registrar,
        "root_message_id": ev.root_message_id.hex(),
        "reply_to_message_id": ev.reply_to_message_id.hex(),
        "supersedes_message_id": ev.supersedes_message_id.hex(),
        "target_message_id": ev.target_message_id.hex(),
        "body_hash": ev.body_hash.hex(),
        "body_size": ev.body_size,
    }
    if isinstance(ev.headers, ArticleHeaders):
        result["subject"] = ev.headers.subject
        result["tags"] = ev.headers.tags
        result["options"] = ev.headers.options
    else:
        result["subject"] = ""
        result["tags"] = ""
        result["options"] = ""
    return result


def decode_v3_head(head_bytes: bytes) -> dict:
    """Decode a v3 encoded feed head into a dict."""
    import sys
    import os
    src_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "src")
    if src_path not in sys.path:
        sys.path.insert(0, src_path)
    from core.article_feed import decode_head

    head = decode_head(head_bytes)
    return {
        "origin": head.origin,
        "board": head.board,
        "latest_feed_seq": head.latest_feed_seq,
        "latest_event_hash": head.latest_event_hash.hex(),
        "article_count": head.article_count,
        "event_count": head.event_count,
        "snapshot_timestamp": head.snapshot_timestamp,
        "signature": head.signature.hex(),
    }
