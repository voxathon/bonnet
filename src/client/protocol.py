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
        tlv_data += struct.pack(">B", field_map[name]) + value

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
    where_bytes = encode_string(where) if where else struct.pack(">B", 0)

    values_data = struct.pack(">B", len(values))
    for vtype, vdata in values:
        values_data += struct.pack(">B", vtype) + vdata

    orderby_bytes = encode_string(orderby) if orderby else struct.pack(">B", 0)

    return (
        struct.pack(">B", COMMANDS["QUERY_POSTS"])
        + encode_string(board)
        + where_bytes
        + values_data
        + orderby_bytes
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
        + encode_string(culprit_pubkey.hex())
        + encode_string(reporter_pubkey.hex())
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
        + encode_string(pubkey.hex())
        + ids_data
        + struct.pack(">q", expires_at)
        + encode_string(notes)
    )


def build_punishment_get(pubkey: bytes) -> bytes:
    return struct.pack(">B", COMMANDS["PUNISHMENT_GET"]) + encode_string(pubkey.hex())


def build_punishment_list_active() -> bytes:
    return struct.pack(">B", COMMANDS["PUNISHMENT_LIST_ACTIVE"])


def build_is_banned(pubkey: bytes) -> bytes:
    return struct.pack(">B", COMMANDS["IS_BANNED"]) + encode_string(pubkey.hex())


def parse_register_resp(payload: bytes) -> str:
    username, _ = decode_string(payload, 0)
    return username


def parse_get_user_resp(payload: bytes, username: str) -> User:
    offset = 0
    pubkey = payload[offset:offset+32]
    offset += 32
    registrar, offset = decode_string(payload, offset)
    return User(
        username=username,
        registrar=registrar,
        record_origin="",  # Server doesn't return this in GET_USER
        relay="",          # Server doesn't return this in GET_USER
        public_key=pubkey.hex(),
    )


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
    return parse_post_list_resp(payload)


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

    return Punishment(
        pubkey=pubkey.hex(), report_ids=report_ids, expires_at=expires_at, notes=notes
    )


def parse_punishment_list_resp(payload: bytes) -> list[Punishment]:
    offset = 0
    count = struct.unpack(">H", payload[offset : offset + 2])[0]
    offset += 2

    punishments = []
    for _ in range(count):
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

        punishments.append(
            Punishment(
                pubkey=pubkey.hex(),
                report_ids=report_ids,
                expires_at=expires_at,
                notes=notes,
            )
        )

    return punishments


def parse_is_banned_resp(payload: bytes) -> BannedStatus:
    offset = 0
    banned = payload[offset]
    offset += 1
    reason, offset = decode_string(payload, offset)

    return BannedStatus(banned=bool(banned), reason=reason)
