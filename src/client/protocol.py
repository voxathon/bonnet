"""Bonnet protocol v3 binary codec.

Builders and parsers for all v3 wire commands. The v2 command table and
v2-only builders (mutable posts, dedicated report/punishment/rule commands,
post signing, content search, query posts) have been removed per the v3
cutover. Opcodes shared between v2 and v3 (REGISTER, GET_USER, LIST_USERS,
LIST_PEERS, BOARD_CREATE, BOARD_LIST, USER_PROMOTE, USER_DEMOTE, GET_PUBKEY,
USER_REGISTRY_*) are retained with their original wire format and routed
through /v3/command by the HTTP client.

Control events (cancel, restore, purge, rule, report, punishment, board
close/reopen, pin/unpin, thread close/reopen) are published via
ARTICLE_PUBLISH with the appropriate event_type — they do not have separate
opcodes. BOARD_SET_STATE (0x1A) is the only control command with its own
opcode (for board close/reopen with idempotency checks).
"""

import os
import struct
import time
from dataclasses import dataclass
from typing import Optional

from core.article_feed import (
    Submission,
    ArticleHeaders,
    RuleHeaders,
    ReportHeaders,
    PunishmentHeaders,
    PinHeaders,
    UserHeaders,
    encode_submission,
    decode_event,
    decode_head,
    compute_body_hash,
    author_signature_payload,
    EVENT_ARTICLE,
    EVENT_CANCEL,
    EVENT_RESTORE,
    EVENT_PURGE,
    EVENT_RULE,
    EVENT_RULE_REVOKE,
    EVENT_REPORT,
    EVENT_PUNISHMENT,
    EVENT_PUNISHMENT_REVOKE,
    EVENT_BOARD_CLOSE,
    EVENT_BOARD_REOPEN,
    EVENT_ARTICLE_PIN,
    EVENT_ARTICLE_UNPIN,
    EVENT_THREAD_CLOSE,
    EVENT_THREAD_REOPEN,
    SCHEME_V3,
    ZERO_HASH,
    ZERO_MESSAGE_ID,
    FLAG_INCLUDE_CANCELLED,
    FLAG_INCLUDE_SUPERSEDED,
    FLAG_INCLUDE_PURGED,
    FLAG_INCLUDE_CONTROLS,
    FLAG_INCLUDE_BODIES,
    SELECTOR_ARTICLE_NUM,
    SELECTOR_MESSAGE_ID,
)
from core.crypto import Identity

from .models import (
    User,
    Board,
    Peer,
    BanStatus,
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


# ---------------------------------------------------------------------------
# Frame / string utilities (shared with v2 wire format)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# v3 command opcode table (single source of truth)
# ---------------------------------------------------------------------------

V3_COMMANDS = {
    # Shared with v2 (identical wire format, routed via /v3/command)
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
    "USER_PROMOTE": 0x20,
    "USER_DEMOTE": 0x21,
    "GET_PUBKEY": 0x30,
    "PEER_KEY_ROTATE": 0x70,
    "PEER_KEY_LIST": 0x71,
    # v3 article feed commands
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

# Human-readable event type names
EVENT_TYPE_NAMES = {
    0x01: "ARTICLE", 0x02: "CANCEL", 0x03: "RESTORE", 0x04: "PURGE",
    0x05: "RULE", 0x06: "RULE_REVOKE", 0x07: "REPORT", 0x08: "PUNISHMENT",
    0x09: "PUNISHMENT_REVOKE", 0x0A: "BOARD_CLOSE", 0x0B: "BOARD_REOPEN",
    0x0C: "ARTICLE_PIN", 0x0D: "ARTICLE_UNPIN", 0x0E: "THREAD_CLOSE",
    0x0F: "THREAD_REOPEN", 0x10: "USER_REGISTER", 0x11: "USER_REVOKE",
}


# ---------------------------------------------------------------------------
# Builders for shared opcodes (retained from v2, routed via /v3/command)
# ---------------------------------------------------------------------------

def build_register(username: str, registrar: str) -> bytes:
    return (
        struct.pack(">B", V3_COMMANDS["REGISTER"])
        + encode_string(username)
        + encode_string(registrar)
    )


def build_get_user(username: str) -> bytes:
    """Build a GET_USER request.

    The server's _cmd_get handler parses a u8-length username string (not a
    32-byte pubkey as the v3 spec name GET_USERS_BY_PUBKEY suggests). This
    builder matches the actual server wire format.
    """
    return struct.pack(">B", V3_COMMANDS["GET_USER"]) + encode_string(username)


def build_list_users(offset: int, limit: int) -> bytes:
    return struct.pack(">BII", V3_COMMANDS["LIST_USERS"], offset, limit)


def build_list_peers() -> bytes:
    return struct.pack(">B", V3_COMMANDS["LIST_PEERS"])


def build_board_create(name: str) -> bytes:
    return struct.pack(">B", V3_COMMANDS["BOARD_CREATE"]) + encode_string(name)


def build_board_list() -> bytes:
    return struct.pack(">B", V3_COMMANDS["BOARD_LIST"])


def build_user_promote(username: str) -> bytes:
    return struct.pack(">B", V3_COMMANDS["USER_PROMOTE"]) + encode_string(username)


def build_user_demote(username: str) -> bytes:
    return struct.pack(">B", V3_COMMANDS["USER_DEMOTE"]) + encode_string(username)


def build_get_pubkey() -> bytes:
    return struct.pack(">B", V3_COMMANDS["GET_PUBKEY"])


# ---------------------------------------------------------------------------
# Parsers for shared opcodes
# ---------------------------------------------------------------------------

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


def parse_get_user_resp(payload: bytes) -> User:
    """Parse a GET_USER success response.

    Format: pubkey:32 + registrar_len:u8 + registrar_bytes
    """
    pubkey = payload[:32]
    registrar, _ = decode_string(payload, 32)
    return User(
        username="",
        registrar=registrar,
        record_origin="",
        relay="",
        public_key=pubkey.hex(),
    )


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


def parse_get_pubkey_resp(payload: bytes) -> str:
    return payload[:32].hex()


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
        struct.pack(">B", V3_COMMANDS["USER_REGISTRY_HEAD"])
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
        struct.pack(">B", V3_COMMANDS["USER_REGISTRY_NODES"])
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
        struct.pack(">B", V3_COMMANDS["USER_REGISTRY_RECORDS"])
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
        struct.pack(">B", V3_COMMANDS["USER_REGISTRY_HEADS"])
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
        struct.pack(">B", V3_COMMANDS["USER_REGISTRY_HEAD_CHAIN"])
        + struct.pack(">H", len(origin_b)) + origin_b
        + struct.pack(">Q", start_seq)
        + struct.pack(">H", max_count)
    )


# ---------------------------------------------------------------------------
# PEER_KEY_ROTATE (0x70) / PEER_KEY_LIST (0x71)
# ---------------------------------------------------------------------------

def build_peer_key_rotate(origin: str, old_pubkey: bytes, new_pubkey: bytes,
                          signature: bytes) -> bytes:
    """Build a PEER_KEY_ROTATE request.

    Format: opcode:u8 + origin_len:u8 + origin + old_pubkey:32 + new_pubkey:32 + signature:64
    The signature is an Ed25519 signature over (old_pubkey || new_pubkey) using
    the old private key, proving key ownership.
    """
    origin_b = origin.encode("utf-8")
    if len(origin_b) > 255:
        raise ProtocolError(f"Origin too long: {len(origin_b)} bytes")
    if len(old_pubkey) != 32 or len(new_pubkey) != 32:
        raise ProtocolError("Public keys must be 32 bytes")
    if len(signature) != 64:
        raise ProtocolError("Signature must be 64 bytes")
    return (
        struct.pack(">B", V3_COMMANDS["PEER_KEY_ROTATE"])
        + struct.pack(">B", len(origin_b)) + origin_b
        + old_pubkey + new_pubkey + signature
    )


def build_peer_key_list() -> bytes:
    return struct.pack(">B", V3_COMMANDS["PEER_KEY_LIST"])


def parse_peer_key_list_resp(payload: bytes) -> list[dict]:
    """Parse PEER_KEY_LIST success response.

    Format: count:u16 + repeated { origin_len:u8 + origin + pubkey:32 }
    """
    offset = 0
    count = struct.unpack(">H", payload[offset:offset + 2])[0]
    offset += 2
    keys = []
    for _ in range(count):
        origin, offset = decode_string(payload, offset)
        pubkey = payload[offset:offset + 32]
        offset += 32
        keys.append({"origin": origin, "publickey": pubkey})
    return keys


# ===========================================================================
# v3 article feed builders and parsers (§13.4)
# ===========================================================================

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


# ---------------------------------------------------------------------------
# Submission construction + signing helpers
# ---------------------------------------------------------------------------

def make_message_id() -> bytes:
    """Generate a random 32-byte message ID."""
    return os.urandom(32)


def build_submission(
    event_type: int,
    origin: str,
    board: str,
    actor_pubkey: bytes,
    actor_username: str,
    actor_registrar: str,
    body: bytes = b"",
    headers=None,
    message_id: Optional[bytes] = None,
    created_at: Optional[int] = None,
    root_message_id: Optional[bytes] = None,
    reply_to_message_id: Optional[bytes] = None,
    supersedes_message_id: Optional[bytes] = None,
    target_message_id: Optional[bytes] = None,
) -> tuple[Submission, bytes]:
    """Construct a v3 Submission and compute its body hash.

    Returns (submission, body) where body is the raw body bytes to send.
    The caller is responsible for signing the submission and sending via
    build_article_publish or build_board_set_state.
    """
    body_hash = compute_body_hash(body)
    sub = Submission(
        event_type=event_type,
        origin=origin,
        board=board,
        message_id=message_id or make_message_id(),
        created_at=created_at if created_at is not None else int(time.time()),
        actor_pubkey=actor_pubkey,
        actor_username=actor_username,
        actor_registrar=actor_registrar,
        root_message_id=root_message_id or ZERO_MESSAGE_ID,
        reply_to_message_id=reply_to_message_id or ZERO_MESSAGE_ID,
        supersedes_message_id=supersedes_message_id or ZERO_MESSAGE_ID,
        target_message_id=target_message_id or ZERO_MESSAGE_ID,
        headers=headers,
        body_hash=body_hash,
        body_size=len(body),
    )
    return sub, body


def sign_submission(submission: Submission, private_key: bytes) -> bytes:
    """Sign a submission with an Ed25519 private key (SCHEME_V3).

    Returns the 64-byte author signature.
    """
    identity = Identity.from_private_key(private_key)
    return identity.sign(author_signature_payload(submission))


def encode_and_sign_submission(submission: Submission, body: bytes,
                               private_key: bytes) -> bytes:
    """Encode a submission, sign it, and build the ARTICLE_PUBLISH request.

    Convenience wrapper for build_article_publish(sign_submission(sub, key)).
    Returns the complete ARTICLE_PUBLISH command bytes ready to send.
    """
    author_sig = sign_submission(submission, private_key)
    return build_article_publish(
        encode_submission(submission), body, SCHEME_V3, author_sig,
    )


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
                      selector, include_body: bool = True) -> bytes:
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


def parse_feed_head_resp(payload: bytes) -> dict:
    """Parse FEED_HEAD success response.

    Returns dict with 'head_bytes', 'accepted_at', 'source_relay'.
    Trailing witness metadata (accepted_at, source_relay) is advisory and
    may be absent from older servers — defaults to (0, "") in that case.
    """
    head_len = struct.unpack(">H", payload[0:2])[0]
    head_bytes = payload[2:2 + head_len]
    offset = 2 + head_len
    accepted_at, source_relay = 0, ""
    if len(payload) >= offset + 10:
        accepted_at = struct.unpack(">q", payload[offset:offset + 8])[0]
        offset += 8
        relay_len = struct.unpack(">H", payload[offset:offset + 2])[0]
        offset += 2
        source_relay = payload[offset:offset + relay_len].decode("utf-8", errors="replace")
    return {"head_bytes": head_bytes, "accepted_at": accepted_at, "source_relay": source_relay}


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


def parse_feed_events_resp(payload: bytes) -> list[dict]:
    """Parse FEED_EVENTS success response.

    Returns list of dicts with 'event_bytes', 'accepted_at', 'source_relay'.
    Trailing witness metadata per event is advisory and may be absent from
    older servers — defaults to (0, "") in that case.
    """
    offset = 0
    count = struct.unpack(">H", payload[offset:offset + 2])[0]
    offset += 2
    events = []
    for _ in range(count):
        event_len = struct.unpack(">I", payload[offset:offset + 4])[0]
        offset += 4
        event_bytes = payload[offset:offset + event_len]
        offset += event_len
        accepted_at, source_relay = 0, ""
        if len(payload) >= offset + 10:
            accepted_at = struct.unpack(">q", payload[offset:offset + 8])[0]
            offset += 8
            relay_len = struct.unpack(">H", payload[offset:offset + 2])[0]
            offset += 2
            source_relay = payload[offset:offset + relay_len].decode("utf-8", errors="replace")
            offset += relay_len
        events.append({"event_bytes": event_bytes, "accepted_at": accepted_at,
                        "source_relay": source_relay})
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

    Format: count:u16 + repeated { origin:u16 + board:u16 + head_len:u16 + head
    + accepted_at:i64 + relay_len:u16 + relay_bytes }

    Trailing witness metadata per entry is advisory and may be absent from
    older servers — defaults to (0, "") in that case.
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
        accepted_at, source_relay = 0, ""
        if len(payload) >= offset + 10:
            accepted_at = struct.unpack(">q", payload[offset:offset + 8])[0]
            offset += 8
            relay_len = struct.unpack(">H", payload[offset:offset + 2])[0]
            offset += 2
            source_relay = payload[offset:offset + relay_len].decode("utf-8", errors="replace")
            offset += relay_len
        results.append({"origin": origin, "board": board, "head_bytes": head_bytes,
                         "accepted_at": accepted_at, "source_relay": source_relay})
    return results


# --- ARTICLE_SEARCH (§13.4) ---

def build_article_search(board: str, text_query: str = "",
                         offset: int = 0, limit: int = 50,
                         flags: int = 0,
                         event_type_mask: int = 0,
                         actor_pubkey: bytes = None,
                         subject_pubkey: bytes = None,
                         target_message_id: bytes = None,
                         created_after: int = 0,
                         created_before: int = 0) -> bytes:
    """Build an ARTICLE_SEARCH request with structured filters.

    event_type_mask: bitmask selecting event types (bit (type-1) set; 0 = all).
    actor_pubkey: filter by actor/author public key (None = no filter).
    subject_pubkey: filter by typed subject — culprit/punished key (None = none).
    target_message_id: filter by target_message_id field (None = no filter).
    created_after/created_before: time window (0 = unbounded).
    """
    out = struct.pack(">B", V3_COMMANDS["ARTICLE_SEARCH"])
    out += _encode_v3_str("")  # origin (local)
    out += _encode_v3_str(board)
    out += struct.pack(">I", event_type_mask)
    out += (actor_pubkey if actor_pubkey else b"\x00" * 32)
    out += (subject_pubkey if subject_pubkey else b"\x00" * 32)
    out += (target_message_id if target_message_id else b"\x00" * 32)
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


# --- BOARD_SET_STATE (§13.4) ---

def build_board_set_state(encoded_submission: bytes, body: bytes,
                          author_signature_scheme: int,
                          author_signature: bytes) -> bytes:
    """Build a BOARD_SET_STATE request.

    Same framing as ARTICLE_PUBLISH but dispatched to opcode 0x1A.
    Only EVENT_BOARD_CLOSE (0x0A) and EVENT_BOARD_REOPEN (0x0B) are accepted.
    """
    return (
        struct.pack(">B", V3_COMMANDS["BOARD_SET_STATE"])
        + struct.pack(">I", len(encoded_submission)) + encoded_submission
        + struct.pack(">I", len(body)) + body
        + struct.pack(">B", author_signature_scheme)
        + struct.pack(">H", len(author_signature)) + author_signature
    )


def parse_board_set_state_resp(payload: bytes) -> dict:
    """Parse BOARD_SET_STATE success response.

    Same format as ARTICLE_PUBLISH: event_len:u32 + encoded_event +
    head_len:u16 + encoded_head
    """
    return parse_article_publish_resp(payload)


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


# ---------------------------------------------------------------------------
# Event / head decoding helpers for client-side consumption
# ---------------------------------------------------------------------------

def decode_v3_event(event_bytes: bytes) -> dict:
    """Decode a v3 encoded event into a dict of fields."""
    ev = decode_event(event_bytes)
    result = {
        "feed_seq": ev.feed_seq,
        "article_num": ev.article_num,
        "message_id": ev.message_id.hex(),
        "event_type": ev.event_type,
        "event_type_name": EVENT_TYPE_NAMES.get(ev.event_type, "UNKNOWN"),
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
