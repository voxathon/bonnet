"""Protocol v3 immutable article feed primitives.

Implements Phase 1 of ARTICLE_FEED_PROTOCOL_V3_IMPLEMENTATION_PLAN.md:
  - Event/head dataclasses
  - Strict canonical encoders/decoders (no JSON for signed bytes)
  - Domain-separated hashes and Ed25519 signatures
  - SQLite feed store (feed_events/heads/state/conflicts/staging + projections)
  - Body content-addressed store with reference counting
  - Atomic local append and remote range acceptance

No network integration lives here. Protocol command handling stays in
net/commands.py; projection/business logic stays in AME or a dedicated service.

The extensions codec is implemented now because events are immutable —
migration (Phase 6) will rely on it. Normal publication encodes
extension_count=0; only the trusted local migration path creates non-empty
extensions via append_authoritative_event(allow_migration=True).
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import sqlite3
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from core.crypto import Identity


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FORMAT_VERSION = 1
SUBMISSION_VERSION = 1
HEAD_FORMAT_VERSION = 1

HASH_SIZE = 32
SIGNATURE_SIZE = 64
MESSAGE_ID_SIZE = 32
ZERO_HASH = b"\x00" * HASH_SIZE
ZERO_MESSAGE_ID = b"\x00" * MESSAGE_ID_SIZE

# Event types (§6)
EVENT_ARTICLE = 0x01
EVENT_CANCEL = 0x02
EVENT_RESTORE = 0x03
EVENT_PURGE = 0x04
EVENT_RULE = 0x05
EVENT_RULE_REVOKE = 0x06
EVENT_REPORT = 0x07
EVENT_PUNISHMENT = 0x08
EVENT_PUNISHMENT_REVOKE = 0x09
EVENT_BOARD_CLOSE = 0x0A
EVENT_BOARD_REOPEN = 0x0B
EVENT_ARTICLE_PIN = 0x0C
EVENT_ARTICLE_UNPIN = 0x0D
EVENT_THREAD_CLOSE = 0x0E
EVENT_THREAD_REOPEN = 0x0F
EVENT_USER_REGISTER = 0x10
EVENT_USER_REVOKE = 0x11

VALID_EVENT_TYPES = frozenset(range(0x01, 0x12))
RESERVED_EVENT_TYPES = frozenset(range(0x12, 0x20))

# Signature schemes (§8.4)
SCHEME_NONE = 0          # migration-only, no durable author signature
SCHEME_V3 = 1            # protocol-v3 author signature
SCHEME_LEGACY_V2 = 2     # preserved protocol-v2 POST_SIGN signature
VALID_SCHEMES = frozenset({SCHEME_NONE, SCHEME_V3, SCHEME_LEGACY_V2})

# Migration extension types (§8.2)
EXT_LEGACY_DESCRIPTOR = 0x0001
EXT_LEGACY_AUTHOR_SIGNED_PAYLOAD = 0x0002
EXT_LEGACY_AUTHOR_SIGNATURE = 0x0003
EXT_LEGACY_ORIGIN_SIGNED_PAYLOAD = 0x0004
EXT_LEGACY_ORIGIN_SIGNATURE = 0x0005
EXT_LEGACY_UNRESOLVED_REFERENCES = 0x0006
VALID_EXTENSION_TYPES = frozenset(range(0x0001, 0x0007))

# Legacy source object types (§8.2)
LEGACY_POST = 0x01
LEGACY_RULE = 0x02
LEGACY_REPORT = 0x03
LEGACY_PUNISHMENT = 0x04

# Projected states (§11, §13.4)
STATE_ACTIVE = 0x01
STATE_CANCELLED = 0x02
STATE_SUPERSEDED = 0x03
STATE_PURGED = 0x04

# Selector types (§13.4)
SELECTOR_ARTICLE_NUM = 0x01
SELECTOR_MESSAGE_ID = 0x02

# Body status (§13.4)
BODY_NOT_REQUESTED = 0x00
BODY_INCLUDED = 0x01
BODY_AVAILABLE_NOT_INCLUDED = 0x02
BODY_UNAVAILABLE = 0x03

# Article query flags (§13.4)
FLAG_INCLUDE_CANCELLED = 0x0001
FLAG_INCLUDE_SUPERSEDED = 0x0002
FLAG_INCLUDE_PURGED = 0x0004
FLAG_INCLUDE_CONTROLS = 0x0008
FLAG_INCLUDE_BODIES = 0x0010

# Domain-separation tags (exact strings from §7.5/§8.3/§8.4/§8.5/§9)
DOMAIN_EVENT_HASH = b"bonnet-feed-event-hash-v1"
DOMAIN_BODY_HASH = b"bonnet-article-body-v1"
DOMAIN_AUTHOR_SIG = b"bonnet-feed-author-signature-v1"
DOMAIN_ORIGIN_SIG = b"bonnet-feed-origin-signature-v1"
DOMAIN_HEAD_SIG = b"bonnet-feed-head-signature-v1"
DOMAIN_HEAD_HASH = b"bonnet-feed-head-hash-v1"

# Field bounds (§8)
MAX_ORIGIN_LEN = 255
MAX_BOARD_LEN = 255
MAX_ACTOR_NAME_LEN = 255
MAX_HEADERS_LEN = 65536
MAX_EXTENSIONS_LEN = 262144
DEFAULT_MAX_BODY_SIZE = 1024 * 1024  # 1 MiB default; configurable


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class InvalidOrigin(ValueError):
    pass


class DecodeError(ValueError):
    pass


class MessageIdCollision(Exception):
    def __init__(self, message_id: bytes):
        self.message_id = message_id
        super().__init__(f"message_id collision: {message_id.hex()}")


class FeedAcceptanceError(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


# ---------------------------------------------------------------------------
# Origin normalization (§7.1)
# ---------------------------------------------------------------------------

def normalize_origin(value: str) -> str:
    """Canonicalize an origin string per §7.1.

    DNS origins are IDNA-encoded, lowercased, and stored without a trailing dot.
    IP literals are stored in compressed form without IPv6 brackets.
    Rejects whitespace, URL schemes, paths, ports, and empty labels.
    """
    if not isinstance(value, str):
        raise InvalidOrigin("origin must be a str")
    if not value:
        raise InvalidOrigin("origin must not be empty")
    if value.strip() != value:
        raise InvalidOrigin("origin must not contain leading/trailing whitespace")
    if any(ch.isspace() for ch in value):
        raise InvalidOrigin("origin must not contain whitespace")
    if "://" in value:
        raise InvalidOrigin("origin must not contain a URL scheme")
    if "/" in value:
        raise InvalidOrigin("origin must not contain a path")

    # Try IP literal first (before port check, since IPv6 contains ':')
    try:
        ip = ipaddress.ip_address(value)
        return ip.compressed
    except ValueError:
        pass

    if ":" in value:
        raise InvalidOrigin("origin must not contain a port")

    # DNS name: IDNA-encode, lowercase, strip trailing dot
    stripped = value.rstrip(".")
    if not stripped:
        raise InvalidOrigin("origin must not be empty after stripping trailing dot")
    labels = stripped.split(".")
    for label in labels:
        if not label:
            raise InvalidOrigin("origin must not contain empty labels")
    try:
        encoded = stripped.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidOrigin(f"IDNA encoding failed: {exc}") from exc
    canonical = encoded.lower()
    if canonical.endswith("."):
        canonical = canonical[:-1]

    # Idempotency: re-encoding the canonical form must produce the same result
    try:
        re_encoded = canonical.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise InvalidOrigin(f"origin does not round-trip: {value!r}")
    if re_encoded != canonical:
        raise InvalidOrigin(f"origin does not round-trip: {value!r} -> {canonical!r}")
    return canonical


# ---------------------------------------------------------------------------
# Header dataclasses (§8.1)
# ---------------------------------------------------------------------------

@dataclass
class ArticleHeaders:
    subject: str = ""
    tags: str = ""
    options: str = ""


@dataclass
class RuleHeaders:
    rule_name: str = ""


@dataclass
class ReportHeaders:
    culprit_pubkey: bytes = b"\x00" * 32
    target_origin: str = ""
    target_board: str = ""
    target_article_id: bytes = ZERO_MESSAGE_ID
    rule_message_ids: list = field(default_factory=list)
    evidence_hashes: list = field(default_factory=list)


@dataclass
class PunishmentHeaders:
    punished_pubkey: bytes = b"\x00" * 32
    expires_at: int = 0
    report_ids: list = field(default_factory=list)
    rule_ids: list = field(default_factory=list)


@dataclass
class PinHeaders:
    priority: int = 0


@dataclass
class UserHeaders:
    username: str = ""
    publickey: bytes = b"\x00" * 32
    flags: int = 0
    seq_numbr: int = 0
    creation_time: int = 0


# Events with empty headers: CANCEL, RESTORE, PURGE, RULE_REVOKE,
# PUNISHMENT_REVOKE, BOARD_CLOSE, BOARD_REOPEN, ARTICLE_UNPIN,
# THREAD_CLOSE, THREAD_REOPEN. Represented by None.


# ---------------------------------------------------------------------------
# Migration extension (§8.2)
# ---------------------------------------------------------------------------

@dataclass
class Extension:
    type: int
    value: bytes


# ---------------------------------------------------------------------------
# Submission (§13.4) — client payload before origin allocation
# ---------------------------------------------------------------------------

@dataclass
class Submission:
    submission_version: int = SUBMISSION_VERSION
    event_type: int = EVENT_ARTICLE
    origin: str = ""
    board: str = ""
    message_id: bytes = ZERO_MESSAGE_ID
    created_at: int = 0
    actor_pubkey: bytes = b"\x00" * 32
    actor_username: str = ""
    actor_registrar: str = ""
    root_message_id: bytes = ZERO_MESSAGE_ID
    reply_to_message_id: bytes = ZERO_MESSAGE_ID
    supersedes_message_id: bytes = ZERO_MESSAGE_ID
    target_message_id: bytes = ZERO_MESSAGE_ID
    headers: object = None  # ArticleHeaders | RuleHeaders | ReportHeaders | PunishmentHeaders | PinHeaders | None
    body_hash: bytes = ZERO_HASH
    body_size: int = 0


# ---------------------------------------------------------------------------
# Event (§8) — complete signed event
# ---------------------------------------------------------------------------

@dataclass
class Event:
    format_version: int = FORMAT_VERSION
    event_type: int = EVENT_ARTICLE
    origin: str = ""
    board: str = ""
    feed_seq: int = 0
    previous_event_hash: bytes = ZERO_HASH
    message_id: bytes = ZERO_MESSAGE_ID
    article_num: int = 0
    created_at: int = 0
    actor_pubkey: bytes = b"\x00" * 32
    actor_username: str = ""
    actor_registrar: str = ""
    root_message_id: bytes = ZERO_MESSAGE_ID
    reply_to_message_id: bytes = ZERO_MESSAGE_ID
    supersedes_message_id: bytes = ZERO_MESSAGE_ID
    target_message_id: bytes = ZERO_MESSAGE_ID
    headers: object = None
    extensions: list = field(default_factory=list)  # list[Extension]
    body_hash: bytes = ZERO_HASH
    body_size: int = 0
    author_signature_scheme: int = SCHEME_V3
    author_signature: bytes = b""
    origin_signature: bytes = b"\x00" * SIGNATURE_SIZE


# ---------------------------------------------------------------------------
# Feed head (§9)
# ---------------------------------------------------------------------------

@dataclass
class FeedHead:
    format_version: int = HEAD_FORMAT_VERSION
    origin: str = ""
    board: str = ""
    latest_feed_seq: int = 0
    latest_event_hash: bytes = ZERO_HASH
    article_count: int = 0
    event_count: int = 0
    snapshot_timestamp: int = 0
    signature: bytes = b"\x00" * SIGNATURE_SIZE


# ---------------------------------------------------------------------------
# Acceptance result
# ---------------------------------------------------------------------------

@dataclass
class AcceptResult:
    accepted: bool
    reason: str = ""
    head: Optional[FeedHead] = None
    accepted_count: int = 0


# ---------------------------------------------------------------------------
# Binary encoding helpers
# ---------------------------------------------------------------------------

def _pack_u8(v: int) -> bytes:
    return struct.pack(">B", v)


def _pack_u16(v: int) -> bytes:
    return struct.pack(">H", v)


def _pack_u32(v: int) -> bytes:
    return struct.pack(">I", v)


def _pack_u64(v: int) -> bytes:
    return struct.pack(">Q", v)


def _pack_i64(v: int) -> bytes:
    return struct.pack(">q", v)


def _pack_i32(v: int) -> bytes:
    return struct.pack(">i", v)


def _pack_str_u16(s: str) -> bytes:
    b = s.encode("utf-8")
    return struct.pack(">H", len(b)) + b


def _pack_bytes_u16(b: bytes) -> bytes:
    return struct.pack(">H", len(b)) + b


def _read_u8(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 1 > len(data):
        raise DecodeError("truncated u8")
    return data[offset], offset + 1


def _read_u16(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(data):
        raise DecodeError("truncated u16")
    return struct.unpack(">H", data[offset:offset + 2])[0], offset + 2


def _read_u32(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 4 > len(data):
        raise DecodeError("truncated u32")
    return struct.unpack(">I", data[offset:offset + 4])[0], offset + 4


def _read_u64(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 8 > len(data):
        raise DecodeError("truncated u64")
    return struct.unpack(">Q", data[offset:offset + 8])[0], offset + 8


def _read_i64(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 8 > len(data):
        raise DecodeError("truncated i64")
    return struct.unpack(">q", data[offset:offset + 8])[0], offset + 8


def _read_i32(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 4 > len(data):
        raise DecodeError("truncated i32")
    return struct.unpack(">i", data[offset:offset + 4])[0], offset + 4


def _read_fixed(data: bytes, offset: int, n: int) -> tuple[bytes, int]:
    if offset + n > len(data):
        raise DecodeError(f"truncated fixed-{n}")
    return data[offset:offset + n], offset + n


def _read_str_u16(data: bytes, offset: int, max_len: int) -> tuple[str, int]:
    length, offset = _read_u16(data, offset)
    if length > max_len:
        raise DecodeError(f"string length {length} exceeds max {max_len}")
    if offset + length > len(data):
        raise DecodeError("truncated string body")
    try:
        s = data[offset:offset + length].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError(f"invalid UTF-8: {exc}") from exc
    return s, offset + length


def _read_bytes_u16(data: bytes, offset: int, max_len: int) -> tuple[bytes, int]:
    length, offset = _read_u16(data, offset)
    if length > max_len:
        raise DecodeError(f"bytes length {length} exceeds max {max_len}")
    if offset + length > len(data):
        raise DecodeError("truncated bytes body")
    return data[offset:offset + length], offset + length


def _read_bytes_u32(data: bytes, offset: int, max_len: int) -> tuple[bytes, int]:
    length, offset = _read_u32(data, offset)
    if length > max_len:
        raise DecodeError(f"bytes length {length} exceeds max {max_len}")
    if offset + length > len(data):
        raise DecodeError("truncated bytes body")
    return data[offset:offset + length], offset + length


# ---------------------------------------------------------------------------
# Type-specific header encoders (§8.1)
# ---------------------------------------------------------------------------

def _encode_headers(event_type: int, headers) -> bytes:
    if event_type == EVENT_ARTICLE:
        return _encode_article_headers(headers)
    if event_type == EVENT_RULE:
        return _encode_rule_headers(headers)
    if event_type == EVENT_REPORT:
        return _encode_report_headers(headers)
    if event_type == EVENT_PUNISHMENT:
        return _encode_punishment_headers(headers)
    if event_type == EVENT_ARTICLE_PIN:
        return _encode_pin_headers(headers)
    if event_type == EVENT_USER_REGISTER:
        return _encode_user_headers(headers)
    # Empty-headers types
    if headers is not None:
        raise DecodeError(f"event_type {event_type:#04x} must have empty headers")
    return b""


def _encode_article_headers(headers) -> bytes:
    if not isinstance(headers, ArticleHeaders):
        raise DecodeError("ARTICLE requires ArticleHeaders")
    return (
        _pack_str_u16(headers.subject)
        + _pack_str_u16(headers.tags)
        + _pack_str_u16(headers.options)
    )


def _encode_rule_headers(headers) -> bytes:
    if not isinstance(headers, RuleHeaders):
        raise DecodeError("RULE requires RuleHeaders")
    return _pack_str_u16(headers.rule_name)


def _encode_report_headers(headers) -> bytes:
    if not isinstance(headers, ReportHeaders):
        raise DecodeError("REPORT requires ReportHeaders")
    if len(headers.culprit_pubkey) != 32:
        raise DecodeError("culprit_pubkey must be 32 bytes")
    if len(headers.target_article_id) != 32:
        raise DecodeError("target_article_id must be 32 bytes")
    for rid in headers.rule_message_ids:
        if len(rid) != 32:
            raise DecodeError("rule_message_id must be 32 bytes")
    for eh in headers.evidence_hashes:
        if len(eh) != 32:
            raise DecodeError("evidence_hash must be 32 bytes")
    out = (
        headers.culprit_pubkey
        + _pack_str_u16(headers.target_origin)
        + _pack_str_u16(headers.target_board)
        + headers.target_article_id
        + _pack_u16(len(headers.rule_message_ids))
    )
    for rid in headers.rule_message_ids:
        out += rid
    out += _pack_u16(len(headers.evidence_hashes))
    for eh in headers.evidence_hashes:
        out += eh
    return out


def _encode_punishment_headers(headers) -> bytes:
    if not isinstance(headers, PunishmentHeaders):
        raise DecodeError("PUNISHMENT requires PunishmentHeaders")
    if len(headers.punished_pubkey) != 32:
        raise DecodeError("punished_pubkey must be 32 bytes")
    for rid in headers.report_ids:
        if len(rid) != 32:
            raise DecodeError("report_id must be 32 bytes")
    for rid in headers.rule_ids:
        if len(rid) != 32:
            raise DecodeError("rule_id must be 32 bytes")
    out = (
        headers.punished_pubkey
        + _pack_i64(headers.expires_at)
        + _pack_u16(len(headers.report_ids))
    )
    for rid in headers.report_ids:
        out += rid
    out += _pack_u16(len(headers.rule_ids))
    for rid in headers.rule_ids:
        out += rid
    return out


def _encode_pin_headers(headers) -> bytes:
    if not isinstance(headers, PinHeaders):
        raise DecodeError("ARTICLE_PIN requires PinHeaders")
    return _pack_i32(headers.priority)


def _encode_user_headers(headers) -> bytes:
    if not isinstance(headers, UserHeaders):
        raise DecodeError("USER_REGISTER requires UserHeaders")
    if len(headers.publickey) != 32:
        raise DecodeError("publickey must be 32 bytes")
    return (
        _pack_str_u16(headers.username)
        + headers.publickey
        + struct.pack(">B", headers.flags)
        + struct.pack(">Q", headers.seq_numbr)
        + struct.pack(">q", headers.creation_time)
    )


# ---------------------------------------------------------------------------
# Type-specific header decoders (§8.1)
# ---------------------------------------------------------------------------

def _decode_headers(event_type: int, data: bytes) -> tuple[object, int]:
    if event_type == EVENT_ARTICLE:
        return _decode_article_headers(data)
    if event_type == EVENT_RULE:
        return _decode_rule_headers(data)
    if event_type == EVENT_REPORT:
        return _decode_report_headers(data)
    if event_type == EVENT_PUNISHMENT:
        return _decode_punishment_headers(data)
    if event_type == EVENT_ARTICLE_PIN:
        return _decode_pin_headers(data)
    if event_type == EVENT_USER_REGISTER:
        return _decode_user_headers(data)
    if len(data) != 0:
        raise DecodeError(f"event_type {event_type:#04x} must have empty headers")
    return None, len(data)


def _decode_article_headers(data: bytes) -> tuple[ArticleHeaders, int]:
    offset = 0
    subject, offset = _read_str_u16(data, offset, MAX_HEADERS_LEN)
    tags, offset = _read_str_u16(data, offset, MAX_HEADERS_LEN)
    options, offset = _read_str_u16(data, offset, MAX_HEADERS_LEN)
    if offset != len(data):
        raise DecodeError("trailing bytes in ARTICLE headers")
    return ArticleHeaders(subject=subject, tags=tags, options=options), offset


def _decode_rule_headers(data: bytes) -> tuple[RuleHeaders, int]:
    offset = 0
    rule_name, offset = _read_str_u16(data, offset, MAX_HEADERS_LEN)
    if offset != len(data):
        raise DecodeError("trailing bytes in RULE headers")
    return RuleHeaders(rule_name=rule_name), offset


def _decode_report_headers(data: bytes) -> tuple[ReportHeaders, int]:
    offset = 0
    culprit_pubkey, offset = _read_fixed(data, offset, 32)
    target_origin, offset = _read_str_u16(data, offset, MAX_ORIGIN_LEN)
    target_board, offset = _read_str_u16(data, offset, MAX_BOARD_LEN)
    target_article_id, offset = _read_fixed(data, offset, 32)
    rule_count, offset = _read_u16(data, offset)
    rule_ids = []
    for _ in range(rule_count):
        rid, offset = _read_fixed(data, offset, 32)
        rule_ids.append(rid)
    evidence_count, offset = _read_u16(data, offset)
    evidence_hashes = []
    for _ in range(evidence_count):
        eh, offset = _read_fixed(data, offset, 32)
        evidence_hashes.append(eh)
    if offset != len(data):
        raise DecodeError("trailing bytes in REPORT headers")
    return ReportHeaders(
        culprit_pubkey=culprit_pubkey, target_origin=target_origin,
        target_board=target_board, target_article_id=target_article_id,
        rule_message_ids=rule_ids, evidence_hashes=evidence_hashes,
    ), offset


def _decode_punishment_headers(data: bytes) -> tuple[PunishmentHeaders, int]:
    offset = 0
    punished_pubkey, offset = _read_fixed(data, offset, 32)
    expires_at, offset = _read_i64(data, offset)
    report_count, offset = _read_u16(data, offset)
    report_ids = []
    for _ in range(report_count):
        rid, offset = _read_fixed(data, offset, 32)
        report_ids.append(rid)
    rule_count, offset = _read_u16(data, offset)
    rule_ids = []
    for _ in range(rule_count):
        rid, offset = _read_fixed(data, offset, 32)
        rule_ids.append(rid)
    if offset != len(data):
        raise DecodeError("trailing bytes in PUNISHMENT headers")
    return PunishmentHeaders(
        punished_pubkey=punished_pubkey, expires_at=expires_at,
        report_ids=report_ids, rule_ids=rule_ids,
    ), offset


def _decode_pin_headers(data: bytes) -> tuple[PinHeaders, int]:
    offset = 0
    priority, offset = _read_i32(data, offset)
    if offset != len(data):
        raise DecodeError("trailing bytes in ARTICLE_PIN headers")
    return PinHeaders(priority=priority), offset


def _decode_user_headers(data: bytes) -> tuple[UserHeaders, int]:
    offset = 0
    username, offset = _read_str_u16(data, offset, MAX_ORIGIN_LEN)
    publickey, offset = _read_fixed(data, offset, 32)
    flags, offset = _read_u8(data, offset)
    seq_numbr, offset = _read_u64(data, offset)
    creation_time, offset = _read_i64(data, offset)
    if offset != len(data):
        raise DecodeError("trailing bytes in USER_REGISTER headers")
    return UserHeaders(username=username, publickey=publickey,
                       flags=flags, seq_numbr=seq_numbr,
                       creation_time=creation_time), offset


# ---------------------------------------------------------------------------
# Extensions codec (§8.2)
# ---------------------------------------------------------------------------

def _encode_extensions(extensions: list) -> bytes:
    out = _pack_u16(len(extensions))
    last_type = 0
    for ext in extensions:
        if ext.type <= 0 or ext.type > 0xFFFF:
            raise DecodeError(f"invalid extension type {ext.type}")
        if ext.type <= last_type:
            raise DecodeError("extensions must be in strictly ascending type order")
        if ext.type not in VALID_EXTENSION_TYPES:
            raise DecodeError(f"unknown extension type {ext.type:#06x}")
        last_type = ext.type
        if len(ext.value) > 0xFFFFFFFF:
            raise DecodeError("extension value too large")
        out += _pack_u16(ext.type) + _pack_u32(len(ext.value)) + ext.value
    return out


def _decode_extensions(data: bytes, max_len: int) -> tuple[list, int]:
    if len(data) > max_len:
        raise DecodeError(f"extensions length {len(data)} exceeds max {max_len}")
    offset = 0
    count, offset = _read_u16(data, offset)
    extensions = []
    last_type = 0
    for _ in range(count):
        ext_type, offset = _read_u16(data, offset)
        if ext_type <= last_type:
            raise DecodeError("extensions must be in strictly ascending type order")
        if ext_type not in VALID_EXTENSION_TYPES:
            raise DecodeError(f"unknown extension type {ext_type:#06x}")
        last_type = ext_type
        value, offset = _read_bytes_u32(data, offset, max_len)
        extensions.append(Extension(type=ext_type, value=value))
    if offset != len(data):
        raise DecodeError("trailing bytes in extensions block")
    return extensions, offset


# ---------------------------------------------------------------------------
# Submission codec (§13.4)
# ---------------------------------------------------------------------------

def encode_submission(s: Submission) -> bytes:
    if s.submission_version != SUBMISSION_VERSION:
        raise DecodeError(f"submission_version must be {SUBMISSION_VERSION}")
    if s.event_type not in VALID_EVENT_TYPES and s.event_type not in RESERVED_EVENT_TYPES:
        raise DecodeError(f"invalid event_type {s.event_type:#04x}")
    if len(s.message_id) != MESSAGE_ID_SIZE:
        raise DecodeError("message_id must be 32 bytes")
    if len(s.actor_pubkey) != 32:
        raise DecodeError("actor_pubkey must be 32 bytes")
    for field_name in ("root_message_id", "reply_to_message_id",
                       "supersedes_message_id", "target_message_id"):
        if len(getattr(s, field_name)) != MESSAGE_ID_SIZE:
            raise DecodeError(f"{field_name} must be 32 bytes")
    if len(s.body_hash) != HASH_SIZE:
        raise DecodeError("body_hash must be 32 bytes")
    if s.body_size < 0 or s.body_size > 0xFFFFFFFFFFFFFFFF:
        raise DecodeError("body_size out of range")

    header_bytes = _encode_headers(s.event_type, s.headers)
    if len(header_bytes) > MAX_HEADERS_LEN:
        raise DecodeError("headers exceed max length")

    return (
        _pack_u8(s.submission_version)
        + _pack_u8(s.event_type)
        + _pack_str_u16(s.origin)
        + _pack_str_u16(s.board)
        + s.message_id
        + _pack_i64(s.created_at)
        + s.actor_pubkey
        + _pack_str_u16(s.actor_username)
        + _pack_str_u16(s.actor_registrar)
        + s.root_message_id
        + s.reply_to_message_id
        + s.supersedes_message_id
        + s.target_message_id
        + _pack_u32(len(header_bytes)) + header_bytes
        + s.body_hash
        + _pack_u64(s.body_size)
    )


def decode_submission(data: bytes) -> Submission:
    offset = 0
    sv, offset = _read_u8(data, offset)
    if sv != SUBMISSION_VERSION:
        raise DecodeError(f"submission_version must be {SUBMISSION_VERSION}, got {sv}")
    event_type, offset = _read_u8(data, offset)
    if event_type not in VALID_EVENT_TYPES and event_type not in RESERVED_EVENT_TYPES:
        raise DecodeError(f"invalid event_type {event_type:#04x}")
    origin, offset = _read_str_u16(data, offset, MAX_ORIGIN_LEN)
    board, offset = _read_str_u16(data, offset, MAX_BOARD_LEN)
    message_id, offset = _read_fixed(data, offset, MESSAGE_ID_SIZE)
    created_at, offset = _read_i64(data, offset)
    actor_pubkey, offset = _read_fixed(data, offset, 32)
    actor_username, offset = _read_str_u16(data, offset, MAX_ACTOR_NAME_LEN)
    actor_registrar, offset = _read_str_u16(data, offset, MAX_ACTOR_NAME_LEN)
    root_message_id, offset = _read_fixed(data, offset, MESSAGE_ID_SIZE)
    reply_to_message_id, offset = _read_fixed(data, offset, MESSAGE_ID_SIZE)
    supersedes_message_id, offset = _read_fixed(data, offset, MESSAGE_ID_SIZE)
    target_message_id, offset = _read_fixed(data, offset, MESSAGE_ID_SIZE)
    header_len, offset = _read_u32(data, offset)
    if header_len > MAX_HEADERS_LEN:
        raise DecodeError(f"headers length {header_len} exceeds max")
    if offset + header_len > len(data):
        raise DecodeError("truncated headers body")
    header_bytes = data[offset:offset + header_len]
    headers, _ = _decode_headers(event_type, header_bytes)
    offset += header_len
    body_hash, offset = _read_fixed(data, offset, HASH_SIZE)
    body_size, offset = _read_u64(data, offset)
    if offset != len(data):
        raise DecodeError(f"trailing bytes: {len(data) - offset} extra")
    return Submission(
        submission_version=sv, event_type=event_type, origin=origin, board=board,
        message_id=message_id, created_at=created_at, actor_pubkey=actor_pubkey,
        actor_username=actor_username, actor_registrar=actor_registrar,
        root_message_id=root_message_id, reply_to_message_id=reply_to_message_id,
        supersedes_message_id=supersedes_message_id, target_message_id=target_message_id,
        headers=headers, body_hash=body_hash, body_size=body_size,
    )


def validate_submission(s: Submission) -> None:
    """Validate bounds and invariants for a normal (non-migration) submission."""
    if s.submission_version != SUBMISSION_VERSION:
        raise DecodeError(f"submission_version must be {SUBMISSION_VERSION}")
    if s.event_type not in VALID_EVENT_TYPES:
        raise DecodeError(f"event_type {s.event_type:#04x} not a valid v3 type")
    if not s.origin:
        raise DecodeError("origin must not be empty")
    if len(s.origin.encode("utf-8")) > MAX_ORIGIN_LEN:
        raise DecodeError("origin exceeds max length")
    if not s.board:
        raise DecodeError("board must not be empty")
    if len(s.board.encode("utf-8")) > MAX_BOARD_LEN:
        raise DecodeError("board exceeds max length")
    if s.message_id == ZERO_MESSAGE_ID:
        raise DecodeError("message_id must not be all-zero")
    if len(s.actor_pubkey) != 32:
        raise DecodeError("actor_pubkey must be 32 bytes")
    if len(s.actor_username.encode("utf-8")) > MAX_ACTOR_NAME_LEN:
        raise DecodeError("actor_username exceeds max length")
    if len(s.actor_registrar.encode("utf-8")) > MAX_ACTOR_NAME_LEN:
        raise DecodeError("actor_registrar exceeds max length")
    if len(s.body_hash) != HASH_SIZE:
        raise DecodeError("body_hash must be 32 bytes")
    if s.body_size < 0:
        raise DecodeError("body_size must not be negative")
    # Verify body_hash matches body_size semantics: empty body has a real hash
    # (the caller is responsible for computing body_hash correctly)


# ---------------------------------------------------------------------------
# Event codec (§8)
# ---------------------------------------------------------------------------

def _encode_event_without_origin_sig(e: Event) -> bytes:
    """Encode all event fields except the final 64-byte origin_signature."""
    if e.format_version != FORMAT_VERSION:
        raise DecodeError(f"format_version must be {FORMAT_VERSION}")
    if e.event_type not in VALID_EVENT_TYPES and e.event_type not in RESERVED_EVENT_TYPES:
        raise DecodeError(f"invalid event_type {e.event_type:#04x}")
    if len(e.origin.encode("utf-8")) > MAX_ORIGIN_LEN:
        raise DecodeError("origin exceeds max length")
    if len(e.board.encode("utf-8")) > MAX_BOARD_LEN:
        raise DecodeError("board exceeds max length")
    if e.feed_seq < 0 or e.feed_seq > 0xFFFFFFFFFFFFFFFF:
        raise DecodeError("feed_seq out of range")
    if len(e.previous_event_hash) != HASH_SIZE:
        raise DecodeError("previous_event_hash must be 32 bytes")
    if len(e.message_id) != MESSAGE_ID_SIZE:
        raise DecodeError("message_id must be 32 bytes")
    if e.article_num < 0 or e.article_num > 0xFFFFFFFFFFFFFFFF:
        raise DecodeError("article_num out of range")
    if len(e.actor_pubkey) != 32:
        raise DecodeError("actor_pubkey must be 32 bytes")
    for fn in ("root_message_id", "reply_to_message_id",
               "supersedes_message_id", "target_message_id"):
        if len(getattr(e, fn)) != MESSAGE_ID_SIZE:
            raise DecodeError(f"{fn} must be 32 bytes")
    if e.author_signature_scheme not in VALID_SCHEMES:
        raise DecodeError(f"invalid author_signature_scheme {e.author_signature_scheme}")
    if len(e.body_hash) != HASH_SIZE:
        raise DecodeError("body_hash must be 32 bytes")
    if e.body_size < 0 or e.body_size > 0xFFFFFFFFFFFFFFFF:
        raise DecodeError("body_size out of range")

    header_bytes = _encode_headers(e.event_type, e.headers)
    if len(header_bytes) > MAX_HEADERS_LEN:
        raise DecodeError("headers exceed max length")

    ext_bytes = _encode_extensions(e.extensions)
    if len(ext_bytes) > MAX_EXTENSIONS_LEN:
        raise DecodeError("extensions exceed max length")

    return (
        _pack_u8(e.format_version)
        + _pack_u8(e.event_type)
        + _pack_str_u16(e.origin)
        + _pack_str_u16(e.board)
        + _pack_u64(e.feed_seq)
        + e.previous_event_hash
        + e.message_id
        + _pack_u64(e.article_num)
        + _pack_i64(e.created_at)
        + e.actor_pubkey
        + _pack_str_u16(e.actor_username)
        + _pack_str_u16(e.actor_registrar)
        + e.root_message_id
        + e.reply_to_message_id
        + e.supersedes_message_id
        + e.target_message_id
        + _pack_u32(len(header_bytes)) + header_bytes
        + _pack_u32(len(ext_bytes)) + ext_bytes
        + e.body_hash
        + _pack_u64(e.body_size)
        + _pack_u8(e.author_signature_scheme)
        + _pack_bytes_u16(e.author_signature)
    )


def encode_event(e: Event) -> bytes:
    """Encode the complete event including the 64-byte origin_signature."""
    if len(e.origin_signature) != SIGNATURE_SIZE:
        raise DecodeError("origin_signature must be 64 bytes")
    return _encode_event_without_origin_sig(e) + e.origin_signature


def decode_event(data: bytes, *, allow_unknown_types: bool = False) -> Event:
    offset = 0
    fv, offset = _read_u8(data, offset)
    if fv != FORMAT_VERSION:
        raise DecodeError(f"format_version must be {FORMAT_VERSION}, got {fv}")
    event_type, offset = _read_u8(data, offset)
    if event_type not in VALID_EVENT_TYPES and event_type not in RESERVED_EVENT_TYPES:
        raise DecodeError(f"invalid event_type {event_type:#04x}")
    if event_type not in VALID_EVENT_TYPES and not allow_unknown_types:
        raise DecodeError(f"event_type {event_type:#04x} not a valid v3 type")

    origin, offset = _read_str_u16(data, offset, MAX_ORIGIN_LEN)
    board, offset = _read_str_u16(data, offset, MAX_BOARD_LEN)
    feed_seq, offset = _read_u64(data, offset)
    previous_event_hash, offset = _read_fixed(data, offset, HASH_SIZE)
    message_id, offset = _read_fixed(data, offset, MESSAGE_ID_SIZE)
    article_num, offset = _read_u64(data, offset)
    created_at, offset = _read_i64(data, offset)
    actor_pubkey, offset = _read_fixed(data, offset, 32)
    actor_username, offset = _read_str_u16(data, offset, MAX_ACTOR_NAME_LEN)
    actor_registrar, offset = _read_str_u16(data, offset, MAX_ACTOR_NAME_LEN)
    root_message_id, offset = _read_fixed(data, offset, MESSAGE_ID_SIZE)
    reply_to_message_id, offset = _read_fixed(data, offset, MESSAGE_ID_SIZE)
    supersedes_message_id, offset = _read_fixed(data, offset, MESSAGE_ID_SIZE)
    target_message_id, offset = _read_fixed(data, offset, MESSAGE_ID_SIZE)

    header_len, offset = _read_u32(data, offset)
    if header_len > MAX_HEADERS_LEN:
        raise DecodeError(f"headers length {header_len} exceeds max")
    if offset + header_len > len(data):
        raise DecodeError("truncated headers body")
    header_bytes = data[offset:offset + header_len]
    headers, _ = _decode_headers(event_type, header_bytes)
    offset += header_len

    ext_len, offset = _read_u32(data, offset)
    if ext_len > MAX_EXTENSIONS_LEN:
        raise DecodeError(f"extensions length {ext_len} exceeds max")
    if offset + ext_len > len(data):
        raise DecodeError("truncated extensions body")
    ext_bytes = data[offset:offset + ext_len]
    extensions, _ = _decode_extensions(ext_bytes, MAX_EXTENSIONS_LEN)
    offset += ext_len

    body_hash, offset = _read_fixed(data, offset, HASH_SIZE)
    body_size, offset = _read_u64(data, offset)
    author_scheme, offset = _read_u8(data, offset)
    if author_scheme not in VALID_SCHEMES:
        raise DecodeError(f"invalid author_signature_scheme {author_scheme}")
    author_signature, offset = _read_bytes_u16(data, offset, 64)
    origin_signature, offset = _read_fixed(data, offset, SIGNATURE_SIZE)
    if offset != len(data):
        raise DecodeError(f"trailing bytes: {len(data) - offset} extra")

    return Event(
        format_version=fv, event_type=event_type, origin=origin, board=board,
        feed_seq=feed_seq, previous_event_hash=previous_event_hash,
        message_id=message_id, article_num=article_num, created_at=created_at,
        actor_pubkey=actor_pubkey, actor_username=actor_username,
        actor_registrar=actor_registrar, root_message_id=root_message_id,
        reply_to_message_id=reply_to_message_id,
        supersedes_message_id=supersedes_message_id,
        target_message_id=target_message_id, headers=headers,
        extensions=extensions, body_hash=body_hash, body_size=body_size,
        author_signature_scheme=author_scheme, author_signature=author_signature,
        origin_signature=origin_signature,
    )


def validate_event(e: Event, *, allow_extensions: bool = False) -> None:
    """Validate event invariants. Normal publication requires empty extensions."""
    if e.format_version != FORMAT_VERSION:
        raise DecodeError(f"format_version must be {FORMAT_VERSION}")
    if e.event_type not in VALID_EVENT_TYPES:
        raise DecodeError(f"event_type {e.event_type:#04x} not a valid v3 type")
    if e.feed_seq < 1:
        raise DecodeError("feed_seq must be >= 1")
    if e.message_id == ZERO_MESSAGE_ID:
        raise DecodeError("message_id must not be all-zero")
    if e.body_size < 0:
        raise DecodeError("body_size must not be negative")
    if not allow_extensions and e.extensions:
        raise DecodeError("normal publication must not include extensions")
    if e.author_signature_scheme == SCHEME_V3 and not e.author_signature:
        raise DecodeError("scheme 1 requires a non-empty author_signature")
    if e.author_signature_scheme == SCHEME_NONE and e.author_signature:
        raise DecodeError("scheme 0 must have an empty author_signature")
    if len(e.origin_signature) != SIGNATURE_SIZE:
        raise DecodeError("origin_signature must be 64 bytes")


# ---------------------------------------------------------------------------
# Feed head codec (§9)
# ---------------------------------------------------------------------------

def encode_head(h: FeedHead) -> bytes:
    if h.format_version != HEAD_FORMAT_VERSION:
        raise DecodeError(f"head format_version must be {HEAD_FORMAT_VERSION}")
    if len(h.origin.encode("utf-8")) > MAX_ORIGIN_LEN:
        raise DecodeError("head origin exceeds max length")
    if len(h.board.encode("utf-8")) > MAX_BOARD_LEN:
        raise DecodeError("head board exceeds max length")
    if len(h.latest_event_hash) != HASH_SIZE:
        raise DecodeError("latest_event_hash must be 32 bytes")
    if len(h.signature) != SIGNATURE_SIZE:
        raise DecodeError("head signature must be 64 bytes")
    return encode_head_payload(h) + h.signature


def encode_head_payload(h: FeedHead) -> bytes:
    return (
        DOMAIN_HEAD_SIG
        + _pack_u8(h.format_version)
        + _pack_str_u16(h.origin)
        + _pack_str_u16(h.board)
        + _pack_u64(h.latest_feed_seq)
        + h.latest_event_hash
        + _pack_u64(h.article_count)
        + _pack_u64(h.event_count)
        + _pack_i64(h.snapshot_timestamp)
    )


def decode_head(data: bytes) -> FeedHead:
    offset = 0
    domain, offset = _read_fixed(data, offset, len(DOMAIN_HEAD_SIG))
    if domain != DOMAIN_HEAD_SIG:
        raise DecodeError("invalid head domain prefix")
    fv, offset = _read_u8(data, offset)
    if fv != HEAD_FORMAT_VERSION:
        raise DecodeError(f"head format_version must be {HEAD_FORMAT_VERSION}, got {fv}")
    origin, offset = _read_str_u16(data, offset, MAX_ORIGIN_LEN)
    board, offset = _read_str_u16(data, offset, MAX_BOARD_LEN)
    latest_feed_seq, offset = _read_u64(data, offset)
    latest_event_hash, offset = _read_fixed(data, offset, HASH_SIZE)
    article_count, offset = _read_u64(data, offset)
    event_count, offset = _read_u64(data, offset)
    snapshot_timestamp, offset = _read_i64(data, offset)
    signature, offset = _read_fixed(data, offset, SIGNATURE_SIZE)
    if offset != len(data):
        raise DecodeError(f"trailing bytes in head: {len(data) - offset} extra")
    return FeedHead(
        format_version=fv, origin=origin, board=board,
        latest_feed_seq=latest_feed_seq, latest_event_hash=latest_event_hash,
        article_count=article_count, event_count=event_count,
        snapshot_timestamp=snapshot_timestamp, signature=signature,
    )


def make_empty_head(origin: str, board: str, snapshot_timestamp: int = 0) -> FeedHead:
    return FeedHead(
        format_version=HEAD_FORMAT_VERSION, origin=origin, board=board,
        latest_feed_seq=0, latest_event_hash=ZERO_HASH,
        article_count=0, event_count=0,
        snapshot_timestamp=snapshot_timestamp, signature=b"\x00" * SIGNATURE_SIZE,
    )


# ---------------------------------------------------------------------------
# Hashes (§7.5, §8.3, §9)
# ---------------------------------------------------------------------------

def _sha256(*chunks: bytes) -> bytes:
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
    return h.digest()


def compute_event_hash(encoded_event: bytes) -> bytes:
    return _sha256(DOMAIN_EVENT_HASH, encoded_event)


def compute_body_hash(body: bytes) -> bytes:
    return _sha256(DOMAIN_BODY_HASH, body)


def compute_head_hash(encoded_head: bytes) -> bytes:
    return _sha256(DOMAIN_HEAD_HASH, encoded_head)


# ---------------------------------------------------------------------------
# Signatures (§8.4, §8.5, §9)
# ---------------------------------------------------------------------------

def author_signature_payload(submission: Submission) -> bytes:
    return DOMAIN_AUTHOR_SIG + encode_submission(submission)


def sign_author(submission: Submission, identity: Identity) -> bytes:
    return identity.sign(author_signature_payload(submission))


def verify_author_signature(submission: Submission, signature: bytes,
                            pubkey: bytes) -> bool:
    return Identity.verify(pubkey, author_signature_payload(submission), signature)


def origin_signature_payload(event: Event) -> bytes:
    return DOMAIN_ORIGIN_SIG + _encode_event_without_origin_sig(event)


def sign_origin(event: Event, identity: Identity) -> bytes:
    return identity.sign(origin_signature_payload(event))


def verify_origin_signature(event: Event, pubkey: bytes) -> bool:
    return Identity.verify(pubkey, origin_signature_payload(event), event.origin_signature)


def head_signature_payload(head: FeedHead) -> bytes:
    return encode_head_payload(head)


def sign_head(head: FeedHead, identity: Identity) -> FeedHead:
    head.signature = identity.sign(head_signature_payload(head))
    return head


def verify_head_signature(head: FeedHead, pubkey: bytes) -> bool:
    return Identity.verify(pubkey, head_signature_payload(head), head.signature)


# ---------------------------------------------------------------------------
# ArticleFeedStore — SQLite feed store + body CAS
# ---------------------------------------------------------------------------

class ArticleFeedStore:
    """SQLite-backed article feed store with content-addressed body storage.

    Uses raw sqlite3 (not core.orm) because we need BEGIN IMMEDIATE and atomic
    multi-table transactions. Follows the merkle_registry.py store pattern:
    check_same_thread=False + RLock + WAL.
    """

    def __init__(self, db_path: str, bodies_dir: str,
                 max_body_size: int = DEFAULT_MAX_BODY_SIZE):
        self._db_path = db_path
        self._bodies_dir = bodies_dir
        self._max_body_size = max_body_size
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        os.makedirs(bodies_dir, exist_ok=True)

        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._lock = threading.RLock()
        self._init_schema()

    # --- Schema ---

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS feed_events (
                origin                TEXT NOT NULL,
                board                 TEXT NOT NULL,
                feed_seq              INTEGER NOT NULL,
                event_hash            BLOB NOT NULL,
                previous_event_hash   BLOB NOT NULL,
                message_id            BLOB NOT NULL,
                event_type            INTEGER NOT NULL,
                article_num           INTEGER NOT NULL DEFAULT 0,
                created_at            INTEGER NOT NULL,
                actor_pubkey          BLOB NOT NULL,
                target_message_id     BLOB NOT NULL DEFAULT x'0000000000000000000000000000000000000000000000000000000000000000',
                supersedes_message_id BLOB NOT NULL DEFAULT x'0000000000000000000000000000000000000000000000000000000000000000',
                body_hash             BLOB NOT NULL,
                body_size             INTEGER NOT NULL,
                encoded_event         BLOB NOT NULL,
                source_relay          TEXT NOT NULL,
                accepted_at           INTEGER NOT NULL,
                is_authoritative      INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (origin, board, feed_seq),
                UNIQUE (message_id)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS feed_events_hash
                ON feed_events(origin, board, event_hash);
            CREATE INDEX IF NOT EXISTS feed_events_article
                ON feed_events(origin, board, article_num);
            CREATE INDEX IF NOT EXISTS feed_events_actor
                ON feed_events(actor_pubkey, event_type, created_at);
            CREATE INDEX IF NOT EXISTS feed_events_target
                ON feed_events(origin, board, target_message_id);
            CREATE INDEX IF NOT EXISTS feed_events_supersedes
                ON feed_events(origin, board, supersedes_message_id);

            CREATE TABLE IF NOT EXISTS feed_heads (
                origin              TEXT NOT NULL,
                board               TEXT NOT NULL,
                latest_feed_seq     INTEGER NOT NULL,
                head_hash           BLOB NOT NULL,
                latest_event_hash   BLOB NOT NULL,
                encoded_head        BLOB NOT NULL,
                is_authoritative    INTEGER NOT NULL DEFAULT 0,
                accepted_at         INTEGER NOT NULL,
                PRIMARY KEY (origin, board, latest_feed_seq, head_hash)
            );

            CREATE TABLE IF NOT EXISTS feed_state (
                origin                    TEXT NOT NULL,
                board                     TEXT NOT NULL,
                highest_accepted_seq      INTEGER NOT NULL,
                current_head_hash         BLOB NOT NULL,
                current_event_hash        BLOB NOT NULL,
                current_article_count     INTEGER NOT NULL,
                current_event_count       INTEGER NOT NULL,
                PRIMARY KEY (origin, board)
            );

            CREATE TABLE IF NOT EXISTS feed_conflicts (
                origin              TEXT NOT NULL,
                board               TEXT NOT NULL,
                feed_seq            INTEGER NOT NULL,
                candidate_hash      BLOB NOT NULL,
                encoded_candidate   BLOB NOT NULL,
                source_relay        TEXT NOT NULL,
                observed_at         INTEGER NOT NULL,
                reason              TEXT NOT NULL,
                PRIMARY KEY (origin, board, feed_seq, candidate_hash)
            );

            CREATE TABLE IF NOT EXISTS feed_staging (
                candidate_head_hash   BLOB NOT NULL,
                origin                TEXT NOT NULL,
                board                 TEXT NOT NULL,
                feed_seq              INTEGER NOT NULL,
                event_hash            BLOB NOT NULL,
                encoded_event         BLOB NOT NULL,
                staged_at             INTEGER NOT NULL,
                PRIMARY KEY (candidate_head_hash, feed_seq)
            );

            CREATE TABLE IF NOT EXISTS article_projection (
                origin                  TEXT NOT NULL,
                board                   TEXT NOT NULL,
                article_num             INTEGER NOT NULL,
                message_id              BLOB NOT NULL,
                current_state           TEXT NOT NULL,
                root_message_id         BLOB NOT NULL,
                reply_to_message_id     BLOB NOT NULL,
                replacement_message_id  BLOB,
                subject                 TEXT NOT NULL,
                tags                    TEXT NOT NULL,
                options                 TEXT NOT NULL,
                author_pubkey           BLOB NOT NULL,
                author_username         TEXT NOT NULL,
                created_at              INTEGER NOT NULL,
                body_hash               BLOB NOT NULL,
                body_size               INTEGER NOT NULL,
                latest_control_seq      INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (origin, board, article_num),
                UNIQUE (message_id)
            );

            CREATE TABLE IF NOT EXISTS punishment_projection (
                message_id          BLOB PRIMARY KEY,
                origin              TEXT NOT NULL,
                board               TEXT NOT NULL,
                feed_seq            INTEGER NOT NULL,
                punished_pubkey     BLOB NOT NULL,
                expires_at          INTEGER NOT NULL,
                created_at          INTEGER NOT NULL,
                issuer_pubkey       BLOB NOT NULL,
                body_hash           BLOB NOT NULL,
                revoked_by          BLOB
            );

            CREATE TABLE IF NOT EXISTS user_projection (
                message_id      BLOB PRIMARY KEY,
                origin          TEXT NOT NULL,
                board           TEXT NOT NULL,
                feed_seq        INTEGER NOT NULL,
                username        TEXT NOT NULL,
                publickey       BLOB NOT NULL,
                flags           INTEGER NOT NULL,
                seq_numbr       INTEGER NOT NULL,
                creation_time   INTEGER NOT NULL,
                revoked         INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS user_projection_pubkey
                ON user_projection(publickey);
            CREATE INDEX IF NOT EXISTS user_projection_origin_username
                ON user_projection(origin, username);

            CREATE TABLE IF NOT EXISTS article_bodies (
                body_hash       BLOB PRIMARY KEY,
                body_size       INTEGER NOT NULL,
                present         INTEGER NOT NULL,
                verified_at     INTEGER,
                relative_path   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS article_body_refs (
                body_hash    BLOB NOT NULL,
                message_id   BLOB NOT NULL,
                origin       TEXT NOT NULL,
                board        TEXT NOT NULL,
                retained     INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (body_hash, message_id),
                FOREIGN KEY (body_hash) REFERENCES article_bodies(body_hash)
            );
        """)
        self._conn.commit()

    # --- Read: feed state ---

    def get_feed_state(self, origin: str, board: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT highest_accepted_seq, current_head_hash, "
                "current_event_hash, current_article_count, current_event_count "
                "FROM feed_state WHERE origin=? AND board=?",
                (origin, board),
            ).fetchone()
        if not row:
            return None
        return {
            "highest_accepted_seq": row[0],
            "current_head_hash": bytes(row[1]),
            "current_event_hash": bytes(row[2]),
            "current_article_count": row[3],
            "current_event_count": row[4],
        }

    def _ensure_state(self, origin: str, board: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO feed_state "
            "(origin, board, highest_accepted_seq, current_head_hash, "
            " current_event_hash, current_article_count, current_event_count) "
            "VALUES (?, ?, 0, ?, ?, 0, 0)",
            (origin, board, ZERO_HASH, ZERO_HASH),
        )

    def create_empty_feed(self, origin: str, board: str,
                          identity: Identity) -> FeedHead:
        """Create and store a signed empty feed head for a new board.

        Per §9: BOARD_CREATE creates and stores the signed empty head before
        making the board visible. For an empty feed, sequence and counts are
        zero and the event hash is 32 zero bytes.

        This is idempotent: if a head already exists for (origin, board) at
        seq 0, it returns the existing head without creating a duplicate.
        """
        with self._lock:
            # Check if an empty head already exists
            existing = self._conn.execute(
                "SELECT encoded_head FROM feed_heads "
                "WHERE origin=? AND board=? AND latest_feed_seq=0 "
                "ORDER BY accepted_at DESC LIMIT 1",
                (origin, board),
            ).fetchone()
            if existing:
                return decode_head(bytes(existing[0]))

            # Create the empty head
            head = make_empty_head(origin, board, int(time.time()))
            sign_head(head, identity)
            encoded = encode_head(head)
            head_hash = compute_head_hash(encoded)

            self._ensure_state(origin, board)
            now = int(time.time())
            self._conn.execute(
                "INSERT OR REPLACE INTO feed_heads "
                "(origin, board, latest_feed_seq, head_hash, latest_event_hash, "
                " encoded_head, is_authoritative, accepted_at) "
                "VALUES (?, ?, 0, ?, ?, ?, 1, ?)",
                (origin, board, head_hash, ZERO_HASH, encoded, now),
            )
            self._conn.commit()
            return head

    def get_head(self, origin: str, board: str) -> Optional[FeedHead]:
        with self._lock:
            state = self.get_feed_state(origin, board)
            if state is None or state["highest_accepted_seq"] == 0:
                row = self._conn.execute(
                    "SELECT encoded_head FROM feed_heads "
                    "WHERE origin=? AND board=? AND latest_feed_seq=0 "
                    "ORDER BY accepted_at DESC LIMIT 1",
                    (origin, board),
                ).fetchone()
            else:
                row = self._conn.execute(
                    "SELECT encoded_head FROM feed_heads "
                    "WHERE origin=? AND board=? AND latest_feed_seq=? "
                    "AND head_hash=?",
                    (origin, board, state["highest_accepted_seq"],
                     state["current_head_hash"]),
                ).fetchone()
        if not row:
            return None
        return decode_head(bytes(row[0]))

    def list_heads(self, offset: int = 0, limit: int = 100) -> list:
        with self._lock:
            rows = self._conn.execute(
                "SELECT origin, board, encoded_head FROM feed_heads "
                "ORDER BY accepted_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        result = []
        for r in rows:
            result.append((r[0], r[1], decode_head(bytes(r[2]))))
        return result

    # --- Read: events ---

    def get_event(self, origin: str, board: str, feed_seq: int) -> Optional[Event]:
        with self._lock:
            row = self._conn.execute(
                "SELECT encoded_event FROM feed_events "
                "WHERE origin=? AND board=? AND feed_seq=?",
                (origin, board, feed_seq),
            ).fetchone()
        if not row:
            return None
        return decode_event(bytes(row[0]))

    def get_event_by_message_id(self, message_id: bytes) -> Optional[Event]:
        with self._lock:
            row = self._conn.execute(
                "SELECT encoded_event FROM feed_events WHERE message_id=?",
                (message_id,),
            ).fetchone()
        if not row:
            return None
        return decode_event(bytes(row[0]))

    def get_events_range(self, origin: str, board: str, start_seq: int,
                         max_count: int, max_bytes: int = 0) -> list:
        """Fetch contiguous ascending events starting at start_seq.

        If max_bytes > 0, stops when total encoded bytes would exceed it.
        Returns fewer than max_count if the byte limit is reached or the feed
        ends. Requires contiguous ascending events; stops at the first gap.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT feed_seq, encoded_event FROM feed_events "
                "WHERE origin=? AND board=? AND feed_seq >= ? "
                "ORDER BY feed_seq ASC LIMIT ?",
                (origin, board, start_seq, max_count),
            ).fetchall()
        events = []
        total_bytes = 0
        expected_seq = start_seq
        for r in rows:
            seq = r[0]
            if seq != expected_seq:
                break
            encoded = bytes(r[1])
            if max_bytes > 0 and total_bytes + len(encoded) > max_bytes:
                break
            events.append(decode_event(encoded))
            total_bytes += len(encoded)
            expected_seq += 1
        return events

    # --- Body CAS reads ---

    def has_body(self, body_hash: bytes) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT present FROM article_bodies WHERE body_hash=?",
                (body_hash,),
            ).fetchone()
        return bool(row and row[0])

    def get_body(self, body_hash: bytes) -> Optional[bytes]:
        with self._lock:
            row = self._conn.execute(
                "SELECT body_size, present, relative_path FROM article_bodies "
                "WHERE body_hash=?",
                (body_hash,),
            ).fetchone()
            if not row or not row[1]:
                return None
            body_size = row[0]
            rel_path = row[2]
        full_path = os.path.join(self._bodies_dir, rel_path)
        if not os.path.exists(full_path):
            with self._lock:
                self._conn.execute(
                    "UPDATE article_bodies SET present=0, verified_at=NULL "
                    "WHERE body_hash=?",
                    (body_hash,),
                )
                self._conn.commit()
            return None
        with open(full_path, "rb") as f:
            body = f.read()
        # Recheck hash on read (§12.5: never trust a filename)
        if len(body) != body_size or compute_body_hash(body) != body_hash:
            with self._lock:
                self._conn.execute(
                    "UPDATE article_bodies SET present=0, verified_at=NULL "
                    "WHERE body_hash=?",
                    (body_hash,),
                )
                self._conn.commit()
            return None
        with self._lock:
            self._conn.execute(
                "UPDATE article_bodies SET verified_at=? WHERE body_hash=?",
                (int(time.time()), body_hash),
            )
            self._conn.commit()
        return body

    # --- Body CAS writes ---

    def _body_rel_path(self, body_hash: bytes) -> str:
        hex_str = body_hash.hex()
        return os.path.join(hex_str[:2], hex_str[2:])

    def _store_body_bytes(self, body: bytes) -> bytes:
        """Write body to CAS, verify, atomic rename. Returns body_hash."""
        if len(body) > self._max_body_size:
            raise FeedAcceptanceError(
                f"body size {len(body)} exceeds max {self._max_body_size}")
        body_hash = compute_body_hash(body)
        rel_path = self._body_rel_path(body_hash)
        full_path = os.path.join(self._bodies_dir, rel_path)
        dir_path = os.path.dirname(full_path)
        os.makedirs(dir_path, exist_ok=True)

        if os.path.exists(full_path):
            # Already present — verify it
            with open(full_path, "rb") as f:
                existing = f.read()
            if len(existing) == len(body) and compute_body_hash(existing) == body_hash:
                with self._lock:
                    self._conn.execute(
                        "INSERT OR IGNORE INTO article_bodies "
                        "(body_hash, body_size, present, verified_at, relative_path) "
                        "VALUES (?, ?, 1, ?, ?)",
                        (body_hash, len(body), int(time.time()), rel_path),
                    )
                    self._conn.commit()
                return body_hash
            # File exists but corrupt — overwrite via temp

        tmp_path = full_path + ".tmp." + str(os.getpid()) + "." + str(threading.get_ident())
        with open(tmp_path, "wb") as f:
            f.write(body)
        with open(tmp_path, "rb") as f:
            verify_body = f.read()
        if len(verify_body) != len(body) or compute_body_hash(verify_body) != body_hash:
            os.remove(tmp_path)
            raise FeedAcceptanceError("body verification failed before rename")
        os.replace(tmp_path, full_path)

        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO article_bodies "
                "(body_hash, body_size, present, verified_at, relative_path) "
                "VALUES (?, ?, 1, ?, ?)",
                (body_hash, len(body), int(time.time()), rel_path),
            )
            self._conn.commit()
        return body_hash

    def _add_body_ref(self, body_hash: bytes, message_id: bytes,
                      origin: str, board: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO article_body_refs "
            "(body_hash, message_id, origin, board, retained) "
            "VALUES (?, ?, ?, ?, 1)",
            (body_hash, message_id, origin, board),
        )

    def mark_ref_not_retained(self, body_hash: bytes, message_id: bytes) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE article_body_refs SET retained=0 "
                "WHERE body_hash=? AND message_id=?",
                (body_hash, message_id),
            )
            self._conn.commit()

    def purge_body_if_unreferenced(self, body_hash: bytes) -> bool:
        """Remove a local blob only when no retained reference remains."""
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM article_body_refs "
                "WHERE body_hash=? AND retained=1",
                (body_hash,),
            ).fetchone()
            if row[0] > 0:
                return False
            rel = self._conn.execute(
                "SELECT relative_path FROM article_bodies WHERE body_hash=?",
                (body_hash,),
            ).fetchone()
            if rel:
                full_path = os.path.join(self._bodies_dir, rel[0])
                if os.path.exists(full_path):
                    os.remove(full_path)
            self._conn.execute(
                "UPDATE article_bodies SET present=0, verified_at=NULL "
                "WHERE body_hash=?",
                (body_hash,),
            )
            self._conn.commit()
            return True

    # --- Projection helpers ---

    def _update_article_projection(self, event: Event) -> None:
        """Insert/update article_projection for ARTICLE and control events.

        Called atomically during event append. Handles:
        - ARTICLE: insert new projection row as 'active'
        - ARTICLE with supersedes_message_id: mark old article 'superseded' + insert new
        - CANCEL: set target 'cancelled'
        - RESTORE: set target 'active'
        - PURGE: set target 'purged', mark body ref not retained, delete local body
        """
        et = event.event_type
        if et == EVENT_ARTICLE:
            headers = event.headers
            if not isinstance(headers, ArticleHeaders):
                return
            # If superseding, mark the old article
            if event.supersedes_message_id != ZERO_MESSAGE_ID:
                self._conn.execute(
                    "UPDATE article_projection SET current_state='superseded', "
                    " replacement_message_id=?, latest_control_seq=? "
                    " WHERE origin=? AND board=? AND message_id=?",
                    (event.message_id, event.feed_seq,
                     event.origin, event.board, event.supersedes_message_id),
                )
            # Insert the new article as active
            self._conn.execute(
                "INSERT OR REPLACE INTO article_projection "
                "(origin, board, article_num, message_id, current_state, "
                " root_message_id, reply_to_message_id, replacement_message_id, "
                " subject, tags, options, author_pubkey, author_username, "
                " created_at, body_hash, body_size, latest_control_seq) "
                "VALUES (?, ?, ?, ?, 'active', ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
                (event.origin, event.board, event.article_num, event.message_id,
                 event.root_message_id, event.reply_to_message_id,
                 headers.subject, headers.tags, headers.options,
                 event.actor_pubkey, event.actor_username,
                 event.created_at, event.body_hash, event.body_size),
            )
        elif et == EVENT_CANCEL:
            self._conn.execute(
                "UPDATE article_projection SET current_state='cancelled', "
                " latest_control_seq=? "
                " WHERE origin=? AND board=? AND message_id=?",
                (event.feed_seq, event.origin, event.board, event.target_message_id),
            )
        elif et == EVENT_RESTORE:
            self._conn.execute(
                "UPDATE article_projection SET current_state='active', "
                " latest_control_seq=? "
                " WHERE origin=? AND board=? AND message_id=?",
                (event.feed_seq, event.origin, event.board, event.target_message_id),
            )
        elif et == EVENT_PURGE:
            self._conn.execute(
                "UPDATE article_projection SET current_state='purged', "
                " latest_control_seq=? "
                " WHERE origin=? AND board=? AND message_id=?",
                (event.feed_seq, event.origin, event.board, event.target_message_id),
            )
            # Mark body ref as not retained and attempt local body removal
            self._conn.execute(
                "UPDATE article_body_refs SET retained=0 "
                " WHERE origin=? AND board=? AND message_id=?",
                (event.origin, event.board, event.target_message_id),
            )
            # Try to remove the local body blob if no other retained refs
            row = self._conn.execute(
                "SELECT ap.body_hash FROM article_projection ap "
                " WHERE ap.origin=? AND ap.board=? AND ap.message_id=?",
                (event.origin, event.board, event.target_message_id),
            ).fetchone()
            if row:
                body_hash = bytes(row[0])
                self._purge_body_if_unreferenced_locked(body_hash)

    def _purge_body_if_unreferenced_locked(self, body_hash: bytes) -> None:
        """Delete a local blob only when no retained reference remains.

        Internal version that operates within the current transaction
        (does not acquire the lock or commit).
        """
        row = self._conn.execute(
            "SELECT COUNT(*) FROM article_body_refs "
            "WHERE body_hash=? AND retained=1",
            (body_hash,),
        ).fetchone()
        if row[0] > 0:
            return
        rel = self._conn.execute(
            "SELECT relative_path FROM article_bodies WHERE body_hash=?",
            (body_hash,),
        ).fetchone()
        if rel:
            full_path = os.path.join(self._bodies_dir, rel[0])
            if os.path.exists(full_path):
                try:
                    os.remove(full_path)
                except OSError:
                    pass
        self._conn.execute(
            "UPDATE article_bodies SET present=0, verified_at=NULL "
            "WHERE body_hash=?",
            (body_hash,),
        )

    def _update_punishment_projection(self, event: Event) -> None:
        """Insert/update punishment_projection for PUNISHMENT and REVOKE events."""
        if event.event_type == EVENT_PUNISHMENT:
            headers = event.headers
            if not isinstance(headers, PunishmentHeaders):
                return
            self._conn.execute(
                "INSERT OR REPLACE INTO punishment_projection "
                "(message_id, origin, board, feed_seq, punished_pubkey, "
                " expires_at, created_at, issuer_pubkey, body_hash, revoked_by) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                (event.message_id, event.origin, event.board, event.feed_seq,
                 headers.punished_pubkey, headers.expires_at,
                 event.created_at, event.actor_pubkey, event.body_hash),
            )
        elif event.event_type == EVENT_PUNISHMENT_REVOKE:
            # Mark the target punishment as revoked
            self._conn.execute(
                "UPDATE punishment_projection SET revoked_by=? "
                "WHERE message_id=?",
                (event.message_id, event.target_message_id),
            )

    def _update_user_projection(self, event: Event) -> None:
        """Insert/update user_projection for USER_REGISTER and REVOKE events."""
        if event.event_type == EVENT_USER_REGISTER:
            headers = event.headers
            if not isinstance(headers, UserHeaders):
                return
            self._conn.execute(
                "INSERT OR REPLACE INTO user_projection "
                "(message_id, origin, board, feed_seq, username, "
                " publickey, flags, seq_numbr, creation_time, revoked) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
                (event.message_id, event.origin, event.board, event.feed_seq,
                 headers.username, headers.publickey, headers.flags,
                 headers.seq_numbr, headers.creation_time),
            )
        elif event.event_type == EVENT_USER_REVOKE:
            self._conn.execute(
                "UPDATE user_projection SET revoked=1 "
                "WHERE message_id=?",
                (event.target_message_id,),
            )

    def rebuild_article_projection(self, origin: str, board: str) -> int:
        """Truncate and reconstruct article_projection from accepted events.

        Processes ALL events in feed order (ARTICLE + CANCEL + RESTORE + PURGE)
        to correctly compute projection state.
        """
        with self._lock:
            self._conn.execute(
                "DELETE FROM article_projection WHERE origin=? AND board=?",
                (origin, board),
            )
            rows = self._conn.execute(
                "SELECT encoded_event FROM feed_events "
                "WHERE origin=? AND board=? "
                "ORDER BY feed_seq ASC",
                (origin, board),
            ).fetchall()
            count = 0
            for r in rows:
                event = decode_event(bytes(r[0]))
                if event.event_type == EVENT_ARTICLE:
                    count += 1
                self._update_article_projection(event)
            self._conn.commit()
            return count

    def rebuild_punishment_projection(self, origin: str, board: str) -> int:
        """Truncate and reconstruct punishment_projection from accepted events."""
        with self._lock:
            self._conn.execute(
                "DELETE FROM punishment_projection WHERE origin=? AND board=?",
                (origin, board),
            )
            rows = self._conn.execute(
                "SELECT encoded_event FROM feed_events "
                "WHERE origin=? AND board=? "
                "AND event_type IN (?, ?) "
                "ORDER BY feed_seq ASC",
                (origin, board, EVENT_PUNISHMENT, EVENT_PUNISHMENT_REVOKE),
            ).fetchall()
            count = 0
            for r in rows:
                event = decode_event(bytes(r[0]))
                self._update_punishment_projection(event)
                self._update_user_projection(event)
                if event.event_type == EVENT_PUNISHMENT:
                    count += 1
            self._conn.commit()
            return count

    def rebuild_user_projection(self, origin: str, board: str) -> int:
        """Truncate and reconstruct user_projection from accepted events."""
        with self._lock:
            self._conn.execute(
                "DELETE FROM user_projection WHERE origin=? AND board=?",
                (origin, board),
            )
            rows = self._conn.execute(
                "SELECT encoded_event FROM feed_events "
                "WHERE origin=? AND board=? "
                "AND event_type IN (?, ?) "
                "ORDER BY feed_seq ASC",
                (origin, board, EVENT_USER_REGISTER, EVENT_USER_REVOKE),
            ).fetchall()
            count = 0
            for r in rows:
                event = decode_event(bytes(r[0]))
                self._update_user_projection(event)
                if event.event_type == EVENT_USER_REGISTER:
                    count += 1
            self._conn.commit()
            return count

    def get_user_by_pubkey(self, pubkey: bytes) -> Optional[dict]:
        """Return the latest non-revoked user projection for a pubkey."""
        with self._lock:
            row = self._conn.execute(
                "SELECT message_id, origin, username, publickey, flags, "
                "       seq_numbr, creation_time, revoked "
                "FROM user_projection "
                "WHERE publickey=? AND revoked=0 "
                "ORDER BY creation_time DESC, origin ASC, seq_numbr DESC LIMIT 1",
                (pubkey,),
            ).fetchone()
            if row is None:
                return None
            return {
                "message_id": bytes(row[0]),
                "origin": row[1],
                "username": row[2],
                "publickey": bytes(row[3]),
                "flags": row[4],
                "seq_numbr": row[5],
                "creation_time": row[6],
                "revoked": row[7],
            }

    def list_users_by_origin(self, origin: str) -> list:
        """Return all non-revoked user projections for an origin."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT username, publickey, flags, seq_numbr, creation_time "
                "FROM user_projection "
                "WHERE origin=? AND revoked=0 "
                "ORDER BY username ASC",
                (origin,),
            ).fetchall()
            return [
                {"username": r[0], "publickey": bytes(r[1]), "flags": r[2],
                 "seq_numbr": r[3], "creation_time": r[4]}
                for r in rows
            ]

    # --- Authoritative local append (normal publication) ---

    def append_authoritative(
        self,
        submission: Submission,
        body: bytes,
        author_signature_scheme: int,
        author_signature: bytes,
        identity: Identity,
        *,
        expected_origin: str,
    ) -> tuple:
        """Append a new event to a local authoritative feed.

        Allocates feed_seq, article_num, and previous_event_hash atomically,
        constructs the complete event, signs it with the origin key, and
        commits event + head + state + projection + body atomically.

        Returns (Event, FeedHead).
        Raises MessageIdCollision if a duplicate message_id has different content.
        """
        validate_submission(submission)
        if author_signature_scheme not in VALID_SCHEMES:
            raise FeedAcceptanceError(f"invalid author_signature_scheme {author_signature_scheme}")
        if submission.origin != expected_origin:
            raise FeedAcceptanceError("submission origin does not match expected canonical origin")

        # Normal publication: scheme must be 1, no extensions
        if author_signature_scheme != SCHEME_V3:
            raise FeedAcceptanceError("normal publication requires scheme 1 (SCHEME_V3)")

        # Verify body hash and size
        actual_body_hash = compute_body_hash(body)
        if actual_body_hash != submission.body_hash:
            raise FeedAcceptanceError("body_hash does not match supplied body")
        if len(body) != submission.body_size:
            raise FeedAcceptanceError("body_size does not match supplied body")
        if len(body) > self._max_body_size:
            raise FeedAcceptanceError("body exceeds max size")

        # Verify author signature
        if not verify_author_signature(submission, author_signature, submission.actor_pubkey):
            raise FeedAcceptanceError("author signature verification failed")

        with self._lock:
            return self._append_authoritative_locked(
                submission, body, author_signature_scheme, author_signature,
                identity, expected_origin, allow_extensions=False,
            )

    def append_authoritative_event(
        self,
        event: Event,
        identity: Identity,
        *,
        expected_origin: str,
        allow_migration: bool = True,
        body: bytes = None,
    ) -> tuple:
        """Append a pre-constructed event (migration path).

        The event may have non-empty extensions and scheme 0 or 2.
        feed_seq, article_num, and previous_event_hash are overwritten with
        allocated values. The origin signature is recomputed.
        """
        # Pre-allocation validation: check only the fields that won't be
        # overwritten by the store. feed_seq, previous_event_hash, and
        # article_num are allocated by the store, so skip those checks.
        if not allow_migration:
            validate_event(event, allow_extensions=False)
        else:
            # For migration events, validate selectively (skip feed_seq check
            # since it's 0 pre-allocation and will be overwritten)
            if event.format_version != FORMAT_VERSION:
                raise DecodeError(f"format_version must be {FORMAT_VERSION}")
            if event.event_type not in VALID_EVENT_TYPES:
                raise DecodeError(f"event_type {event.event_type:#04x} not valid")
            if event.message_id == ZERO_MESSAGE_ID:
                raise DecodeError("message_id must not be all-zero")
            if event.body_size < 0:
                raise DecodeError("body_size must not be negative")
            if not event.extensions:
                raise FeedAcceptanceError(
                    "migration append requires non-empty extensions")
            if event.author_signature_scheme not in (SCHEME_NONE, SCHEME_LEGACY_V2):
                raise FeedAcceptanceError(
                    "migration append requires scheme 0 or 2")
        if event.origin != expected_origin:
            raise FeedAcceptanceError("event origin does not match expected canonical origin")

        with self._lock:
            submission = _event_to_submission(event)
            if body is None:
                body = b""
                if event.body_size > 0:
                    body = self.get_body(event.body_hash) or b""
                    if not body and event.body_hash != compute_body_hash(b""):
                        raise FeedAcceptanceError(
                            "migration event body not available in CAS")
            return self._append_authoritative_locked(
                submission, body, event.author_signature_scheme,
                event.author_signature, identity, expected_origin,
                allow_extensions=allow_migration,
                prebuilt_extensions=event.extensions,
            )

    def _append_authoritative_locked(
        self,
        submission: Submission,
        body: bytes,
        author_signature_scheme: int,
        author_signature: bytes,
        identity: Identity,
        expected_origin: str,
        *,
        allow_extensions: bool = False,
        prebuilt_extensions: list = None,
    ) -> tuple:
        origin = submission.origin
        board = submission.board

        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._ensure_state(origin, board)
            state = self.get_feed_state(origin, board)
            highest_seq = state["highest_accepted_seq"]
            feed_seq = highest_seq + 1
            previous_event_hash = state["current_event_hash"]

            # Idempotency check
            existing = self._conn.execute(
                "SELECT encoded_event FROM feed_events WHERE message_id=?",
                (submission.message_id,),
            ).fetchone()
            if existing:
                existing_event = decode_event(bytes(existing[0]))
                existing_sub = _event_to_submission(existing_event)
                if (encode_submission(existing_sub) == encode_submission(submission)
                        and existing_event.author_signature_scheme == author_signature_scheme
                        and existing_event.author_signature == author_signature):
                    # Idempotent — return existing event + current head
                    self._conn.rollback()
                    head = self.get_head(origin, board)
                    return existing_event, head
                self._conn.rollback()
                raise MessageIdCollision(submission.message_id)

            # Allocate article_num for ARTICLE events
            article_num = 0
            if submission.event_type == EVENT_ARTICLE:
                row = self._conn.execute(
                    "SELECT MAX(article_num) FROM feed_events "
                    "WHERE origin=? AND board=? AND event_type=?",
                    (origin, board, EVENT_ARTICLE),
                ).fetchone()
                max_anum = row[0] if row and row[0] is not None else 0
                article_num = max_anum + 1

            extensions = prebuilt_extensions if prebuilt_extensions is not None else []
            if not allow_extensions and extensions:
                self._conn.rollback()
                raise FeedAcceptanceError("extensions not allowed for normal publication")

            event = Event(
                format_version=FORMAT_VERSION,
                event_type=submission.event_type,
                origin=origin,
                board=board,
                feed_seq=feed_seq,
                previous_event_hash=previous_event_hash,
                message_id=submission.message_id,
                article_num=article_num,
                created_at=submission.created_at,
                actor_pubkey=submission.actor_pubkey,
                actor_username=submission.actor_username,
                actor_registrar=submission.actor_registrar,
                root_message_id=submission.root_message_id,
                reply_to_message_id=submission.reply_to_message_id,
                supersedes_message_id=submission.supersedes_message_id,
                target_message_id=submission.target_message_id,
                headers=submission.headers,
                extensions=extensions,
                body_hash=submission.body_hash,
                body_size=submission.body_size,
                author_signature_scheme=author_signature_scheme,
                author_signature=author_signature,
                origin_signature=b"\x00" * SIGNATURE_SIZE,
            )

            # Sign with origin key
            event.origin_signature = sign_origin(event, identity)
            encoded = encode_event(event)
            event_hash = compute_event_hash(encoded)

            # Store body (even empty body gets stored for uniformity)
            if submission.body_size > 0:
                self._store_body_bytes(body)
            elif submission.body_hash == compute_body_hash(b""):
                # Empty body — record it without a file
                self._conn.execute(
                    "INSERT OR IGNORE INTO article_bodies "
                    "(body_hash, body_size, present, verified_at, relative_path) "
                    "VALUES (?, 0, 1, ?, '')",
                    (submission.body_hash, int(time.time())),
                )
            self._add_body_ref(submission.body_hash, submission.message_id, origin, board)

            now = int(time.time())
            self._conn.execute(
                "INSERT INTO feed_events "
                "(origin, board, feed_seq, event_hash, previous_event_hash, "
                " message_id, event_type, article_num, created_at, actor_pubkey, "
                " target_message_id, supersedes_message_id, "
                " body_hash, body_size, encoded_event, source_relay, "
                " accepted_at, is_authoritative) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
                (origin, board, feed_seq, event_hash, previous_event_hash,
                 submission.message_id, submission.event_type, article_num,
                 submission.created_at, submission.actor_pubkey,
                 submission.target_message_id, submission.supersedes_message_id,
                 submission.body_hash, submission.body_size, encoded,
                 expected_origin, now),
            )

            # Update projections
            self._update_article_projection(event)
            self._update_punishment_projection(event)
            self._update_user_projection(event)

            # Build and store new head
            new_article_count = state["current_article_count"]
            new_event_count = state["current_event_count"] + 1
            if submission.event_type == EVENT_ARTICLE:
                new_article_count += 1

            head = FeedHead(
                format_version=HEAD_FORMAT_VERSION,
                origin=origin, board=board,
                latest_feed_seq=feed_seq,
                latest_event_hash=event_hash,
                article_count=new_article_count,
                event_count=new_event_count,
                snapshot_timestamp=now,
                signature=b"\x00" * SIGNATURE_SIZE,
            )
            sign_head(head, identity)
            encoded_head = encode_head(head)
            head_hash = compute_head_hash(encoded_head)

            self._conn.execute(
                "INSERT OR REPLACE INTO feed_heads "
                "(origin, board, latest_feed_seq, head_hash, latest_event_hash, "
                " encoded_head, is_authoritative, accepted_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                (origin, board, feed_seq, head_hash, event_hash,
                 encoded_head, now),
            )

            self._conn.execute(
                "UPDATE feed_state SET "
                " highest_accepted_seq=?, current_head_hash=?, "
                " current_event_hash=?, current_article_count=?, "
                " current_event_count=? "
                " WHERE origin=? AND board=?",
                (feed_seq, head_hash, event_hash, new_article_count,
                 new_event_count, origin, board),
            )

            self._conn.commit()
            return event, head
        except Exception:
            try:
                self._conn.rollback()
            except Exception:
                pass
            raise

    # --- Remote range acceptance (§10) ---

    def accept_remote_range(
        self,
        origin: str,
        board: str,
        head: FeedHead,
        events: list,
        origin_pubkey: bytes,
        source_relay: str,
    ) -> AcceptResult:
        """Accept a complete contiguous remote event range.

        Implements all 14 acceptance rules from §10. The range must be
        complete (final event seq == head.latest_feed_seq). For partial
        ranges, use stage_events + promote_staged.
        """
        try:
            with self._lock:
                return self._accept_remote_range_locked(
                    origin, board, head, events, origin_pubkey, source_relay)
        except FeedAcceptanceError as exc:
            return AcceptResult(False, exc.reason)

    def _accept_remote_range_locked(
        self, origin, board, head, events, origin_pubkey, source_relay,
    ) -> AcceptResult:
        # Rule 1: head origin/board must match
        if head.origin != origin or head.board != board:
            raise FeedAcceptanceError("head origin/board mismatch")

        # Rule 2: verify head signature
        if not verify_head_signature(head, origin_pubkey):
            raise FeedAcceptanceError("head signature verification failed")

        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._ensure_state(origin, board)
            state = self.get_feed_state(origin, board)
            highest = state["highest_accepted_seq"]

            # Rule 3: reject rollback
            if head.latest_feed_seq < highest:
                self._conn.rollback()
                return AcceptResult(False, "rollback: head seq below accepted", head)

            # Rule 4: equal sequence
            if head.latest_feed_seq == highest:
                existing_hash_row = self._conn.execute(
                    "SELECT head_hash FROM feed_heads "
                    "WHERE origin=? AND board=? AND latest_feed_seq=? "
                    "AND head_hash=?",
                    (origin, board, highest, state["current_head_hash"]),
                ).fetchone()
                incoming_head_hash = compute_head_hash(encode_head(head))
                if existing_hash_row and bytes(existing_hash_row[0]) == incoming_head_hash:
                    self._conn.rollback()
                    return AcceptResult(True, "idempotent", head)
                self._conn.rollback()
                self._store_conflict(origin, board, head, source_relay,
                                     "equivocation: same seq different head hash")
                return AcceptResult(False, "equivocation: same seq different head hash", head)

            # Rule 5: higher sequence — validate range
            if not events:
                self._conn.rollback()
                return AcceptResult(False, "no events for advancing head", head)

            # Rule 6: first event must be highest_accepted_seq + 1
            first_seq = events[0].feed_seq
            if first_seq != highest + 1:
                self._conn.rollback()
                return AcceptResult(False, f"first event seq {first_seq} != expected {highest + 1}", head)

            # Rule 7: contiguity
            for i in range(1, len(events)):
                if events[i].feed_seq != events[i - 1].feed_seq + 1:
                    self._conn.rollback()
                    return AcceptResult(False, "non-contiguous event range", head)

            # Rule 8: first event previous hash matches local tip
            if highest == 0:
                expected_prev = ZERO_HASH
            else:
                expected_prev = state["current_event_hash"]
            if events[0].previous_event_hash != expected_prev:
                self._conn.rollback()
                return AcceptResult(False, "first event previous_event_hash mismatch", head)

            # Rule 9: each later previous hash matches preceding event hash
            for i in range(1, len(events)):
                prev_hash = compute_event_hash(encode_event(events[i - 1]))
                if events[i].previous_event_hash != prev_hash:
                    self._conn.rollback()
                    return AcceptResult(False, f"event {i} previous_event_hash mismatch", head)

            # Rule 10: every event origin/board matches feed
            for ev in events:
                if ev.origin != origin or ev.board != board:
                    self._conn.rollback()
                    return AcceptResult(False, "event origin/board mismatch", head)

            # Rule 11: verify signatures
            for ev in events:
                if not verify_origin_signature(ev, origin_pubkey):
                    self._conn.rollback()
                    return AcceptResult(False, f"event {ev.feed_seq} origin signature invalid", head)
                if ev.author_signature_scheme == SCHEME_V3:
                    sub = _event_to_submission(ev)
                    if not verify_author_signature(sub, ev.author_signature, ev.actor_pubkey):
                        self._conn.rollback()
                        return AcceptResult(False, f"event {ev.feed_seq} author signature invalid", head)
                if ev.event_type not in VALID_EVENT_TYPES:
                    self._conn.rollback()
                    return AcceptResult(False, f"event {ev.feed_seq} unknown event type", head)

            # Rule 12: final event hash must match head tip
            final_event_hash = compute_event_hash(encode_event(events[-1]))
            if final_event_hash != head.latest_event_hash:
                self._conn.rollback()
                return AcceptResult(False, "final event hash != head latest_event_hash", head)

            # Rule 13: event count must agree with head
            if len(events) != head.event_count - highest:
                self._conn.rollback()
                return AcceptResult(False, f"event count {len(events)} != expected {head.event_count - highest}", head)

            # Rule 14: commit atomically
            now = int(time.time())
            article_count = state["current_article_count"]
            for ev in events:
                encoded = encode_event(ev)
                event_hash = compute_event_hash(encoded)
                self._conn.execute(
                    "INSERT INTO feed_events "
                    "(origin, board, feed_seq, event_hash, previous_event_hash, "
                    " message_id, event_type, article_num, created_at, actor_pubkey, "
                    " target_message_id, supersedes_message_id, "
                    " body_hash, body_size, encoded_event, source_relay, "
                    " accepted_at, is_authoritative) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
                    (origin, board, ev.feed_seq, event_hash, ev.previous_event_hash,
                     ev.message_id, ev.event_type, ev.article_num, ev.created_at,
                     ev.actor_pubkey, ev.target_message_id, ev.supersedes_message_id,
                     ev.body_hash, ev.body_size, encoded,
                     source_relay, now),
                )
                self._add_body_ref(ev.body_hash, ev.message_id, origin, board)
                self._update_article_projection(ev)
                self._update_punishment_projection(ev)
                self._update_user_projection(ev)
                if ev.event_type == EVENT_ARTICLE:
                    article_count += 1

            encoded_head = encode_head(head)
            head_hash = compute_head_hash(encoded_head)
            self._conn.execute(
                "INSERT OR REPLACE INTO feed_heads "
                "(origin, board, latest_feed_seq, head_hash, latest_event_hash, "
                " encoded_head, is_authoritative, accepted_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
                (origin, board, head.latest_feed_seq, head_hash,
                 head.latest_event_hash, encoded_head, now),
            )
            self._conn.execute(
                "UPDATE feed_state SET "
                " highest_accepted_seq=?, current_head_hash=?, "
                " current_event_hash=?, current_article_count=?, "
                " current_event_count=? "
                " WHERE origin=? AND board=?",
                (head.latest_feed_seq, head_hash, head.latest_event_hash,
                 article_count, head.event_count, origin, board),
            )
            self._conn.commit()
            return AcceptResult(True, "accepted", head, len(events))
        except Exception:
            try:
                self._conn.rollback()
            except Exception:
                pass
            raise

    def _store_conflict(self, origin, board, head, source_relay, reason):
        """Store a conflict record in its own transaction (call after rollback)."""
        encoded_head = encode_head(head)
        head_hash = compute_head_hash(encoded_head)
        now = int(time.time())
        self._conn.execute(
            "INSERT OR REPLACE INTO feed_conflicts "
            "(origin, board, feed_seq, candidate_hash, encoded_candidate, "
            " source_relay, observed_at, reason) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (origin, board, head.latest_feed_seq, head_hash, encoded_head,
             source_relay, now, reason),
        )
        self._conn.commit()

    def list_conflicts(self, origin: str, board: str) -> list:
        with self._lock:
            rows = self._conn.execute(
                "SELECT feed_seq, candidate_hash, reason, observed_at "
                "FROM feed_conflicts WHERE origin=? AND board=? "
                "ORDER BY observed_at DESC",
                (origin, board),
            ).fetchall()
        return [
            {"feed_seq": r[0], "candidate_hash": bytes(r[1]),
             "reason": r[2], "observed_at": r[3]}
            for r in rows
        ]

    # --- Staging (multi-page ranges, §10) ---

    def stage_events(self, candidate_head_hash: bytes, events: list) -> None:
        """Stage events for a candidate head (multi-page range)."""
        now = int(time.time())
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                for ev in events:
                    encoded = encode_event(ev)
                    event_hash = compute_event_hash(encoded)
                    self._conn.execute(
                        "INSERT OR REPLACE INTO feed_staging "
                        "(candidate_head_hash, origin, board, feed_seq, "
                        " event_hash, encoded_event, staged_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (candidate_head_hash, ev.origin, ev.board,
                         ev.feed_seq, event_hash, encoded, now),
                    )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def promote_staged(
        self,
        origin: str,
        board: str,
        head: FeedHead,
        origin_pubkey: bytes,
        source_relay: str,
    ) -> AcceptResult:
        """Verify staged events against candidate head and promote atomically."""
        try:
            with self._lock:
                return self._promote_staged_locked(
                    origin, board, head, origin_pubkey, source_relay)
        except FeedAcceptanceError as exc:
            return AcceptResult(False, exc.reason)

    def _promote_staged_locked(self, origin, board, head, origin_pubkey, source_relay):
        if not verify_head_signature(head, origin_pubkey):
            raise FeedAcceptanceError("head signature verification failed")
        if head.origin != origin or head.board != board:
            raise FeedAcceptanceError("head origin/board mismatch")

        candidate_head_hash = compute_head_hash(encode_head(head))
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._ensure_state(origin, board)
            state = self.get_feed_state(origin, board)
            highest = state["highest_accepted_seq"]

            if head.latest_feed_seq < highest:
                self._conn.rollback()
                return AcceptResult(False, "rollback", head)
            if head.latest_feed_seq == highest:
                incoming_hash = candidate_head_hash
                if incoming_hash == state["current_head_hash"]:
                    self._conn.rollback()
                    return AcceptResult(True, "idempotent", head)
                self._conn.rollback()
                self._store_conflict(origin, board, head, source_relay,
                                     "equivocation")
                return AcceptResult(False, "equivocation", head)

            rows = self._conn.execute(
                "SELECT feed_seq, encoded_event FROM feed_staging "
                "WHERE candidate_head_hash=? AND origin=? AND board=? "
                "ORDER BY feed_seq ASC",
                (candidate_head_hash, origin, board),
            ).fetchall()
            if not rows:
                self._conn.rollback()
                return AcceptResult(False, "no staged events for candidate head", head)

            events = []
            for r in rows:
                events.append(decode_event(bytes(r[1])))

            # Validate contiguous range from highest+1 to head.latest_feed_seq
            if events[0].feed_seq != highest + 1:
                self._conn.rollback()
                return AcceptResult(False, "staged range does not start at expected seq", head)
            for i in range(1, len(events)):
                if events[i].feed_seq != events[i - 1].feed_seq + 1:
                    self._conn.rollback()
                    return AcceptResult(False, "staged range not contiguous", head)
            if events[-1].feed_seq != head.latest_feed_seq:
                self._conn.rollback()
                return AcceptResult(False, "staged range incomplete for head", head)

            # Verify hash chain
            if highest == 0:
                expected_prev = ZERO_HASH
            else:
                expected_prev = state["current_event_hash"]
            if events[0].previous_event_hash != expected_prev:
                self._conn.rollback()
                return AcceptResult(False, "first staged previous_event_hash mismatch", head)
            for i in range(1, len(events)):
                prev_hash = compute_event_hash(encode_event(events[i - 1]))
                if events[i].previous_event_hash != prev_hash:
                    self._conn.rollback()
                    return AcceptResult(False, f"staged event {i} previous_event_hash mismatch", head)

            # Verify signatures and feed identity
            for ev in events:
                if ev.origin != origin or ev.board != board:
                    self._conn.rollback()
                    return AcceptResult(False, "staged event origin/board mismatch", head)
                if not verify_origin_signature(ev, origin_pubkey):
                    self._conn.rollback()
                    return AcceptResult(False, f"staged event {ev.feed_seq} origin sig invalid", head)
                if ev.author_signature_scheme == SCHEME_V3:
                    sub = _event_to_submission(ev)
                    if not verify_author_signature(sub, ev.author_signature, ev.actor_pubkey):
                        self._conn.rollback()
                        return AcceptResult(False, f"staged event {ev.feed_seq} author sig invalid", head)

            # Final event hash must match head tip
            final_hash = compute_event_hash(encode_event(events[-1]))
            if final_hash != head.latest_event_hash:
                self._conn.rollback()
                return AcceptResult(False, "staged final hash != head tip", head)

            # Event count
            if len(events) != head.event_count - highest:
                self._conn.rollback()
                return AcceptResult(False, "staged event count mismatch", head)

            # Promote
            now = int(time.time())
            article_count = state["current_article_count"]
            for ev in events:
                encoded = encode_event(ev)
                event_hash = compute_event_hash(encoded)
                self._conn.execute(
                    "INSERT INTO feed_events "
                    "(origin, board, feed_seq, event_hash, previous_event_hash, "
                    " message_id, event_type, article_num, created_at, actor_pubkey, "
                    " target_message_id, supersedes_message_id, "
                    " body_hash, body_size, encoded_event, source_relay, "
                    " accepted_at, is_authoritative) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
                    (origin, board, ev.feed_seq, event_hash, ev.previous_event_hash,
                     ev.message_id, ev.event_type, ev.article_num, ev.created_at,
                     ev.actor_pubkey, ev.target_message_id, ev.supersedes_message_id,
                     ev.body_hash, ev.body_size, encoded,
                     source_relay, now),
                )
                self._add_body_ref(ev.body_hash, ev.message_id, origin, board)
                self._update_article_projection(ev)
                self._update_punishment_projection(ev)
                self._update_user_projection(ev)
                if ev.event_type == EVENT_ARTICLE:
                    article_count += 1

            encoded_head = encode_head(head)
            head_hash = compute_head_hash(encoded_head)
            self._conn.execute(
                "INSERT OR REPLACE INTO feed_heads "
                "(origin, board, latest_feed_seq, head_hash, latest_event_hash, "
                " encoded_head, is_authoritative, accepted_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
                (origin, board, head.latest_feed_seq, head_hash,
                 head.latest_event_hash, encoded_head, now),
            )
            self._conn.execute(
                "UPDATE feed_state SET "
                " highest_accepted_seq=?, current_head_hash=?, "
                " current_event_hash=?, current_article_count=?, "
                " current_event_count=? "
                " WHERE origin=? AND board=?",
                (head.latest_feed_seq, head_hash, head.latest_event_hash,
                 article_count, head.event_count, origin, board),
            )
            # Clean up promoted staging rows
            self._conn.execute(
                "DELETE FROM feed_staging WHERE candidate_head_hash=?",
                (candidate_head_hash,),
            )
            self._conn.commit()
            return AcceptResult(True, "promoted", head, len(events))
        except Exception:
            try:
                self._conn.rollback()
            except Exception:
                pass
            raise

    def clean_staging(self, max_age_seconds: int = 3600) -> int:
        """Delete stale/incomplete staging rows older than max_age_seconds."""
        cutoff = int(time.time()) - max_age_seconds
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM feed_staging WHERE staged_at < ?",
                (cutoff,),
            )
            self._conn.commit()
            return cur.rowcount

    # --- Article projection queries ---

    def get_article_projection(self, origin: str, board: str,
                               article_num: int) -> Optional[dict]:
        """Get article projection by article_num."""
        with self._lock:
            row = self._conn.execute(
                "SELECT origin, board, article_num, message_id, current_state, "
                " root_message_id, reply_to_message_id, replacement_message_id, "
                " subject, tags, options, author_pubkey, author_username, "
                " created_at, body_hash, body_size, latest_control_seq "
                " FROM article_projection "
                " WHERE origin=? AND board=? AND article_num=?",
                (origin, board, article_num),
            ).fetchone()
        if not row:
            return None
        return self._row_to_article_projection(row)

    def get_article_projection_by_message_id(
        self, origin: str, board: str, message_id: bytes,
    ) -> Optional[dict]:
        """Get article projection by message_id."""
        with self._lock:
            row = self._conn.execute(
                "SELECT origin, board, article_num, message_id, current_state, "
                " root_message_id, reply_to_message_id, replacement_message_id, "
                " subject, tags, options, author_pubkey, author_username, "
                " created_at, body_hash, body_size, latest_control_seq "
                " FROM article_projection "
                " WHERE origin=? AND board=? AND message_id=?",
                (origin, board, message_id),
            ).fetchone()
        if not row:
            return None
        return self._row_to_article_projection(row)

    @staticmethod
    def _row_to_article_projection(row) -> dict:
        return {
            "origin": row[0],
            "board": row[1],
            "article_num": row[2],
            "message_id": bytes(row[3]),
            "current_state": row[4],
            "root_message_id": bytes(row[5]),
            "reply_to_message_id": bytes(row[6]),
            "replacement_message_id": bytes(row[7]) if row[7] else None,
            "subject": row[8],
            "tags": row[9],
            "options": row[10],
            "author_pubkey": bytes(row[11]),
            "author_username": row[12],
            "created_at": row[13],
            "body_hash": bytes(row[14]),
            "body_size": row[15],
            "latest_control_seq": row[16],
        }

    def list_article_projections(
        self, origin: str, board: str, offset: int = 0, limit: int = 100,
        include_cancelled: bool = False,
        include_superseded: bool = False,
        include_purged: bool = False,
    ) -> list:
        """List article projections with lifecycle filtering.

        Default: only 'active' articles. Flags include other states.
        """
        states = ["active"]
        if include_cancelled:
            states.append("cancelled")
        if include_superseded:
            states.append("superseded")
        if include_purged:
            states.append("purged")
        placeholders = ",".join("?" * len(states))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT origin, board, article_num, message_id, current_state, "
                f" root_message_id, reply_to_message_id, replacement_message_id, "
                f" subject, tags, options, author_pubkey, author_username, "
                f" created_at, body_hash, body_size, latest_control_seq "
                f" FROM article_projection "
                f" WHERE origin=? AND board=? AND current_state IN ({placeholders}) "
                f" ORDER BY article_num ASC LIMIT ? OFFSET ?",
                [origin, board] + states + [limit, offset],
            ).fetchall()
        return [self._row_to_article_projection(r) for r in rows]

    def get_control_events_for_article(
        self, origin: str, board: str, target_message_id: bytes,
    ) -> list:
        """Get all control events targeting an article message ID.

        Returns events in feed_seq order. Includes CANCEL, RESTORE, PURGE,
        and any ARTICLE that supersedes the target.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT encoded_event FROM feed_events "
                " WHERE origin=? AND board=? "
                " AND (target_message_id=? OR supersedes_message_id=?) "
                " AND event_type IN (?, ?, ?, ?) "
                " ORDER BY feed_seq ASC",
                (origin, board, target_message_id, target_message_id,
                 EVENT_CANCEL, EVENT_RESTORE, EVENT_PURGE, EVENT_ARTICLE),
            ).fetchall()
        return [decode_event(bytes(r[0])) for r in rows]

    def is_body_available(self, body_hash: bytes, message_id: bytes) -> bool:
        """Check if a body is present and the ref is retained for a message."""
        with self._lock:
            body_row = self._conn.execute(
                "SELECT present FROM article_bodies WHERE body_hash=?",
                (body_hash,),
            ).fetchone()
            if not body_row or not body_row[0]:
                return False
            ref_row = self._conn.execute(
                "SELECT retained FROM article_body_refs "
                " WHERE body_hash=? AND message_id=?",
                (body_hash, message_id),
            ).fetchone()
            if not ref_row or not ref_row[0]:
                return False
            return True

    def search_article_projections(
        self,
        origin: str,
        board: str,
        states: list,
        actor_pubkey: bytes = None,
        created_after: int = 0,
        created_before: int = 0,
        text_query: str = "",
        offset: int = 0,
        limit: int = 100,
    ) -> list:
        """Search article projections with structured filters.

        states: list of allowed current_state strings.
        actor_pubkey: filter by author public key (None = any).
        created_after/created_before: time window (0 = unbounded).
        text_query: substring search over subject and tags.
        """
        where_parts = ["origin=?", "board=?"]
        params = [origin, board]

        state_placeholders = ",".join("?" * len(states))
        where_parts.append(f"current_state IN ({state_placeholders})")
        params.extend(states)

        if actor_pubkey is not None:
            where_parts.append("author_pubkey=?")
            params.append(actor_pubkey)
        if created_after > 0:
            where_parts.append("created_at >= ?")
            params.append(created_after)
        if created_before > 0:
            where_parts.append("created_at <= ?")
            params.append(created_before)
        if text_query:
            where_parts.append("(subject LIKE ? OR tags LIKE ?)")
            params.extend([f"%{text_query}%", f"%{text_query}%"])

        where_clause = " AND ".join(where_parts)
        params.extend([limit, offset])

        with self._lock:
            rows = self._conn.execute(
                f"SELECT origin, board, article_num, message_id, current_state, "
                f" root_message_id, reply_to_message_id, replacement_message_id, "
                f" subject, tags, options, author_pubkey, author_username, "
                f" created_at, body_hash, body_size, latest_control_seq "
                f" FROM article_projection "
                f" WHERE {where_clause} "
                f" ORDER BY article_num ASC LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        return [self._row_to_article_projection(r) for r in rows]

    # --- Lifecycle ---

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event_to_submission(event: Event) -> Submission:
    """Extract a Submission from an Event (strip origin-allocated fields)."""
    return Submission(
        submission_version=SUBMISSION_VERSION,
        event_type=event.event_type,
        origin=event.origin,
        board=event.board,
        message_id=event.message_id,
        created_at=event.created_at,
        actor_pubkey=event.actor_pubkey,
        actor_username=event.actor_username,
        actor_registrar=event.actor_registrar,
        root_message_id=event.root_message_id,
        reply_to_message_id=event.reply_to_message_id,
        supersedes_message_id=event.supersedes_message_id,
        target_message_id=event.target_message_id,
        headers=event.headers,
        body_hash=event.body_hash,
        body_size=event.body_size,
    )
