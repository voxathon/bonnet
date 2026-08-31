"""Canonical record codec for the firehose protocol.

Standalone encoder/decoder with no SQLite or networking dependencies. Covers
crypto domain separation, primitive encodings, the metadata map, actor
intents, origin records, origin heads, relay witnesses, and origin key
rotation proofs.
"""

from __future__ import annotations

import hashlib
import struct
import unicodedata
from dataclasses import dataclass, field

from bonnet.core.crypto import Identity

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INTENT_FORMAT = 1
RECORD_FORMAT = 1
HEAD_FORMAT = 1
WITNESS_FORMAT = 1

ID_SIZE = 32
KEY_SIZE = 32
SIG_SIZE = 64
ZERO_ID = b"\x00" * ID_SIZE
ZERO_HASH = b"\x00" * ID_SIZE

MAX_U63 = (1 << 63) - 1
MAX_ORIGIN_HOSTNAME = 253
MAX_BOARD = 255
MAX_KIND = 128
MAX_METADATA = 1 << 20
MAX_METADATA_FIELDS = 256
MAX_TEXT_FIELD = 4096
MAX_RANGE_RESPONSE = 1 << 24

# Domain separation tags. These namespace every hash and signature the ledger
# produces, so a signature over one structure can never verify against another.
# The `untp.` prefix is the substrate's namespace, distinct from the `bonnet.`
# application record kinds in core.kinds. Form is <object>.<operation>.v1, kept
# uniform even where an object has a single operation, so adding one later never
# forces a rename. The trailing NUL keeps no tag a prefix of another.
#
# Changing any of these invalidates every signature and hash ever produced.
DOMAIN_BODY = b"untp.body.hash.v1\x00"
DOMAIN_INTENT_SIG = b"untp.intent.signature.v1\x00"
DOMAIN_RECORD_SIG = b"untp.record.signature.v1\x00"
DOMAIN_EVENT_HASH = b"untp.event.hash.v1\x00"
DOMAIN_HEAD_SIG = b"untp.head.signature.v1\x00"
DOMAIN_HEAD_HASH = b"untp.head.hash.v1\x00"
DOMAIN_WITNESS_SIG = b"untp.witness.signature.v1\x00"
DOMAIN_KEY_ROTATION_PROOF = b"untp.key.rotation.proof.v1\x00"

# Metadata value types
VT_BYTES = 0x01
VT_TEXT = 0x02
VT_U64 = 0x03
VT_I64 = 0x04
VT_BOOL = 0x05
VT_ID_LIST = 0x06
VT_TEXT_LIST = 0x07

_VALID_VALUE_TYPES = frozenset(
    {
        VT_BYTES,
        VT_TEXT,
        VT_U64,
        VT_I64,
        VT_BOOL,
        VT_ID_LIST,
        VT_TEXT_LIST,
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CodecError(Exception):
    """Base for all encoding/decoding errors."""


class TruncatedInput(CodecError):
    pass


class TrailingInput(CodecError):
    pass


class LengthExceeded(CodecError):
    pass


class NonCanonical(CodecError):
    pass


class InvalidValue(CodecError):
    pass


# ---------------------------------------------------------------------------
# Primitive encoders
# ---------------------------------------------------------------------------


def enc_u8(v: int) -> bytes:
    if not 0 <= v <= 0xFF:
        raise InvalidValue(f"u8 out of range: {v}")
    return struct.pack(">B", v)


def enc_u16(v: int) -> bytes:
    if not 0 <= v <= 0xFFFF:
        raise InvalidValue(f"u16 out of range: {v}")
    return struct.pack(">H", v)


def enc_u32(v: int) -> bytes:
    if not 0 <= v <= 0xFFFFFFFF:
        raise InvalidValue(f"u32 out of range: {v}")
    return struct.pack(">I", v)


def enc_u64(v: int) -> bytes:
    if not 0 <= v <= MAX_U63:
        raise InvalidValue(f"u64 out of range: {v}")
    return struct.pack(">Q", v)


def enc_i64(v: int) -> bytes:
    if not -(1 << 63) <= v <= MAX_U63:
        raise InvalidValue(f"i64 out of range: {v}")
    return struct.pack(">q", v)


def enc_id32(v: bytes) -> bytes:
    if len(v) != ID_SIZE:
        raise InvalidValue(f"id32 must be {ID_SIZE} bytes, got {len(v)}")
    return v


def enc_key32(v: bytes) -> bytes:
    if len(v) != KEY_SIZE:
        raise InvalidValue(f"key32 must be {KEY_SIZE} bytes, got {len(v)}")
    return v


def enc_sig64(v: bytes) -> bytes:
    if len(v) != SIG_SIZE:
        raise InvalidValue(f"sig64 must be {SIG_SIZE} bytes, got {len(v)}")
    return v


def enc_text16(v: str, max_len: int = 0xFFFF) -> bytes:
    normalized = unicodedata.normalize("NFC", v)
    encoded = normalized.encode("utf-8")
    if len(encoded) > max_len:
        raise LengthExceeded(f"text16 encoded length {len(encoded)} exceeds {max_len}")
    return struct.pack(">H", len(encoded)) + encoded


def enc_blob32(v: bytes, max_len: int = 0xFFFFFFFF) -> bytes:
    if len(v) > max_len:
        raise LengthExceeded(f"blob32 length {len(v)} exceeds {max_len}")
    return struct.pack(">I", len(v)) + v


# ---------------------------------------------------------------------------
# Primitive decoders
# ---------------------------------------------------------------------------


class _Reader:
    __slots__ = ("data", "offset")

    def __init__(self, data: bytes, offset: int = 0):
        self.data = data
        self.offset = offset

    def read(self, n: int) -> bytes:
        if self.offset + n > len(self.data):
            raise TruncatedInput(
                f"need {n} bytes at offset {self.offset}, have {len(self.data) - self.offset}"
            )
        chunk = self.data[self.offset : self.offset + n]
        self.offset += n
        return chunk

    def u8(self) -> int:
        return struct.unpack(">B", self.read(1))[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.read(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.read(4))[0]

    def u64(self) -> int:
        v = struct.unpack(">Q", self.read(8))[0]
        if v > MAX_U63:
            raise NonCanonical(f"u64 exceeds 2^63-1: {v}")
        return v

    def i64(self) -> int:
        return struct.unpack(">q", self.read(8))[0]

    def id32(self) -> bytes:
        return self.read(ID_SIZE)

    def key32(self) -> bytes:
        return self.read(KEY_SIZE)

    def sig64(self) -> bytes:
        return self.read(SIG_SIZE)

    def text16(self, max_len: int = 0xFFFF) -> str:
        n = self.u16()
        if n > max_len:
            raise LengthExceeded(f"text16 length {n} exceeds {max_len}")
        raw = self.read(n)
        try:
            s = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise NonCanonical(f"invalid UTF-8: {e}")
        if not _is_nfc(raw):
            raise NonCanonical("text is not Unicode NFC")
        return s

    def blob32(self, max_len: int = 0xFFFFFFFF) -> bytes:
        n = self.u32()
        if n > max_len:
            raise LengthExceeded(f"blob32 length {n} exceeds {max_len}")
        return self.read(n)

    def expect_end(self) -> None:
        if self.offset < len(self.data):
            raise TrailingInput(
                f"{len(self.data) - self.offset} trailing bytes at offset {self.offset}"
            )


def _is_nfc(utf8_bytes: bytes) -> bool:
    try:
        s = utf8_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return unicodedata.normalize("NFC", s).encode("utf-8") == utf8_bytes


def _normalize_text(s: str) -> str:
    return unicodedata.normalize("NFC", s)


# ---------------------------------------------------------------------------
# Metadata map
# ---------------------------------------------------------------------------


@dataclass
class MetadataField:
    field_id: int
    value_type: int
    value: bytes  # raw canonical value bytes (the content after value_length)


@dataclass
class MetadataMap:
    fields: list[MetadataField] = field(default_factory=list)

    def get(self, field_id: int) -> MetadataField | None:
        for f in self.fields:
            if f.field_id == field_id:
                return f
        return None

    def get_bytes(self, field_id: int) -> bytes | None:
        f = self.get(field_id)
        if f is None or f.value_type != VT_BYTES:
            return None
        return f.value

    def get_text(self, field_id: int) -> str | None:
        f = self.get(field_id)
        if f is None or f.value_type != VT_TEXT:
            return None
        return f.value.decode("utf-8")

    def get_u64(self, field_id: int) -> int | None:
        f = self.get(field_id)
        if f is None or f.value_type != VT_U64:
            return None
        return struct.unpack(">Q", f.value)[0]

    def get_i64(self, field_id: int) -> int | None:
        f = self.get(field_id)
        if f is None or f.value_type != VT_I64:
            return None
        return struct.unpack(">q", f.value)[0]

    def get_bool(self, field_id: int) -> bool | None:
        f = self.get(field_id)
        if f is None or f.value_type != VT_BOOL:
            return None
        return f.value == b"\x01"

    def get_id_list(self, field_id: int) -> list[bytes] | None:
        f = self.get(field_id)
        if f is None or f.value_type != VT_ID_LIST:
            return None
        r = _Reader(f.value)
        count = r.u16()
        return [r.id32() for _ in range(count)]

    def get_text_list(self, field_id: int) -> list[str] | None:
        f = self.get(field_id)
        if f is None or f.value_type != VT_TEXT_LIST:
            return None
        r = _Reader(f.value)
        count = r.u16()
        return [r.text16() for _ in range(count)]


def metadata_text(field_id: int, text: str) -> MetadataField:
    return MetadataField(field_id, VT_TEXT, _normalize_text(text).encode("utf-8"))


def metadata_u64(field_id: int, v: int) -> MetadataField:
    return MetadataField(field_id, VT_U64, enc_u64(v))


def metadata_i64(field_id: int, v: int) -> MetadataField:
    return MetadataField(field_id, VT_I64, enc_i64(v))


def metadata_bool(field_id: int, v: bool) -> MetadataField:
    return MetadataField(field_id, VT_BOOL, b"\x01" if v else b"\x00")


def metadata_bytes(field_id: int, v: bytes) -> MetadataField:
    return MetadataField(field_id, VT_BYTES, v)


def metadata_id_list(field_id: int, ids: list[bytes]) -> MetadataField:
    raw = enc_u16(len(ids))
    for item in ids:
        if len(item) != ID_SIZE:
            raise InvalidValue(f"id list entry must be {ID_SIZE} bytes")
        raw += item
    return MetadataField(field_id, VT_ID_LIST, raw)


def metadata_text_list(field_id: int, texts: list[str]) -> MetadataField:
    normalized = sorted(_normalize_text(t).encode("utf-8") for t in texts)
    raw = enc_u16(len(normalized))
    for encoded in normalized:
        if len(encoded) > MAX_TEXT_FIELD:
            raise LengthExceeded(f"text list entry exceeds {MAX_TEXT_FIELD}")
        raw += struct.pack(">H", len(encoded)) + encoded
    return MetadataField(field_id, VT_TEXT_LIST, raw)


def encode_metadata(m: MetadataMap) -> bytes:
    fields = m.fields
    if len(fields) > MAX_METADATA_FIELDS:
        raise LengthExceeded(f"metadata field count {len(fields)} exceeds {MAX_METADATA_FIELDS}")
    out = enc_u16(len(fields))
    prev_id = -1
    for f in fields:
        if f.field_id <= prev_id:
            raise NonCanonical(
                f"metadata field IDs must be strictly increasing; {f.field_id} after {prev_id}"
            )
        if f.value_type not in _VALID_VALUE_TYPES:
            raise InvalidValue(f"invalid value type 0x{f.value_type:02x}")
        if len(f.value) > 0xFFFFFFFF:
            raise LengthExceeded("metadata field value exceeds u32")
        out += enc_u16(f.field_id)
        out += enc_u8(f.value_type)
        out += enc_u32(len(f.value))
        out += f.value
        prev_id = f.field_id
    if len(out) - 2 > MAX_METADATA:
        raise LengthExceeded(f"metadata encoded size exceeds {MAX_METADATA}")
    return out


def decode_metadata(data: bytes) -> MetadataMap:
    r = _Reader(data)
    count = r.u16()
    if count > MAX_METADATA_FIELDS:
        raise LengthExceeded(f"metadata field count {count} exceeds {MAX_METADATA_FIELDS}")
    fields = []
    prev_id = -1
    total = 0
    for _ in range(count):
        fid = r.u16()
        if fid <= prev_id:
            raise NonCanonical(
                f"metadata field IDs must be strictly increasing; {fid} after {prev_id}"
            )
        vtype = r.u8()
        if vtype not in _VALID_VALUE_TYPES:
            raise InvalidValue(f"invalid metadata value type 0x{vtype:02x}")
        vlen = r.u32()
        vbytes = r.read(vlen)
        _validate_value(vtype, vbytes)
        fields.append(MetadataField(fid, vtype, vbytes))
        prev_id = fid
        total += vlen
    if total > MAX_METADATA:
        raise LengthExceeded(f"metadata total value bytes exceed {MAX_METADATA}")
    r.expect_end()
    return MetadataMap(fields)


def _validate_value(vtype: int, v: bytes) -> None:
    if vtype == VT_TEXT:
        try:
            v.decode("utf-8")
        except UnicodeDecodeError:
            raise NonCanonical("TEXT value is not valid UTF-8")
        if not _is_nfc(v):
            raise NonCanonical("TEXT value is not NFC")
        if len(v) > MAX_TEXT_FIELD:
            raise LengthExceeded(f"TEXT value exceeds {MAX_TEXT_FIELD}")
    elif vtype == VT_U64:
        if len(v) != 8:
            raise NonCanonical(f"U64 value must be 8 bytes, got {len(v)}")
        val = struct.unpack(">Q", v)[0]
        if val > MAX_U63:
            raise NonCanonical("U64 value exceeds 2^63-1")
    elif vtype == VT_I64:
        if len(v) != 8:
            raise NonCanonical(f"I64 value must be 8 bytes, got {len(v)}")
    elif vtype == VT_BOOL:
        if len(v) != 1 or v not in (b"\x00", b"\x01"):
            raise NonCanonical("BOOL value must be 0x00 or 0x01")
    elif vtype == VT_BYTES:
        pass
    elif vtype == VT_ID_LIST:
        r = _Reader(v)
        count = r.u16()
        for _ in range(count):
            r.id32()
        r.expect_end()
    elif vtype == VT_TEXT_LIST:
        r = _Reader(v)
        count = r.u16()
        items = []
        for _ in range(count):
            n = r.u16()
            if n > MAX_TEXT_FIELD:
                raise LengthExceeded(f"TEXT_LIST entry exceeds {MAX_TEXT_FIELD}")
            raw = r.read(n)
            try:
                items.append(raw.decode("utf-8"))
            except UnicodeDecodeError:
                raise NonCanonical("TEXT_LIST entry is not valid UTF-8")
            if not _is_nfc(raw):
                raise NonCanonical("TEXT_LIST entry is not NFC")
        r.expect_end()
        encoded = [t.encode("utf-8") for t in items]
        if encoded != sorted(encoded):
            raise NonCanonical("TEXT_LIST must be sorted by encoded UTF-8 bytes")
        if len(set(encoded)) != len(encoded):
            raise NonCanonical("TEXT_LIST must not contain duplicates")


# ---------------------------------------------------------------------------
# Hash and signature domain functions
# ---------------------------------------------------------------------------


def compute_body_hash(body: bytes) -> bytes:
    return hashlib.sha256(DOMAIN_BODY + body).digest()


def compute_event_hash(encoded_record: bytes) -> bytes:
    return hashlib.sha256(DOMAIN_EVENT_HASH + encoded_record).digest()


def compute_head_hash(encoded_head: bytes) -> bytes:
    return hashlib.sha256(DOMAIN_HEAD_HASH + encoded_head).digest()


def sign_intent(identity: Identity, encoded_intent: bytes) -> bytes:
    return identity.sign(DOMAIN_INTENT_SIG + encoded_intent)


def verify_intent_signature(actor_pubkey: bytes, encoded_intent: bytes, signature: bytes) -> bool:
    return Identity.verify(actor_pubkey, DOMAIN_INTENT_SIG + encoded_intent, signature)


def sign_record(identity: Identity, encoded_unsigned_record: bytes) -> bytes:
    return identity.sign(DOMAIN_RECORD_SIG + encoded_unsigned_record)


def verify_record_signature(
    origin_pubkey: bytes, encoded_unsigned_record: bytes, signature: bytes
) -> bool:
    return Identity.verify(origin_pubkey, DOMAIN_RECORD_SIG + encoded_unsigned_record, signature)


def sign_head(identity: Identity, encoded_unsigned_head: bytes) -> bytes:
    return identity.sign(DOMAIN_HEAD_SIG + encoded_unsigned_head)


def verify_head_signature(
    origin_pubkey: bytes, encoded_unsigned_head: bytes, signature: bytes
) -> bool:
    return Identity.verify(origin_pubkey, DOMAIN_HEAD_SIG + encoded_unsigned_head, signature)


def sign_witness(identity: Identity, encoded_unsigned_witness: bytes) -> bytes:
    return identity.sign(DOMAIN_WITNESS_SIG + encoded_unsigned_witness)


def verify_witness_signature(
    relay_pubkey: bytes, encoded_unsigned_witness: bytes, signature: bytes
) -> bool:
    return Identity.verify(relay_pubkey, DOMAIN_WITNESS_SIG + encoded_unsigned_witness, signature)


def sign_key_rotation_proof(
    new_identity: Identity, origin: str, old_pubkey: bytes, new_pubkey: bytes
) -> bytes:
    payload = (
        enc_text16(origin, MAX_ORIGIN_HOSTNAME) + enc_key32(old_pubkey) + enc_key32(new_pubkey)
    )
    return new_identity.sign(DOMAIN_KEY_ROTATION_PROOF + payload)


def verify_key_rotation_proof(
    new_pubkey: bytes, origin: str, old_pubkey: bytes, proof: bytes
) -> bool:
    payload = (
        enc_text16(origin, MAX_ORIGIN_HOSTNAME) + enc_key32(old_pubkey) + enc_key32(new_pubkey)
    )
    return Identity.verify(new_pubkey, DOMAIN_KEY_ROTATION_PROOF + payload, proof)


# ---------------------------------------------------------------------------
# Actor Intent
# ---------------------------------------------------------------------------


@dataclass
class Intent:
    intent_format: int = INTENT_FORMAT
    event_id: bytes = ZERO_ID
    kind: str = ""
    schema_version: int = 1
    origin: str = ""
    actor_pubkey: bytes = b"\x00" * KEY_SIZE
    actor_username: str = ""
    actor_registrar: str = ""
    board: str = ""
    article_id: bytes = ZERO_ID
    target_origin: str = ""
    target_board: str = ""
    target_article_id: bytes = ZERO_ID
    target_event_id: bytes = ZERO_ID
    metadata: MetadataMap = field(default_factory=MetadataMap)
    body_hash: bytes = ZERO_HASH
    body_size: int = 0


def encode_intent(intent: Intent) -> bytes:
    if intent.intent_format != INTENT_FORMAT:
        raise InvalidValue(f"intent_format must be {INTENT_FORMAT}")
    if intent.event_id == ZERO_ID:
        raise InvalidValue("event_id must be non-zero")
    out = enc_u8(intent.intent_format)
    out += enc_id32(intent.event_id)
    out += enc_text16(intent.kind, MAX_KIND)
    out += enc_u16(intent.schema_version)
    out += enc_text16(intent.origin, MAX_ORIGIN_HOSTNAME)
    out += enc_key32(intent.actor_pubkey)
    out += enc_text16(intent.actor_username, MAX_TEXT_FIELD)
    out += enc_text16(intent.actor_registrar, MAX_ORIGIN_HOSTNAME)
    out += enc_text16(intent.board, MAX_BOARD)
    out += enc_id32(intent.article_id)
    out += enc_text16(intent.target_origin, MAX_ORIGIN_HOSTNAME)
    out += enc_text16(intent.target_board, MAX_BOARD)
    out += enc_id32(intent.target_article_id)
    out += enc_id32(intent.target_event_id)
    out += enc_blob32(encode_metadata(intent.metadata), MAX_METADATA)
    out += enc_id32(intent.body_hash)
    out += enc_u64(intent.body_size)
    return out


def decode_intent(data: bytes) -> Intent:
    r = _Reader(data)
    fmt = r.u8()
    if fmt != INTENT_FORMAT:
        raise InvalidValue(f"intent_format must be {INTENT_FORMAT}, got {fmt}")
    intent = Intent(
        intent_format=fmt,
        event_id=r.id32(),
        kind=r.text16(MAX_KIND),
        schema_version=r.u16(),
        origin=r.text16(MAX_ORIGIN_HOSTNAME),
        actor_pubkey=r.key32(),
        actor_username=r.text16(MAX_TEXT_FIELD),
        actor_registrar=r.text16(MAX_ORIGIN_HOSTNAME),
        board=r.text16(MAX_BOARD),
        article_id=r.id32(),
        target_origin=r.text16(MAX_ORIGIN_HOSTNAME),
        target_board=r.text16(MAX_BOARD),
        target_article_id=r.id32(),
        target_event_id=r.id32(),
        metadata=decode_metadata(r.blob32(MAX_METADATA)),
        body_hash=r.id32(),
        body_size=r.u64(),
    )
    r.expect_end()
    return intent


# ---------------------------------------------------------------------------
# Origin Record
# ---------------------------------------------------------------------------


@dataclass
class Record:
    record_format: int = RECORD_FORMAT
    origin: str = ""
    origin_seq: int = 0
    previous_event_hash: bytes = ZERO_HASH
    event_id: bytes = ZERO_ID
    kind: str = ""
    schema_version: int = 1
    created_at: int = 0
    actor_pubkey: bytes = b"\x00" * KEY_SIZE
    actor_username: str = ""
    actor_registrar: str = ""
    board: str = ""
    article_id: bytes = ZERO_ID
    article_num: int = 0
    target_origin: str = ""
    target_board: str = ""
    target_article_id: bytes = ZERO_ID
    target_event_id: bytes = ZERO_ID
    metadata: MetadataMap = field(default_factory=MetadataMap)
    body_hash: bytes = ZERO_HASH
    body_size: int = 0
    actor_signature: bytes = b"\x00" * SIG_SIZE
    origin_signature: bytes = b"\x00" * SIG_SIZE


def encode_unsigned_record(rec: Record) -> bytes:
    if rec.record_format != RECORD_FORMAT:
        raise InvalidValue(f"record_format must be {RECORD_FORMAT}")
    out = enc_u8(rec.record_format)
    out += enc_text16(rec.origin, MAX_ORIGIN_HOSTNAME)
    out += enc_u64(rec.origin_seq)
    out += enc_id32(rec.previous_event_hash)
    out += enc_id32(rec.event_id)
    out += enc_text16(rec.kind, MAX_KIND)
    out += enc_u16(rec.schema_version)
    out += enc_i64(rec.created_at)
    out += enc_key32(rec.actor_pubkey)
    out += enc_text16(rec.actor_username, MAX_TEXT_FIELD)
    out += enc_text16(rec.actor_registrar, MAX_ORIGIN_HOSTNAME)
    out += enc_text16(rec.board, MAX_BOARD)
    out += enc_id32(rec.article_id)
    out += enc_u64(rec.article_num)
    out += enc_text16(rec.target_origin, MAX_ORIGIN_HOSTNAME)
    out += enc_text16(rec.target_board, MAX_BOARD)
    out += enc_id32(rec.target_article_id)
    out += enc_id32(rec.target_event_id)
    out += enc_blob32(encode_metadata(rec.metadata), MAX_METADATA)
    out += enc_id32(rec.body_hash)
    out += enc_u64(rec.body_size)
    out += enc_sig64(rec.actor_signature)
    return out


def encode_record(rec: Record) -> bytes:
    return encode_unsigned_record(rec) + enc_sig64(rec.origin_signature)


def decode_record(data: bytes) -> Record:
    r = _Reader(data)
    fmt = r.u8()
    if fmt != RECORD_FORMAT:
        raise InvalidValue(f"record_format must be {RECORD_FORMAT}, got {fmt}")
    rec = Record(
        record_format=fmt,
        origin=r.text16(MAX_ORIGIN_HOSTNAME),
        origin_seq=r.u64(),
        previous_event_hash=r.id32(),
        event_id=r.id32(),
        kind=r.text16(MAX_KIND),
        schema_version=r.u16(),
        created_at=r.i64(),
        actor_pubkey=r.key32(),
        actor_username=r.text16(MAX_TEXT_FIELD),
        actor_registrar=r.text16(MAX_ORIGIN_HOSTNAME),
        board=r.text16(MAX_BOARD),
        article_id=r.id32(),
        article_num=r.u64(),
        target_origin=r.text16(MAX_ORIGIN_HOSTNAME),
        target_board=r.text16(MAX_BOARD),
        target_article_id=r.id32(),
        target_event_id=r.id32(),
        metadata=decode_metadata(r.blob32(MAX_METADATA)),
        body_hash=r.id32(),
        body_size=r.u64(),
        actor_signature=r.sig64(),
        origin_signature=r.sig64(),
    )
    r.expect_end()
    return rec


def decode_unsigned_record(data: bytes) -> tuple[Record, bytes]:
    """Decode an unsigned record, returning (record_without_origin_sig, origin_sig)."""
    r = _Reader(data)
    fmt = r.u8()
    if fmt != RECORD_FORMAT:
        raise InvalidValue(f"record_format must be {RECORD_FORMAT}, got {fmt}")
    rec = Record(
        record_format=fmt,
        origin=r.text16(MAX_ORIGIN_HOSTNAME),
        origin_seq=r.u64(),
        previous_event_hash=r.id32(),
        event_id=r.id32(),
        kind=r.text16(MAX_KIND),
        schema_version=r.u16(),
        created_at=r.i64(),
        actor_pubkey=r.key32(),
        actor_username=r.text16(MAX_TEXT_FIELD),
        actor_registrar=r.text16(MAX_ORIGIN_HOSTNAME),
        board=r.text16(MAX_BOARD),
        article_id=r.id32(),
        article_num=r.u64(),
        target_origin=r.text16(MAX_ORIGIN_HOSTNAME),
        target_board=r.text16(MAX_BOARD),
        target_article_id=r.id32(),
        target_event_id=r.id32(),
        metadata=decode_metadata(r.blob32(MAX_METADATA)),
        body_hash=r.id32(),
        body_size=r.u64(),
        actor_signature=r.sig64(),
    )
    origin_sig = r.sig64()
    r.expect_end()
    rec.origin_signature = origin_sig
    return rec, origin_sig


def reconstruct_intent_from_record(rec: Record) -> Intent:
    """Reconstruct the actor intent from a record for signature verification."""
    return Intent(
        intent_format=INTENT_FORMAT,
        event_id=rec.event_id,
        kind=rec.kind,
        schema_version=rec.schema_version,
        origin=rec.origin,
        actor_pubkey=rec.actor_pubkey,
        actor_username=rec.actor_username,
        actor_registrar=rec.actor_registrar,
        board=rec.board,
        article_id=rec.article_id,
        target_origin=rec.target_origin,
        target_board=rec.target_board,
        target_article_id=rec.target_article_id,
        target_event_id=rec.target_event_id,
        metadata=rec.metadata,
        body_hash=rec.body_hash,
        body_size=rec.body_size,
    )


# ---------------------------------------------------------------------------
# Origin Head
# ---------------------------------------------------------------------------


@dataclass
class Head:
    head_format: int = HEAD_FORMAT
    origin: str = ""
    latest_origin_seq: int = 0
    latest_event_hash: bytes = ZERO_HASH
    event_count: int = 0
    generated_at: int = 0
    origin_pubkey: bytes = b"\x00" * KEY_SIZE
    origin_signature: bytes = b"\x00" * SIG_SIZE


def encode_unsigned_head(h: Head) -> bytes:
    if h.head_format != HEAD_FORMAT:
        raise InvalidValue(f"head_format must be {HEAD_FORMAT}")
    out = enc_u8(h.head_format)
    out += enc_text16(h.origin, MAX_ORIGIN_HOSTNAME)
    out += enc_u64(h.latest_origin_seq)
    out += enc_id32(h.latest_event_hash)
    out += enc_u64(h.event_count)
    out += enc_i64(h.generated_at)
    out += enc_key32(h.origin_pubkey)
    return out


def encode_head(h: Head) -> bytes:
    return encode_unsigned_head(h) + enc_sig64(h.origin_signature)


def decode_head(data: bytes) -> Head:
    r = _Reader(data)
    fmt = r.u8()
    if fmt != HEAD_FORMAT:
        raise InvalidValue(f"head_format must be {HEAD_FORMAT}, got {fmt}")
    h = Head(
        head_format=fmt,
        origin=r.text16(MAX_ORIGIN_HOSTNAME),
        latest_origin_seq=r.u64(),
        latest_event_hash=r.id32(),
        event_count=r.u64(),
        generated_at=r.i64(),
        origin_pubkey=r.key32(),
        origin_signature=r.sig64(),
    )
    r.expect_end()
    return h


# ---------------------------------------------------------------------------
# Relay Witness
# ---------------------------------------------------------------------------


@dataclass
class Witness:
    witness_format: int = WITNESS_FORMAT
    event_origin: str = ""
    event_id: bytes = ZERO_ID
    event_hash: bytes = ZERO_HASH
    relay_pubkey: bytes = b"\x00" * KEY_SIZE
    relay_hostname: str = ""
    received_from_pubkey: bytes = b"\x00" * KEY_SIZE
    received_from_hostname: str = ""
    seen_at: int = 0
    relay_signature: bytes = b"\x00" * SIG_SIZE


def encode_unsigned_witness(w: Witness) -> bytes:
    if w.witness_format != WITNESS_FORMAT:
        raise InvalidValue(f"witness_format must be {WITNESS_FORMAT}")
    out = enc_u8(w.witness_format)
    out += enc_text16(w.event_origin, MAX_ORIGIN_HOSTNAME)
    out += enc_id32(w.event_id)
    out += enc_id32(w.event_hash)
    out += enc_key32(w.relay_pubkey)
    out += enc_text16(w.relay_hostname, MAX_ORIGIN_HOSTNAME)
    out += enc_key32(w.received_from_pubkey)
    out += enc_text16(w.received_from_hostname, MAX_ORIGIN_HOSTNAME)
    out += enc_i64(w.seen_at)
    return out


def encode_witness(w: Witness) -> bytes:
    return encode_unsigned_witness(w) + enc_sig64(w.relay_signature)


def decode_witness(data: bytes) -> Witness:
    r = _Reader(data)
    fmt = r.u8()
    if fmt != WITNESS_FORMAT:
        raise InvalidValue(f"witness_format must be {WITNESS_FORMAT}, got {fmt}")
    w = Witness(
        witness_format=fmt,
        event_origin=r.text16(MAX_ORIGIN_HOSTNAME),
        event_id=r.id32(),
        event_hash=r.id32(),
        relay_pubkey=r.key32(),
        relay_hostname=r.text16(MAX_ORIGIN_HOSTNAME),
        received_from_pubkey=r.key32(),
        received_from_hostname=r.text16(MAX_ORIGIN_HOSTNAME),
        seen_at=r.i64(),
        relay_signature=r.sig64(),
    )
    r.expect_end()
    return w


def is_origin_witness(w: Witness) -> bool:
    """An origin witness has an all-zero upstream key and empty hostname."""
    return w.received_from_pubkey == b"\x00" * KEY_SIZE and w.received_from_hostname == ""


def make_origin_witness(
    origin: str,
    event_id: bytes,
    event_hash: bytes,
    origin_identity: Identity,
    hostname: str,
    seen_at: int,
) -> Witness:
    """Create the terminating witness signed by the origin itself."""
    w = Witness(
        witness_format=WITNESS_FORMAT,
        event_origin=origin,
        event_id=event_id,
        event_hash=event_hash,
        relay_pubkey=origin_identity.public_key,
        relay_hostname=hostname,
        received_from_pubkey=b"\x00" * KEY_SIZE,
        received_from_hostname="",
        seen_at=seen_at,
    )
    w.relay_signature = sign_witness(origin_identity, encode_unsigned_witness(w))
    return w
