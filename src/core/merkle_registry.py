"""Generic Merkle registry primitives shared by all Bonnet registries.

Per PEERED_MODERATION_MERKLE_ACL_IMPLEMENTATION_PLAN §7.2, reusable code is
extracted from user_registry.py into this module:

  - Sparse Merkle tree implementation (CSMT)
  - Default hashes
  - Inclusion/non-inclusion proofs
  - Proof encoders/decoders
  - Generic signed-head payload and verification
  - Rollback/equivocation acceptance logic
  - Generic head/state/node persistence helpers

Registry type domain separation (§7.3): every hash and head signature is
domain-separated by registry_type ("users", "reports", "punishments"). A user
head cannot be replayed as a punishment head. Domain separation is achieved
both via explicit registry_type encoding in the signed head payload AND via
distinct per-registry_type hash domain constants.

This module is parameterized by registry_type. The user_registry module
instantiates it with registry_type="users"; future report and punishment
registry modules will instantiate it with their own types.
"""

import hashlib
import os
import struct
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Constants (registry-type-independent)
# ---------------------------------------------------------------------------

TREE_DEPTH = 256
HASH_SIZE = 32
SIGNATURE_SIZE = 64

HEAD_FORMAT_VERSION = 1
HEAD_HASH_ALGORITHM = 1  # SHA-256

MAX_REGISTRY_SEQ = (1 << 63) - 1  # SQLite INTEGER is signed 64-bit

ZERO_HASH = b"\x00" * HASH_SIZE

# Canonical registry type identifiers
REGISTRY_TYPE_USERS = "users"
REGISTRY_TYPE_REPORTS = "reports"
REGISTRY_TYPE_PUNISHMENTS = "punishments"
VALID_REGISTRY_TYPES = frozenset({REGISTRY_TYPE_USERS, REGISTRY_TYPE_REPORTS, REGISTRY_TYPE_PUNISHMENTS})


# ---------------------------------------------------------------------------
# Registry-type domain separation
# ---------------------------------------------------------------------------

def _domain_bytes(registry_type: str, suffix: str) -> bytes:
    """Build a domain-separation tag that binds a hash to a registry type.

    Format: b"bonnet-" + registry_type + b"-registry-" + suffix + b"-v1"
    """
    rt = registry_type.encode("utf-8")
    s = suffix.encode("utf-8")
    return b"bonnet-" + rt + b"-registry-" + s + b"-v1"


def _domain_empty(registry_type: str) -> bytes:
    return _domain_bytes(registry_type, "empty")


def _domain_key(registry_type: str) -> bytes:
    return _domain_bytes(registry_type, "key")


def _domain_record(registry_type: str) -> bytes:
    return _domain_bytes(registry_type, "record")


def _domain_leaf(registry_type: str) -> bytes:
    return _domain_bytes(registry_type, "leaf")


def _domain_node(registry_type: str) -> bytes:
    return _domain_bytes(registry_type, "node")


def _domain_head_sig(registry_type: str) -> bytes:
    return _domain_bytes(registry_type, "head")


def _domain_head_hash(registry_type: str) -> bytes:
    return _domain_bytes(registry_type, "signed-head")


# ---------------------------------------------------------------------------
# Hash helpers (parameterized by registry_type)
# ---------------------------------------------------------------------------

def _sha256(*chunks: bytes) -> bytes:
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
    return h.digest()


def compute_registry_key(registry_type: str, origin: str, name: str) -> bytes:
    """Compute a 32-byte registry key from (registry_type, origin, name).

    For users, name is the username. For reports, name encodes
    (origin, report_num, rollover). For punishments, name encodes
    (origin, punishment_id, rollover). Callers are responsible for building
    the name string deterministically.
    """
    origin_b = origin.encode("utf-8")
    name_b = name.encode("utf-8")
    return _sha256(
        _domain_key(registry_type),
        struct.pack(">H", len(origin_b)), origin_b,
        struct.pack(">H", len(name_b)), name_b,
    )


def compute_value_hash(registry_type: str, raw_record: bytes) -> bytes:
    return _sha256(_domain_record(registry_type), raw_record)


def _leaf_hash(registry_type: str, key_bytes: bytes, value_hash: bytes) -> bytes:
    return _sha256(_domain_leaf(registry_type), key_bytes, value_hash)


def _node_hash(registry_type: str, level: int, left: bytes, right: bytes) -> bytes:
    return _sha256(_domain_node(registry_type), struct.pack(">H", level), left, right)


# ---------------------------------------------------------------------------
# Default hashes — precomputed per registry_type at first use
# ---------------------------------------------------------------------------

_default_hashes_cache: dict[str, list[bytes]] = {}
_empty_leaf_cache: dict[str, bytes] = {}
_empty_root_cache: dict[str, bytes] = {}


def _build_default_hashes(registry_type: str) -> list[bytes]:
    """Precompute the 257 default hashes for a 256-bit sparse Merkle tree."""
    empty_leaf = _sha256(_domain_empty(registry_type))
    _empty_leaf_cache[registry_type] = empty_leaf

    hashes: list[bytes] = [b""] * (TREE_DEPTH + 1)
    hashes[TREE_DEPTH] = empty_leaf
    for lvl in range(TREE_DEPTH - 1, -1, -1):
        hashes[lvl] = _node_hash(registry_type, lvl, hashes[lvl + 1], hashes[lvl + 1])
    _empty_root_cache[registry_type] = hashes[0]
    return hashes


def get_default_hashes(registry_type: str) -> list[bytes]:
    """Return the precomputed default hashes for a registry type (cached)."""
    cached = _default_hashes_cache.get(registry_type)
    if cached is not None:
        return cached
    if registry_type not in VALID_REGISTRY_TYPES:
        # Allow arbitrary registry_type strings for future types, but validate
        # the common ones. Non-empty, non-whitespace is sufficient.
        if not registry_type or not registry_type.strip():
            raise ValueError("registry_type must be a non-empty string")
    hashes = _build_default_hashes(registry_type)
    _default_hashes_cache[registry_type] = hashes
    return hashes


def get_empty_leaf(registry_type: str) -> bytes:
    get_default_hashes(registry_type)  # populates cache
    return _empty_leaf_cache[registry_type]


def get_empty_root(registry_type: str) -> bytes:
    get_default_hashes(registry_type)  # populates cache
    return _empty_root_cache[registry_type]


# ---------------------------------------------------------------------------
# Bitmap helpers
# ---------------------------------------------------------------------------

def _bitmap_set(bitmap: bytearray, index: int) -> None:
    bitmap[index // 8] |= 1 << (7 - (index % 8))


def _bitmap_get(bitmap: bytes, index: int) -> int:
    return (bitmap[index // 8] >> (7 - (index % 8))) & 1


def _popcount(data: bytes) -> int:
    return sum(bin(b).count("1") for b in data)


# ---------------------------------------------------------------------------
# Compressed Sparse Merkle Tree (parameterized by registry_type)
# ---------------------------------------------------------------------------

class CSMT:
    """In-memory 256-bit Compressed Sparse Merkle Tree.

    Stores only non-default nodes. Supports insert, update, delete,
    deterministic root computation, and compressed proof generation.

    All hashes are domain-separated by registry_type.
    """

    def __init__(self, registry_type: str):
        self._registry_type = registry_type
        self._default_hashes = get_default_hashes(registry_type)
        self._nodes: dict[tuple[int, int], bytes] = {}
        self._leaves: dict[int, bytes] = {}
        self._value_hashes: dict[int, bytes] = {}

    @property
    def registry_type(self) -> str:
        return self._registry_type

    @staticmethod
    def _key_to_int(key: bytes) -> int:
        if len(key) != HASH_SIZE:
            raise ValueError(f"Key must be {HASH_SIZE} bytes, got {len(key)}")
        return int.from_bytes(key, "big")

    def insert(self, key: bytes, value_hash: bytes) -> None:
        k = self._key_to_int(key)
        if k in self._leaves:
            raise ValueError(f"Duplicate key: {key.hex()}")
        self._set_leaf(k, key, value_hash)

    def update(self, key: bytes, value_hash: bytes) -> None:
        k = self._key_to_int(key)
        if k not in self._leaves:
            raise KeyError(f"Key not found: {key.hex()}")
        self._set_leaf(k, key, value_hash)

    def upsert(self, key: bytes, value_hash: bytes) -> None:
        k = self._key_to_int(key)
        self._set_leaf(k, key, value_hash)

    def delete(self, key: bytes) -> bool:
        k = self._key_to_int(key)
        if k not in self._leaves:
            return False
        del self._leaves[k]
        self._value_hashes.pop(k, None)
        self._nodes.pop((TREE_DEPTH, k), None)
        for level in range(TREE_DEPTH - 1, -1, -1):
            parent_prefix = k >> (TREE_DEPTH - level)
            left_prefix = parent_prefix << 1
            right_prefix = (parent_prefix << 1) | 1
            left = self._nodes.get((level + 1, left_prefix), self._default_hashes[level + 1])
            right = self._nodes.get((level + 1, right_prefix), self._default_hashes[level + 1])
            if left == self._default_hashes[level + 1] and right == self._default_hashes[level + 1]:
                self._nodes.pop((level, parent_prefix), None)
            else:
                self._nodes[(level, parent_prefix)] = _node_hash(self._registry_type, level, left, right)
        return True

    def _set_leaf(self, k: int, key_bytes: bytes, value_hash: bytes) -> None:
        leaf_h = _leaf_hash(self._registry_type, key_bytes, value_hash)
        self._leaves[k] = leaf_h
        self._value_hashes[k] = value_hash
        self._nodes[(TREE_DEPTH, k)] = leaf_h
        for level in range(TREE_DEPTH - 1, -1, -1):
            parent_prefix = k >> (TREE_DEPTH - level)
            left_prefix = parent_prefix << 1
            right_prefix = (parent_prefix << 1) | 1
            left = self._nodes.get((level + 1, left_prefix), self._default_hashes[level + 1])
            right = self._nodes.get((level + 1, right_prefix), self._default_hashes[level + 1])
            self._nodes[(level, parent_prefix)] = _node_hash(self._registry_type, level, left, right)

    def root(self) -> bytes:
        return self._nodes.get((0, 0), self._default_hashes[0])

    def leaf_count(self) -> int:
        return len(self._leaves)

    def contains(self, key: bytes) -> bool:
        return self._key_to_int(key) in self._leaves

    def get_node(self, level: int, prefix: int) -> bytes:
        return self._nodes.get((level, prefix), self._default_hashes[level])

    def inclusion_proof(self, key: bytes) -> bytes:
        k = self._key_to_int(key)
        if k not in self._leaves:
            raise KeyError(f"Key not in tree: {key.hex()}")
        value_hash = self._value_hashes[k]
        bitmap = bytearray(HASH_SIZE)
        siblings: list[bytes] = []
        for i in range(TREE_DEPTH):
            level = TREE_DEPTH - i
            bit = (k >> (TREE_DEPTH - level)) & 1
            parent_prefix = k >> (TREE_DEPTH - (level - 1))
            sibling_prefix = (parent_prefix << 1) | (1 - bit)
            sibling_h = self._nodes.get((level, sibling_prefix), self._default_hashes[level])
            if sibling_h != self._default_hashes[level]:
                _bitmap_set(bitmap, i)
                siblings.append(sibling_h)
        return _encode_proof(key, True, value_hash, bitmap, siblings)

    def non_inclusion_proof(self, key: bytes) -> bytes:
        k = self._key_to_int(key)
        if k in self._leaves:
            raise ValueError(f"Key is in tree: {key.hex()}")
        bitmap = bytearray(HASH_SIZE)
        siblings: list[bytes] = []
        for i in range(TREE_DEPTH):
            level = TREE_DEPTH - i
            bit = (k >> (TREE_DEPTH - level)) & 1
            parent_prefix = k >> (TREE_DEPTH - (level - 1))
            sibling_prefix = (parent_prefix << 1) | (1 - bit)
            sibling_h = self._nodes.get((level, sibling_prefix), self._default_hashes[level])
            if sibling_h != self._default_hashes[level]:
                _bitmap_set(bitmap, i)
                siblings.append(sibling_h)
        return _encode_proof(key, False, None, bitmap, siblings)


# ---------------------------------------------------------------------------
# Proof encoding / decoding (registry-type-independent wire format)
# ---------------------------------------------------------------------------

def _encode_proof(key: bytes, is_inclusion: bool,
                  value_hash: bytes | None,
                  bitmap: bytearray,
                  siblings: list[bytes]) -> bytes:
    parts = [key]
    if is_inclusion:
        if value_hash is None:
            raise ValueError("Inclusion proof requires value_hash")
        parts.append(value_hash)
    parts.append(bytes(bitmap))
    parts.append(struct.pack(">H", len(siblings)))
    for s in siblings:
        parts.append(s)
    return b"".join(parts)


def _decode_proof(data: bytes, is_inclusion: bool):
    min_len = HASH_SIZE + HASH_SIZE + 2  # key + bitmap + count
    if is_inclusion:
        min_len += HASH_SIZE  # value_hash
    if len(data) < min_len:
        raise ValueError(f"Proof too short: {len(data)} < {min_len}")
    offset = 0
    key = data[offset:offset + HASH_SIZE]
    offset += HASH_SIZE
    value_hash = None
    if is_inclusion:
        value_hash = data[offset:offset + HASH_SIZE]
        offset += HASH_SIZE
    bitmap = data[offset:offset + HASH_SIZE]
    offset += HASH_SIZE
    sibling_count = struct.unpack(">H", data[offset:offset + 2])[0]
    offset += 2
    if sibling_count > TREE_DEPTH:
        raise ValueError(f"Sibling count {sibling_count} exceeds {TREE_DEPTH}")
    expected_len = offset + sibling_count * HASH_SIZE
    if len(data) != expected_len:
        raise ValueError(f"Trailing/truncated data: expected {expected_len}, got {len(data)}")
    pc = _popcount(bitmap)
    if pc != sibling_count:
        raise ValueError(f"Bitmap popcount {pc} != sibling_count {sibling_count}")
    siblings: list[bytes] = []
    for _ in range(sibling_count):
        siblings.append(data[offset:offset + HASH_SIZE])
        offset += HASH_SIZE
    if is_inclusion:
        return key, value_hash, bitmap, siblings
    return key, bitmap, siblings


def decode_inclusion_proof(data: bytes):
    return _decode_proof(data, True)


def decode_non_inclusion_proof(data: bytes):
    return _decode_proof(data, False)


# ---------------------------------------------------------------------------
# Proof verification (parameterized by registry_type)
# ---------------------------------------------------------------------------

def _reconstruct_root(registry_type: str, key_bytes: bytes, start_hash: bytes,
                      bitmap: bytes, siblings: list[bytes]) -> bytes:
    k = int.from_bytes(key_bytes, "big")
    defaults = get_default_hashes(registry_type)
    current = start_hash
    sib_idx = 0
    for i in range(TREE_DEPTH):
        level = TREE_DEPTH - i
        bit = (k >> (TREE_DEPTH - level)) & 1
        if _bitmap_get(bitmap, i):
            sibling = siblings[sib_idx]
            sib_idx += 1
        else:
            sibling = defaults[level]
        if bit == 0:
            current = _node_hash(registry_type, level - 1, current, sibling)
        else:
            current = _node_hash(registry_type, level - 1, sibling, current)
    return current


def verify_inclusion_proof(registry_type: str, proof: bytes, expected_root: bytes) -> bool:
    try:
        key, value_hash, bitmap, siblings = decode_inclusion_proof(proof)
    except (ValueError, struct.error):
        return False
    leaf_h = _leaf_hash(registry_type, key, value_hash)
    reconstructed = _reconstruct_root(registry_type, key, leaf_h, bitmap, siblings)
    return reconstructed == expected_root


def verify_non_inclusion_proof(registry_type: str, proof: bytes, expected_root: bytes) -> bool:
    try:
        key, bitmap, siblings = decode_non_inclusion_proof(proof)
    except (ValueError, struct.error):
        return False
    empty_leaf = get_empty_leaf(registry_type)
    reconstructed = _reconstruct_root(registry_type, key, empty_leaf, bitmap, siblings)
    return reconstructed == expected_root


# ---------------------------------------------------------------------------
# Subtree child verification (parameterized by registry_type)
# ---------------------------------------------------------------------------

def verify_node_children(registry_type: str, level: int, left_hash: bytes,
                         right_hash: bytes, expected_hash: bytes) -> bool:
    return _node_hash(registry_type, level, left_hash, right_hash) == expected_hash


# ---------------------------------------------------------------------------
# Generic signed registry head (parameterized by registry_type)
# ---------------------------------------------------------------------------

@dataclass
class SignedHead:
    """Generic signed registry head.

    The registry_type field provides explicit domain separation in the signed
    payload, so a head signed for the users registry cannot be replayed as a
    reports or punishments head.
    """
    registry_type: str
    format_version: int
    hash_algorithm: int
    origin: str
    registry_seq: int
    snapshot_timestamp: int
    leaf_count: int
    merkle_root: bytes
    previous_head_hash: bytes
    signature: bytes

    @property
    def head_hash(self) -> bytes:
        return compute_head_hash(self.registry_type, encode_head(self))


def encode_head_payload(head: SignedHead) -> bytes:
    """Encode the signed payload of a head (excluding the signature).

    Includes registry_type as an explicit length-prefixed field so the signed
    payload is bound to a specific registry type.
    """
    rt_b = head.registry_type.encode("utf-8")
    origin_b = head.origin.encode("utf-8")
    return (
        _domain_head_sig(head.registry_type)
        + struct.pack(">B", head.format_version)
        + struct.pack(">B", head.hash_algorithm)
        + struct.pack(">H", len(rt_b)) + rt_b
        + struct.pack(">H", len(origin_b)) + origin_b
        + struct.pack(">Q", head.registry_seq)
        + struct.pack(">q", head.snapshot_timestamp)
        + struct.pack(">Q", head.leaf_count)
        + head.merkle_root
        + head.previous_head_hash
    )


def encode_head(head: SignedHead) -> bytes:
    return encode_head_payload(head) + head.signature


def decode_head(data: bytes, expected_registry_type: str | None = None) -> SignedHead:
    """Decode a signed head.

    If expected_registry_type is provided, the decoded registry_type must match
    or a ValueError is raised. This prevents cross-type replay.

    Wire format:
      domain_prefix (variable: b"bonnet-" + rt + b"-registry-head-v1")
      format_version (1 byte)
      hash_algorithm (1 byte)
      rt_len (2 bytes BE) + rt (rt_len bytes UTF-8)
      origin_len (2 bytes BE) + origin (origin_len bytes UTF-8)
      registry_seq (8 bytes BE)
      snapshot_timestamp (8 bytes BE, signed)
      leaf_count (8 bytes BE)
      merkle_root (32 bytes)
      previous_head_hash (32 bytes)
      signature (64 bytes)
    """
    suffix = b"-registry-head-v1"
    prefix_start = b"bonnet-"

    # Determine the registry_type from the domain prefix
    if expected_registry_type is not None:
        domain = _domain_head_sig(expected_registry_type)
        if len(data) < len(domain) or data[:len(domain)] != domain:
            raise ValueError(f"Invalid head domain prefix for registry_type={expected_registry_type}")
        offset = len(domain)
        expected_rt_b = expected_registry_type.encode("utf-8")
    else:
        # Scan for the domain suffix to extract registry_type
        idx = data.find(suffix)
        if idx < 0 or not data.startswith(prefix_start):
            raise ValueError("Invalid head domain prefix")
        rt_b_from_domain = data[len(prefix_start):idx]
        domain = data[:idx + len(suffix)]
        offset = len(domain)
        expected_rt_b = None

    # Fixed fields: format_version(1) + hash_algorithm(1) + rt_len(2) + rt + origin_len(2) + origin + 8+8+8+32+32+64
    if len(data) < offset + 1 + 1 + 2:
        raise ValueError("Head too short for format_version and hash_algorithm")
    format_version = data[offset]
    offset += 1
    hash_algorithm = data[offset]
    offset += 1

    # registry_type length-prefixed field
    rt_len = struct.unpack(">H", data[offset:offset + 2])[0]
    offset += 2
    if offset + rt_len > len(data):
        raise ValueError("Head registry_type exceeds data length")
    rt_b = data[offset:offset + rt_len]
    offset += rt_len
    registry_type = rt_b.decode("utf-8")

    if expected_registry_type is not None:
        if rt_b != expected_rt_b:
            raise ValueError(f"registry_type mismatch in payload: got {registry_type}, expected {expected_registry_type}")
    else:
        # Verify the rt extracted from the payload matches the domain prefix
        if expected_rt_b is None and rt_b != rt_b_from_domain:
            raise ValueError("registry_type mismatch between domain prefix and payload field")

    # origin
    origin_len = struct.unpack(">H", data[offset:offset + 2])[0]
    offset += 2
    if offset + origin_len + 8 + 8 + 8 + 32 + 32 + 64 > len(data):
        raise ValueError("Head fields exceed data length")
    origin = data[offset:offset + origin_len].decode("utf-8")
    offset += origin_len
    registry_seq = struct.unpack(">Q", data[offset:offset + 8])[0]
    offset += 8
    snapshot_timestamp = struct.unpack(">q", data[offset:offset + 8])[0]
    offset += 8
    leaf_count = struct.unpack(">Q", data[offset:offset + 8])[0]
    offset += 8
    merkle_root = data[offset:offset + 32]
    offset += 32
    previous_head_hash = data[offset:offset + 32]
    offset += 32
    signature = data[offset:offset + 64]
    offset += 64
    if offset != len(data):
        raise ValueError(f"Trailing data: expected {offset}, got {len(data)}")

    return SignedHead(
        registry_type=registry_type,
        format_version=format_version,
        hash_algorithm=hash_algorithm,
        origin=origin,
        registry_seq=registry_seq,
        snapshot_timestamp=snapshot_timestamp,
        leaf_count=leaf_count,
        merkle_root=merkle_root,
        previous_head_hash=previous_head_hash,
        signature=signature,
    )


def sign_head(
    registry_type: str,
    origin: str,
    registry_seq: int,
    snapshot_timestamp: int,
    leaf_count: int,
    merkle_root: bytes,
    previous_head_hash: bytes,
    identity,
) -> SignedHead:
    head = SignedHead(
        registry_type=registry_type,
        format_version=HEAD_FORMAT_VERSION,
        hash_algorithm=HEAD_HASH_ALGORITHM,
        origin=origin,
        registry_seq=registry_seq,
        snapshot_timestamp=snapshot_timestamp,
        leaf_count=leaf_count,
        merkle_root=merkle_root,
        previous_head_hash=previous_head_hash,
        signature=b"",
    )
    payload = encode_head_payload(head)
    sig = identity.sign(payload)
    head.signature = sig
    return head


def verify_head(head: SignedHead, origin_pubkey: bytes) -> bool:
    if head.format_version != HEAD_FORMAT_VERSION:
        return False
    if head.hash_algorithm != HEAD_HASH_ALGORITHM:
        return False
    payload = encode_head_payload(head)
    from core.crypto import Identity
    return Identity.verify(origin_pubkey, payload, head.signature)


def compute_head_hash(registry_type: str, encoded_head: bytes) -> bytes:
    return _sha256(_domain_head_hash(registry_type), encoded_head)


# ---------------------------------------------------------------------------
# Acceptance result
# ---------------------------------------------------------------------------

@dataclass
class AcceptResult:
    accepted: bool
    reason: str = ""
    head: SignedHead | None = None


# ---------------------------------------------------------------------------
# Generic SQLite-backed registry store
# ---------------------------------------------------------------------------

class MerkleRegistryStore:
    """Generic SQLite sidecar for signed registry heads, records, nodes, state.

    All tables are keyed by (registry_type, origin, ...) so a single database
    can hold multiple registry types, or each registry type can use its own
    database file. Per §7.4, either approach is acceptable.
    """

    def __init__(self, db_path: str):
        self._db_path = db_path
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._lock = threading.RLock()
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS registry_heads (
                registry_type        TEXT NOT NULL,
                origin               TEXT NOT NULL,
                registry_seq         INTEGER NOT NULL,
                snapshot_timestamp   INTEGER NOT NULL,
                leaf_count           INTEGER NOT NULL,
                merkle_root          BLOB NOT NULL,
                previous_head_hash   BLOB NOT NULL,
                signature            BLOB NOT NULL,
                encoded_head         BLOB NOT NULL,
                head_hash            BLOB NOT NULL,
                is_authoritative     INTEGER NOT NULL DEFAULT 0,
                accepted_at          INTEGER NOT NULL,
                PRIMARY KEY (registry_type, origin, registry_seq)
            );

            CREATE UNIQUE INDEX IF NOT EXISTS registry_heads_type_origin_hash
                ON registry_heads(registry_type, origin, head_hash);

            CREATE TABLE IF NOT EXISTS registry_records (
                registry_type     TEXT NOT NULL,
                origin            TEXT NOT NULL,
                registry_key      BLOB NOT NULL,
                record_name       TEXT NOT NULL,
                raw_record        BLOB NOT NULL,
                value_hash        BLOB NOT NULL,
                source_seq        INTEGER NOT NULL,
                PRIMARY KEY (registry_type, origin, registry_key)
            );

            CREATE TABLE IF NOT EXISTS registry_nodes (
                registry_type     TEXT NOT NULL,
                origin            TEXT NOT NULL,
                registry_seq      INTEGER NOT NULL,
                level             INTEGER NOT NULL,
                prefix            BLOB NOT NULL,
                node_hash         BLOB NOT NULL,
                PRIMARY KEY (registry_type, origin, registry_seq, level, prefix)
            );

            CREATE TABLE IF NOT EXISTS registry_state (
                registry_type            TEXT NOT NULL,
                origin                   TEXT NOT NULL,
                highest_accepted_seq     INTEGER NOT NULL,
                current_head_hash        BLOB NOT NULL,
                current_merkle_root      BLOB NOT NULL,
                current_leaf_count       INTEGER NOT NULL,
                dirty_generation         INTEGER NOT NULL DEFAULT 0,
                snapshotted_generation   INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (registry_type, origin)
            );
        """)
        self._conn.commit()

    def get_state(self, registry_type: str, origin: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT highest_accepted_seq, current_head_hash, current_merkle_root, "
                "current_leaf_count, dirty_generation, snapshotted_generation "
                "FROM registry_state WHERE registry_type=? AND origin=?",
                (registry_type, origin),
            ).fetchone()
        if not row:
            return None
        return {
            "highest_accepted_seq": row[0],
            "current_head_hash": bytes(row[1]),
            "current_merkle_root": bytes(row[2]),
            "current_leaf_count": row[3],
            "dirty_generation": row[4],
            "snapshotted_generation": row[5],
        }

    def _ensure_state(self, registry_type: str, origin: str) -> None:
        empty_root = get_empty_root(registry_type)
        self._conn.execute(
            "INSERT OR IGNORE INTO registry_state "
            "(registry_type, origin, highest_accepted_seq, current_head_hash, "
            " current_merkle_root, current_leaf_count, dirty_generation, "
            " snapshotted_generation) "
            "VALUES (?, ?, 0, ?, ?, 0, 0, 0)",
            (registry_type, origin, ZERO_HASH, empty_root),
        )

    def get_head(self, registry_type: str, origin: str,
                 registry_seq: int = 0) -> SignedHead | None:
        with self._lock:
            if registry_seq == 0:
                state = self.get_state(registry_type, origin)
                if state is None or state["highest_accepted_seq"] == 0:
                    return None
                registry_seq = state["highest_accepted_seq"]
            row = self._conn.execute(
                "SELECT encoded_head FROM registry_heads "
                "WHERE registry_type=? AND origin=? AND registry_seq=?",
                (registry_type, origin, registry_seq),
            ).fetchone()
        if not row:
            return None
        return decode_head(bytes(row[0]), expected_registry_type=registry_type)

    def list_heads(self, registry_type: str, origin: str | None = None,
                   offset: int = 0, limit: int = 100) -> list[SignedHead]:
        with self._lock:
            if origin:
                rows = self._conn.execute(
                    "SELECT encoded_head FROM registry_heads "
                    "WHERE registry_type=? AND origin=? "
                    "ORDER BY registry_seq DESC LIMIT ? OFFSET ?",
                    (registry_type, origin, limit, offset),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT encoded_head FROM registry_heads "
                    "WHERE registry_type=? "
                    "ORDER BY accepted_at DESC LIMIT ? OFFSET ?",
                    (registry_type, limit, offset),
                ).fetchall()
        return [decode_head(bytes(r[0]), expected_registry_type=registry_type) for r in rows]

    def get_record(self, registry_type: str, origin: str, key: bytes) -> bytes | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT raw_record FROM registry_records "
                "WHERE registry_type=? AND origin=? AND registry_key=?",
                (registry_type, origin, key),
            ).fetchone()
        return bytes(row[0]) if row else None

    def get_all_records(self, registry_type: str, origin: str) -> list[tuple[bytes, bytes, bytes]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT registry_key, raw_record, value_hash FROM registry_records "
                "WHERE registry_type=? AND origin=?",
                (registry_type, origin),
            ).fetchall()
        return [(bytes(r[0]), bytes(r[1]), bytes(r[2])) for r in rows]

    def get_node(self, registry_type: str, origin: str, registry_seq: int,
                 level: int, prefix: bytes) -> bytes | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT node_hash FROM registry_nodes "
                "WHERE registry_type=? AND origin=? AND registry_seq=? "
                "AND level=? AND prefix=?",
                (registry_type, origin, registry_seq, level, prefix),
            ).fetchone()
        return bytes(row[0]) if row else None

    def get_all_nodes(self, registry_type: str, origin: str,
                      registry_seq: int) -> list[tuple[int, bytes, bytes]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT level, prefix, node_hash FROM registry_nodes "
                "WHERE registry_type=? AND origin=? AND registry_seq=?",
                (registry_type, origin, registry_seq),
            ).fetchall()
        return [(r[0], bytes(r[1]), bytes(r[2])) for r in rows]

    def mark_dirty(self, registry_type: str, origin: str) -> None:
        with self._lock:
            self._ensure_state(registry_type, origin)
            self._conn.execute(
                "UPDATE registry_state SET dirty_generation = dirty_generation + 1 "
                "WHERE registry_type=? AND origin=?",
                (registry_type, origin),
            )
            self._conn.commit()

    def store_authoritative_head(
        self,
        registry_type: str,
        origin: str,
        head: SignedHead,
        records: list[tuple[bytes, str, bytes, bytes]],
        nodes: list[tuple[int, bytes, bytes]],
    ) -> None:
        if head.registry_seq > MAX_REGISTRY_SEQ:
            raise ValueError(f"registry_seq {head.registry_seq} exceeds SQLite signed 64-bit max")
        encoded = encode_head(head)
        h_hash = compute_head_hash(registry_type, encoded)
        now = int(time.time())
        with self._lock:
            self._ensure_state(registry_type, origin)
            self._conn.commit()
            with self._conn:
                self._conn.execute(
                    "INSERT OR REPLACE INTO registry_heads "
                    "(registry_type, origin, registry_seq, snapshot_timestamp, leaf_count, "
                    " merkle_root, previous_head_hash, signature, encoded_head, "
                    " head_hash, is_authoritative, accepted_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)",
                    (registry_type, origin, head.registry_seq, head.snapshot_timestamp,
                     head.leaf_count, head.merkle_root, head.previous_head_hash,
                     head.signature, encoded, h_hash, now),
                )
                self._store_records_and_nodes(registry_type, origin, head.registry_seq, records, nodes)
                self._gc_old_nodes(registry_type, origin, head.registry_seq)
                self._conn.execute(
                    "UPDATE registry_state SET "
                    " highest_accepted_seq=?, current_head_hash=?, "
                    " current_merkle_root=?, current_leaf_count=?, "
                    " snapshotted_generation=dirty_generation "
                    " WHERE registry_type=? AND origin=?",
                    (head.registry_seq, h_hash, head.merkle_root,
                     head.leaf_count, registry_type, origin),
                )

    def accept_remote_head(
        self,
        registry_type: str,
        origin: str,
        head: SignedHead,
        origin_pubkey: bytes,
        records: list[tuple[bytes, str, bytes, bytes]],
        nodes: list[tuple[int, bytes, bytes]],
    ) -> AcceptResult:
        if head.registry_seq > MAX_REGISTRY_SEQ:
            return AcceptResult(False, "registry_seq exceeds signed 64-bit max")
        if head.registry_type != registry_type:
            return AcceptResult(False, f"registry_type mismatch: head={head.registry_type} expected={registry_type}")
        if not verify_head(head, origin_pubkey):
            return AcceptResult(False, "signature verification failed")
        if head.origin != origin:
            return AcceptResult(False, "origin mismatch between requested and signed head")
        encoded = encode_head(head)
        h_hash = compute_head_hash(registry_type, encoded)
        now = int(time.time())
        with self._lock:
            self._ensure_state(registry_type, origin)
            self._conn.commit()
            state = self.get_state(registry_type, origin)
            highest = state["highest_accepted_seq"]
            if head.registry_seq < highest:
                return AcceptResult(False, f"rollback: seq {head.registry_seq} < highest {highest}")
            if head.registry_seq == highest and highest > 0:
                existing_hash = self._conn.execute(
                    "SELECT head_hash FROM registry_heads "
                    "WHERE registry_type=? AND origin=? AND registry_seq=?",
                    (registry_type, origin, head.registry_seq),
                ).fetchone()
                if existing_hash and bytes(existing_hash[0]) != h_hash:
                    return AcceptResult(False, "equivocation: same seq with different head hash")
                if existing_hash and bytes(existing_hash[0]) == h_hash:
                    return AcceptResult(True, "idempotent", head)
            with self._conn:
                self._conn.execute(
                    "INSERT OR REPLACE INTO registry_heads "
                    "(registry_type, origin, registry_seq, snapshot_timestamp, leaf_count, "
                    " merkle_root, previous_head_hash, signature, encoded_head, "
                    " head_hash, is_authoritative, accepted_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
                    (registry_type, origin, head.registry_seq, head.snapshot_timestamp,
                     head.leaf_count, head.merkle_root, head.previous_head_hash,
                     head.signature, encoded, h_hash, now),
                )
                self._store_records_and_nodes(registry_type, origin, head.registry_seq, records, nodes)
                self._gc_old_nodes(registry_type, origin, head.registry_seq)
                self._conn.execute(
                    "UPDATE registry_state SET "
                    " highest_accepted_seq=?, current_head_hash=?, "
                    " current_merkle_root=?, current_leaf_count=? "
                    " WHERE registry_type=? AND origin=?",
                    (head.registry_seq, h_hash, head.merkle_root,
                     head.leaf_count, registry_type, origin),
                )
        return AcceptResult(True, "accepted", head)

    def _store_records_and_nodes(
        self,
        registry_type: str,
        origin: str,
        registry_seq: int,
        records: list[tuple[bytes, str, bytes, bytes]],
        nodes: list[tuple[int, bytes, bytes]],
    ) -> None:
        self._conn.execute(
            "DELETE FROM registry_records "
            "WHERE registry_type=? AND origin=? AND source_seq < ?",
            (registry_type, origin, registry_seq - 1),
        )
        for key, record_name, raw_record, value_hash in records:
            self._conn.execute(
                "INSERT OR REPLACE INTO registry_records "
                "(registry_type, origin, registry_key, record_name, raw_record, value_hash, source_seq) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (registry_type, origin, key, record_name, raw_record, value_hash, registry_seq),
            )
        for level, prefix, node_hash in nodes:
            self._conn.execute(
                "INSERT OR REPLACE INTO registry_nodes "
                "(registry_type, origin, registry_seq, level, prefix, node_hash) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (registry_type, origin, registry_seq, level, prefix, node_hash),
            )

    def _gc_old_nodes(self, registry_type: str, origin: str, current_seq: int) -> None:
        keep_threshold = current_seq - 1
        self._conn.execute(
            "DELETE FROM registry_nodes "
            "WHERE registry_type=? AND origin=? AND registry_seq < ?",
            (registry_type, origin, keep_threshold),
        )

    def close(self) -> None:
        with self._lock:
            self._conn.close()
