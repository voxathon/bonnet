"""
Authenticated user registry: Merkle primitives, signed heads, and sidecar
persistence.

Phase 2 — pure Merkle primitives (no networking, no SQLite):
  - Domain-separated SHA-256 hash helpers
  - Precomputed default hashes for a 256-bit sparse Merkle tree
  - Compressed Sparse Merkle Tree (CSMT) with insert / update / delete
  - Deterministic root computation
  - Compressed inclusion and non-inclusion proof generation and verification
  - Strict proof parser
  - Subtree child verification

Phase 3 — signed heads and sidecar storage:
  - Canonical binary encoding for signed registry heads
  - Ed25519 head signing and verification
  - SQLite-backed UserRegistryStore (heads, records, nodes, state)
  - Rollback and equivocation enforcement
  - Dirty-generation snapshot construction via RegistryService
"""

import hashlib
import os
import struct
import sqlite3
import threading
import time
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TREE_DEPTH = 256

_DOMAIN_EMPTY = b"bonnet-user-registry-empty-v1"
_DOMAIN_KEY = b"bonnet-user-registry-key-v1"
_DOMAIN_RECORD = b"bonnet-user-registry-record-v1"
_DOMAIN_LEAF = b"bonnet-user-registry-leaf-v1"
_DOMAIN_NODE = b"bonnet-user-registry-node-v1"
_DOMAIN_HEAD_SIG = b"bonnet-user-registry-head-v1"
_DOMAIN_HEAD_HASH = b"bonnet-user-registry-signed-head-v1"

HASH_SIZE = 32
SIGNATURE_SIZE = 64

HEAD_FORMAT_VERSION = 1
HEAD_HASH_ALGORITHM = 1  # SHA-256

MAX_REGISTRY_SEQ = (1 << 63) - 1  # SQLite INTEGER is signed 64-bit

EMPTY_LEAF = hashlib.sha256(_DOMAIN_EMPTY).digest()


# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------

def _sha256(*chunks: bytes) -> bytes:
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
    return h.digest()


def compute_registry_key(origin: str, username: str) -> bytes:
    origin_b = origin.encode("utf-8")
    username_b = username.encode("utf-8")
    return _sha256(
        _DOMAIN_KEY,
        struct.pack(">H", len(origin_b)), origin_b,
        struct.pack(">H", len(username_b)), username_b,
    )


def compute_value_hash(raw_record: bytes) -> bytes:
    return _sha256(_DOMAIN_RECORD, raw_record)


def _leaf_hash(key_bytes: bytes, value_hash: bytes) -> bytes:
    return _sha256(_DOMAIN_LEAF, key_bytes, value_hash)


def _node_hash(level: int, left: bytes, right: bytes) -> bytes:
    return _sha256(_DOMAIN_NODE, struct.pack(">H", level), left, right)


# ---------------------------------------------------------------------------
# Default hashes — precomputed at module load
# ---------------------------------------------------------------------------

DEFAULT_HASHES: list[bytes] = [b""] * (TREE_DEPTH + 1)
DEFAULT_HASHES[TREE_DEPTH] = EMPTY_LEAF
for _lvl in range(TREE_DEPTH - 1, -1, -1):
    DEFAULT_HASHES[_lvl] = _node_hash(_lvl, DEFAULT_HASHES[_lvl + 1], DEFAULT_HASHES[_lvl + 1])

EMPTY_ROOT = DEFAULT_HASHES[0]


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
# Compressed Sparse Merkle Tree
# ---------------------------------------------------------------------------

class CSMT:
    """In-memory 256-bit Compressed Sparse Merkle Tree.

    Stores only non-default nodes.  Supports insert, update, delete,
    deterministic root computation, and compressed proof generation.
    """

    def __init__(self):
        self._nodes: dict[tuple[int, int], bytes] = {}
        self._leaves: dict[int, bytes] = {}
        self._value_hashes: dict[int, bytes] = {}

    @staticmethod
    def _key_to_int(key: bytes) -> int:
        if len(key) != HASH_SIZE:
            raise ValueError(f"Key must be {HASH_SIZE} bytes, got {len(key)}")
        return int.from_bytes(key, "big")

    @staticmethod
    def _key_to_bytes(key: int) -> bytes:
        return key.to_bytes(HASH_SIZE, "big")

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
            left = self._nodes.get((level + 1, left_prefix), DEFAULT_HASHES[level + 1])
            right = self._nodes.get((level + 1, right_prefix), DEFAULT_HASHES[level + 1])
            if left == DEFAULT_HASHES[level + 1] and right == DEFAULT_HASHES[level + 1]:
                self._nodes.pop((level, parent_prefix), None)
            else:
                self._nodes[(level, parent_prefix)] = _node_hash(level, left, right)
        return True

    def _set_leaf(self, k: int, key_bytes: bytes, value_hash: bytes) -> None:
        leaf_h = _leaf_hash(key_bytes, value_hash)
        self._leaves[k] = leaf_h
        self._value_hashes[k] = value_hash
        self._nodes[(TREE_DEPTH, k)] = leaf_h
        for level in range(TREE_DEPTH - 1, -1, -1):
            parent_prefix = k >> (TREE_DEPTH - level)
            left_prefix = parent_prefix << 1
            right_prefix = (parent_prefix << 1) | 1
            left = self._nodes.get((level + 1, left_prefix), DEFAULT_HASHES[level + 1])
            right = self._nodes.get((level + 1, right_prefix), DEFAULT_HASHES[level + 1])
            self._nodes[(level, parent_prefix)] = _node_hash(level, left, right)

    def root(self) -> bytes:
        return self._nodes.get((0, 0), DEFAULT_HASHES[0])

    def leaf_count(self) -> int:
        return len(self._leaves)

    def contains(self, key: bytes) -> bool:
        return self._key_to_int(key) in self._leaves

    def get_node(self, level: int, prefix: int) -> bytes:
        return self._nodes.get((level, prefix), DEFAULT_HASHES[level])

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
            sibling_h = self._nodes.get((level, sibling_prefix), DEFAULT_HASHES[level])
            if sibling_h != DEFAULT_HASHES[level]:
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
            sibling_h = self._nodes.get((level, sibling_prefix), DEFAULT_HASHES[level])
            if sibling_h != DEFAULT_HASHES[level]:
                _bitmap_set(bitmap, i)
                siblings.append(sibling_h)
        return _encode_proof(key, False, None, bitmap, siblings)


# ---------------------------------------------------------------------------
# Proof encoding / decoding
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
# Proof verification
# ---------------------------------------------------------------------------

def _reconstruct_root(key_bytes: bytes, start_hash: bytes,
                      bitmap: bytes, siblings: list[bytes]) -> bytes:
    k = int.from_bytes(key_bytes, "big")
    current = start_hash
    sib_idx = 0
    for i in range(TREE_DEPTH):
        level = TREE_DEPTH - i
        bit = (k >> (TREE_DEPTH - level)) & 1
        if _bitmap_get(bitmap, i):
            sibling = siblings[sib_idx]
            sib_idx += 1
        else:
            sibling = DEFAULT_HASHES[level]
        if bit == 0:
            current = _node_hash(level - 1, current, sibling)
        else:
            current = _node_hash(level - 1, sibling, current)
    return current


def verify_inclusion_proof(proof: bytes, expected_root: bytes) -> bool:
    try:
        key, value_hash, bitmap, siblings = decode_inclusion_proof(proof)
    except (ValueError, struct.error):
        return False
    leaf_h = _leaf_hash(key, value_hash)
    reconstructed = _reconstruct_root(key, leaf_h, bitmap, siblings)
    return reconstructed == expected_root


def verify_non_inclusion_proof(proof: bytes, expected_root: bytes) -> bool:
    try:
        key, bitmap, siblings = decode_non_inclusion_proof(proof)
    except (ValueError, struct.error):
        return False
    reconstructed = _reconstruct_root(key, EMPTY_LEAF, bitmap, siblings)
    return reconstructed == expected_root


# ---------------------------------------------------------------------------
# Subtree child verification
# ---------------------------------------------------------------------------

def verify_node_children(level: int, left_hash: bytes, right_hash: bytes,
                         expected_hash: bytes) -> bool:
    return _node_hash(level, left_hash, right_hash) == expected_hash


# ---------------------------------------------------------------------------
# Signed registry head (Phase 3, Section 8)
# ---------------------------------------------------------------------------

@dataclass
class SignedHead:
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
        return compute_head_hash(encode_head(self))


def encode_head_payload(head: SignedHead) -> bytes:
    origin_b = head.origin.encode("utf-8")
    return (
        _DOMAIN_HEAD_SIG
        + struct.pack(">B", head.format_version)
        + struct.pack(">B", head.hash_algorithm)
        + struct.pack(">H", len(origin_b)) + origin_b
        + struct.pack(">Q", head.registry_seq)
        + struct.pack(">q", head.snapshot_timestamp)
        + struct.pack(">Q", head.leaf_count)
        + head.merkle_root
        + head.previous_head_hash
    )


def encode_head(head: SignedHead) -> bytes:
    return encode_head_payload(head) + head.signature


def decode_head(data: bytes) -> SignedHead:
    min_len = (
        len(_DOMAIN_HEAD_SIG)
        + 1 + 1  # format_version, hash_algorithm
        + 2       # origin length
        + 8 + 8 + 8  # seq, timestamp, leaf_count
        + 32 + 32  # merkle_root, previous_head_hash
        + 64       # signature
    )
    if len(data) < min_len:
        raise ValueError(f"Head too short: {len(data)} < {min_len}")
    offset = 0
    domain = data[offset:offset + len(_DOMAIN_HEAD_SIG)]
    offset += len(_DOMAIN_HEAD_SIG)
    if domain != _DOMAIN_HEAD_SIG:
        raise ValueError("Invalid head domain prefix")
    format_version = data[offset]
    offset += 1
    hash_algorithm = data[offset]
    offset += 1
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
    origin: str,
    registry_seq: int,
    snapshot_timestamp: int,
    leaf_count: int,
    merkle_root: bytes,
    previous_head_hash: bytes,
    identity,
) -> SignedHead:
    head = SignedHead(
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


def compute_head_hash(encoded_head: bytes) -> bytes:
    return _sha256(_DOMAIN_HEAD_HASH, encoded_head)


ZERO_HASH = b"\x00" * HASH_SIZE


# ---------------------------------------------------------------------------
# Acceptance result
# ---------------------------------------------------------------------------

@dataclass
class AcceptResult:
    accepted: bool
    reason: str = ""
    head: SignedHead | None = None


# ---------------------------------------------------------------------------
# SQLite-backed UserRegistryStore (Phase 3, Section 10)
# ---------------------------------------------------------------------------

class UserRegistryStore:
    """SQLite sidecar for signed registry heads, records, nodes, and state."""

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
                origin              TEXT NOT NULL,
                registry_seq        INTEGER NOT NULL,
                snapshot_timestamp  INTEGER NOT NULL,
                leaf_count          INTEGER NOT NULL,
                merkle_root         BLOB NOT NULL,
                previous_head_hash  BLOB NOT NULL,
                signature           BLOB NOT NULL,
                encoded_head        BLOB NOT NULL,
                head_hash           BLOB NOT NULL,
                is_authoritative    INTEGER NOT NULL DEFAULT 0,
                accepted_at         INTEGER NOT NULL,
                PRIMARY KEY (origin, registry_seq)
            );

            CREATE UNIQUE INDEX IF NOT EXISTS registry_heads_origin_head_hash
                ON registry_heads(origin, head_hash);

            CREATE TABLE IF NOT EXISTS registry_records (
                origin          TEXT NOT NULL,
                registry_key    BLOB NOT NULL,
                username        TEXT NOT NULL,
                raw_record      BLOB NOT NULL,
                value_hash      BLOB NOT NULL,
                source_seq      INTEGER NOT NULL,
                PRIMARY KEY (origin, registry_key)
            );

            CREATE TABLE IF NOT EXISTS registry_nodes (
                origin          TEXT NOT NULL,
                registry_seq    INTEGER NOT NULL,
                level           INTEGER NOT NULL,
                prefix          BLOB NOT NULL,
                node_hash       BLOB NOT NULL,
                PRIMARY KEY (origin, registry_seq, level, prefix)
            );

            CREATE TABLE IF NOT EXISTS registry_state (
                origin                  TEXT PRIMARY KEY,
                highest_accepted_seq    INTEGER NOT NULL,
                current_head_hash       BLOB NOT NULL,
                current_merkle_root     BLOB NOT NULL,
                current_leaf_count      INTEGER NOT NULL,
                dirty_generation        INTEGER NOT NULL DEFAULT 0,
                snapshotted_generation  INTEGER NOT NULL DEFAULT 0
            );
        """)
        self._conn.commit()

    def get_state(self, origin: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT highest_accepted_seq, current_head_hash, current_merkle_root, "
                "current_leaf_count, dirty_generation, snapshotted_generation "
                "FROM registry_state WHERE origin=?",
                (origin,),
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

    def _ensure_state(self, origin: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO registry_state "
            "(origin, highest_accepted_seq, current_head_hash, current_merkle_root, "
            " current_leaf_count, dirty_generation, snapshotted_generation) "
            "VALUES (?, 0, ?, ?, 0, 0, 0)",
            (origin, ZERO_HASH, EMPTY_ROOT),
        )

    def get_head(self, origin: str, registry_seq: int = 0) -> SignedHead | None:
        with self._lock:
            if registry_seq == 0:
                state = self.get_state(origin)
                if state is None or state["highest_accepted_seq"] == 0:
                    return None
                registry_seq = state["highest_accepted_seq"]
            row = self._conn.execute(
                "SELECT encoded_head FROM registry_heads WHERE origin=? AND registry_seq=?",
                (origin, registry_seq),
            ).fetchone()
        if not row:
            return None
        return decode_head(bytes(row[0]))

    def list_heads(self, origin: str | None = None, offset: int = 0,
                   limit: int = 100) -> list[SignedHead]:
        with self._lock:
            if origin:
                rows = self._conn.execute(
                    "SELECT encoded_head FROM registry_heads WHERE origin=? "
                    "ORDER BY registry_seq DESC LIMIT ? OFFSET ?",
                    (origin, limit, offset),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT encoded_head FROM registry_heads "
                    "ORDER BY accepted_at DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
        return [decode_head(bytes(r[0])) for r in rows]

    def get_record(self, origin: str, key: bytes) -> bytes | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT raw_record FROM registry_records WHERE origin=? AND registry_key=?",
                (origin, key),
            ).fetchone()
        return bytes(row[0]) if row else None

    def get_all_records(self, origin: str) -> list[tuple[bytes, bytes, bytes]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT registry_key, raw_record, value_hash FROM registry_records WHERE origin=?",
                (origin,),
            ).fetchall()
        return [(bytes(r[0]), bytes(r[1]), bytes(r[2])) for r in rows]

    def get_node(self, origin: str, registry_seq: int, level: int,
                 prefix: bytes) -> bytes | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT node_hash FROM registry_nodes WHERE origin=? AND registry_seq=? "
                "AND level=? AND prefix=?",
                (origin, registry_seq, level, prefix),
            ).fetchone()
        return bytes(row[0]) if row else None

    def get_all_nodes(self, origin: str, registry_seq: int) -> list[tuple[int, bytes, bytes]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT level, prefix, node_hash FROM registry_nodes "
                "WHERE origin=? AND registry_seq=?",
                (origin, registry_seq),
            ).fetchall()
        return [(r[0], bytes(r[1]), bytes(r[2])) for r in rows]

    def mark_dirty(self, origin: str) -> None:
        with self._lock:
            self._ensure_state(origin)
            self._conn.execute(
                "UPDATE registry_state SET dirty_generation = dirty_generation + 1 WHERE origin=?",
                (origin,),
            )
            self._conn.commit()

    def store_authoritative_head(
        self,
        origin: str,
        head: SignedHead,
        records: list[tuple[bytes, str, bytes, bytes]],
        nodes: list[tuple[int, bytes, bytes]],
    ) -> None:
        if head.registry_seq > MAX_REGISTRY_SEQ:
            raise ValueError(f"registry_seq {head.registry_seq} exceeds SQLite signed 64-bit max")
        encoded = encode_head(head)
        h_hash = compute_head_hash(encoded)
        now = int(time.time())
        with self._lock:
            self._ensure_state(origin)
            self._conn.commit()
            with self._conn:
                self._conn.execute(
                    "INSERT OR REPLACE INTO registry_heads "
                    "(origin, registry_seq, snapshot_timestamp, leaf_count, "
                    " merkle_root, previous_head_hash, signature, encoded_head, "
                    " head_hash, is_authoritative, accepted_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)",
                    (origin, head.registry_seq, head.snapshot_timestamp,
                     head.leaf_count, head.merkle_root, head.previous_head_hash,
                     head.signature, encoded, h_hash, now),
                )
                self._store_records_and_nodes(origin, head.registry_seq, records, nodes)
                self._gc_old_nodes(origin, head.registry_seq)
                self._conn.execute(
                    "UPDATE registry_state SET "
                    " highest_accepted_seq=?, current_head_hash=?, "
                    " current_merkle_root=?, current_leaf_count=?, "
                    " snapshotted_generation=dirty_generation "
                    " WHERE origin=?",
                    (head.registry_seq, h_hash, head.merkle_root,
                     head.leaf_count, origin),
                )

    def accept_remote_head(
        self,
        origin: str,
        head: SignedHead,
        origin_pubkey: bytes,
        records: list[tuple[bytes, str, bytes, bytes]],
        nodes: list[tuple[int, bytes, bytes]],
    ) -> AcceptResult:
        if head.registry_seq > MAX_REGISTRY_SEQ:
            return AcceptResult(False, "registry_seq exceeds signed 64-bit max")
        if not verify_head(head, origin_pubkey):
            return AcceptResult(False, "signature verification failed")
        if head.origin != origin:
            return AcceptResult(False, "origin mismatch between requested and signed head")
        encoded = encode_head(head)
        h_hash = compute_head_hash(encoded)
        now = int(time.time())
        with self._lock:
            self._ensure_state(origin)
            self._conn.commit()
            state = self.get_state(origin)
            highest = state["highest_accepted_seq"]
            if head.registry_seq < highest:
                return AcceptResult(False, f"rollback: seq {head.registry_seq} < highest {highest}")
            if head.registry_seq == highest and highest > 0:
                existing_hash = self._conn.execute(
                    "SELECT head_hash FROM registry_heads WHERE origin=? AND registry_seq=?",
                    (origin, head.registry_seq),
                ).fetchone()
                if existing_hash and bytes(existing_hash[0]) != h_hash:
                    return AcceptResult(False, "equivocation: same seq with different head hash")
                if existing_hash and bytes(existing_hash[0]) == h_hash:
                    return AcceptResult(True, "idempotent", head)
            with self._conn:
                self._conn.execute(
                    "INSERT OR REPLACE INTO registry_heads "
                    "(origin, registry_seq, snapshot_timestamp, leaf_count, "
                    " merkle_root, previous_head_hash, signature, encoded_head, "
                    " head_hash, is_authoritative, accepted_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
                    (origin, head.registry_seq, head.snapshot_timestamp,
                     head.leaf_count, head.merkle_root, head.previous_head_hash,
                     head.signature, encoded, h_hash, now),
                )
                self._store_records_and_nodes(origin, head.registry_seq, records, nodes)
                self._gc_old_nodes(origin, head.registry_seq)
                self._conn.execute(
                    "UPDATE registry_state SET "
                    " highest_accepted_seq=?, current_head_hash=?, "
                    " current_merkle_root=?, current_leaf_count=? "
                    " WHERE origin=?",
                    (head.registry_seq, h_hash, head.merkle_root,
                     head.leaf_count, origin),
                )
        return AcceptResult(True, "accepted", head)

    def _store_records_and_nodes(
        self,
        origin: str,
        registry_seq: int,
        records: list[tuple[bytes, str, bytes, bytes]],
        nodes: list[tuple[int, bytes, bytes]],
    ) -> None:
        self._conn.execute(
            "DELETE FROM registry_records WHERE origin=? AND source_seq < ?",
            (origin, registry_seq - 1),
        )
        for key, username, raw_record, value_hash in records:
            self._conn.execute(
                "INSERT OR REPLACE INTO registry_records "
                "(origin, registry_key, username, raw_record, value_hash, source_seq) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (origin, key, username, raw_record, value_hash, registry_seq),
            )
        for level, prefix, node_hash in nodes:
            self._conn.execute(
                "INSERT OR REPLACE INTO registry_nodes "
                "(origin, registry_seq, level, prefix, node_hash) "
                "VALUES (?, ?, ?, ?, ?)",
                (origin, registry_seq, level, prefix, node_hash),
            )

    def _gc_old_nodes(self, origin: str, current_seq: int) -> None:
        keep_threshold = current_seq - 1
        self._conn.execute(
            "DELETE FROM registry_nodes WHERE origin=? AND registry_seq < ?",
            (origin, keep_threshold),
        )

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# ---------------------------------------------------------------------------
# RegistryService — ties Ume + CSMT + Store together (Phase 3, Section 9)
# ---------------------------------------------------------------------------

class RegistryService:
    """Manages authoritative snapshot construction and remote head acceptance.

    Call ``mark_dirty()`` after local UME mutations.  Call ``build_snapshot()``
    to lazily produce a signed head.  Call ``accept_remote_snapshot()`` to
    ingest a verified remote head with records and nodes.
    """

    def __init__(self, store: UserRegistryStore, ume, identity, origin: str):
        self._store = store
        self._ume = ume
        self._identity = identity
        self._origin = origin
        self._snapshot_lock = threading.Lock()

    def mark_dirty(self) -> None:
        self._store.mark_dirty(self._origin)

    def get_current_head(self) -> SignedHead | None:
        return self._store.get_head(self._origin)

    def build_snapshot(self) -> SignedHead:
        with self._snapshot_lock:
            state = self._store.get_state(self._origin)
            if state is None:
                self._store.mark_dirty(self._origin)
                state = self._store.get_state(self._origin)

            if state["dirty_generation"] == state["snapshotted_generation"]:
                head = self._store.get_head(self._origin)
                if head is not None:
                    return head

            raw_records = self._ume.snapshot_raw_records()
            tree = CSMT()
            records_for_store: list[tuple[bytes, str, bytes, bytes]] = []
            from engine.ume import User, RECORD_SIZE
            for raw in raw_records:
                if len(raw) != RECORD_SIZE:
                    continue
                user = User.decode(raw)
                if user.record_origin != self._origin:
                    continue
                if not user.username:
                    continue
                key = compute_registry_key(self._origin, user.username)
                vh = compute_value_hash(raw)
                if tree.contains(key):
                    tree.upsert(key, vh)
                else:
                    tree.insert(key, vh)
                records_for_store.append((key, user.username, raw, vh))

            root = tree.root()
            leaf_count = tree.leaf_count()

            if state is not None and state["snapshotted_generation"] > 0:
                if root == state["current_merkle_root"] and leaf_count == state["current_leaf_count"]:
                    self._store.mark_dirty(self._origin)  # consume dirty
                    state2 = self._store.get_state(self._origin)
                    if state2["dirty_generation"] == state2["snapshotted_generation"]:
                        pass
                    existing = self._store.get_head(self._origin)
                    if existing is not None:
                        return existing

            prev_head = self._store.get_head(self._origin)
            if prev_head is not None:
                prev_hash = prev_head.head_hash
                new_seq = prev_head.registry_seq + 1
            else:
                prev_hash = ZERO_HASH
                new_seq = 1

            now = int(time.time())
            head = sign_head(
                origin=self._origin,
                registry_seq=new_seq,
                snapshot_timestamp=now,
                leaf_count=leaf_count,
                merkle_root=root,
                previous_head_hash=prev_hash,
                identity=self._identity,
            )

            nodes_for_store: list[tuple[int, bytes, bytes]] = []
            for (level, prefix), node_hash in tree._nodes.items():
                prefix_bytes = prefix.to_bytes((level + 7) // 8 or 1, "big")
                nodes_for_store.append((level, prefix_bytes, node_hash))

            self._store.store_authoritative_head(
                origin=self._origin,
                head=head,
                records=records_for_store,
                nodes=nodes_for_store,
            )
            return head

    def accept_remote_snapshot(
        self,
        origin: str,
        head: SignedHead,
        origin_pubkey: bytes,
        records: list[tuple[bytes, str, bytes, bytes]],
        nodes: list[tuple[int, bytes, bytes]],
    ) -> AcceptResult:
        return self._store.accept_remote_head(origin, head, origin_pubkey, records, nodes)
