"""User registry: user-specific Merkle registry built on generic primitives.

This module provides the user-registry-specific bindings of the generic
merkle_registry primitives, with registry_type="users". It preserves the
backward-compatible API surface that the rest of the codebase imports.

Per PEERED_MODERATION plan §7.2, reusable Merkle primitives are extracted into
core.merkle_registry. This module keeps user-specific record validation and
UME normalization, and delegates all crypto/tree/proof/head/store operations
to the generic module.
"""

import time
import threading

from core.merkle_registry import (
    TREE_DEPTH,
    HASH_SIZE,
    SIGNATURE_SIZE,
    HEAD_FORMAT_VERSION,
    HEAD_HASH_ALGORITHM,
    MAX_REGISTRY_SEQ,
    ZERO_HASH,
    REGISTRY_TYPE_USERS,
    _sha256,
    _domain_empty,
    _domain_key,
    _domain_record,
    _domain_leaf,
    _domain_node,
    _domain_head_sig,
    _domain_head_hash,
    get_default_hashes,
    get_empty_leaf,
    get_empty_root,
    compute_registry_key as _gen_compute_registry_key,
    compute_value_hash as _gen_compute_value_hash,
    _leaf_hash as _gen_leaf_hash,
    _node_hash as _gen_node_hash,
    CSMT as _GenCSMT,
    _encode_proof,
    _decode_proof,
    decode_inclusion_proof,
    decode_non_inclusion_proof,
    _reconstruct_root,
    verify_inclusion_proof as _gen_verify_inclusion_proof,
    verify_non_inclusion_proof as _gen_verify_non_inclusion_proof,
    verify_node_children as _gen_verify_node_children,
    SignedHead,
    encode_head_payload,
    encode_head,
    decode_head as _gen_decode_head,
    sign_head as _gen_sign_head,
    verify_head as _gen_verify_head,
    compute_head_hash as _gen_compute_head_hash,
    AcceptResult,
    MerkleRegistryStore,
)

# ---------------------------------------------------------------------------
# Registry type binding
# ---------------------------------------------------------------------------

_REGISTRY_TYPE = REGISTRY_TYPE_USERS  # "users"

# ---------------------------------------------------------------------------
# Domain constants (backward-compatible exports)
# ---------------------------------------------------------------------------

_DOMAIN_EMPTY = _domain_empty(_REGISTRY_TYPE)
_DOMAIN_KEY = _domain_key(_REGISTRY_TYPE)
_DOMAIN_RECORD = _domain_record(_REGISTRY_TYPE)
_DOMAIN_LEAF = _domain_leaf(_REGISTRY_TYPE)
_DOMAIN_NODE = _domain_node(_REGISTRY_TYPE)
_DOMAIN_HEAD_SIG = _domain_head_sig(_REGISTRY_TYPE)
_DOMAIN_HEAD_HASH = _domain_head_hash(_REGISTRY_TYPE)

# ---------------------------------------------------------------------------
# Default hashes (bound to users)
# ---------------------------------------------------------------------------

DEFAULT_HASHES = get_default_hashes(_REGISTRY_TYPE)
EMPTY_LEAF = get_empty_leaf(_REGISTRY_TYPE)
EMPTY_ROOT = get_empty_root(_REGISTRY_TYPE)

# ---------------------------------------------------------------------------
# Hash helpers (bound to users — backward-compatible signatures)
# ---------------------------------------------------------------------------

def compute_registry_key(origin: str, username: str) -> bytes:
    return _gen_compute_registry_key(_REGISTRY_TYPE, origin, username)


def compute_value_hash(raw_record: bytes) -> bytes:
    return _gen_compute_value_hash(_REGISTRY_TYPE, raw_record)


def _leaf_hash(key_bytes: bytes, value_hash: bytes) -> bytes:
    return _gen_leaf_hash(_REGISTRY_TYPE, key_bytes, value_hash)


def _node_hash(level: int, left: bytes, right: bytes) -> bytes:
    return _gen_node_hash(_REGISTRY_TYPE, level, left, right)


# ---------------------------------------------------------------------------
# CSMT (bound to users)
# ---------------------------------------------------------------------------

class CSMT(_GenCSMT):
    """User-registry CSMT. Binds registry_type='users'."""

    def __init__(self):
        super().__init__(_REGISTRY_TYPE)


# ---------------------------------------------------------------------------
# Proof verification (bound to users — backward-compatible signatures)
# ---------------------------------------------------------------------------

def verify_inclusion_proof(proof: bytes, expected_root: bytes) -> bool:
    return _gen_verify_inclusion_proof(_REGISTRY_TYPE, proof, expected_root)


def verify_non_inclusion_proof(proof: bytes, expected_root: bytes) -> bool:
    return _gen_verify_non_inclusion_proof(_REGISTRY_TYPE, proof, expected_root)


def verify_node_children(level: int, left_hash: bytes, right_hash: bytes,
                         expected_hash: bytes) -> bool:
    return _gen_verify_node_children(_REGISTRY_TYPE, level, left_hash, right_hash, expected_hash)


# ---------------------------------------------------------------------------
# Signed head helpers (bound to users — backward-compatible signatures)
# ---------------------------------------------------------------------------

def sign_head(
    origin: str,
    registry_seq: int,
    snapshot_timestamp: int,
    leaf_count: int,
    merkle_root: bytes,
    previous_head_hash: bytes,
    identity,
) -> SignedHead:
    return _gen_sign_head(
        registry_type=_REGISTRY_TYPE,
        origin=origin,
        registry_seq=registry_seq,
        snapshot_timestamp=snapshot_timestamp,
        leaf_count=leaf_count,
        merkle_root=merkle_root,
        previous_head_hash=previous_head_hash,
        identity=identity,
    )


def verify_head(head: SignedHead, origin_pubkey: bytes) -> bool:
    return _gen_verify_head(head, origin_pubkey)


def decode_head(data: bytes) -> SignedHead:
    return _gen_decode_head(data, expected_registry_type=_REGISTRY_TYPE)


def compute_head_hash(encoded_head: bytes) -> bytes:
    return _gen_compute_head_hash(_REGISTRY_TYPE, encoded_head)


# ---------------------------------------------------------------------------
# UserRegistryStore — thin wrapper over MerkleRegistryStore
# ---------------------------------------------------------------------------

class UserRegistryStore:
    """SQLite sidecar for signed user registry heads, records, nodes, state.

    Delegates to MerkleRegistryStore with registry_type='users'.
    """

    def __init__(self, db_path: str):
        self._store = MerkleRegistryStore(db_path)
        self._rt = _REGISTRY_TYPE

    def get_state(self, origin: str) -> dict | None:
        return self._store.get_state(self._rt, origin)

    def get_head(self, origin: str, registry_seq: int = 0) -> SignedHead | None:
        return self._store.get_head(self._rt, origin, registry_seq)

    def list_heads(self, origin: str | None = None, offset: int = 0,
                   limit: int = 100) -> list[SignedHead]:
        return self._store.list_heads(self._rt, origin, offset, limit)

    def get_record(self, origin: str, key: bytes) -> bytes | None:
        return self._store.get_record(self._rt, origin, key)

    def get_all_records(self, origin: str) -> list[tuple[bytes, bytes, bytes]]:
        return self._store.get_all_records(self._rt, origin)

    def get_node(self, origin: str, registry_seq: int, level: int,
                 prefix: bytes) -> bytes | None:
        return self._store.get_node(self._rt, origin, registry_seq, level, prefix)

    def get_all_nodes(self, origin: str, registry_seq: int) -> list[tuple[int, bytes, bytes]]:
        return self._store.get_all_nodes(self._rt, origin, registry_seq)

    def mark_dirty(self, origin: str) -> None:
        self._store.mark_dirty(self._rt, origin)

    def store_authoritative_head(
        self,
        origin: str,
        head: SignedHead,
        records: list[tuple[bytes, str, bytes, bytes]],
        nodes: list[tuple[int, bytes, bytes]],
    ) -> None:
        self._store.store_authoritative_head(self._rt, origin, head, records, nodes)

    def accept_remote_head(
        self,
        origin: str,
        head: SignedHead,
        origin_pubkey: bytes,
        records: list[tuple[bytes, str, bytes, bytes]],
        nodes: list[tuple[int, bytes, bytes]],
    ) -> AcceptResult:
        return self._store.accept_remote_head(self._rt, origin, head, origin_pubkey, records, nodes)

    def close(self) -> None:
        self._store.close()


# ---------------------------------------------------------------------------
# RegistryService — ties Ume + CSMT + Store together
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
