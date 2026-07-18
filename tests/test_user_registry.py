"""Tests for Merkle primitives (Phase 2), signed heads, persistence,
and snapshot construction (Phase 3).

Phase 2: domain-separated hashes, default hashes, CSMT insert/update/delete,
deterministic root, compressed inclusion/non-inclusion proofs, strict proof
parser, subtree verification, and randomized property tests.

Phase 3: signed-head encoding/signing/verification, SQLite-backed
UserRegistryStore, rollback/equivocation enforcement, dirty-generation
snapshots, Ume snapshot_raw_records, export timestamps, and upsert
creation_time correction.
"""

import os
import random
import struct
import time

import pytest

from core.user_registry import (
    TREE_DEPTH,
    HASH_SIZE,
    EMPTY_LEAF,
    EMPTY_ROOT,
    DEFAULT_HASHES,
    compute_registry_key,
    compute_value_hash,
    _leaf_hash,
    _node_hash,
    CSMT,
    decode_inclusion_proof,
    decode_non_inclusion_proof,
    verify_inclusion_proof,
    verify_non_inclusion_proof,
    verify_node_children,
    _sha256,
    _DOMAIN_KEY,
    _DOMAIN_RECORD,
    _DOMAIN_LEAF,
    _DOMAIN_NODE,
    _DOMAIN_EMPTY,
    SignedHead,
    encode_head,
    encode_head_payload,
    decode_head,
    sign_head,
    verify_head,
    compute_head_hash,
    ZERO_HASH,
    HEAD_FORMAT_VERSION,
    HEAD_HASH_ALGORITHM,
    AcceptResult,
    UserRegistryStore,
    RegistryService,
)
from core.crypto import Identity
from engine.ume import Ume, User, RECORD_SIZE


# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------


class TestHashHelpers:

    def test_empty_leaf_is_domain_separated(self):
        import hashlib
        assert EMPTY_LEAF == hashlib.sha256(_DOMAIN_EMPTY).digest()

    def test_registry_key_deterministic(self):
        k1 = compute_registry_key("origin1", "alice")
        k2 = compute_registry_key("origin1", "alice")
        assert k1 == k2
        assert len(k1) == HASH_SIZE

    def test_registry_key_differs_by_origin(self):
        k1 = compute_registry_key("origin1", "alice")
        k2 = compute_registry_key("origin2", "alice")
        assert k1 != k2

    def test_registry_key_differs_by_username(self):
        k1 = compute_registry_key("origin1", "alice")
        k2 = compute_registry_key("origin1", "bob")
        assert k1 != k2

    def test_value_hash_deterministic(self):
        record = b"\x00" * 1079
        h1 = compute_value_hash(record)
        h2 = compute_value_hash(record)
        assert h1 == h2
        assert len(h1) == HASH_SIZE

    def test_value_hash_differs_on_one_byte(self):
        r1 = b"\x00" * 1079
        r2 = b"\x00" * 1078 + b"\x01"
        assert compute_value_hash(r1) != compute_value_hash(r2)

    def test_leaf_hash_includes_key_and_value(self):
        key = b"\x11" * 32
        vh = b"\x22" * 32
        lh = _leaf_hash(key, vh)
        import hashlib
        expected = hashlib.sha256(_DOMAIN_LEAF + key + vh).digest()
        assert lh == expected

    def test_node_hash_includes_level(self):
        left = b"\x00" * 32
        right = b"\x01" * 32
        h0 = _node_hash(0, left, right)
        h1 = _node_hash(1, left, right)
        assert h0 != h1

    def test_node_hash_order_matters(self):
        left = b"\x00" * 32
        right = b"\x01" * 32
        assert _node_hash(5, left, right) != _node_hash(5, right, left)


# ---------------------------------------------------------------------------
# Default hashes
# ---------------------------------------------------------------------------


class TestDefaultHashes:

    def test_default_at_leaf_level_is_empty_leaf(self):
        assert DEFAULT_HASHES[TREE_DEPTH] == EMPTY_LEAF

    def test_default_parent_is_hash_of_two_children(self):
        for lvl in range(TREE_DEPTH - 1, -1, -1):
            expected = _node_hash(lvl, DEFAULT_HASHES[lvl + 1], DEFAULT_HASHES[lvl + 1])
            assert DEFAULT_HASHES[lvl] == expected

    def test_empty_root_is_default_0(self):
        assert EMPTY_ROOT == DEFAULT_HASHES[0]

    def test_all_defaults_are_32_bytes(self):
        for h in DEFAULT_HASHES:
            assert len(h) == HASH_SIZE

    def test_consecutive_defaults_differ(self):
        for lvl in range(TREE_DEPTH):
            assert DEFAULT_HASHES[lvl] != DEFAULT_HASHES[lvl + 1]


# ---------------------------------------------------------------------------
# CSMT — insert / update / delete / root
# ---------------------------------------------------------------------------


def _random_key(seed: int) -> bytes:
    rng = random.Random(seed)
    return rng.randbytes(32)


def _random_value(seed: int) -> bytes:
    rng = random.Random(seed * 31 + 1)
    return rng.randbytes(32)


class TestCSMTBasics:

    def test_empty_tree_root_is_empty_root(self):
        t = CSMT()
        assert t.root() == EMPTY_ROOT

    def test_empty_tree_leaf_count_zero(self):
        t = CSMT()
        assert t.leaf_count() == 0

    def test_insert_one_key_changes_root(self):
        t = CSMT()
        key = _random_key(1)
        vh = _random_value(1)
        t.insert(key, vh)
        assert t.root() != EMPTY_ROOT
        assert t.leaf_count() == 1

    def test_contains(self):
        t = CSMT()
        key = _random_key(42)
        vh = _random_value(42)
        t.insert(key, vh)
        assert t.contains(key)
        assert not t.contains(_random_key(99))

    def test_duplicate_insert_raises(self):
        t = CSMT()
        key = _random_key(1)
        t.insert(key, _random_value(1))
        with pytest.raises(ValueError, match="Duplicate key"):
            t.insert(key, _random_value(2))

    def test_update_existing_key(self):
        t = CSMT()
        key = _random_key(1)
        t.insert(key, _random_value(1))
        root_before = t.root()
        t.update(key, _random_value(2))
        root_after = t.root()
        assert root_before != root_after

    def test_update_missing_key_raises(self):
        t = CSMT()
        with pytest.raises(KeyError):
            t.update(_random_key(1), _random_value(1))

    def test_upsert_inserts_new(self):
        t = CSMT()
        key = _random_key(1)
        t.upsert(key, _random_value(1))
        assert t.contains(key)

    def test_upsert_updates_existing(self):
        t = CSMT()
        key = _random_key(1)
        t.upsert(key, _random_value(1))
        r1 = t.root()
        t.upsert(key, _random_value(2))
        r2 = t.root()
        assert r1 != r2

    def test_delete_existing_key(self):
        t = CSMT()
        key = _random_key(1)
        t.insert(key, _random_value(1))
        assert t.delete(key)
        assert not t.contains(key)
        assert t.leaf_count() == 0
        assert t.root() == EMPTY_ROOT

    def test_delete_missing_key_returns_false(self):
        t = CSMT()
        assert not t.delete(_random_key(1))

    def test_delete_restores_root(self):
        t = CSMT()
        k1, k2 = _random_key(1), _random_key(2)
        v1, v2 = _random_value(1), _random_value(2)
        t.insert(k1, v1)
        t.insert(k2, v2)
        root_two = t.root()
        t.delete(k2)
        root_one = t.root()
        t.insert(k2, v2)
        assert t.root() == root_two
        t.delete(k2)
        t.delete(k1)
        assert t.root() == EMPTY_ROOT


# ---------------------------------------------------------------------------
# Determinism — insertion order does not change the root
# ---------------------------------------------------------------------------


class TestDeterminism:

    def test_insertion_order_does_not_change_root(self):
        keys = [_random_key(i) for i in range(20)]
        vals = [_random_value(i) for i in range(20)]

        t1 = CSMT()
        for k, v in zip(keys, vals):
            t1.insert(k, v)

        t2 = CSMT()
        order = list(range(20))
        random.Random(12345).shuffle(order)
        for i in order:
            t2.insert(keys[i], vals[i])

        assert t1.root() == t2.root()
        assert t1.leaf_count() == t2.leaf_count()

    def test_one_changed_byte_changes_root(self):
        t = CSMT()
        key = _random_key(1)
        v1 = _random_value(1)
        v2 = bytes(v1[:-1]) + bytes([v1[-1] ^ 0x01])
        t.insert(key, v1)
        r1 = t.root()
        t.delete(key)
        t.insert(key, v2)
        r2 = t.root()
        assert r1 != r2


# ---------------------------------------------------------------------------
# Insert / update / delete affect only the expected path
# ---------------------------------------------------------------------------


class TestPathIsolation:

    def test_delete_then_reinsert_restores_all_nodes(self):
        t = CSMT()
        for i in range(10):
            t.insert(_random_key(i), _random_value(i))
        snapshot = dict(t._nodes)
        extra_key = _random_key(999)
        extra_val = _random_value(999)
        t.insert(extra_key, extra_val)
        t.delete(extra_key)
        assert t._nodes == snapshot

    def test_updating_one_key_preserves_another_keys_verification(self):
        t = CSMT()
        k1, k2 = _random_key(1), _random_key(2)
        t.insert(k1, _random_value(1))
        t.insert(k2, _random_value(2))
        root = t.root()
        proof1 = t.inclusion_proof(k1)
        assert verify_inclusion_proof(proof1, root)
        t.update(k2, _random_value(22))
        root2 = t.root()
        proof1_after = t.inclusion_proof(k1)
        assert verify_inclusion_proof(proof1, root)
        assert verify_inclusion_proof(proof1_after, root2)


# ---------------------------------------------------------------------------
# Inclusion proofs
# ---------------------------------------------------------------------------


class TestInclusionProof:

    def test_valid_inclusion_proof_verifies(self):
        t = CSMT()
        key = _random_key(5)
        t.insert(key, _random_value(5))
        proof = t.inclusion_proof(key)
        assert verify_inclusion_proof(proof, t.root())

    def test_inclusion_proof_multiple_keys(self):
        t = CSMT()
        for i in range(20):
            t.insert(_random_key(i), _random_value(i))
        root = t.root()
        for i in range(20):
            key = _random_key(i)
            proof = t.inclusion_proof(key)
            assert verify_inclusion_proof(proof, root), f"Proof failed for key {i}"

    def test_inclusion_proof_missing_key_raises(self):
        t = CSMT()
        with pytest.raises(KeyError):
            t.inclusion_proof(_random_key(1))

    def test_compressed_equals_full_reconstruction(self):
        t = CSMT()
        for i in range(10):
            t.insert(_random_key(i), _random_value(i))
        key = _random_key(5)
        proof = t.inclusion_proof(key)
        k_bytes, vh, bitmap, siblings = decode_inclusion_proof(proof)

        full_siblings = []
        sib_idx = 0
        for i in range(TREE_DEPTH):
            if (bitmap[i // 8] >> (7 - (i % 8))) & 1:
                full_siblings.append(siblings[sib_idx])
                sib_idx += 1
            else:
                full_siblings.append(DEFAULT_HASHES[TREE_DEPTH - i])

        k_int = int.from_bytes(k_bytes, "big")
        current = _leaf_hash(k_bytes, vh)
        for i in range(TREE_DEPTH):
            level = TREE_DEPTH - i
            bit = (k_int >> (TREE_DEPTH - level)) & 1
            sib = full_siblings[i]
            if bit == 0:
                current = _node_hash(level - 1, current, sib)
            else:
                current = _node_hash(level - 1, sib, current)

        assert current == t.root()


# ---------------------------------------------------------------------------
# Non-inclusion proofs
# ---------------------------------------------------------------------------


class TestNonInclusionProof:

    def test_valid_non_inclusion_proof_verifies(self):
        t = CSMT()
        t.insert(_random_key(1), _random_value(1))
        absent = _random_key(999)
        proof = t.non_inclusion_proof(absent)
        assert verify_non_inclusion_proof(proof, t.root())

    def test_non_inclusion_proof_empty_tree(self):
        t = CSMT()
        proof = t.non_inclusion_proof(_random_key(1))
        assert verify_non_inclusion_proof(proof, EMPTY_ROOT)

    def test_non_inclusion_proof_multiple_absent_keys(self):
        t = CSMT()
        for i in range(10):
            t.insert(_random_key(i), _random_value(i))
        root = t.root()
        for i in range(100, 110):
            proof = t.non_inclusion_proof(_random_key(i))
            assert verify_non_inclusion_proof(proof, root), f"Failed for absent key {i}"

    def test_non_inclusion_proof_for_present_key_raises(self):
        t = CSMT()
        key = _random_key(1)
        t.insert(key, _random_value(1))
        with pytest.raises(ValueError, match="Key is in tree"):
            t.non_inclusion_proof(key)


# ---------------------------------------------------------------------------
# Proof tampering — all modifications must fail verification
# ---------------------------------------------------------------------------


class TestProofTampering:

    def test_modified_value_hash_fails(self):
        t = CSMT()
        key = _random_key(5)
        t.insert(key, _random_value(5))
        proof = bytearray(t.inclusion_proof(key))
        proof[32] ^= 0x01  # flip first byte of value_hash
        assert not verify_inclusion_proof(bytes(proof), t.root())

    def test_modified_key_fails(self):
        t = CSMT()
        key = _random_key(5)
        t.insert(key, _random_value(5))
        proof = bytearray(t.inclusion_proof(key))
        proof[0] ^= 0x01  # flip first byte of key
        assert not verify_inclusion_proof(bytes(proof), t.root())

    def test_modified_sibling_fails(self):
        t = CSMT()
        for i in range(10):
            t.insert(_random_key(i), _random_value(i))
        key = _random_key(5)
        proof = bytearray(t.inclusion_proof(key))
        _, _, _, siblings = decode_inclusion_proof(bytes(proof))
        if len(siblings) > 0:
            offset = 32 + 32 + 32 + 2  # key + vh + bitmap + count
            proof[offset] ^= 0x01
            assert not verify_inclusion_proof(bytes(proof), t.root())

    def test_modified_bitmap_fails(self):
        t = CSMT()
        for i in range(10):
            t.insert(_random_key(i), _random_value(i))
        key = _random_key(5)
        proof = bytearray(t.inclusion_proof(key))
        proof[64] ^= 0x80  # flip MSB of bitmap
        assert not verify_inclusion_proof(bytes(proof), t.root())

    def test_wrong_root_fails(self):
        t = CSMT()
        key = _random_key(5)
        t.insert(key, _random_value(5))
        proof = t.inclusion_proof(key)
        wrong_root = bytes(b ^ 0x01 for b in t.root())
        assert not verify_inclusion_proof(proof, wrong_root)

    def test_non_inclusion_wrong_root_fails(self):
        t = CSMT()
        t.insert(_random_key(1), _random_value(1))
        proof = t.non_inclusion_proof(_random_key(999))
        wrong_root = bytes(b ^ 0x01 for b in t.root())
        assert not verify_non_inclusion_proof(proof, wrong_root)

    def test_non_inclusion_key_is_caller_responsibility(self):
        """A non-inclusion proof verifies for any empty position.  Modifying
        the key may produce a valid proof for a *different* empty position.
        The caller must check that the key in the proof matches the requested
        key — the proof itself only proves 'this position is default'."""
        t = CSMT()
        t.insert(_random_key(1), _random_value(1))
        absent = _random_key(999)
        proof = t.non_inclusion_proof(absent)
        assert verify_non_inclusion_proof(proof, t.root())
        key, _, _ = decode_non_inclusion_proof(proof)
        assert key == absent


# ---------------------------------------------------------------------------
# Proof parsing — truncated and trailing data
# ---------------------------------------------------------------------------


class TestProofParsing:

    def test_truncated_inclusion_proof(self):
        t = CSMT()
        key = _random_key(1)
        t.insert(key, _random_value(1))
        proof = t.inclusion_proof(key)
        truncated = proof[:len(proof) - 1]
        assert not verify_inclusion_proof(truncated, t.root())

    def test_trailing_inclusion_proof(self):
        t = CSMT()
        key = _random_key(1)
        t.insert(key, _random_value(1))
        proof = t.inclusion_proof(key)
        padded = proof + b"\x00"
        assert not verify_inclusion_proof(padded, t.root())

    def test_truncated_non_inclusion_proof(self):
        t = CSMT()
        t.insert(_random_key(1), _random_value(1))
        proof = t.non_inclusion_proof(_random_key(999))
        truncated = proof[:len(proof) - 1]
        assert not verify_non_inclusion_proof(truncated, t.root())

    def test_trailing_non_inclusion_proof(self):
        t = CSMT()
        t.insert(_random_key(1), _random_value(1))
        proof = t.non_inclusion_proof(_random_key(999))
        padded = proof + b"\x00"
        assert not verify_non_inclusion_proof(padded, t.root())

    def test_empty_proof_rejected(self):
        assert not verify_inclusion_proof(b"", EMPTY_ROOT)
        assert not verify_non_inclusion_proof(b"", EMPTY_ROOT)

    def test_sibling_count_exceeding_depth_rejected(self):
        t = CSMT()
        key = _random_key(1)
        t.insert(key, _random_value(1))
        proof = bytearray(t.inclusion_proof(key))
        offset = 32 + 32 + 32
        count = struct.unpack(">H", bytes(proof[offset:offset + 2]))[0]
        if count < TREE_DEPTH:
            proof[offset] = 0x01
            proof[offset + 1] = 0x00  # set count to 256
            assert not verify_inclusion_proof(bytes(proof), t.root())

    def test_bitmap_popcount_mismatch_rejected(self):
        t = CSMT()
        key = _random_key(1)
        t.insert(key, _random_value(1))
        proof = bytearray(t.inclusion_proof(key))
        proof[64] ^= 0x80  # flip a bitmap bit without changing sibling count
        assert not verify_inclusion_proof(bytes(proof), t.root())


# ---------------------------------------------------------------------------
# Subtree child verification
# ---------------------------------------------------------------------------


class TestSubtreeVerification:

    def test_valid_children_verify(self):
        left = b"\xAA" * 32
        right = b"\xBB" * 32
        parent = _node_hash(5, left, right)
        assert verify_node_children(5, left, right, parent)

    def test_tampered_left_child_fails(self):
        left = b"\xAA" * 32
        right = b"\xBB" * 32
        parent = _node_hash(5, left, right)
        bad_left = bytes(left[:-1]) + bytes([left[-1] ^ 0x01])
        assert not verify_node_children(5, bad_left, right, parent)

    def test_tampered_right_child_fails(self):
        left = b"\xAA" * 32
        right = b"\xBB" * 32
        parent = _node_hash(5, left, right)
        bad_right = bytes(right[:-1]) + bytes([right[-1] ^ 0x01])
        assert not verify_node_children(5, left, bad_right, parent)

    def test_wrong_level_fails(self):
        left = b"\xAA" * 32
        right = b"\xBB" * 32
        parent = _node_hash(5, left, right)
        assert not verify_node_children(6, left, right, parent)

    def test_csmt_children_verify_against_tree(self):
        t = CSMT()
        for i in range(5):
            t.insert(_random_key(i), _random_value(i))
        root = t.root()
        left = t.get_node(1, 0)
        right = t.get_node(1, 1)
        assert verify_node_children(0, left, right, root)


# ---------------------------------------------------------------------------
# Randomized property tests
# ---------------------------------------------------------------------------


class TestRandomizedProperties:

    def test_all_inclusion_proofs_verify_after_random_inserts(self):
        rng = random.Random(42)
        t = CSMT()
        entries = []
        for _ in range(30):
            key = rng.randbytes(32)
            val = rng.randbytes(32)
            if not t.contains(key):
                t.insert(key, val)
                entries.append(key)
        root = t.root()
        for key in entries:
            assert verify_inclusion_proof(t.inclusion_proof(key), root)

    def test_all_non_inclusion_proofs_verify(self):
        rng = random.Random(99)
        t = CSMT()
        for _ in range(15):
            key = rng.randbytes(32)
            if not t.contains(key):
                t.insert(key, rng.randbytes(32))
        root = t.root()
        for _ in range(20):
            key = rng.randbytes(32)
            if not t.contains(key):
                proof = t.non_inclusion_proof(key)
                assert verify_non_inclusion_proof(proof, root)

    def test_delete_all_restores_empty_root(self):
        rng = random.Random(7)
        t = CSMT()
        keys = []
        for _ in range(20):
            key = rng.randbytes(32)
            if not t.contains(key):
                t.insert(key, rng.randbytes(32))
                keys.append(key)
        for key in keys:
            t.delete(key)
        assert t.root() == EMPTY_ROOT
        assert t.leaf_count() == 0

    def test_insertion_order_independence_randomized(self):
        rng = random.Random(55)
        pairs = []
        for _ in range(25):
            key = rng.randbytes(32)
            val = rng.randbytes(32)
            pairs.append((key, val))

        t1 = CSMT()
        for k, v in pairs:
            if not t1.contains(k):
                t1.insert(k, v)

        order = list(range(len(pairs)))
        rng.shuffle(order)
        t2 = CSMT()
        for i in order:
            k, v = pairs[i]
            if not t2.contains(k):
                t2.insert(k, v)

        assert t1.root() == t2.root()


# ---------------------------------------------------------------------------
# Phase 3: Signed head encoding and verification
# ---------------------------------------------------------------------------


def _make_test_identity():
    return Identity.generate()


def _make_test_head(origin="origin.test", seq=1, root=None, prev_hash=None, identity=None):
    if identity is None:
        identity = _make_test_identity()
    if root is None:
        root = b"\xAB" * 32
    if prev_hash is None:
        prev_hash = ZERO_HASH
    return sign_head(
        origin=origin,
        registry_seq=seq,
        snapshot_timestamp=1700000000,
        leaf_count=5,
        merkle_root=root,
        previous_head_hash=prev_hash,
        identity=identity,
    ), identity


class TestSignedHeadEncoding:

    def test_round_trip(self):
        head, ident = _make_test_head()
        encoded = encode_head(head)
        decoded = decode_head(encoded)
        assert decoded.format_version == head.format_version
        assert decoded.origin == head.origin
        assert decoded.registry_seq == head.registry_seq
        assert decoded.snapshot_timestamp == head.snapshot_timestamp
        assert decoded.leaf_count == head.leaf_count
        assert decoded.merkle_root == head.merkle_root
        assert decoded.previous_head_hash == head.previous_head_hash
        assert decoded.signature == head.signature

    def test_head_hash_deterministic(self):
        head, _ = _make_test_head()
        h1 = compute_head_hash(encode_head(head))
        h2 = compute_head_hash(encode_head(head))
        assert h1 == h2
        assert len(h1) == HASH_SIZE

    def test_truncated_head_rejected(self):
        head, _ = _make_test_head()
        encoded = encode_head(head)
        with pytest.raises(ValueError):
            decode_head(encoded[:-1])

    def test_trailing_head_rejected(self):
        head, _ = _make_test_head()
        encoded = encode_head(head) + b"\x00"
        with pytest.raises(ValueError):
            decode_head(encoded)


class TestSignedHeadVerification:

    def test_valid_signature_verifies(self):
        head, ident = _make_test_head()
        assert verify_head(head, ident.public_key)

    def test_wrong_key_fails(self):
        head, _ = _make_test_head()
        other = Identity.generate()
        assert not verify_head(head, other.public_key)

    def test_modified_origin_fails(self):
        head, ident = _make_test_head()
        head.origin = "evil.test"
        assert not verify_head(head, ident.public_key)

    def test_modified_seq_fails(self):
        head, ident = _make_test_head()
        head.registry_seq = 999
        assert not verify_head(head, ident.public_key)

    def test_modified_root_fails(self):
        head, ident = _make_test_head()
        head.merkle_root = b"\xFF" * 32
        assert not verify_head(head, ident.public_key)

    def test_modified_timestamp_fails(self):
        head, ident = _make_test_head()
        head.snapshot_timestamp = 9999999999
        assert not verify_head(head, ident.public_key)

    def test_modified_leaf_count_fails(self):
        head, ident = _make_test_head()
        head.leaf_count = 999
        assert not verify_head(head, ident.public_key)

    def test_modified_prev_hash_fails(self):
        head, ident = _make_test_head()
        head.previous_head_hash = b"\xFF" * 32
        assert not verify_head(head, ident.public_key)

    def test_modified_signature_fails(self):
        head, ident = _make_test_head()
        head.signature = bytes(head.signature[:-1]) + bytes([head.signature[-1] ^ 0x01])
        assert not verify_head(head, ident.public_key)

    def test_previous_head_hash_zero_for_seq_1(self):
        head, ident = _make_test_head(seq=1)
        assert head.previous_head_hash == ZERO_HASH

    def test_previous_head_hash_set_for_seq_2(self):
        head1, ident = _make_test_head(seq=1)
        h1_hash = head1.head_hash
        head2, _ = _make_test_head(seq=2, prev_hash=h1_hash, identity=ident)
        assert head2.previous_head_hash == h1_hash

    def test_head_chain_linkage_verifies(self):
        ident = Identity.generate()
        h1, _ = _make_test_head(seq=1, identity=ident)
        h2, _ = _make_test_head(seq=2, prev_hash=h1.head_hash, identity=ident)
        assert h2.previous_head_hash == h1.head_hash
        assert verify_head(h2, ident.public_key)


# ---------------------------------------------------------------------------
# Phase 3: SQLite-backed UserRegistryStore
# ---------------------------------------------------------------------------


@pytest.fixture
def store(temp_dir):
    s = UserRegistryStore(os.path.join(temp_dir, "user_registry.db"))
    yield s
    s.close()


class TestUserRegistryStoreBasics:

    def test_empty_store_has_no_state(self, store):
        assert store.get_state("origin.test") is None

    def test_empty_store_has_no_head(self, store):
        assert store.get_head("origin.test") is None

    def test_mark_dirty_creates_state(self, store):
        store.mark_dirty("origin.test")
        state = store.get_state("origin.test")
        assert state is not None
        assert state["dirty_generation"] == 1
        assert state["snapshotted_generation"] == 0

    def test_mark_dirty_increments(self, store):
        store.mark_dirty("origin.test")
        store.mark_dirty("origin.test")
        state = store.get_state("origin.test")
        assert state["dirty_generation"] == 2


class TestStoreAuthoritativeHead:

    def test_store_and_retrieve_head(self, store):
        head, ident = _make_test_head()
        store.store_authoritative_head("origin.test", head, [], [])
        retrieved = store.get_head("origin.test")
        assert retrieved is not None
        assert retrieved.registry_seq == head.registry_seq
        assert retrieved.merkle_root == head.merkle_root
        assert retrieved.origin == head.origin

    def test_state_advances_after_store(self, store):
        head, ident = _make_test_head(seq=1)
        store.store_authoritative_head("origin.test", head, [], [])
        state = store.get_state("origin.test")
        assert state["highest_accepted_seq"] == 1
        assert state["current_merkle_root"] == head.merkle_root
        assert state["current_leaf_count"] == head.leaf_count

    def test_store_multiple_heads_advances_seq(self, store):
        ident = Identity.generate()
        h1, _ = _make_test_head(seq=1, identity=ident)
        store.store_authoritative_head("origin.test", h1, [], [])
        h2, _ = _make_test_head(seq=2, root=b"\xBB" * 32,
                                prev_hash=h1.head_hash, identity=ident)
        store.store_authoritative_head("origin.test", h2, [], [])
        state = store.get_state("origin.test")
        assert state["highest_accepted_seq"] == 2
        assert store.get_head("origin.test").registry_seq == 2


class TestStoreRemoteAcceptance:

    def test_accept_valid_remote_head(self, store):
        head, ident = _make_test_head(origin="remote.test")
        result = store.accept_remote_head("remote.test", head, ident.public_key, [], [])
        assert result.accepted
        assert result.head is not None

    def test_reject_bad_signature(self, store):
        head, ident = _make_test_head(origin="remote.test")
        head.signature = b"\x00" * 64
        result = store.accept_remote_head("remote.test", head, ident.public_key, [], [])
        assert not result.accepted
        assert "signature" in result.reason

    def test_reject_origin_mismatch(self, store):
        head, ident = _make_test_head(origin="remote.test")
        result = store.accept_remote_head("other.test", head, ident.public_key, [], [])
        assert not result.accepted
        assert "origin" in result.reason

    def test_reject_rollback(self, store):
        ident = Identity.generate()
        h2, _ = _make_test_head(seq=2, origin="remote.test", identity=ident)
        result = store.accept_remote_head("remote.test", h2, ident.public_key, [], [])
        assert result.accepted
        h1, _ = _make_test_head(seq=1, origin="remote.test", identity=ident)
        result = store.accept_remote_head("remote.test", h1, ident.public_key, [], [])
        assert not result.accepted
        assert "rollback" in result.reason

    def test_idempotent_same_seq_same_hash(self, store):
        head, ident = _make_test_head(origin="remote.test")
        r1 = store.accept_remote_head("remote.test", head, ident.public_key, [], [])
        assert r1.accepted
        r2 = store.accept_remote_head("remote.test", head, ident.public_key, [], [])
        assert r2.accepted
        assert "idempotent" in r2.reason

    def test_reject_equivocation(self, store):
        ident = Identity.generate()
        h1a, _ = _make_test_head(seq=1, origin="remote.test", root=b"\xAA" * 32, identity=ident)
        r1 = store.accept_remote_head("remote.test", h1a, ident.public_key, [], [])
        assert r1.accepted
        h1b, _ = _make_test_head(seq=1, origin="remote.test", root=b"\xBB" * 32, identity=ident)
        r2 = store.accept_remote_head("remote.test", h1b, ident.public_key, [], [])
        assert not r2.accepted
        assert "equivocation" in r2.reason

    def test_crash_reopen_retains_state(self, temp_dir):
        db_path = os.path.join(temp_dir, "user_registry.db")
        store1 = UserRegistryStore(db_path)
        head, ident = _make_test_head(origin="remote.test", seq=5)
        store1.accept_remote_head("remote.test", head, ident.public_key, [], [])
        store1.close()
        store2 = UserRegistryStore(db_path)
        state = store2.get_state("remote.test")
        assert state["highest_accepted_seq"] == 5
        retrieved = store2.get_head("remote.test")
        assert retrieved.registry_seq == 5
        store2.close()

    def test_failed_transaction_does_not_advance(self, store):
        head, ident = _make_test_head(origin="remote.test", seq=1)
        result = store.accept_remote_head("remote.test", head, ident.public_key, [], [])
        assert result.accepted
        bad_head, _ = _make_test_head(origin="remote.test", seq=1 << 63)
        result = store.accept_remote_head("remote.test", bad_head, ident.public_key, [], [])
        assert not result.accepted
        state = store.get_state("remote.test")
        assert state["highest_accepted_seq"] == 1


# ---------------------------------------------------------------------------
# Phase 3: RegistryService — snapshot construction
# ---------------------------------------------------------------------------


def _make_ume(temp_dir, origin="origin.test"):
    ume = Ume(os.path.join(temp_dir, "userfile"))
    ident = Identity.generate()
    ume.ensure_root_user(origin, ident.public_key)
    return ume, ident


@pytest.fixture
def registry_setup(temp_dir):
    ume, ident = _make_ume(temp_dir)
    store = UserRegistryStore(os.path.join(temp_dir, "user_registry.db"))
    svc = RegistryService(store, ume, ident, "origin.test")
    ume.register_mutation_callback(svc.mark_dirty)
    yield svc, store, ume, ident
    store.close()


class TestRegistryServiceSnapshot:

    def test_first_bootstrap_creates_seq_1(self, registry_setup):
        svc, store, ume, ident = registry_setup
        head = svc.build_snapshot()
        assert head.registry_seq == 1
        assert head.origin == "origin.test"
        assert head.leaf_count >= 1
        assert head.previous_head_hash == ZERO_HASH
        assert verify_head(head, ident.public_key)

    def test_no_mutation_returns_same_head(self, registry_setup):
        svc, store, ume, ident = registry_setup
        h1 = svc.build_snapshot()
        h2 = svc.build_snapshot()
        assert h1.head_hash == h2.head_hash
        assert h1.registry_seq == h2.registry_seq

    def test_mutation_increments_seq(self, registry_setup):
        svc, store, ume, ident = registry_setup
        h1 = svc.build_snapshot()
        ume.put("alice", "origin.test", Identity.generate().public_key,
                record_origin="origin.test", relay="origin.test")
        h2 = svc.build_snapshot()
        assert h2.registry_seq == h1.registry_seq + 1
        assert h2.merkle_root != h1.merkle_root
        assert h2.previous_head_hash == h1.head_hash

    def test_delete_increments_seq(self, registry_setup):
        svc, store, ume, ident = registry_setup
        ume.put("alice", "origin.test", Identity.generate().public_key,
                record_origin="origin.test", relay="origin.test")
        h1 = svc.build_snapshot()
        ume.delete(username="alice")
        h2 = svc.build_snapshot()
        assert h2.registry_seq == h1.registry_seq + 1
        assert h2.leaf_count == h1.leaf_count - 1

    def test_update_increments_seq(self, registry_setup):
        svc, store, ume, ident = registry_setup
        pub1 = Identity.generate().public_key
        ume.put("alice", "origin.test", pub1,
                record_origin="origin.test", relay="origin.test")
        h1 = svc.build_snapshot()
        pub2 = Identity.generate().public_key
        ume.upd(username="alice", new_publickey=pub2)
        h2 = svc.build_snapshot()
        assert h2.registry_seq == h1.registry_seq + 1
        assert h2.merkle_root != h1.merkle_root

    def test_snapshot_excludes_non_native_records(self, registry_setup):
        svc, store, ume, ident = registry_setup
        ume.upsert_remote_user("remote_bob", "remote.test",
                               Identity.generate().public_key,
                               "remote.test", "peer.example.com")
        head = svc.build_snapshot()
        assert head.leaf_count == 1

    def test_head_chain_linkage(self, registry_setup):
        svc, store, ume, ident = registry_setup
        h1 = svc.build_snapshot()
        ume.put("alice", "origin.test", Identity.generate().public_key,
                record_origin="origin.test", relay="origin.test")
        h2 = svc.build_snapshot()
        assert h2.previous_head_hash == h1.head_hash

    def test_records_stored_in_sidecar(self, registry_setup):
        svc, store, ume, ident = registry_setup
        ume.put("alice", "origin.test", Identity.generate().public_key,
                record_origin="origin.test", relay="origin.test")
        head = svc.build_snapshot()
        key = compute_registry_key("origin.test", "alice")
        raw = store.get_record("origin.test", key)
        assert raw is not None
        assert len(raw) == RECORD_SIZE

    def test_rebuild_after_reopen(self, temp_dir):
        ume, ident = _make_ume(temp_dir)
        db_path = os.path.join(temp_dir, "user_registry.db")
        store1 = UserRegistryStore(db_path)
        svc1 = RegistryService(store1, ume, ident, "origin.test")
        ume.register_mutation_callback(svc1.mark_dirty)
        h1 = svc1.build_snapshot()
        store1.close()

        store2 = UserRegistryStore(db_path)
        svc2 = RegistryService(store2, ume, ident, "origin.test")
        h2 = svc2.build_snapshot()
        assert h2.head_hash == h1.head_hash
        store2.close()


# ---------------------------------------------------------------------------
# Phase 3: Ume changes — snapshot_raw_records, export, upsert
# ---------------------------------------------------------------------------


class TestUmeSnapshotRawRecords:

    def test_returns_exact_record_size(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        ume.put("alice", "origin.test", Identity.generate().public_key,
                record_origin="origin.test", relay="origin.test")
        records = ume.snapshot_raw_records()
        assert len(records) == 1
        assert len(records[0]) == RECORD_SIZE

    def test_excludes_deleted_slots(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        ume.put("alice", "origin.test", Identity.generate().public_key)
        ume.put("bob", "origin.test", Identity.generate().public_key)
        ume.delete(username="alice")
        records = ume.snapshot_raw_records()
        assert len(records) == 1

    def test_empty_file_returns_empty_list(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        records = ume.snapshot_raw_records()
        assert records == []

    def test_round_trip_through_decode(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        pub = Identity.generate().public_key
        ume.put("alice", "origin.test", pub,
                record_origin="origin.test", relay="origin.test")
        records = ume.snapshot_raw_records()
        user = User.decode(records[0])
        assert user.username == "alice"
        assert user.publickey == pub
        assert user.record_origin == "origin.test"


class TestUmeExportTimestamps:

    def test_export_includes_creation_time(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        ume.put("alice", "origin.test", Identity.generate().public_key,
                record_origin="orig", relay="rel")
        export_path = os.path.join(temp_dir, "export.txt")
        ume.export(export_path)
        with open(export_path, "r") as f:
            content = f.read()
        assert "creation_time=" in content
        assert "relay_time=" in content


class TestUmeUpsertCreationTime:

    def test_insert_with_creation_time(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        pub = Identity.generate().public_key
        ct = 1609459200
        ume.upsert_remote_user("remote1", "remote.test", pub,
                               "remote.test", "relay.test", creation_time=ct)
        user = ume.get("remote1")
        assert user.creation_time == ct

    def test_insert_without_creation_time_uses_now(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        pub = Identity.generate().public_key
        before = int(time.time())
        ume.upsert_remote_user("remote1", "remote.test", pub,
                               "remote.test", "relay.test")
        after = int(time.time())
        user = ume.get("remote1")
        assert before <= user.creation_time <= after

    def test_update_corrects_creation_time(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        pub = Identity.generate().public_key
        ume.upsert_remote_user("remote1", "remote.test", pub,
                               "remote.test", "relay.test", creation_time=1000)
        ume.upsert_remote_user("remote1", "remote.test", pub,
                               "remote.test", "relay.test", creation_time=2000)
        user = ume.get("remote1")
        assert user.creation_time == 2000

    def test_update_rejects_future_creation_time(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        pub = Identity.generate().public_key
        ume.upsert_remote_user("remote1", "remote.test", pub,
                               "remote.test", "relay.test", creation_time=1000)
        with pytest.raises(ValueError, match="future"):
            ume.upsert_remote_user("remote1", "remote.test", pub,
                                   "remote.test", "relay.test",
                                   creation_time=int(time.time()) + 10000)

    def test_update_rejects_excessive_correction(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        pub = Identity.generate().public_key
        ume.upsert_remote_user("remote1", "remote.test", pub,
                               "remote.test", "relay.test", creation_time=1000)
        with pytest.raises(ValueError, match="exceeds"):
            ume.upsert_remote_user("remote1", "remote.test", pub,
                                   "remote.test", "relay.test",
                                   creation_time=1000 + 200000,
                                   max_creation_time_correction=86400)

    def test_update_preserves_local_moderation_state(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        pub = Identity.generate().public_key
        ume.upsert_remote_user("remote1", "remote.test", pub,
                               "remote.test", "relay.test", creation_time=1000)
        ume.upd(username="remote1", new_banned=True)
        ume.upsert_remote_user("remote1", "remote.test", pub,
                               "remote.test", "relay.test", creation_time=2000)
        user = ume.get("remote1")
        assert user.is_banned is True

    def test_backward_compatible_without_creation_time(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        pub = Identity.generate().public_key
        status = ume.upsert_remote_user("remote1", "remote.test", pub,
                                        "remote.test", "relay.test")
        assert status == 1
        status2 = ume.upsert_remote_user("remote1", "new_reg", pub,
                                         "remote.test", "new_relay")
        assert status2 == 2
