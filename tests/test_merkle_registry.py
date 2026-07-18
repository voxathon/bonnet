"""Tests for generic Merkle registry primitives and registry type domain
separation (Phase 2, §7.2/§7.3).

Verifies:
  - Generic primitives in merkle_registry.py work for multiple registry types
  - Domain separation: hashes, trees, and signed heads are bound to a
    registry_type and cannot be replayed across types
  - Generic MerkleRegistryStore works for multiple registry types in one DB
  - User-registry backward compatibility is preserved
"""

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.merkle_registry import (
    TREE_DEPTH,
    HASH_SIZE,
    ZERO_HASH,
    HEAD_FORMAT_VERSION,
    HEAD_HASH_ALGORITHM,
    REGISTRY_TYPE_USERS,
    REGISTRY_TYPE_REPORTS,
    REGISTRY_TYPE_PUNISHMENTS,
    CSMT as GenCSMT,
    SignedHead,
    encode_head,
    encode_head_payload,
    decode_head,
    sign_head,
    verify_head,
    compute_head_hash,
    compute_registry_key as gen_compute_registry_key,
    compute_value_hash as gen_compute_value_hash,
    get_default_hashes,
    get_empty_leaf,
    get_empty_root,
    verify_inclusion_proof,
    verify_non_inclusion_proof,
    verify_node_children,
    AcceptResult,
    MerkleRegistryStore,
)
from core.crypto import Identity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _random_key(seed: int) -> bytes:
    import random
    rng = random.Random(seed)
    return rng.randbytes(32)


def _random_value(seed: int) -> bytes:
    import random
    rng = random.Random(seed * 31 + 1)
    return rng.randbytes(32)


def _make_head(registry_type, origin="origin.test", seq=1, root=None,
               prev_hash=None, identity=None):
    if identity is None:
        identity = Identity.generate()
    if root is None:
        root = b"\xAB" * 32
    if prev_hash is None:
        prev_hash = ZERO_HASH
    return sign_head(
        registry_type=registry_type,
        origin=origin,
        registry_seq=seq,
        snapshot_timestamp=1700000000,
        leaf_count=5,
        merkle_root=root,
        previous_head_hash=prev_hash,
        identity=identity,
    ), identity


# ---------------------------------------------------------------------------
# Domain separation: hashes differ by registry type
# ---------------------------------------------------------------------------

class TestDomainSeparationHashes:
    """Per §7.3: every hash is domain-separated by registry_type."""

    def test_empty_leaf_differs_by_type(self):
        assert get_empty_leaf("users") != get_empty_leaf("reports")
        assert get_empty_leaf("users") != get_empty_leaf("punishments")
        assert get_empty_leaf("reports") != get_empty_leaf("punishments")

    def test_empty_root_differs_by_type(self):
        assert get_empty_root("users") != get_empty_root("reports")
        assert get_empty_root("users") != get_empty_root("punishments")

    def test_default_hashes_differ_by_type(self):
        users_dh = get_default_hashes("users")
        reports_dh = get_default_hashes("reports")
        for i in range(TREE_DEPTH + 1):
            assert users_dh[i] != reports_dh[i]

    def test_registry_key_differs_by_type(self):
        k_users = gen_compute_registry_key("users", "origin.test", "alice")
        k_reports = gen_compute_registry_key("reports", "origin.test", "alice")
        assert k_users != k_reports

    def test_value_hash_differs_by_type(self):
        record = b"\x00" * 100
        h_users = gen_compute_value_hash("users", record)
        h_reports = gen_compute_value_hash("reports", record)
        assert h_users != h_reports

    def test_all_hashes_are_32_bytes(self):
        for rt in ("users", "reports", "punishments"):
            dh = get_default_hashes(rt)
            for h in dh:
                assert len(h) == HASH_SIZE


# ---------------------------------------------------------------------------
# Domain separation: CSMT trees are bound to a registry type
# ---------------------------------------------------------------------------

class TestDomainSeparationCSMT:
    """A tree built with users hashes has a different root than one built with
    reports hashes for the same key/value."""

    def test_same_data_different_type_different_root(self):
        key = _random_key(1)
        vh = _random_value(1)

        t_users = GenCSMT("users")
        t_users.insert(key, vh)

        t_reports = GenCSMT("reports")
        t_reports.insert(key, vh)

        assert t_users.root() != t_reports.root()
        assert t_users.root() != get_empty_root("users")
        assert t_reports.root() != get_empty_root("reports")

    def test_proofs_are_type_specific(self):
        key = _random_key(1)
        vh = _random_value(1)

        t = GenCSMT("users")
        t.insert(key, vh)
        root = t.root()
        proof = t.inclusion_proof(key)

        # Verifies against users root
        assert verify_inclusion_proof("users", proof, root)
        # Does NOT verify against reports root (different empty hashes)
        assert not verify_inclusion_proof("reports", proof, root)

    def test_node_children_type_specific(self):
        from core.merkle_registry import _node_hash
        left = b"\xAA" * 32
        right = b"\xBB" * 32
        parent_users = _node_hash("users", 5, left, right)
        parent_reports = _node_hash("reports", 5, left, right)
        assert parent_users != parent_reports
        assert verify_node_children("users", 5, left, right, parent_users)
        assert not verify_node_children("reports", 5, left, right, parent_users)


# ---------------------------------------------------------------------------
# Domain separation: signed heads cannot be replayed across types
# ---------------------------------------------------------------------------

class TestDomainSeparationSignedHeads:
    """Per §7.3: a head signed for the users registry cannot be replayed as a
    reports or punishments head."""

    def test_head_includes_registry_type(self):
        head, _ = _make_head("users")
        assert head.registry_type == "users"

    def test_head_encoding_differs_by_type(self):
        ident = Identity.generate()
        h_users, _ = _make_head("users", identity=ident)
        h_reports, _ = _make_head("reports", identity=ident, root=h_users.merkle_root,
                                  prev_hash=h_users.previous_head_hash)
        assert encode_head(h_users) != encode_head(h_reports)

    def test_head_hash_differs_by_type(self):
        ident = Identity.generate()
        h_users, _ = _make_head("users", identity=ident)
        h_reports, _ = _make_head("reports", identity=ident, root=h_users.merkle_root,
                                  prev_hash=h_users.previous_head_hash)
        assert h_users.head_hash != h_reports.head_hash

    def test_decode_with_wrong_expected_type_fails(self):
        head, _ = _make_head("users")
        encoded = encode_head(head)
        with pytest.raises(ValueError, match="domain prefix"):
            decode_head(encoded, expected_registry_type="reports")

    def test_decode_without_expected_type_works(self):
        head, _ = _make_head("users")
        encoded = encode_head(head)
        decoded = decode_head(encoded)
        assert decoded.registry_type == "users"
        assert decoded.origin == head.origin

    def test_users_head_not_replayable_as_reports_via_store(self, tmp_path):
        """A users head signed by origin A cannot be accepted into a reports
        registry store for the same origin."""
        store = MerkleRegistryStore(str(tmp_path / "test.db"))
        head, ident = _make_head("users", origin="origin.test")
        result = store.accept_remote_head("reports", "origin.test", head, ident.public_key, [], [])
        assert not result.accepted
        assert "registry_type mismatch" in result.reason
        store.close()

    def test_verify_head_rejects_cross_type(self):
        """verify_head checks the signature over the full payload including
        registry_type, so modifying registry_type invalidates the signature."""
        head, ident = _make_head("users")
        assert verify_head(head, ident.public_key)
        head.registry_type = "reports"
        assert not verify_head(head, ident.public_key)


# ---------------------------------------------------------------------------
# Generic MerkleRegistryStore works for multiple types in one DB
# ---------------------------------------------------------------------------

class TestGenericStore:
    """Per §7.4: a single MerkleRegistryStore can hold multiple registry types."""

    def test_multiple_types_in_one_db(self, tmp_path):
        store = MerkleRegistryStore(str(tmp_path / "multi.db"))

        # Store a users head
        h_users, ident_u = _make_head("users", origin="origin.test", seq=1, root=b"\xAA" * 32)
        store.store_authoritative_head("users", "origin.test", h_users, [], [])

        # Store a reports head with a different root
        h_reports, ident_r = _make_head("reports", origin="origin.test", seq=1, root=b"\xBB" * 32)
        store.store_authoritative_head("reports", "origin.test", h_reports, [], [])

        # Both are retrievable independently
        assert store.get_head("users", "origin.test").registry_seq == 1
        assert store.get_head("reports", "origin.test").registry_seq == 1

        # States are independent
        state_u = store.get_state("users", "origin.test")
        state_r = store.get_state("reports", "origin.test")
        assert state_u["highest_accepted_seq"] == 1
        assert state_r["highest_accepted_seq"] == 1
        assert state_u["current_merkle_root"] != state_r["current_merkle_root"]

        store.close()

    def test_rollback_protection_per_type(self, tmp_path):
        store = MerkleRegistryStore(str(tmp_path / "rollback.db"))
        ident = Identity.generate()

        # Accept users seq=2
        h2, _ = _make_head("users", origin="o.test", seq=2, identity=ident)
        r = store.accept_remote_head("users", "o.test", h2, ident.public_key, [], [])
        assert r.accepted

        # Users seq=1 is rejected as rollback
        h1, _ = _make_head("users", origin="o.test", seq=1, identity=ident)
        r = store.accept_remote_head("users", "o.test", h1, ident.public_key, [], [])
        assert not r.accepted
        assert "rollback" in r.reason

        # But reports seq=1 is fine (independent registry)
        h1r, _ = _make_head("reports", origin="o.test", seq=1, identity=ident)
        r = store.accept_remote_head("reports", "o.test", h1r, ident.public_key, [], [])
        assert r.accepted

        store.close()

    def test_equivocation_protection_per_type(self, tmp_path):
        store = MerkleRegistryStore(str(tmp_path / "equiv.db"))
        ident = Identity.generate()

        h1a, _ = _make_head("users", origin="o.test", seq=1, root=b"\xAA" * 32, identity=ident)
        r = store.accept_remote_head("users", "o.test", h1a, ident.public_key, [], [])
        assert r.accepted

        h1b, _ = _make_head("users", origin="o.test", seq=1, root=b"\xBB" * 32, identity=ident)
        r = store.accept_remote_head("users", "o.test", h1b, ident.public_key, [], [])
        assert not r.accepted
        assert "equivocation" in r.reason

        store.close()

    def test_idempotent_per_type(self, tmp_path):
        store = MerkleRegistryStore(str(tmp_path / "idem.db"))
        head, ident = _make_head("users", origin="o.test")
        r1 = store.accept_remote_head("users", "o.test", head, ident.public_key, [], [])
        assert r1.accepted
        r2 = store.accept_remote_head("users", "o.test", head, ident.public_key, [], [])
        assert r2.accepted
        assert "idempotent" in r2.reason
        store.close()


# ---------------------------------------------------------------------------
# User-registry backward compatibility
# ---------------------------------------------------------------------------

class TestUserRegistryBackwardCompat:
    """The user_registry module wrappers produce correct users-type heads."""

    def test_user_sign_head_has_users_type(self):
        from core.user_registry import sign_head, ZERO_HASH
        ident = Identity.generate()
        head = sign_head(
            origin="o.test",
            registry_seq=1,
            snapshot_timestamp=1700000000,
            leaf_count=1,
            merkle_root=b"\xAB" * 32,
            previous_head_hash=ZERO_HASH,
            identity=ident,
        )
        assert head.registry_type == "users"
        assert verify_head(head, ident.public_key)

    def test_user_decode_head_round_trip(self):
        from core.user_registry import sign_head, encode_head, decode_head, ZERO_HASH
        ident = Identity.generate()
        head = sign_head(
            origin="o.test",
            registry_seq=1,
            snapshot_timestamp=1700000000,
            leaf_count=1,
            merkle_root=b"\xAB" * 32,
            previous_head_hash=ZERO_HASH,
            identity=ident,
        )
        encoded = encode_head(head)
        decoded = decode_head(encoded)
        assert decoded.registry_type == "users"
        assert decoded.origin == "o.test"

    def test_user_csmt_uses_users_domain(self):
        from core.user_registry import CSMT, EMPTY_ROOT
        t = CSMT()
        assert t.root() == EMPTY_ROOT
        assert t.registry_type == "users"

    def test_user_compute_key_uses_users_domain(self):
        from core.user_registry import compute_registry_key
        k_user = compute_registry_key("o.test", "alice")
        k_gen = gen_compute_registry_key("users", "o.test", "alice")
        assert k_user == k_gen
