"""Tests for src/bonnet/core/trust.py — atomic origin-key pinning and rotation.

Exit gate (§13 Phase 3):
  - Origin pin first use, repeat use, mismatch, configured pin, and rotation
  - Concurrent first-contact produces one pin (atomic TOFU)
"""

import os
import struct
import threading
import time

import pytest

from bonnet.core.crypto import Identity
from bonnet.core.trust import TRUST_MODE_CONFIGURED, TRUST_MODE_TOFU, TrustStore


@pytest.fixture
def store(tmp_path):
    db_path = str(tmp_path / "trust.db")
    ts = TrustStore(db_path)
    yield ts
    ts.close()


@pytest.fixture
def keypair():
    ident = Identity.generate()
    return ident, ident.public_key


class TestTOFUPinning:
    def test_first_contact_pins(self, store, keypair):
        _, pub = keypair
        assert store.tofu_pin("bbs.example.com", pub) is True
        assert store.get_pin("bbs.example.com") == pub

    def test_repeat_contact_same_key_succeeds(self, store, keypair):
        _, pub = keypair
        store.tofu_pin("bbs.example.com", pub)
        assert store.tofu_pin("bbs.example.com", pub) is True

    def test_repeat_contact_different_key_fails(self, store, keypair):
        _, pub = keypair
        store.tofu_pin("bbs.example.com", pub)
        other_pub = Identity.generate().public_key
        assert store.tofu_pin("bbs.example.com", other_pub) is False

    def test_different_origins_independent(self, store, keypair):
        _, pub = keypair
        other_pub = Identity.generate().public_key
        assert store.tofu_pin("a.example.com", pub) is True
        assert store.tofu_pin("b.example.com", other_pub) is True

    def test_pin_info_returns_metadata(self, store, keypair):
        _, pub = keypair
        store.tofu_pin("bbs.example.com", pub)
        info = store.get_pin_info("bbs.example.com")
        assert info is not None
        assert info["publickey"] == pub
        assert info["trust_mode"] == TRUST_MODE_TOFU
        assert info["first_seen"] > 0
        assert info["last_rotated"] > 0

    def test_get_pin_returns_none_for_unknown(self, store):
        assert store.get_pin("unknown.example.com") is None
        assert store.get_pin_info("unknown.example.com") is None


class TestConfiguredPin:
    def test_configured_pin_sets_key(self, store, keypair):
        _, pub = keypair
        store.configured_pin("bbs.example.com", pub)
        info = store.get_pin_info("bbs.example.com")
        assert info["trust_mode"] == TRUST_MODE_CONFIGURED
        assert info["publickey"] == pub

    def test_configured_pin_overwrites_tofu(self, store, keypair):
        ident, pub = keypair
        store.tofu_pin("bbs.example.com", pub)
        new_pub = Identity.generate().public_key
        store.configured_pin("bbs.example.com", new_pub)
        assert store.get_pin("bbs.example.com") == new_pub
        info = store.get_pin_info("bbs.example.com")
        assert info["trust_mode"] == TRUST_MODE_CONFIGURED


class TestRotation:
    def test_valid_rotation_succeeds(self, store, keypair):
        old_ident, old_pub = keypair
        new_ident = Identity.generate()
        new_pub = new_ident.public_key

        store.tofu_pin("bbs.example.com", old_pub)

        origin_bytes = b"bbs.example.com"
        payload = struct.pack("B", len(origin_bytes)) + origin_bytes + old_pub + new_pub
        signature = old_ident.sign(payload)

        assert store.verify_rotation("bbs.example.com", old_pub, new_pub, signature) is True
        assert store.get_pin("bbs.example.com") == new_pub

    def test_rotation_with_wrong_old_key_fails(self, store, keypair):
        old_ident, old_pub = keypair
        new_pub = Identity.generate().public_key
        wrong_ident = Identity.generate()

        store.tofu_pin("bbs.example.com", old_pub)

        origin_bytes = b"bbs.example.com"
        payload = (
            struct.pack("B", len(origin_bytes)) + origin_bytes + wrong_ident.public_key + new_pub
        )
        signature = wrong_ident.sign(payload)

        assert (
            store.verify_rotation("bbs.example.com", wrong_ident.public_key, new_pub, signature)
            is False
        )
        assert store.get_pin("bbs.example.com") == old_pub

    def test_rotation_with_bad_signature_fails(self, store, keypair):
        old_ident, old_pub = keypair
        new_pub = Identity.generate().public_key

        store.tofu_pin("bbs.example.com", old_pub)

        bad_sig = os.urandom(64)
        assert store.verify_rotation("bbs.example.com", old_pub, new_pub, bad_sig) is False
        assert store.get_pin("bbs.example.com") == old_pub

    def test_rotation_for_unpinned_origin_fails(self, store, keypair):
        old_ident, old_pub = keypair
        new_pub = Identity.generate().public_key

        origin_bytes = b"unknown.example.com"
        payload = struct.pack("B", len(origin_bytes)) + origin_bytes + old_pub + new_pub
        signature = old_ident.sign(payload)

        assert store.verify_rotation("unknown.example.com", old_pub, new_pub, signature) is False

    def test_rotation_updates_last_rotated(self, store, keypair):
        old_ident, old_pub = keypair
        new_pub = Identity.generate().public_key

        store.tofu_pin("bbs.example.com", old_pub)
        before = store.get_pin_info("bbs.example.com")["last_rotated"]

        time.sleep(1.1)

        origin_bytes = b"bbs.example.com"
        payload = struct.pack("B", len(origin_bytes)) + origin_bytes + old_pub + new_pub
        signature = old_ident.sign(payload)

        store.verify_rotation("bbs.example.com", old_pub, new_pub, signature)
        after = store.get_pin_info("bbs.example.com")["last_rotated"]
        assert after > before


class TestResetPin:
    def test_reset_removes_pin(self, store, keypair):
        _, pub = keypair
        store.tofu_pin("bbs.example.com", pub)
        assert store.reset_pin("bbs.example.com") is True
        assert store.get_pin("bbs.example.com") is None

    def test_reset_unknown_origin_returns_false(self, store):
        assert store.reset_pin("unknown.example.com") is False

    def test_repin_after_reset(self, store, keypair):
        _, old_pub = keypair
        store.tofu_pin("bbs.example.com", old_pub)
        store.reset_pin("bbs.example.com")
        new_pub = Identity.generate().public_key
        assert store.tofu_pin("bbs.example.com", new_pub) is True


class TestListPins:
    def test_list_empty(self, store):
        assert store.list_pins() == []

    def test_list_multiple(self, store):
        pub1 = Identity.generate().public_key
        pub2 = Identity.generate().public_key
        store.tofu_pin("a.example.com", pub1)
        store.tofu_pin("b.example.com", pub2)
        pins = store.list_pins()
        origins = {p["origin"] for p in pins}
        assert origins == {"a.example.com", "b.example.com"}


class TestConcurrentFirstContact:
    """TOFU insertion must be atomic — concurrent first-contact produces one pin."""

    def test_concurrent_tofu_same_key(self, store, keypair):
        """Two threads TOFU-pin the same origin with the same key.
        Both should see True (same key == match)."""
        _, pub = keypair
        results = []
        barrier = threading.Barrier(2)

        def try_tofu():
            barrier.wait()
            results.append(store.tofu_pin("bbs.example.com", pub))

        t1 = threading.Thread(target=try_tofu)
        t2 = threading.Thread(target=try_tofu)
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        assert len(results) == 2
        assert all(r is True for r in results)
        assert store.get_pin("bbs.example.com") == pub

    def test_concurrent_tofu_different_keys_one_wins(self, store):
        """Two threads TOFU-pin the same origin with DIFFERENT keys.
        One should succeed (True), the other should fail (False — mismatch).
        Exactly one key should be pinned."""
        pub1 = Identity.generate().public_key
        pub2 = Identity.generate().public_key
        results = []
        barrier = threading.Barrier(2)

        def try_tofu(key):
            def run():
                barrier.wait()
                results.append(store.tofu_pin("bbs.example.com", key))

            return run

        t1 = threading.Thread(target=try_tofu(pub1))
        t2 = threading.Thread(target=try_tofu(pub2))
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        assert len(results) == 2
        # One True, one False
        assert sum(1 for r in results if r) == 1
        assert sum(1 for r in results if not r) == 1
        # Exactly one key is pinned
        pinned = store.get_pin("bbs.example.com")
        assert pinned in (pub1, pub2)


class TestRestartSurvival:
    def test_pins_survive_restart(self, tmp_path):
        db_path = str(tmp_path / "trust.db")
        ts1 = TrustStore(db_path)
        pub = Identity.generate().public_key
        ts1.tofu_pin("bbs.example.com", pub)
        ts1.close()

        ts2 = TrustStore(db_path)
        assert ts2.get_pin("bbs.example.com") == pub
        assert ts2.get_pin_info("bbs.example.com")["trust_mode"] == TRUST_MODE_TOFU
        ts2.close()
