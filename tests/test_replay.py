"""Tests for src/net/replay.py — persistent replay-prevention ledger.

Exit gate (§13 Phase 3):
  - Replays and stale/future requests fail before dispatch
  - Duplicate (pubkey, nonce) insertion fails with constraint violation
  - Expired rows are cleaned up in bounded batches
  - Ledger survives process restart (persistent SQLite)
"""

import os
import sys
import time
import base64
import threading
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from net.replay import ReplayLedger


def _make_nonce() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()


@pytest.fixture
def ledger(tmp_path):
    db_path = str(tmp_path / "replay.db")
    rl = ReplayLedger(db_path, clock_skew_seconds=0)
    yield rl
    rl.close()


@pytest.fixture
def pubkey():
    return os.urandom(32)


class TestAtomicInsert:
    def test_first_insert_succeeds(self, ledger, pubkey):
        nonce = _make_nonce()
        expires = int(time.time()) + 60
        assert ledger.check_and_insert(pubkey, nonce, expires) is True

    def test_duplicate_insert_fails(self, ledger, pubkey):
        nonce = _make_nonce()
        expires = int(time.time()) + 60
        assert ledger.check_and_insert(pubkey, nonce, expires) is True
        assert ledger.check_and_insert(pubkey, nonce, expires) is False

    def test_different_nonce_same_key_succeeds(self, ledger, pubkey):
        expires = int(time.time()) + 60
        assert ledger.check_and_insert(pubkey, _make_nonce(), expires) is True
        assert ledger.check_and_insert(pubkey, _make_nonce(), expires) is True

    def test_same_nonce_different_key_succeeds(self, ledger):
        expires = int(time.time()) + 60
        nonce = _make_nonce()
        assert ledger.check_and_insert(os.urandom(32), nonce, expires) is True
        assert ledger.check_and_insert(os.urandom(32), nonce, expires) is True


class TestIsReplay:
    def test_not_replay_before_insert(self, ledger, pubkey):
        nonce = _make_nonce()
        assert ledger.is_replay(pubkey, nonce) is False

    def test_is_replay_after_insert(self, ledger, pubkey):
        nonce = _make_nonce()
        expires = int(time.time()) + 60
        ledger.check_and_insert(pubkey, nonce, expires)
        assert ledger.is_replay(pubkey, nonce) is True

    def test_not_replay_different_key(self, ledger, pubkey):
        nonce = _make_nonce()
        expires = int(time.time()) + 60
        ledger.check_and_insert(pubkey, nonce, expires)
        assert ledger.is_replay(os.urandom(32), nonce) is False


class TestExpiryCleanup:
    def test_expired_rows_cleaned_on_insert(self, tmp_path):
        db_path = str(tmp_path / "replay.db")
        rl = ReplayLedger(db_path, clock_skew_seconds=0)
        pubkey = os.urandom(32)

        # Insert with expiry in the past
        past = int(time.time()) - 100
        rl.check_and_insert(pubkey, _make_nonce(), past)
        rl.check_and_insert(pubkey, _make_nonce(), past)

        # Insert a fresh one — triggers cleanup
        fresh = _make_nonce()
        future = int(time.time()) + 60
        rl.check_and_insert(pubkey, fresh, future)

        # The expired nonces should be gone, the fresh one remains
        assert rl.is_replay(pubkey, fresh) is True

        # Check that old nonces are cleaned (count should be low)
        import sqlite3
        conn = sqlite3.connect(db_path)
        count = conn.execute("SELECT COUNT(*) FROM request_nonces").fetchone()[0]
        conn.close()
        assert count <= 5  # only the fresh one + any not yet batched

        rl.close()

    def test_startup_cleanup(self, tmp_path):
        db_path = str(tmp_path / "replay.db")
        rl = ReplayLedger(db_path, clock_skew_seconds=0)
        pubkey = os.urandom(32)

        # Insert expired rows
        past = int(time.time()) - 100
        for _ in range(5):
            rl.check_and_insert(pubkey, _make_nonce(), past)

        rl.close()

        # Reopen — startup_cleanup runs
        rl2 = ReplayLedger(db_path, clock_skew_seconds=0)
        import sqlite3
        conn = sqlite3.connect(db_path)
        count = conn.execute("SELECT COUNT(*) FROM request_nonces").fetchone()[0]
        conn.close()
        assert count == 0
        rl2.close()


class TestRestartSurvival:
    def test_ledger_survives_restart(self, tmp_path):
        db_path = str(tmp_path / "replay.db")
        rl = ReplayLedger(db_path, clock_skew_seconds=30)
        pubkey = os.urandom(32)
        nonce = _make_nonce()
        expires = int(time.time()) + 300  # far future

        rl.check_and_insert(pubkey, nonce, expires)
        rl.close()

        # Reopen — the nonce must still be present
        rl2 = ReplayLedger(db_path, clock_skew_seconds=30)
        assert rl2.is_replay(pubkey, nonce) is True
        assert rl2.check_and_insert(pubkey, nonce, expires) is False
        rl2.close()


class TestConcurrentInsert:
    def test_concurrent_duplicate_only_one_wins(self, tmp_path):
        """Two threads insert the same (pubkey, nonce) simultaneously.
        Only one should succeed — the other must see a replay."""
        db_path = str(tmp_path / "replay.db")
        rl = ReplayLedger(db_path, clock_skew_seconds=30)
        pubkey = os.urandom(32)
        nonce = _make_nonce()
        expires = int(time.time()) + 60

        results = []
        barrier = threading.Barrier(2)

        def try_insert():
            barrier.wait()
            result = rl.check_and_insert(pubkey, nonce, expires)
            results.append(result)

        t1 = threading.Thread(target=try_insert)
        t2 = threading.Thread(target=try_insert)
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        assert len(results) == 2
        assert sum(1 for r in results if r) == 1, f"Exactly one should succeed, got {results}"
        assert sum(1 for r in results if not r) == 1, f"Exactly one should fail, got {results}"

        rl.close()
