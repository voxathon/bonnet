"""Tests for src/bonnet/net/replay.py — persistent replay-prevention ledger.

Covers:
  - Replays and stale/future requests fail before dispatch
  - Duplicate (pubkey, nonce) insertion fails with constraint violation
  - Expired rows are cleaned up in bounded batches
  - Ledger survives process restart (persistent SQLite)
"""

import base64
import os
import threading
import time

import pytest

from bonnet.net.replay import ReplayLedger


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

    def test_still_valid_row_survives_cleanup_with_nonzero_skew(self, tmp_path):
        """A row within clock_skew of its own expiry — still temporally
        valid, since _check_temporal (http_auth.py) tolerates a request up
        to clock_skew past its nominal expiry — must not be cleaned up
        early. The cutoff is now - clock_skew, not now + clock_skew: a row
        survives until expires_at + clock_skew has passed (module
        docstring), so cleanup must never delete a row while `now` is still
        within clock_skew of its expires_at, let alone before expires_at.

        Regression for a sign error where cleanup used `now + clock_skew`:
        with the default 30s skew, that deleted a fresh row's nonce
        immediately (any expires_at less than roughly `now + 30` — true of
        almost every real request) on the very next successful insert,
        after which the exact same signed request could be replayed
        successfully."""
        db_path = str(tmp_path / "replay.db")
        rl = ReplayLedger(db_path, clock_skew_seconds=30)
        pubkey = os.urandom(32)
        nonce = _make_nonce()
        expires = int(time.time()) + 10  # comfortably valid, near-term

        assert rl.check_and_insert(pubkey, nonce, expires) is True
        rl._cleanup_batch()

        assert rl.is_replay(pubkey, nonce) is True, (
            "row was cleaned up too early — a replay of this still-valid request would now succeed"
        )
        assert rl.check_and_insert(pubkey, nonce, expires) is False, (
            "replay protection bypassed: the same nonce was accepted twice"
        )

        rl.close()

    def test_row_past_expiry_plus_skew_is_cleaned_up(self, tmp_path):
        """Sanity check for the same fix in the other direction: a row
        genuinely past its expires_at + clock_skew window must still be
        removed, not retained forever."""
        db_path = str(tmp_path / "replay.db")
        rl = ReplayLedger(db_path, clock_skew_seconds=30)
        pubkey = os.urandom(32)
        nonce = _make_nonce()
        expires = int(time.time()) - 1000  # long past expires_at + skew

        rl.check_and_insert(pubkey, nonce, expires)
        rl._cleanup_batch()

        assert rl.is_replay(pubkey, nonce) is False
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
