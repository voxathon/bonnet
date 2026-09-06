# Copyright 2026 The Bonnet Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Persistent replay-prevention ledger.

Before dispatching an authenticated command the server atomically records
(client_public_key, nonce, expires_at); a duplicate is rejected with 409 and
never dispatched.

The ledger is SQLite under data_dir, so a process restart does not reopen the
validity window. Rows survive until expires_at + clock_skew_seconds has
passed, and expired rows are removed in bounded batches after successful
insertions and at startup.

    CREATE TABLE request_nonces (
        publickey BLOB NOT NULL,
        nonce BLOB NOT NULL,
        expires_at INTEGER NOT NULL,
        PRIMARY KEY (publickey, nonce)
    );
    CREATE INDEX request_nonces_expiry ON request_nonces (expires_at);

The check-and-insert is INSERT OR IGNORE plus a rows-affected check: zero
rows affected means the (publickey, nonce) pair already exists, i.e. a replay.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time


class ReplayLedger:
    """SQLite-backed nonce ledger with atomic insert-or-reject."""

    def __init__(self, db_path: str, clock_skew_seconds: int = 300):
        self._db_path = db_path
        self._clock_skew = clock_skew_seconds
        self._lock = threading.Lock()

        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._init_schema()
        self.startup_cleanup()

    def _init_schema(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS request_nonces (
                publickey BLOB NOT NULL,
                nonce BLOB NOT NULL,
                expires_at INTEGER NOT NULL,
                PRIMARY KEY (publickey, nonce)
            )
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS request_nonces_expiry
            ON request_nonces (expires_at)
        """)
        self._conn.commit()

    def check_and_insert(self, publickey: bytes, nonce: str, expires_at: int) -> bool:
        """Atomically insert (publickey, nonce, expires_at).

        Returns True if the insert succeeded (not a replay).
        Returns False if the (publickey, nonce) pair already exists (replay).

        The nonce is stored as raw bytes (decoded from base64url) to ensure
        canonical comparison regardless of encoding variations.
        """
        import base64

        padded = nonce + "=" * (-len(nonce) % 4)
        try:
            nonce_bytes = base64.urlsafe_b64decode(padded)
        except Exception:
            nonce_bytes = nonce.encode("utf-8")

        with self._lock:
            cursor = self._conn.execute(
                "INSERT OR IGNORE INTO request_nonces (publickey, nonce, expires_at) VALUES (?, ?, ?)",
                (publickey, nonce_bytes, expires_at),
            )
            inserted = cursor.rowcount > 0
            self._conn.commit()

            if inserted:
                self._cleanup_batch()

            return inserted

    def is_replay(self, publickey: bytes, nonce: str) -> bool:
        """Check if (publickey, nonce) already exists without inserting."""
        import base64

        padded = nonce + "=" * (-len(nonce) % 4)
        try:
            nonce_bytes = base64.urlsafe_b64decode(padded)
        except Exception:
            nonce_bytes = nonce.encode("utf-8")

        with self._lock:
            cursor = self._conn.execute(
                "SELECT 1 FROM request_nonces WHERE publickey=? AND nonce=?",
                (publickey, nonce_bytes),
            )
            return cursor.fetchone() is not None

    def _cleanup_batch(self, batch_size: int = 100) -> int:
        """Remove expired rows in bounded batches. Returns count deleted.

        A row must survive until expires_at + clock_skew has passed (see
        module docstring) — the same tolerance _check_temporal grants an
        incoming request past its nominal expiry. The cutoff is therefore
        now - clock_skew, not now + clock_skew: a row is eligible for
        deletion only once `now` is clock_skew seconds *past* its expiry,
        not while it's still within clock_skew of expiring. Getting the
        sign wrong here silently deletes a nonce's row while a replay of
        the exact same still-temporally-valid request would still pass
        _check_temporal, defeating replay protection for it.
        """
        cutoff = int(time.time()) - self._clock_skew
        cursor = self._conn.execute(
            "DELETE FROM request_nonces WHERE expires_at < ? AND rowid IN "
            "(SELECT rowid FROM request_nonces WHERE expires_at < ? LIMIT ?)",
            (cutoff, cutoff, batch_size),
        )
        self._conn.commit()
        return cursor.rowcount

    def startup_cleanup(self) -> int:
        """Remove all expired rows on startup. Returns count deleted."""
        return self._cleanup_batch(batch_size=10000)

    def close(self) -> None:
        with self._lock:
            self._conn.close()
