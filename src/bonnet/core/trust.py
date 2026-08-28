"""Shared origin-key pinning and rotation verification.

Used by both sides: the client pins the origins it talks to, the server pins
its federation peers. Pins live in a SQLite `origin_keys` table, where
`trust_mode` is either 'tofu' (adopted on first contact) or 'configured'
(supplied by the operator and never auto-adopted).

TOFU pinning is a single atomic INSERT OR IGNORE + SELECT, so concurrent
first contact with the same origin converges on one pin instead of racing.

A single-hop rotation is accepted only when the origin is currently pinned
to the old key and the proof verifies against the new key, using the same
domain-separated construction as the rest of the protocol
(record.sign_key_rotation_proof / verify_key_rotation_proof — the new key
attests it consents to succeed the old one; record.py separately requires
the rotate record itself to carry a valid origin signature under the old
key, so acceptance is mutual-consent between old and new).

A multi-hop rotation (the origin rotated more than once since this pin was
last refreshed) is not resolved by verify_rotation alone — the caller
(net.firehose_transport) walks the intermediate hops itself, verifying each
one with record.verify_key_rotation_proof, and only calls accept_rotation()
once to commit the final, fully-verified endpoint.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time

TRUST_MODE_TOFU = "tofu"
TRUST_MODE_CONFIGURED = "configured"


class TrustStore:
    """Atomic origin-key pinning with TOFU and rotation support."""

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._lock = threading.Lock()

        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS origin_keys (
                origin TEXT PRIMARY KEY,
                publickey BLOB NOT NULL,
                first_seen INTEGER NOT NULL,
                last_rotated INTEGER NOT NULL,
                trust_mode TEXT NOT NULL
            )
        """)
        self._conn.commit()

    def get_pin(self, origin: str) -> bytes | None:
        """Return the pinned public key for origin, or None if not pinned."""
        with self._lock:
            cursor = self._conn.execute(
                "SELECT publickey FROM origin_keys WHERE origin=?",
                (origin,),
            )
            row = cursor.fetchone()
            if row and row[0]:
                return bytes(row[0])
            return None

    def get_pin_info(self, origin: str) -> dict | None:
        """Return full pin record: publickey, first_seen, last_rotated, trust_mode."""
        with self._lock:
            cursor = self._conn.execute(
                "SELECT publickey, first_seen, last_rotated, trust_mode FROM origin_keys WHERE origin=?",
                (origin,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "publickey": bytes(row[0]),
                "first_seen": row[1],
                "last_rotated": row[2],
                "trust_mode": row[3],
            }

    def tofu_pin(self, origin: str, publickey: bytes) -> bool:
        """Atomic TOFU: insert if not present, compare if present.

        Returns True if:
          - origin was not pinned and is now pinned (first contact), or
          - origin was already pinned with the same key (repeat contact)
        Returns False if:
          - origin was pinned with a DIFFERENT key (mismatch / potential attack)

        This is a single atomic operation: INSERT OR IGNORE ensures only one
        writer can win the race. The subsequent SELECT returns whatever was
        stored, regardless of who wrote it.
        """
        now = int(time.time())
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO origin_keys (origin, publickey, first_seen, last_rotated, trust_mode) "
                "VALUES (?, ?, ?, ?, ?)",
                (origin, publickey, now, now, TRUST_MODE_TOFU),
            )
            self._conn.commit()

            cursor = self._conn.execute(
                "SELECT publickey FROM origin_keys WHERE origin=?",
                (origin,),
            )
            row = cursor.fetchone()
            if not row:
                return False
            return bytes(row[0]) == publickey

    def configured_pin(self, origin: str, publickey: bytes) -> None:
        """Set a configured (non-TOFU) pin. Overwrites any existing pin."""
        now = int(time.time())
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO origin_keys (origin, publickey, first_seen, last_rotated, trust_mode) "
                "VALUES (?, ?, ?, ?, ?)",
                (origin, publickey, now, now, TRUST_MODE_CONFIGURED),
            )
            self._conn.commit()

    def verify_rotation(
        self, origin: str, old_publickey: bytes, new_publickey: bytes, proof: bytes
    ) -> bool:
        """Verify a single-hop key rotation proof and, if valid, commit it.

        Uses record.verify_key_rotation_proof — the same domain-separated
        construction the server verifies when applying a
        bonnet.origin.key.rotate record, so a proof pulled straight off the
        wire (record.metadata field 2) verifies here unmodified.

        Returns True if:
          - origin is currently pinned with old_publickey, AND
          - the proof verifies against new_publickey over (origin, old, new)
        Returns False otherwise.

        On success, updates the pin to new_publickey and sets last_rotated.
        """
        from bonnet.core.record import verify_key_rotation_proof

        existing = self.get_pin(origin)
        if existing is None or existing != old_publickey:
            return False

        if not verify_key_rotation_proof(new_publickey, origin, old_publickey, proof):
            return False

        return self.accept_rotation(origin, old_publickey, new_publickey)

    def accept_rotation(
        self, origin: str, expected_old_publickey: bytes, new_publickey: bytes
    ) -> bool:
        """Commit a pin update for a rotation already verified by the caller.

        No cryptographic check happens here — this is the low-level CAS
        primitive verify_rotation uses for the single-hop case, and that
        net.firehose_transport's multi-hop chain walk calls directly once it
        has independently verified every intermediate hop (a single proof
        cannot attest a multi-hop jump, so verify_rotation's own check does
        not apply there).

        Returns True if the origin was still pinned to expected_old_publickey
        and the update was applied; False otherwise (pin already moved, e.g.
        a concurrent rotation).
        """
        now = int(time.time())
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE origin_keys SET publickey=?, last_rotated=? WHERE origin=? AND publickey=?",
                (new_publickey, now, origin, expected_old_publickey),
            )
            if cursor.rowcount == 0:
                return False
            self._conn.commit()
        return True

    def reset_pin(self, origin: str) -> bool:
        """Remove a pin (operator-initiated reset). Returns True if a pin was removed."""
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM origin_keys WHERE origin=?",
                (origin,),
            )
            self._conn.commit()
            return cursor.rowcount > 0

    def list_pins(self) -> list[dict]:
        """List all pinned origins."""
        with self._lock:
            cursor = self._conn.execute(
                "SELECT origin, publickey, first_seen, last_rotated, trust_mode FROM origin_keys"
            )
            return [
                {
                    "origin": row[0],
                    "publickey": bytes(row[1]),
                    "first_seen": row[2],
                    "last_rotated": row[3],
                    "trust_mode": row[4],
                }
                for row in cursor.fetchall()
            ]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
