"""Shared origin-key pinning and rotation verification.

PROTOCOL_RENOVATION_PLAN §12.2:
  The client identity database needs a separate trust table:
    CREATE TABLE origin_keys (
        origin TEXT PRIMARY KEY,
        publickey BLOB NOT NULL,
        first_seen INTEGER NOT NULL,
        last_rotated INTEGER NOT NULL,
        trust_mode TEXT NOT NULL
    );

  trust_mode initially supports 'tofu' and 'configured'.

  TOFU insertion and comparison must be one atomic database operation.
  The shared trust implementation must replace the current read-then-insert
  behavior and include a concurrent first-contact test.

This module replaces the racy SyncDB.set_peer_pubkey_tofu (read-then-insert)
with an atomic INSERT OR IGNORE + SELECT pattern. Both client origin pins
and server peer-key pins use this implementation.

Rotation verification mirrors SyncDB.rotate_peer_pubkey:
  payload = struct.pack('B', len(origin_bytes)) + origin_bytes + old_pubkey + new_pubkey
  verified with Identity.verify(old_pubkey, payload, signature)
"""

from __future__ import annotations

import os
import sqlite3
import struct
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

    def verify_rotation(self, origin: str, old_publickey: bytes, new_publickey: bytes, signature: bytes) -> bool:
        """Verify a key rotation signed by the old pinned key.

        The canonical rotation payload is:
          struct.pack('B', len(origin_bytes)) + origin_bytes + old_pubkey + new_pubkey

        Returns True if:
          - origin is currently pinned with old_publickey, AND
          - the signature verifies against old_publickey over the payload
        Returns False otherwise.

        On success, updates the pin to new_publickey and sets last_rotated.
        """
        from core.crypto import Identity

        existing = self.get_pin(origin)
        if existing is None or existing != old_publickey:
            return False

        origin_bytes = origin.encode("utf-8")
        payload = struct.pack("B", len(origin_bytes)) + origin_bytes + old_publickey + new_publickey

        if not Identity.verify(old_publickey, payload, signature):
            return False

        now = int(time.time())
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE origin_keys SET publickey=?, last_rotated=? "
                "WHERE origin=? AND publickey=?",
                (new_publickey, now, origin, old_publickey),
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
