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

"""Origin-key pinning and rotation verification.

Used by the gateway, to pin the origins it talks to. Federation sync does
*not* use this — `net.firehose_sync` builds its transport without a trust
store, and the server's own peer-key trust lives in the firehose's
`origin_key_epochs` table under a separate rotation-proof scheme. (This
docstring previously claimed the server pinned its peers here. It does not.)

Pins live in a SQLite `origin_keys` table, where `trust_mode` is either 'tofu'
(adopted on first contact) or 'configured' (supplied by the operator and never
auto-adopted). A second table, `pending_keys`, holds a key that has been
*presented but not adopted*, for the confirm/decline gate in
`gateway.tools.trust_origin_key`. It is a separate table rather than another
`trust_mode` value because `origin_keys` is keyed by origin, and a candidate
for an origin that is already pinned has to coexist with the live pin rather
than replace it.

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
        # A key presented and awaiting a decision. Never consulted when
        # deciding whether a connection is trusted — only origin_keys is —
        # so a stale row here can delay nothing and authorise nothing.
        # `url` and `verify_tls` are how the key was presented. Kept because
        # on first contact nothing else has recorded them yet — the origin is
        # in no joined list — so without them, accepting would have nowhere to
        # reconnect to, and would silently reconnect under different TLS
        # settings than the connection that raised the question.
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS pending_keys (
                origin TEXT PRIMARY KEY,
                publickey BLOB NOT NULL,
                kind TEXT NOT NULL,
                evidence TEXT NOT NULL DEFAULT '',
                url TEXT NOT NULL DEFAULT '',
                verify_tls TEXT NOT NULL DEFAULT 'true',
                seen_at INTEGER NOT NULL
            )
        """)
        # Which key was authoritative over which stretch of an origin's log.
        # A pin answers "who is this origin *now*", which is enough to verify
        # a live connection and not enough to verify a record: seq 400 was
        # countersigned by whatever key was current at seq 400, and after a
        # rotation that is no longer the pinned one.
        #
        # Cached rather than fetched at verification time, and that is the
        # point. Asking the origin for its key history in order to check its
        # records makes verification depend on the origin still being
        # reachable and still willing to answer — and an origin that has gone
        # quiet is indistinguishable from one that is withholding, so a
        # fetch-on-demand design cannot even report which happened. Held here,
        # the history outlives the origin.
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS origin_key_epochs (
                origin TEXT NOT NULL,
                start_seq INTEGER NOT NULL,
                end_seq INTEGER,
                publickey BLOB NOT NULL,
                cached_at INTEGER NOT NULL,
                PRIMARY KEY (origin, start_seq)
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

    # ------------------------------------------------------------------
    # Pending candidates: presented, not adopted
    # ------------------------------------------------------------------

    def record_pending(
        self,
        origin: str,
        publickey: bytes,
        kind: str,
        evidence: str = "",
        url: str = "",
        verify_tls: str = "true",
    ) -> None:
        """Remember a key awaiting a decision, replacing any earlier candidate.

        Replacing rather than accumulating: only the most recently presented
        key can be the one a caller is being asked about, and keeping older
        candidates around would let a decision be confirmed against a key that
        is no longer on offer.
        """
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO pending_keys "
                "(origin, publickey, kind, evidence, url, verify_tls, seen_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (origin, publickey, kind, evidence, url, verify_tls, int(time.time())),
            )
            self._conn.commit()

    def get_pending(self, origin: str) -> dict | None:
        """The key awaiting a decision for `origin`, or None."""
        with self._lock:
            row = self._conn.execute(
                "SELECT publickey, kind, evidence, url, verify_tls, seen_at"
                " FROM pending_keys WHERE origin=?",
                (origin,),
            ).fetchone()
        if not row:
            return None
        return {
            "publickey": bytes(row[0]),
            "kind": row[1],
            "evidence": row[2],
            "url": row[3],
            "verify_tls": row[4],
            "seen_at": row[5],
        }

    def list_pending(self) -> list[dict]:
        """Every origin with a decision outstanding, oldest first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT origin, publickey, kind, evidence, url, verify_tls, seen_at"
                " FROM pending_keys ORDER BY seen_at"
            ).fetchall()
        return [
            {
                "origin": r[0],
                "publickey": bytes(r[1]),
                "kind": r[2],
                "evidence": r[3],
                "url": r[4],
                "verify_tls": r[5],
                "seen_at": r[6],
            }
            for r in rows
        ]

    def clear_pending(self, origin: str) -> bool:
        """Drop a pending candidate. True if one was there."""
        with self._lock:
            cursor = self._conn.execute("DELETE FROM pending_keys WHERE origin=?", (origin,))
            self._conn.commit()
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Key epochs: which key signed which stretch of the log
    # ------------------------------------------------------------------

    def cache_epochs(self, origin: str, epochs: list[tuple[int, int | None, bytes]]) -> None:
        """Replace the cached epoch table for an origin.

        The caller is responsible for having *verified* these — see
        `FirehoseTransport.refresh_epoch_cache`, which re-fetches every
        boundary as a full record and checks its signature and rotation proof
        before handing them here. Nothing in this store can tell a verified
        table from an invented one, so it does not pretend to.

        Replace rather than merge: an epoch table is one coherent account of a
        key history, and splicing two of them together could produce a chain
        that neither party ever attested to.
        """
        now = int(time.time())
        with self._lock:
            self._conn.execute("DELETE FROM origin_key_epochs WHERE origin=?", (origin,))
            self._conn.executemany(
                "INSERT INTO origin_key_epochs (origin, start_seq, end_seq, publickey, cached_at) "
                "VALUES (?, ?, ?, ?, ?)",
                [(origin, start, end, pubkey, now) for start, end, pubkey in epochs],
            )
            self._conn.commit()

    def get_cached_epochs(self, origin: str) -> list[tuple[int, int | None, bytes]]:
        """The cached epoch table, ascending. Empty when nothing is cached."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT start_seq, end_seq, publickey FROM origin_key_epochs "
                "WHERE origin=? ORDER BY start_seq",
                (origin,),
            ).fetchall()
        return [(int(r[0]), int(r[1]) if r[1] is not None else None, bytes(r[2])) for r in rows]

    def key_for_seq(self, origin: str, seq: int) -> bytes | None:
        """The key that was authoritative at `seq`, or None if not known.

        None is a real answer, not a failure to be papered over: without an
        epoch covering that sequence a caller cannot say whether a signature is
        forged or merely checked against the wrong key, and reporting the
        second as the first would be an accusation this client cannot support.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT publickey FROM origin_key_epochs "
                "WHERE origin=? AND start_seq<=? AND (end_seq IS NULL OR end_seq>=?) "
                "ORDER BY start_seq DESC LIMIT 1",
                (origin, seq, seq),
            ).fetchone()
            return bytes(row[0]) if row else None

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
