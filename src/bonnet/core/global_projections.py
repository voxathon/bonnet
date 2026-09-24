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

"""Global projections for the firehose protocol.

nav.db     — board directory from bonnet.board.create/close/reopen
users.db   — user registrations and revocations
policy.db  — rules, reports, punishments, revocations, effective-state
routes.db  — transitive peer-discovery dial addresses from bonnet.route.*

All four are rebuildable projections containing applied_events and
per-origin checkpoints. They are never authoritative.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time

from bonnet.core.hostname import normalize_hostname
from bonnet.core.kind_validator import identity_text_violation
from bonnet.core.kinds import PUNISHMENT_TYPE_BY_KIND  # noqa: F401 (re-exported)
from bonnet.core.logging import log_msg
from bonnet.core.record import MetadataMap, Record, verify_key_rotation_proof

# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------


class _BaseProjection:
    """Common applied-events and checkpoint management."""

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._lock = threading.RLock()
        d = os.path.dirname(db_path)
        if d:
            os.makedirs(d, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._init_common()
        self._init_schema()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _init_common(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS applied_events (
                event_id    BLOB NOT NULL,
                origin      TEXT NOT NULL,
                origin_seq  INTEGER NOT NULL,
                kind        TEXT NOT NULL,
                applied_at  INTEGER NOT NULL,
                PRIMARY KEY (origin, event_id)
            );
            CREATE TABLE IF NOT EXISTS projection_checkpoint (
                origin      TEXT PRIMARY KEY,
                last_applied_seq INTEGER NOT NULL DEFAULT 0
            );
        """)

    def _init_schema(self) -> None:
        pass

    def is_applied(self, origin: str, event_id: bytes) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM applied_events WHERE origin=? AND event_id=?",
                (
                    origin,
                    event_id,
                ),
            ).fetchone()
            return row is not None

    def _mark_applied(self, rec: Record) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO applied_events "
            "(event_id, origin, origin_seq, kind, applied_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (rec.event_id, rec.origin, rec.origin_seq, rec.kind, int(time.time())),
        )

    def apply_unknown(self, rec: Record) -> None:
        """Record an unknown kind as applied (no projection effect)."""
        with self._lock:
            if self.is_applied(rec.origin, rec.event_id):
                return
            self._begin()
            try:
                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._commit()
            except Exception:
                self._rollback()
                raise

    def get_checkpoint(self, origin: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT last_applied_seq FROM projection_checkpoint WHERE origin=?",
                (origin,),
            ).fetchone()
            return row[0] if row else 0

    def set_checkpoint(self, origin: str, seq: int) -> None:
        with self._lock:
            self._set_checkpoint(origin, seq)
            self._conn.commit()

    def _set_checkpoint(self, origin: str, seq: int) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO projection_checkpoint (origin, last_applied_seq) VALUES (?, ?)",
            (origin, seq),
        )

    def _begin(self) -> None:
        self._conn.execute("BEGIN IMMEDIATE")

    def _commit(self) -> None:
        self._conn.execute("COMMIT")

    def _rollback(self) -> None:
        try:
            self._conn.execute("ROLLBACK")
        except Exception:
            pass

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("DELETE FROM applied_events")
                self._conn.execute("DELETE FROM projection_checkpoint")
                self._conn.execute("COMMIT")
            except Exception:
                self._rollback()
                raise

    def clear_origin(self, origin: str) -> None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("DELETE FROM applied_events WHERE origin=?", (origin,))
                self._conn.execute("DELETE FROM projection_checkpoint WHERE origin=?", (origin,))
                self._conn.execute("COMMIT")
            except Exception:
                self._rollback()
                raise


# ---------------------------------------------------------------------------
# NavProjection — board directory
# ---------------------------------------------------------------------------


class NavProjection(_BaseProjection):
    """Board directory projection from board lifecycle records."""

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS boards (
                origin          TEXT NOT NULL,
                board           TEXT NOT NULL,
                owner_pubkey    BLOB NOT NULL,
                display_name    TEXT NOT NULL DEFAULT '',
                closed          INTEGER NOT NULL DEFAULT 0,
                created_seq     INTEGER NOT NULL,
                created_at      INTEGER NOT NULL,
                PRIMARY KEY (origin, board)
            );
        """)

    def apply_board_create(self, rec: Record) -> None:
        """Materialize a board.create record into the listable directory.

        First writer wins, same rule and same reason as apply_user_register:
        a record is only ever proof of who *signed* a claim, not that the
        claim is authorized. A second, later board.create for a name someone
        else already holds is a perfectly valid signature over an invalid
        claim — `firehose_commands` refuses the same case at publish time for
        a local caller, but that check never sees a federated record, so the
        rule has to be enforced here too, independent of where the record
        came from.

        A record synced from federation never passes through KindValidator
        (see kind_validator._validate_identity_text's docstring) — this is
        the actual enforcement point for a federated board name carrying a
        control character or reserved character. It is not rejected: the
        record stays accepted in the firehose and keeps relaying normally,
        it simply never gets a row here, so it never surfaces through
        BOARD_LIST/list-boards into a display surface. The event is still
        fetchable directly by event_id for forensics.
        """
        with self._lock:
            if self.is_applied(rec.origin, rec.event_id):
                return
            self._begin()
            try:
                violation = identity_text_violation(rec.board)
                if violation is not None:
                    log_msg(
                        f"SECURITY: BOARD_CREATE: origin={rec.origin!r} seq={rec.origin_seq} "
                        f"event_id={rec.event_id.hex()[:16]} board={rec.board!r} "
                        f"REJECTED FROM PROJECTION ({violation}) — record stays in the "
                        f"firehose and keeps relaying, but will never be listed"
                    )
                    self._mark_applied(rec)
                    self._set_checkpoint(rec.origin, rec.origin_seq)
                    self._commit()
                    return

                owner = rec.metadata.get_bytes(1) or b"\x00" * 32
                display = rec.metadata.get_text(2) or ""

                existing = self._conn.execute(
                    "SELECT owner_pubkey FROM boards WHERE origin=? AND board=?",
                    (rec.origin, rec.board),
                ).fetchone()
                if existing is not None and bytes(existing[0]) != owner:
                    log_msg(
                        f"SECURITY: BOARD_CREATE: origin={rec.origin!r} seq={rec.origin_seq} "
                        f"board={rec.board!r} already owned by "
                        f"{bytes(existing[0]).hex()[:16]}; claim by "
                        f"{owner.hex()[:16]} not applied"
                    )
                    self._mark_applied(rec)
                    self._set_checkpoint(rec.origin, rec.origin_seq)
                    self._commit()
                    return

                self._conn.execute(
                    "INSERT OR REPLACE INTO boards "
                    "(origin, board, owner_pubkey, display_name, closed, created_seq, created_at) "
                    "VALUES (?, ?, ?, ?, 0, ?, ?)",
                    (rec.origin, rec.board, owner, display, rec.origin_seq, rec.created_at),
                )
                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._commit()
            except Exception:
                self._rollback()
                raise

    def apply_board_close(self, rec: Record) -> None:
        with self._lock:
            if self.is_applied(rec.origin, rec.event_id):
                return
            self._begin()
            try:
                self._conn.execute(
                    "UPDATE boards SET closed=1 WHERE origin=? AND board=?",
                    (rec.origin, rec.board),
                )
                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._commit()
            except Exception:
                self._rollback()
                raise

    def apply_board_reopen(self, rec: Record) -> None:
        with self._lock:
            if self.is_applied(rec.origin, rec.event_id):
                return
            self._begin()
            try:
                self._conn.execute(
                    "UPDATE boards SET closed=0 WHERE origin=? AND board=?",
                    (rec.origin, rec.board),
                )
                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._commit()
            except Exception:
                self._rollback()
                raise

    def apply_board_purge(self, rec: Record) -> None:
        """Drop a board entry so its name may be reclaimed.

        Row-delete (not a tombstone flag): a later board.create for the
        empty name wins by the ordinary first-writer rule, in origin
        sequence order. Second purge is a success no-op. Never raises out
        of apply — same contract as close/reopen.
        """
        with self._lock:
            if self.is_applied(rec.origin, rec.event_id):
                return
            self._begin()
            try:
                self._conn.execute(
                    "DELETE FROM boards WHERE origin=? AND board=?",
                    (rec.origin, rec.board),
                )
                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._commit()
            except Exception:
                self._rollback()
                raise

    def list_boards(self, origin: str = None) -> list[dict]:
        with self._lock:
            if origin:
                rows = self._conn.execute(
                    "SELECT origin, board, owner_pubkey, display_name, closed, created_seq "
                    "FROM boards WHERE origin=? ORDER BY board ASC",
                    (origin,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT origin, board, owner_pubkey, display_name, closed, created_seq "
                    "FROM boards ORDER BY origin ASC, board ASC"
                ).fetchall()
            return [
                {
                    "origin": r[0],
                    "board": r[1],
                    "owner_pubkey": bytes(r[2]),
                    "display_name": r[3],
                    "closed": bool(r[4]),
                    "created_seq": r[5],
                }
                for r in rows
            ]

    def get_board(self, origin: str, board: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT origin, board, owner_pubkey, display_name, closed, created_seq "
                "FROM boards WHERE origin=? AND board=?",
                (origin, board),
            ).fetchone()
            if not row:
                return None
            return {
                "origin": row[0],
                "board": row[1],
                "owner_pubkey": bytes(row[2]),
                "display_name": row[3],
                "closed": bool(row[4]),
                "created_seq": row[5],
            }

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("DELETE FROM boards")
                self._conn.execute("DELETE FROM applied_events")
                self._conn.execute("DELETE FROM projection_checkpoint")
                self._conn.execute("COMMIT")
            except Exception:
                self._rollback()
                raise

    def clear_origin(self, origin: str) -> None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("DELETE FROM boards WHERE origin=?", (origin,))
                self._conn.execute("DELETE FROM applied_events WHERE origin=?", (origin,))
                self._conn.execute("DELETE FROM projection_checkpoint WHERE origin=?", (origin,))
                self._conn.execute("COMMIT")
            except Exception:
                self._rollback()
                raise


# ---------------------------------------------------------------------------
# UserProjection — user registrations
# ---------------------------------------------------------------------------


class UserProjection(_BaseProjection):
    """User registration and revocation projection."""

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                origin          TEXT NOT NULL,
                user_pubkey     BLOB NOT NULL,
                username        TEXT NOT NULL,
                flags           INTEGER NOT NULL DEFAULT 0,
                reg_seq         INTEGER NOT NULL,
                created_at      INTEGER NOT NULL,
                revoked         INTEGER NOT NULL DEFAULT 0,
                revoked_seq     INTEGER,
                PRIMARY KEY (origin, user_pubkey)
            );
            CREATE INDEX IF NOT EXISTS idx_users_username
                ON users(username, origin);

            -- Actor key successions. A separate table rather than a column on
            -- `users` on purpose: _init_schema runs on every open, so a new
            -- table costs nothing, while altering `users` would mean a
            -- migration, and every migration here is tempted to clear
            -- applied_events/projection_checkpoint — which are shared by the
            -- whole projection, so it would silently replay unrelated kinds.
            --
            -- Not a denormalization either. old_pubkey is the rotate record's
            -- own actor_pubkey and new_pubkey its metadata field 1; event_id
            -- points back at the signed artifact those came from.
            CREATE TABLE IF NOT EXISTS user_key_rotations (
                origin       TEXT NOT NULL,
                old_pubkey   BLOB NOT NULL,
                new_pubkey   BLOB NOT NULL,
                rotated_seq  INTEGER NOT NULL,
                event_id     BLOB NOT NULL,
                PRIMARY KEY (origin, old_pubkey)
            );
        """)

    def username_holder(self, origin: str, username: str) -> bytes | None:
        """The key holding `username` at `origin`, or None if it is free.

        Revoked registrations do not hold a name — revocation frees it, or a
        squatter would burn every good name permanently. Neither do
        superseded keys: `apply_user_key_rotate` carries the name forward to
        the successor, so only the live head holds it. The old row survives
        so records signed by the retired key still resolve a username, but
        it must never win the holder lookup — otherwise the retired key
        (lower reg_seq) shadows its own successor.

        A federated registration whose username carries a control character
        or reserved character is likewise never bound here — see
        apply_user_register.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT u.user_pubkey FROM users u "
                "LEFT JOIN user_key_rotations r "
                "  ON r.origin = u.origin AND r.old_pubkey = u.user_pubkey "
                "WHERE u.origin=? AND u.username=? AND u.revoked=0 "
                "AND r.new_pubkey IS NULL "
                "ORDER BY u.reg_seq DESC LIMIT 1",
                (origin, username),
            ).fetchone()
            return bytes(row[0]) if row else None

    def apply_user_register(self, rec: Record) -> None:
        """Bind a username to a key at this origin, first writer wins.

        A name already held by a *different* live key is not reassigned; the
        record stays in the firehose and is still relayed, it simply does not
        take the name here. `firehose_commands` refuses the same case at publish
        time so a local caller gets an error rather than silence, but this check
        has to exist independently: federated registrations never pass through
        that handler.

        First-writer-wins is deterministic only because dispatch is ordered.
        `Dispatcher.dispatch_origin` walks records in strict origin_seq order
        and `rebuild_all` replays in that same order, so the winner is a
        property of the log rather than of arrival timing. **Do not parallelize
        dispatch within an origin** without replacing this rule with one that
        does not depend on order.
        """
        with self._lock:
            if self.is_applied(rec.origin, rec.event_id):
                return
            self._begin()
            try:
                username = rec.metadata.get_text(1) or ""
                user_pubkey = rec.metadata.get_bytes(2) or b"\x00" * 32
                flags = rec.metadata.get_u64(3) or 0
                reg_seq = rec.origin_seq

                violation = identity_text_violation(username)
                if violation is not None:
                    log_msg(
                        f"SECURITY: USER_REGISTER: origin={rec.origin!r} seq={rec.origin_seq} "
                        f"event_id={rec.event_id.hex()[:16]} username={username!r} "
                        f"REJECTED FROM PROJECTION ({violation}) — record stays in the "
                        f"firehose and keeps relaying, but the username will never be bound"
                    )
                    self._mark_applied(rec)
                    self._set_checkpoint(rec.origin, rec.origin_seq)
                    self._commit()
                    return

                holder = self._conn.execute(
                    "SELECT u.user_pubkey FROM users u "
                    "LEFT JOIN user_key_rotations r "
                    "  ON r.origin = u.origin AND r.old_pubkey = u.user_pubkey "
                    "WHERE u.origin=? AND u.username=? AND u.revoked=0 "
                    "AND r.new_pubkey IS NULL "
                    "ORDER BY u.reg_seq DESC LIMIT 1",
                    (rec.origin, username),
                ).fetchone()
                if holder is not None and bytes(holder[0]) != user_pubkey:
                    log_msg(
                        f"USER_REGISTER: origin='{rec.origin}' seq={rec.origin_seq} "
                        f"username={username!r} already held by "
                        f"{bytes(holder[0]).hex()[:16]}; registration not applied"
                    )
                    self._mark_applied(rec)
                    self._set_checkpoint(rec.origin, rec.origin_seq)
                    self._commit()
                    return

                self._conn.execute(
                    "INSERT OR REPLACE INTO users "
                    "(origin, user_pubkey, username, flags, reg_seq, created_at, revoked) "
                    "VALUES (?, ?, ?, ?, ?, ?, 0)",
                    (rec.origin, user_pubkey, username, flags, reg_seq, rec.created_at),
                )
                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._commit()
            except Exception:
                self._rollback()
                raise

    def apply_user_revoke(self, rec: Record) -> None:
        with self._lock:
            if self.is_applied(rec.origin, rec.event_id):
                return
            self._begin()
            try:
                # Same-origin guard, matching board_projection.py's control
                # kinds: a remote origin cannot revoke a user it doesn't
                # own, even via replication. Without this, any origin could
                # publish a user.revoke naming another origin as the target
                # and silently revoke that origin's user once this record
                # propagates and is dispatched here.
                if rec.origin != rec.target_origin:
                    self._mark_applied(rec)
                    self._set_checkpoint(rec.origin, rec.origin_seq)
                    self._commit()
                    return
                revoked_pubkey = rec.metadata.get_bytes(1) or b"\x00" * 32
                self._conn.execute(
                    "UPDATE users SET revoked=1, revoked_seq=? WHERE origin=? AND user_pubkey=?",
                    (rec.origin_seq, rec.target_origin, revoked_pubkey),
                )
                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._commit()
            except Exception:
                self._rollback()
                raise

    def apply_user_key_rotate(self, rec: Record) -> None:
        """Succeed an actor's signing key, carrying its identity forward.

        Defensive throughout, because this runs on federated records too and
        `accept_remote_range` never invokes KindValidator — only a locally
        published record has been schema-checked by the time it lands here. A
        malformed or unprovable rotate is marked applied and dropped rather
        than raised: `Dispatcher.dispatch_origin` stops at the first exception
        and leaves the checkpoint behind, so raising would wedge every later
        record from that origin on one bad input.
        """
        with self._lock:
            if self.is_applied(rec.origin, rec.event_id):
                return
            self._begin()
            try:
                old_pubkey = rec.actor_pubkey
                new_pubkey = rec.metadata.get_bytes(1)
                proof = rec.metadata.get_bytes(2)

                # Scoped by lookup rather than by a claimed field: rows are
                # keyed (origin, user_pubkey) and written at rec.origin, so
                # an origin can only ever rotate a key registered with it.
                # A rotate for a key this origin never registered names no
                # row here and is not ours to apply.
                row = self._conn.execute(
                    "SELECT username, flags, created_at FROM users "
                    "WHERE origin=? AND user_pubkey=?",
                    (rec.origin, old_pubkey),
                ).fetchone()

                if (
                    new_pubkey is None
                    or proof is None
                    or row is None
                    or new_pubkey == old_pubkey
                    or not verify_key_rotation_proof(new_pubkey, rec.origin, old_pubkey, proof)
                ):
                    log_msg(
                        f"USER_ROTATE: origin='{rec.origin}' "
                        f"old={old_pubkey.hex()[:16]} rejected "
                        f"(unregistered, malformed, or proof invalid)"
                    )
                    self._mark_applied(rec)
                    self._set_checkpoint(rec.origin, rec.origin_seq)
                    self._commit()
                    return

                username, flags, created_at = row[0], row[1], row[2]

                # A key is single-use per origin: rotating onto a key this
                # origin has ever registered — a previous key of this user,
                # another user's key, a revoked key — would either cycle the
                # succession (both keys reading superseded, nobody able to
                # authenticate) or silently merge two identities. Drop it
                # rather than raise, for the same wedge-avoidance reason as
                # every other defensive return in this method.
                prior = self._conn.execute(
                    "SELECT 1 FROM users WHERE origin=? AND user_pubkey=?",
                    (rec.origin, new_pubkey),
                ).fetchone()
                if prior is not None:
                    log_msg(
                        f"USER_ROTATE: origin='{rec.origin}' "
                        f"old={old_pubkey.hex()[:16]} new={new_pubkey.hex()[:16]} rejected "
                        f"(new key already registered at this origin)"
                    )
                    self._mark_applied(rec)
                    self._set_checkpoint(rec.origin, rec.origin_seq)
                    self._commit()
                    return

                self._conn.execute(
                    "INSERT OR REPLACE INTO user_key_rotations "
                    "(origin, old_pubkey, new_pubkey, rotated_seq, event_id) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (rec.origin, old_pubkey, new_pubkey, rec.origin_seq, rec.event_id),
                )

                # The old row stays, so records signed by the retired key
                # still resolve a username. Its successor is what retires it
                # for authentication — see get_user_by_pubkey.
                self._conn.execute(
                    "INSERT OR REPLACE INTO users "
                    "(origin, user_pubkey, username, flags, reg_seq, created_at, revoked) "
                    "VALUES (?, ?, ?, ?, ?, ?, 0)",
                    (rec.origin, new_pubkey, username, flags, rec.origin_seq, created_at),
                )

                log_msg(
                    f"USER_ROTATE: origin='{rec.origin}' username='{username}' "
                    f"old={old_pubkey.hex()[:16]} new={new_pubkey.hex()[:16]} "
                    f"seq={rec.origin_seq}"
                )
                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._commit()
            except Exception:
                self._rollback()
                raise

    def get_user_by_pubkey(self, origin: str, pubkey: bytes) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT u.origin, u.user_pubkey, u.username, u.flags, u.reg_seq, "
                "u.created_at, u.revoked, u.revoked_seq, r.new_pubkey "
                "FROM users u "
                "LEFT JOIN user_key_rotations r "
                "  ON r.origin = u.origin AND r.old_pubkey = u.user_pubkey "
                "WHERE u.origin=? AND u.user_pubkey=?",
                (origin, pubkey),
            ).fetchone()
            if not row:
                return None
            return {
                "origin": row[0],
                "user_pubkey": bytes(row[1]),
                "username": row[2],
                "flags": row[3],
                "reg_seq": row[4],
                "created_at": row[5],
                "revoked": bool(row[6]),
                "revoked_seq": row[7],
                # Set once this key has been succeeded. Kept distinct from
                # `revoked` so a moderator revocation and a voluntary
                # rotation stay tellable apart.
                "superseded_by": bytes(row[8]) if row[8] is not None else None,
            }

    def get_key_successor(self, origin: str, pubkey: bytes) -> bytes | None:
        """The key that succeeded `pubkey`, or None if it is still current."""
        with self._lock:
            row = self._conn.execute(
                "SELECT new_pubkey FROM user_key_rotations WHERE origin=? AND old_pubkey=?",
                (origin, pubkey),
            ).fetchone()
            return bytes(row[0]) if row else None

    def get_rotation_seq(self, origin: str, pubkey: bytes) -> int | None:
        """The origin_seq at which `pubkey` was succeeded, or None if current."""
        with self._lock:
            row = self._conn.execute(
                "SELECT rotated_seq FROM user_key_rotations WHERE origin=? AND old_pubkey=?",
                (origin, pubkey),
            ).fetchone()
            return int(row[0]) if row else None

    def list_users(self, origin: str = None, include_revoked: bool = False) -> list[dict]:
        # Superseded keys are never listed: the old row survives so records
        # signed by a retired key still resolve a username, but it is not a
        # live user. Without this a twice-rotated name shows up three times.
        # `include_revoked` still shows revoked rows — revocation and
        # rotation stay tellable apart.
        with self._lock:
            if origin:
                if include_revoked:
                    rows = self._conn.execute(
                        "SELECT u.origin, u.user_pubkey, u.username, u.flags, u.reg_seq, u.created_at, u.revoked, u.revoked_seq "
                        "FROM users u LEFT JOIN user_key_rotations r "
                        "  ON r.origin = u.origin AND r.old_pubkey = u.user_pubkey "
                        "WHERE u.origin=? AND r.new_pubkey IS NULL ORDER BY u.username ASC",
                        (origin,),
                    ).fetchall()
                else:
                    rows = self._conn.execute(
                        "SELECT u.origin, u.user_pubkey, u.username, u.flags, u.reg_seq, u.created_at, u.revoked, u.revoked_seq "
                        "FROM users u LEFT JOIN user_key_rotations r "
                        "  ON r.origin = u.origin AND r.old_pubkey = u.user_pubkey "
                        "WHERE u.origin=? AND u.revoked=0 AND r.new_pubkey IS NULL ORDER BY u.username ASC",
                        (origin,),
                    ).fetchall()
            else:
                if include_revoked:
                    rows = self._conn.execute(
                        "SELECT u.origin, u.user_pubkey, u.username, u.flags, u.reg_seq, u.created_at, u.revoked, u.revoked_seq "
                        "FROM users u LEFT JOIN user_key_rotations r "
                        "  ON r.origin = u.origin AND r.old_pubkey = u.user_pubkey "
                        "WHERE r.new_pubkey IS NULL ORDER BY u.origin ASC, u.username ASC"
                    ).fetchall()
                else:
                    rows = self._conn.execute(
                        "SELECT u.origin, u.user_pubkey, u.username, u.flags, u.reg_seq, u.created_at, u.revoked, u.revoked_seq "
                        "FROM users u LEFT JOIN user_key_rotations r "
                        "  ON r.origin = u.origin AND r.old_pubkey = u.user_pubkey "
                        "WHERE u.revoked=0 AND r.new_pubkey IS NULL ORDER BY u.origin ASC, u.username ASC"
                    ).fetchall()
            return [
                {
                    "origin": r[0],
                    "user_pubkey": bytes(r[1]),
                    "username": r[2],
                    "flags": r[3],
                    "reg_seq": r[4],
                    "created_at": r[5],
                    "revoked": bool(r[6]),
                    "revoked_seq": r[7],
                }
                for r in rows
            ]

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("DELETE FROM users")
                self._conn.execute("DELETE FROM user_key_rotations")
                self._conn.execute("DELETE FROM applied_events")
                self._conn.execute("DELETE FROM projection_checkpoint")
                self._conn.execute("COMMIT")
            except Exception:
                self._rollback()
                raise

    def clear_origin(self, origin: str) -> None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("DELETE FROM users WHERE origin=?", (origin,))
                self._conn.execute("DELETE FROM user_key_rotations WHERE origin=?", (origin,))
                self._conn.execute("DELETE FROM applied_events WHERE origin=?", (origin,))
                self._conn.execute("DELETE FROM projection_checkpoint WHERE origin=?", (origin,))
                self._conn.execute("COMMIT")
            except Exception:
                self._rollback()
                raise


# ---------------------------------------------------------------------------
# PolicyProjection — rules, reports, punishments
# ---------------------------------------------------------------------------


class PolicyProjection(_BaseProjection):
    """Moderation policy projection: rules, reports, punishments."""

    def _init_schema(self) -> None:
        # Schema v2: punishments carry a type and a body reference.
        # If an older untyped punishments table exists, reset this projection
        # entirely so the dispatcher replays it from the authoritative
        # firehose (projections are derived state and never authoritative).
        cols = {row[1] for row in self._conn.execute("PRAGMA table_info(punishments)")}
        if cols and "type" not in cols:
            self._conn.executescript("""
                DROP TABLE IF EXISTS punishment_acks;
                DROP TABLE IF EXISTS punishments;
                DELETE FROM applied_events;
                DELETE FROM projection_checkpoint;
            """)

        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS rules (
                event_id        BLOB NOT NULL,
                origin          TEXT NOT NULL,
                origin_seq      INTEGER NOT NULL,
                rule_name       TEXT NOT NULL,
                body_hash       BLOB NOT NULL,
                body_size       INTEGER NOT NULL,
                created_at      INTEGER NOT NULL,
                revoked         INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (origin, event_id)
            );

            CREATE TABLE IF NOT EXISTS reports (
                event_id        BLOB NOT NULL,
                origin          TEXT NOT NULL,
                origin_seq      INTEGER NOT NULL,
                culprit_pubkey  BLOB NOT NULL,
                target_origin   TEXT NOT NULL DEFAULT '',
                target_board    TEXT NOT NULL DEFAULT '',
                target_article_id BLOB NOT NULL DEFAULT x'0000000000000000000000000000000000000000000000000000000000000000',
                target_event_id BLOB NOT NULL DEFAULT x'0000000000000000000000000000000000000000000000000000000000000000',
                body_hash       BLOB NOT NULL,
                body_size       INTEGER NOT NULL,
                created_at      INTEGER NOT NULL,
                PRIMARY KEY (origin, event_id)
            );

            CREATE TABLE IF NOT EXISTS punishments (
                event_id        BLOB NOT NULL,
                origin          TEXT NOT NULL,
                origin_seq      INTEGER NOT NULL,
                type            TEXT NOT NULL CHECK(type IN ('warning', 'ban', 'permaban')),
                punished_pubkey BLOB NOT NULL,
                expires_at      INTEGER NOT NULL,
                body_hash       BLOB NOT NULL,
                body_size       INTEGER NOT NULL,
                created_at      INTEGER NOT NULL,
                revoked         INTEGER NOT NULL DEFAULT 0,
                revoked_by      BLOB,
                PRIMARY KEY (origin, event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_punishments_pubkey
                ON punishments(punished_pubkey, revoked, expires_at);

            CREATE TABLE IF NOT EXISTS punishment_acks (
                ack_event_id        BLOB NOT NULL,
                origin              TEXT NOT NULL DEFAULT '',
                user_pubkey         BLOB NOT NULL,
                punishment_event_id BLOB NOT NULL,
                acked_at            INTEGER NOT NULL,
                PRIMARY KEY (origin, ack_event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_punishment_acks_target
                ON punishment_acks(user_pubkey, punishment_event_id);
        """)

    def apply_rule(self, rec: Record) -> None:
        with self._lock:
            if self.is_applied(rec.origin, rec.event_id):
                return
            self._begin()
            try:
                rule_name = rec.metadata.get_text(1) or ""
                self._conn.execute(
                    "INSERT OR REPLACE INTO rules "
                    "(event_id, origin, origin_seq, rule_name, body_hash, body_size, created_at, revoked) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
                    (
                        rec.event_id,
                        rec.origin,
                        rec.origin_seq,
                        rule_name,
                        rec.body_hash,
                        rec.body_size,
                        rec.created_at,
                    ),
                )
                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._commit()
            except Exception:
                self._rollback()
                raise

    def apply_rule_revoke(self, rec: Record) -> None:
        with self._lock:
            if self.is_applied(rec.origin, rec.event_id):
                return
            self._begin()
            try:
                # Same-origin guard, matching board_projection.py's control
                # kinds: a remote origin cannot revoke a rule it doesn't
                # own, even via replication. Also scope the UPDATE by
                # target_origin, not just event_id — rules.event_id is a
                # global (not per-origin) primary key in this table, so an
                # unscoped match is one fewer layer of defense than it looks.
                if rec.origin != rec.target_origin:
                    self._mark_applied(rec)
                    self._set_checkpoint(rec.origin, rec.origin_seq)
                    self._commit()
                    return
                self._conn.execute(
                    "UPDATE rules SET revoked=1 WHERE event_id=? AND origin=?",
                    (rec.target_event_id, rec.target_origin),
                )
                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._commit()
            except Exception:
                self._rollback()
                raise

    def apply_report(self, rec: Record) -> None:
        with self._lock:
            if self.is_applied(rec.origin, rec.event_id):
                return
            self._begin()
            try:
                culprit = rec.metadata.get_bytes(1) or b"\x00" * 32
                self._conn.execute(
                    "INSERT OR REPLACE INTO reports "
                    "(event_id, origin, origin_seq, culprit_pubkey, "
                    "target_origin, target_board, target_article_id, target_event_id, "
                    "body_hash, body_size, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        rec.event_id,
                        rec.origin,
                        rec.origin_seq,
                        culprit,
                        rec.target_origin,
                        rec.target_board,
                        rec.target_article_id,
                        rec.target_event_id,
                        rec.body_hash,
                        rec.body_size,
                        rec.created_at,
                    ),
                )
                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._commit()
            except Exception:
                self._rollback()
                raise

    def apply_punishment(self, rec: Record) -> None:
        punishment_type = PUNISHMENT_TYPE_BY_KIND.get(rec.kind)
        if punishment_type is None:
            raise ValueError(f"apply_punishment: not a punishment kind: {rec.kind}")
        with self._lock:
            if self.is_applied(rec.origin, rec.event_id):
                return
            self._begin()
            try:
                punished = rec.metadata.get_bytes(1) or b"\x00" * 32
                expires_at = rec.metadata.get_i64(2) or 0
                self._conn.execute(
                    "INSERT OR REPLACE INTO punishments "
                    "(event_id, origin, origin_seq, type, punished_pubkey, expires_at, "
                    "body_hash, body_size, created_at, revoked, revoked_by) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)",
                    (
                        rec.event_id,
                        rec.origin,
                        rec.origin_seq,
                        punishment_type,
                        punished,
                        expires_at,
                        rec.body_hash,
                        rec.body_size,
                        rec.created_at,
                    ),
                )
                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._commit()
            except Exception:
                self._rollback()
                raise

    def apply_punishment_revoke(self, rec: Record) -> None:
        with self._lock:
            if self.is_applied(rec.origin, rec.event_id):
                return
            self._begin()
            try:
                # Same-origin guard, matching board_projection.py's control
                # kinds: a remote origin cannot revoke a punishment it
                # doesn't own, even via replication. Without this, any
                # origin could publish a punishment.revoke naming another
                # origin's punishment event_id as the target and silently
                # lift that origin's ban/permaban once this record
                # propagates and is dispatched here — defeating moderation
                # across federation entirely. Also scope the UPDATE by
                # target_origin, not just event_id — punishments.event_id
                # is a global (not per-origin) primary key in this table.
                if rec.origin != rec.target_origin:
                    self._mark_applied(rec)
                    self._set_checkpoint(rec.origin, rec.origin_seq)
                    self._commit()
                    return
                self._conn.execute(
                    "UPDATE punishments SET revoked=1, revoked_by=? WHERE event_id=? AND origin=?",
                    (rec.event_id, rec.target_event_id, rec.target_origin),
                )
                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._commit()
            except Exception:
                self._rollback()
                raise

    def get_punishment(self, event_id: bytes) -> dict | None:
        """Look up a single punishment by its event ID, or None if unknown."""
        with self._lock:
            row = self._conn.execute(
                "SELECT event_id, origin, origin_seq, type, punished_pubkey, expires_at, "
                "revoked FROM punishments WHERE event_id=?",
                (event_id,),
            ).fetchone()
            if row is None:
                return None
            return {
                "event_id": bytes(row[0]),
                "origin": row[1],
                "origin_seq": row[2],
                "type": row[3],
                "punished_pubkey": bytes(row[4]),
                "expires_at": row[5],
                "revoked": bool(row[6]),
            }

    def apply_punishment_ack(self, rec: Record) -> None:
        """Record a user's acknowledgment of a punishment.

        Acks are local to the user's homeserver and reference the punishment
        event ID regardless of which origin issued it. Re-acking the same
        punishment with a new event is idempotent at the pending-state level.

        The punishment event ID must name a punishment that actually exists
        and actually targets the acker. `firehose_commands._cmd_publish`
        refuses the same case at publish time for a local caller's sake, but
        this check has to exist independently: federated acks never pass
        through that handler, and without it any key could forge a signed
        "acknowledged" record against another user's punishment, a
        nonexistent event ID, or an unrelated event entirely.
        """
        with self._lock:
            if self.is_applied(rec.origin, rec.event_id):
                return
            self._begin()
            try:
                punishment_event_id = rec.metadata.get_bytes(1) or b"\x00" * 32
                row = self._conn.execute(
                    "SELECT punished_pubkey FROM punishments WHERE event_id=?",
                    (punishment_event_id,),
                ).fetchone()
                if row is None or bytes(row[0]) != rec.actor_pubkey:
                    self._mark_applied(rec)
                    self._set_checkpoint(rec.origin, rec.origin_seq)
                    self._commit()
                    return
                self._conn.execute(
                    "INSERT OR IGNORE INTO punishment_acks "
                    "(ack_event_id, origin, user_pubkey, punishment_event_id, acked_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        rec.event_id,
                        rec.origin,
                        rec.actor_pubkey,
                        punishment_event_id,
                        rec.created_at,
                    ),
                )
                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._commit()
            except Exception:
                self._rollback()
                raise

    def list_reports(
        self, culprit_pubkey: bytes | None = None, limit: int = 100, offset: int = 0
    ) -> list[dict]:
        """The moderation queue: reports filed, newest first.

        `apply_report` has been writing this table since reports were
        dispatched, but nothing read it back, so a report arriving over
        federation was stored and then seen by nobody. This is the read side.

        A report is an accusation, not a verdict. It records who filed it
        (`origin`/`origin_seq` locate the signed record), who they name
        (`culprit_pubkey`), and what they point at — an article
        (`target_origin`/`target_board`/`target_article_id`), an event
        (`target_event_id`), or nothing at all. The validator enforces
        exactly one of those three shapes, so a caller can switch on which
        target fields are non-zero without worrying about mixtures.

        The reason is the record body and is not stored here; fetch it with
        `body_hash` if it is wanted.
        """
        sql = (
            "SELECT event_id, origin, origin_seq, culprit_pubkey, target_origin, "
            "target_board, target_article_id, target_event_id, body_hash, body_size, "
            "created_at FROM reports "
        )
        params: tuple = ()
        if culprit_pubkey is not None:
            sql += "WHERE culprit_pubkey=? "
            params = (culprit_pubkey,)
        sql += "ORDER BY created_at DESC, origin_seq DESC LIMIT ? OFFSET ?"
        params = params + (limit, offset)

        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [
            {
                "event_id": bytes(r[0]),
                "origin": r[1],
                "origin_seq": r[2],
                "culprit_pubkey": bytes(r[3]),
                "target_origin": r[4],
                "target_board": r[5],
                "target_article_id": bytes(r[6]),
                "target_event_id": bytes(r[7]),
                "body_hash": bytes(r[8]),
                "body_size": r[9],
                "created_at": r[10],
            }
            for r in rows
        ]

    def list_punishments_for_pubkey(
        self, pubkey: bytes, include_revoked: bool = False
    ) -> list[dict]:
        with self._lock:
            if include_revoked:
                rows = self._conn.execute(
                    "SELECT event_id, origin, origin_seq, type, punished_pubkey, expires_at, "
                    "body_hash, body_size, created_at, revoked, revoked_by "
                    "FROM punishments WHERE punished_pubkey=? "
                    "ORDER BY created_at DESC",
                    (pubkey,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT event_id, origin, origin_seq, type, punished_pubkey, expires_at, "
                    "body_hash, body_size, created_at, revoked, revoked_by "
                    "FROM punishments WHERE punished_pubkey=? AND revoked=0 "
                    "ORDER BY created_at DESC",
                    (pubkey,),
                ).fetchall()
            return [
                {
                    "event_id": bytes(r[0]),
                    "origin": r[1],
                    "origin_seq": r[2],
                    "type": r[3],
                    "punished_pubkey": bytes(r[4]),
                    "expires_at": r[5],
                    "body_hash": bytes(r[6]),
                    "body_size": r[7],
                    "created_at": r[8],
                    "revoked": bool(r[9]),
                    "revoked_by": bytes(r[10]) if r[10] else None,
                }
                for r in rows
            ]

    def list_pending_for_pubkey(
        self,
        pubkey: bytes,
        allowed_origins: set | None = None,
        now: int | None = None,
    ) -> list[dict]:
        """Return the punishments currently gating writes by this user.

        Pending means: unacknowledged warnings, unexpired temporary bans,
        and permabans — all non-revoked. When allowed_origins is provided,
        only punishments issued by those origins are considered.
        """
        if now is None:
            now = int(time.time())
        with self._lock:
            rows = self._conn.execute(
                "SELECT event_id, origin, origin_seq, type, punished_pubkey, expires_at, "
                "body_hash, body_size, created_at "
                "FROM punishments "
                "WHERE punished_pubkey=? AND revoked=0 "
                "AND ("
                "  (type='warning' AND NOT EXISTS ("
                "     SELECT 1 FROM punishment_acks a"
                "     WHERE a.user_pubkey=punishments.punished_pubkey"
                "       AND a.punishment_event_id=punishments.event_id))"
                "  OR (type='ban' AND expires_at > ?)"
                "  OR (type='permaban')"
                ") ORDER BY created_at ASC, origin_seq ASC",
                (pubkey, now),
            ).fetchall()
            result = []
            for r in rows:
                origin = r[1]
                if allowed_origins is not None and origin not in allowed_origins:
                    continue
                result.append(
                    {
                        "type": r[3],
                        "event_id": bytes(r[0]),
                        "origin": origin,
                        "origin_seq": r[2],
                        "expires_at": r[5],
                        "body_hash": bytes(r[6]),
                        "body_size": r[7],
                        "created_at": r[8],
                    }
                )
            return result

    def list_rules(self, origin: str = None, include_revoked: bool = False) -> list[dict]:
        with self._lock:
            if origin:
                if include_revoked:
                    rows = self._conn.execute(
                        "SELECT event_id, origin, origin_seq, rule_name, body_hash, body_size, created_at, revoked "
                        "FROM rules WHERE origin=? ORDER BY origin_seq ASC",
                        (origin,),
                    ).fetchall()
                else:
                    rows = self._conn.execute(
                        "SELECT event_id, origin, origin_seq, rule_name, body_hash, body_size, created_at, revoked "
                        "FROM rules WHERE origin=? AND revoked=0 ORDER BY origin_seq ASC",
                        (origin,),
                    ).fetchall()
            else:
                if include_revoked:
                    rows = self._conn.execute(
                        "SELECT event_id, origin, origin_seq, rule_name, body_hash, body_size, created_at, revoked "
                        "FROM rules ORDER BY origin ASC, origin_seq ASC"
                    ).fetchall()
                else:
                    rows = self._conn.execute(
                        "SELECT event_id, origin, origin_seq, rule_name, body_hash, body_size, created_at, revoked "
                        "FROM rules WHERE revoked=0 ORDER BY origin ASC, origin_seq ASC"
                    ).fetchall()
            return [
                {
                    "event_id": bytes(r[0]),
                    "origin": r[1],
                    "origin_seq": r[2],
                    "rule_name": r[3],
                    "body_hash": bytes(r[4]),
                    "body_size": r[5],
                    "created_at": r[6],
                    "revoked": bool(r[7]),
                }
                for r in rows
            ]

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("DELETE FROM rules")
                self._conn.execute("DELETE FROM reports")
                self._conn.execute("DELETE FROM punishments")
                self._conn.execute("DELETE FROM punishment_acks")
                self._conn.execute("DELETE FROM applied_events")
                self._conn.execute("DELETE FROM projection_checkpoint")
                self._conn.execute("COMMIT")
            except Exception:
                self._rollback()
                raise

    def clear_origin(self, origin: str) -> None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("DELETE FROM rules WHERE origin=?", (origin,))
                self._conn.execute("DELETE FROM reports WHERE origin=?", (origin,))
                self._conn.execute(
                    "DELETE FROM punishment_acks WHERE punishment_event_id IN "
                    "(SELECT event_id FROM punishments WHERE origin=?)",
                    (origin,),
                )
                self._conn.execute("DELETE FROM punishments WHERE origin=?", (origin,))
                self._conn.execute("DELETE FROM applied_events WHERE origin=?", (origin,))
                self._conn.execute("DELETE FROM projection_checkpoint WHERE origin=?", (origin,))
                self._conn.execute("COMMIT")
            except Exception:
                self._rollback()
                raise


# ---------------------------------------------------------------------------
# Route metadata fields + parsing
# ---------------------------------------------------------------------------

#: bonnet.route.announce metadata field numbers. Shared by the projection,
#: the sync manager's transitive learner, and the gateway client/tools so
#: all three agree on the wire shape.
ROUTE_FIELD_HOSTNAME = 1  # TEXT, dial hostname (required)
ROUTE_FIELD_PORT = 2  # U64 1..65535 (required)
ROUTE_FIELD_SCHEME = 3  # TEXT "http" | "https" (optional, default "https")
ROUTE_FIELD_VERIFY_TLS = 4  # BOOL (optional, default False)
ROUTE_FIELD_PRIORITY = 5  # U64 dial-order hint (optional, default 0)

_ROUTE_SCHEMES = frozenset({"http", "https"})


def parse_route_announce(metadata: MetadataMap) -> dict | None:
    """Parse a route-announce metadata map, or None if malformed.

    Pure and total: federated records bypass KindValidator, so the
    projection (and the sync learner, and gateway list_routes) must all
    tolerate garbage without raising. Local publishes were already
    schema-checked; this re-checks because the same bytes can arrive
    from a peer that never validated them.
    """
    try:
        hostname = metadata.get_text(ROUTE_FIELD_HOSTNAME)
        port = metadata.get_u64(ROUTE_FIELD_PORT)
        if hostname is None or port is None:
            return None
        hostname = normalize_hostname(hostname)
        if not hostname or any(c.isspace() or ord(c) < 0x20 for c in hostname):
            return None
        if not 1 <= port <= 65535:
            return None
        scheme = metadata.get_text(ROUTE_FIELD_SCHEME) or "https"
        if scheme not in _ROUTE_SCHEMES:
            return None
        verify_tls = metadata.get_bool(ROUTE_FIELD_VERIFY_TLS)
        priority = metadata.get_u64(ROUTE_FIELD_PRIORITY)
        return {
            "hostname": hostname,
            "port": port,
            "scheme": scheme,
            "verify_tls": bool(verify_tls) if verify_tls is not None else False,
            "priority": priority if priority is not None else 0,
            "endpoint": f"{scheme}://{hostname}:{port}",
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# RouteProjection — transitive peer-discovery dial addresses
# ---------------------------------------------------------------------------


class RouteProjection(_BaseProjection):
    """One live dial address per origin, from bonnet.route.* records.

    Latest origin_seq wins; a withdraw tombstones the row (kept, excluded
    from live reads) until a later announce revives it. Third-party claims
    — a record whose origin is not the route's subject — are hearsay:
    every route row's subject IS its origin, so there is nothing to check
    beyond projecting the announcing origin's own row. Stored and relayed
    regardless; whether a relay *dials* a learned route is the sync
    manager's opt-in policy, never this projection's decision.
    """

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS routes (
                origin          TEXT NOT NULL PRIMARY KEY,
                hostname        TEXT NOT NULL,
                port            INTEGER NOT NULL,
                scheme          TEXT NOT NULL DEFAULT 'https',
                verify_tls      INTEGER NOT NULL DEFAULT 0,
                priority        INTEGER NOT NULL DEFAULT 0,
                announce_event_id BLOB NOT NULL,
                announced_seq   INTEGER NOT NULL,
                updated_seq     INTEGER NOT NULL,
                withdrawn       INTEGER NOT NULL DEFAULT 0,
                created_at      INTEGER NOT NULL
            );
        """)

    def apply_route_announce(self, rec: Record) -> None:
        with self._lock:
            if self.is_applied(rec.origin, rec.event_id):
                return
            self._begin()
            try:
                parsed = parse_route_announce(rec.metadata)
                if parsed is None:
                    self._mark_applied(rec)
                    self._set_checkpoint(rec.origin, rec.origin_seq)
                    self._commit()
                    return
                row = self._conn.execute(
                    "SELECT updated_seq FROM routes WHERE origin=?",
                    (rec.origin,),
                ).fetchone()
                if row is not None and rec.origin_seq < row[0]:
                    # Stale announce loses to newer state (incl. withdraw).
                    self._mark_applied(rec)
                    self._set_checkpoint(rec.origin, rec.origin_seq)
                    self._commit()
                    return
                self._conn.execute(
                    "INSERT OR REPLACE INTO routes "
                    "(origin, hostname, port, scheme, verify_tls, priority, "
                    " announce_event_id, announced_seq, updated_seq, withdrawn, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
                    (
                        rec.origin,
                        parsed["hostname"],
                        parsed["port"],
                        parsed["scheme"],
                        1 if parsed["verify_tls"] else 0,
                        parsed["priority"],
                        rec.event_id,
                        rec.origin_seq,
                        rec.origin_seq,
                        int(time.time()),
                    ),
                )
                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._commit()
            except Exception:
                self._rollback()
                raise

    def apply_route_withdraw(self, rec: Record) -> None:
        with self._lock:
            if self.is_applied(rec.origin, rec.event_id):
                return
            self._begin()
            try:
                # Same-origin guard, matching apply_user_revoke: an origin
                # can only withdraw its own route, never another's.
                if rec.origin != rec.target_origin:
                    self._mark_applied(rec)
                    self._set_checkpoint(rec.origin, rec.origin_seq)
                    self._commit()
                    return
                row = self._conn.execute(
                    "SELECT announce_event_id, updated_seq, withdrawn FROM routes WHERE origin=?",
                    (rec.origin,),
                ).fetchone()
                if (
                    row is not None
                    and bytes(row[0]) == bytes(rec.target_event_id)
                    and rec.origin_seq >= row[1]
                ):
                    self._conn.execute(
                        "UPDATE routes SET withdrawn=1, updated_seq=? WHERE origin=?",
                        (rec.origin_seq, rec.origin),
                    )
                # Else: unknown event, stale withdraw, or already
                # withdrawn — success no-op, still marked applied.
                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._commit()
            except Exception:
                self._rollback()
                raise

    def _row_to_dict(self, r) -> dict:
        return {
            "origin": r[0],
            "hostname": r[1],
            "port": r[2],
            "scheme": r[3],
            "verify_tls": bool(r[4]),
            "priority": r[5],
            "announce_event_id": bytes(r[6]).hex(),
            "announced_seq": r[7],
            "updated_seq": r[8],
            "withdrawn": bool(r[9]),
            "endpoint": f"{r[3]}://{r[1]}:{r[2]}",
        }

    def get_route(self, origin: str, include_withdrawn: bool = False) -> dict | None:
        with self._lock:
            if include_withdrawn:
                row = self._conn.execute(
                    "SELECT origin, hostname, port, scheme, verify_tls, priority, "
                    "announce_event_id, announced_seq, updated_seq, withdrawn "
                    "FROM routes WHERE origin=?",
                    (origin,),
                ).fetchone()
            else:
                row = self._conn.execute(
                    "SELECT origin, hostname, port, scheme, verify_tls, priority, "
                    "announce_event_id, announced_seq, updated_seq, withdrawn "
                    "FROM routes WHERE origin=? AND withdrawn=0",
                    (origin,),
                ).fetchone()
            return self._row_to_dict(row) if row else None

    def list_routes(self, origin: str = None, include_withdrawn: bool = False) -> list[dict]:
        with self._lock:
            clause = "" if include_withdrawn else "AND withdrawn=0"
            if origin:
                rows = self._conn.execute(
                    "SELECT origin, hostname, port, scheme, verify_tls, priority, "
                    "announce_event_id, announced_seq, updated_seq, withdrawn "
                    f"FROM routes WHERE origin=? {clause} ORDER BY origin ASC",
                    (origin,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT origin, hostname, port, scheme, verify_tls, priority, "
                    "announce_event_id, announced_seq, updated_seq, withdrawn "
                    f"FROM routes WHERE 1=1 {clause} ORDER BY origin ASC"
                ).fetchall()
            return [self._row_to_dict(r) for r in rows]

    def list_live_routes(self) -> list[dict]:
        """Live routes only, highest priority first — the sync learner's input."""
        routes = self.list_routes()
        routes.sort(key=lambda r: (-r["priority"], r["origin"]))
        return routes

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("DELETE FROM routes")
                self._conn.execute("DELETE FROM applied_events")
                self._conn.execute("DELETE FROM projection_checkpoint")
                self._conn.execute("COMMIT")
            except Exception:
                self._rollback()
                raise

    def clear_origin(self, origin: str) -> None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("DELETE FROM routes WHERE origin=?", (origin,))
                self._conn.execute("DELETE FROM applied_events WHERE origin=?", (origin,))
                self._conn.execute("DELETE FROM projection_checkpoint WHERE origin=?", (origin,))
                self._conn.execute("COMMIT")
            except Exception:
                self._rollback()
                raise
