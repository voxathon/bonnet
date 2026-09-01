"""Global projections for the firehose protocol.

nav.db     — board directory from bonnet.board.create/close/reopen
users.db   — user registrations and revocations
policy.db  — rules, reports, punishments, revocations, effective-state

All three are rebuildable projections containing applied_events and
per-origin checkpoints. They are never authoritative.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time

from bonnet.core.kinds import PUNISHMENT_TYPE_BY_KIND  # noqa: F401 (re-exported)
from bonnet.core.logging import log_msg
from bonnet.core.record import Record, verify_key_rotation_proof

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
                event_id    BLOB PRIMARY KEY,
                origin      TEXT NOT NULL,
                origin_seq  INTEGER NOT NULL,
                kind        TEXT NOT NULL,
                applied_at  INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS projection_checkpoint (
                origin      TEXT PRIMARY KEY,
                last_applied_seq INTEGER NOT NULL DEFAULT 0
            );
        """)

    def _init_schema(self) -> None:
        pass

    def is_applied(self, event_id: bytes) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM applied_events WHERE event_id=?", (event_id,)
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
            if self.is_applied(rec.event_id):
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
        with self._lock:
            if self.is_applied(rec.event_id):
                return
            self._begin()
            try:
                owner = rec.metadata.get_bytes(1) or b"\x00" * 32
                display = rec.metadata.get_text(2) or ""
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
            if self.is_applied(rec.event_id):
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
            if self.is_applied(rec.event_id):
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

    def ensure_board(
        self, origin: str, board: str, owner_pubkey: bytes, created_seq: int, created_at: int
    ) -> None:
        """Materialize a directory entry for `board` if none exists yet.

        Publishing an article has never required a prior bonnet.board.create
        — the per-board store is created lazily on first write, same as this
        entry — but without one, the board was invisible to list_boards and
        to ARTICLE_LIST's aggregate (origin="") path, which discovers which
        boards to scan by walking this table alone. That made a published,
        directly-gettable article unfindable through either listing. INSERT
        OR IGNORE: a real bonnet.board.create record (see apply_board_create,
        which uses REPLACE) always wins over this synthesized entry, whether
        it arrives before or after the first article.
        """
        with self._lock:
            self._begin()
            try:
                self._conn.execute(
                    "INSERT OR IGNORE INTO boards "
                    "(origin, board, owner_pubkey, display_name, closed, created_seq, created_at) "
                    "VALUES (?, ?, ?, '', 0, ?, ?)",
                    (origin, board, owner_pubkey, created_seq, created_at),
                )
                self._commit()
            except Exception:
                self._rollback()
                raise

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
        squatter would burn every good name permanently. A superseded key still
        does: `apply_user_key_rotate` carries the name forward to the successor,
        so the identity is live even though that particular key is retired.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT user_pubkey FROM users WHERE origin=? AND username=? AND revoked=0 "
                "ORDER BY reg_seq LIMIT 1",
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
            if self.is_applied(rec.event_id):
                return
            self._begin()
            try:
                username = rec.metadata.get_text(1) or ""
                user_pubkey = rec.metadata.get_bytes(2) or b"\x00" * 32
                flags = rec.metadata.get_u64(3) or 0
                reg_seq = rec.origin_seq

                holder = self._conn.execute(
                    "SELECT user_pubkey FROM users "
                    "WHERE origin=? AND username=? AND revoked=0 ORDER BY reg_seq LIMIT 1",
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
            if self.is_applied(rec.event_id):
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
            if self.is_applied(rec.event_id):
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

    def list_users(self, origin: str = None, include_revoked: bool = False) -> list[dict]:
        with self._lock:
            if origin:
                if include_revoked:
                    rows = self._conn.execute(
                        "SELECT origin, user_pubkey, username, flags, reg_seq, created_at, revoked, revoked_seq "
                        "FROM users WHERE origin=? ORDER BY username ASC",
                        (origin,),
                    ).fetchall()
                else:
                    rows = self._conn.execute(
                        "SELECT origin, user_pubkey, username, flags, reg_seq, created_at, revoked, revoked_seq "
                        "FROM users WHERE origin=? AND revoked=0 ORDER BY username ASC",
                        (origin,),
                    ).fetchall()
            else:
                if include_revoked:
                    rows = self._conn.execute(
                        "SELECT origin, user_pubkey, username, flags, reg_seq, created_at, revoked, revoked_seq "
                        "FROM users ORDER BY origin ASC, username ASC"
                    ).fetchall()
                else:
                    rows = self._conn.execute(
                        "SELECT origin, user_pubkey, username, flags, reg_seq, created_at, revoked, revoked_seq "
                        "FROM users WHERE revoked=0 ORDER BY origin ASC, username ASC"
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
                event_id        BLOB PRIMARY KEY,
                origin          TEXT NOT NULL,
                origin_seq      INTEGER NOT NULL,
                rule_name       TEXT NOT NULL,
                body_hash       BLOB NOT NULL,
                body_size       INTEGER NOT NULL,
                created_at      INTEGER NOT NULL,
                revoked         INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS reports (
                event_id        BLOB PRIMARY KEY,
                origin          TEXT NOT NULL,
                origin_seq      INTEGER NOT NULL,
                culprit_pubkey  BLOB NOT NULL,
                target_origin   TEXT NOT NULL DEFAULT '',
                target_board    TEXT NOT NULL DEFAULT '',
                target_article_id BLOB NOT NULL DEFAULT x'0000000000000000000000000000000000000000000000000000000000000000',
                target_event_id BLOB NOT NULL DEFAULT x'0000000000000000000000000000000000000000000000000000000000000000',
                body_hash       BLOB NOT NULL,
                body_size       INTEGER NOT NULL,
                created_at      INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS punishments (
                event_id        BLOB PRIMARY KEY,
                origin          TEXT NOT NULL,
                origin_seq      INTEGER NOT NULL,
                type            TEXT NOT NULL CHECK(type IN ('warning', 'ban', 'permaban')),
                punished_pubkey BLOB NOT NULL,
                expires_at      INTEGER NOT NULL,
                body_hash       BLOB NOT NULL,
                body_size       INTEGER NOT NULL,
                created_at      INTEGER NOT NULL,
                revoked         INTEGER NOT NULL DEFAULT 0,
                revoked_by      BLOB
            );
            CREATE INDEX IF NOT EXISTS idx_punishments_pubkey
                ON punishments(punished_pubkey, revoked, expires_at);

            CREATE TABLE IF NOT EXISTS punishment_acks (
                ack_event_id        BLOB PRIMARY KEY,
                user_pubkey         BLOB NOT NULL,
                punishment_event_id BLOB NOT NULL,
                acked_at            INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_punishment_acks_target
                ON punishment_acks(user_pubkey, punishment_event_id);
        """)

    def apply_rule(self, rec: Record) -> None:
        with self._lock:
            if self.is_applied(rec.event_id):
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
            if self.is_applied(rec.event_id):
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
            if self.is_applied(rec.event_id):
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
            if self.is_applied(rec.event_id):
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
            if self.is_applied(rec.event_id):
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

    def apply_punishment_ack(self, rec: Record) -> None:
        """Record a user's acknowledgment of a punishment.

        Acks are local to the user's homeserver and reference the punishment
        event ID regardless of which origin issued it. Re-acking the same
        punishment with a new event is idempotent at the pending-state level.
        """
        with self._lock:
            if self.is_applied(rec.event_id):
                return
            self._begin()
            try:
                punishment_event_id = rec.metadata.get_bytes(1) or b"\x00" * 32
                self._conn.execute(
                    "INSERT OR IGNORE INTO punishment_acks "
                    "(ack_event_id, user_pubkey, punishment_event_id, acked_at) "
                    "VALUES (?, ?, ?, ?)",
                    (rec.event_id, rec.actor_pubkey, punishment_event_id, rec.created_at),
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
