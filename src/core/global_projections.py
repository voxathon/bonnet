"""Global projections for the Bonnet Firehose Protocol (PROTOCOL.md §14.4).

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

from core.record import Record

# ---------------------------------------------------------------------------
# Kind constants
# ---------------------------------------------------------------------------

KIND_BOARD_CREATE = "bonnet.board.create"
KIND_BOARD_CLOSE = "bonnet.board.close"
KIND_BOARD_REOPEN = "bonnet.board.reopen"
KIND_USER_REGISTER = "bonnet.user.register"
KIND_USER_REVOKE = "bonnet.user.revoke"
KIND_RULE_PUBLISH = "bonnet.rule.publish"
KIND_RULE_REVOKE = "bonnet.rule.revoke"
KIND_REPORT = "bonnet.report"
KIND_PUNISHMENT_WARN = "bonnet.punishment.warn"
KIND_PUNISHMENT_BAN = "bonnet.punishment.ban"
KIND_PUNISHMENT_PERMABAN = "bonnet.punishment.permaban"
KIND_PUNISHMENT_REVOKE = "bonnet.punishment.revoke"
KIND_PUNISHMENT_ACK = "bonnet.punishment.ack"

# Gate D: issuing kind -> stored punishment type name.
PUNISHMENT_TYPE_BY_KIND = {
    KIND_PUNISHMENT_WARN: "warning",
    KIND_PUNISHMENT_BAN: "ban",
    KIND_PUNISHMENT_PERMABAN: "permaban",
}


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
        """)

    def apply_user_register(self, rec: Record) -> None:
        with self._lock:
            if self.is_applied(rec.event_id):
                return
            self._begin()
            try:
                username = rec.metadata.get_text(1) or ""
                user_pubkey = rec.metadata.get_bytes(2) or b"\x00" * 32
                flags = rec.metadata.get_u64(3) or 0
                reg_seq = rec.origin_seq
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

    def get_user_by_pubkey(self, origin: str, pubkey: bytes) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT origin, user_pubkey, username, flags, reg_seq, created_at, revoked, revoked_seq "
                "FROM users WHERE origin=? AND user_pubkey=?",
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
            }

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
        # Gate D schema v2: punishments carry a type and a body reference.
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
                self._conn.execute(
                    "UPDATE rules SET revoked=1 WHERE event_id=?",
                    (rec.target_event_id,),
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
                self._conn.execute(
                    "UPDATE punishments SET revoked=1, revoked_by=? WHERE event_id=?",
                    (rec.event_id, rec.target_event_id),
                )
                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._commit()
            except Exception:
                self._rollback()
                raise

    def apply_punishment_ack(self, rec: Record) -> None:
        """Record a user's acknowledgment of a punishment (Gate D).

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
        """Return the punishments currently gating writes by this user (Gate D).

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
                ") ORDER BY created_at ASC",
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
