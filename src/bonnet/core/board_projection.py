"""Board projection store for the firehose protocol.

Per-board SQLite database at boards/<origin>/<board>/metadata.db containing:
  - articles (metadata, lifecycle, pin, thread state)
  - pending_controls (controls with absent targets)
  - applied_events (idempotent replay tracking)
  - projection_checkpoint (last applied origin_seq)

Normal article queries use only this bounded database.
"""

from __future__ import annotations

import os
import sqlite3
import threading

from bonnet.core.record import ZERO_ID, Record

VISIBILITY_ACTIVE = "active"
VISIBILITY_CANCELLED = "cancelled"
VISIBILITY_SUPERSEDED = "superseded"

BODY_AVAILABLE = "available"
BODY_UNAVAILABLE = "unavailable"
BODY_PURGED = "purged"

PIN_UNPINNED = "unpinned"

THREAD_OPEN = "open"
THREAD_CLOSED = "closed"


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _safe_path_component(s: str) -> str:
    return s.encode("utf-8").hex()


def board_db_path(boards_dir: str, origin: str, board: str) -> str:
    return os.path.join(
        boards_dir, _safe_path_component(origin), _safe_path_component(board), "metadata.db"
    )


def origin_boards_dir(boards_dir: str, origin: str) -> str:
    return os.path.join(boards_dir, _safe_path_component(origin))


def delete_board_dbs(boards_dir: str, origin: str) -> int:
    """Delete every board projection database file for an origin.

    Removes metadata.db and its SQLite sidecar files from each board
    directory under the origin's boards directory, including boards whose
    projections are not currently open. Article body files are untouched.
    Returns the number of files removed.
    """
    root = origin_boards_dir(boards_dir, origin)
    if not os.path.isdir(root):
        return 0
    removed = 0
    for entry in os.listdir(root):
        board_dir = os.path.join(root, entry)
        if not os.path.isdir(board_dir):
            continue
        for suffix in ("", "-wal", "-shm", "-journal"):
            path = os.path.join(board_dir, "metadata.db" + suffix)
            if os.path.exists(path):
                os.remove(path)
                removed += 1
    return removed


# ---------------------------------------------------------------------------
# Article projection row
# ---------------------------------------------------------------------------


class ArticleProjection:
    """One row of the articles table, as read back from a board projection."""

    origin: str
    board: str
    article_num: int
    article_id: bytes
    visibility: str
    body_state: str
    pin_state: str
    thread_state: str
    subject: str
    tags: str
    options: str
    content_type: str
    author_pubkey: bytes
    author_username: str
    author_registrar: str
    created_at: int
    body_hash: bytes
    body_size: int
    root_article_id: bytes
    reply_to_article_id: bytes
    replacement_article_id: bytes | None
    latest_control_seq: int
    event_id: bytes

    __slots__ = (
        "origin",
        "board",
        "article_num",
        "article_id",
        "visibility",
        "body_state",
        "pin_state",
        "thread_state",
        "subject",
        "tags",
        "options",
        "content_type",
        "author_pubkey",
        "author_username",
        "author_registrar",
        "created_at",
        "body_hash",
        "body_size",
        "root_article_id",
        "reply_to_article_id",
        "replacement_article_id",
        "latest_control_seq",
        "event_id",
    )

    def __init__(self, **kwargs):
        for k in self.__slots__:
            setattr(self, k, kwargs.get(k))


# ---------------------------------------------------------------------------
# BoardProjection
# ---------------------------------------------------------------------------


class BoardProjection:
    """Per-board SQLite projection database."""

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._lock = threading.RLock()
        d = os.path.dirname(db_path)
        if d:
            os.makedirs(d, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._init_schema()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS articles (
                origin                  TEXT NOT NULL,
                board                   TEXT NOT NULL,
                article_num             INTEGER NOT NULL,
                article_id              BLOB NOT NULL,
                event_id                BLOB NOT NULL,
                visibility              TEXT NOT NULL DEFAULT 'active',
                body_state              TEXT NOT NULL DEFAULT 'unavailable',
                pin_state               TEXT NOT NULL DEFAULT 'unpinned',
                thread_state            TEXT NOT NULL DEFAULT 'open',
                subject                 TEXT NOT NULL DEFAULT '',
                tags                    TEXT NOT NULL DEFAULT '',
                options                 TEXT NOT NULL DEFAULT '',
                content_type            TEXT NOT NULL DEFAULT '',
                author_pubkey           BLOB NOT NULL,
                author_username         TEXT NOT NULL DEFAULT '',
                author_registrar        TEXT NOT NULL DEFAULT '',
                created_at              INTEGER NOT NULL,
                body_hash               BLOB NOT NULL,
                body_size               INTEGER NOT NULL,
                root_article_id         BLOB NOT NULL DEFAULT x'0000000000000000000000000000000000000000000000000000000000000000',
                reply_to_article_id     BLOB NOT NULL DEFAULT x'0000000000000000000000000000000000000000000000000000000000000000',
                replacement_article_id  BLOB,
                latest_control_seq      INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (origin, board, article_num),
                UNIQUE (origin, board, article_id)
            );
            CREATE INDEX IF NOT EXISTS idx_articles_author
                ON articles(author_pubkey, created_at);
            CREATE INDEX IF NOT EXISTS idx_articles_created
                ON articles(origin, board, created_at);

            CREATE TABLE IF NOT EXISTS pending_controls (
                event_id                BLOB PRIMARY KEY,
                origin                  TEXT NOT NULL,
                origin_seq              INTEGER NOT NULL,
                kind                    TEXT NOT NULL,
                target_origin           TEXT NOT NULL,
                target_board            TEXT NOT NULL,
                target_article_id       BLOB NOT NULL,
                target_event_id         BLOB NOT NULL,
                metadata                BLOB NOT NULL,
                encoded_record          BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS applied_events (
                event_id                BLOB PRIMARY KEY,
                origin                  TEXT NOT NULL,
                origin_seq              INTEGER NOT NULL,
                kind                    TEXT NOT NULL,
                applied_at              INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS projection_checkpoint (
                origin                  TEXT PRIMARY KEY,
                last_applied_seq        INTEGER NOT NULL DEFAULT 0
            );
        """)

    # ------------------------------------------------------------------
    # Checkpoint
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Applied event tracking (idempotency)
    # ------------------------------------------------------------------

    def is_applied(self, event_id: bytes) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM applied_events WHERE event_id=?",
                (event_id,),
            ).fetchone()
            return row is not None

    def _mark_applied(self, rec: Record) -> None:
        import time

        self._conn.execute(
            "INSERT OR IGNORE INTO applied_events "
            "(event_id, origin, origin_seq, kind, applied_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (rec.event_id, rec.origin, rec.origin_seq, rec.kind, int(time.time())),
        )

    # ------------------------------------------------------------------
    # Article operations
    # ------------------------------------------------------------------

    def apply_article(self, rec: Record) -> None:
        """Insert or update an article projection from a bonnet.article record."""
        with self._lock:
            if self.is_applied(rec.event_id):
                return
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                subject = rec.metadata.get_text(1) or ""
                tags_list = rec.metadata.get_text_list(2) or []
                options_list = rec.metadata.get_text_list(3) or []
                content_type = rec.metadata.get_text(4) or ""
                root_id = rec.metadata.get_bytes(5) or ZERO_ID
                reply_id = rec.metadata.get_bytes(6) or ZERO_ID
                superseded_id = rec.metadata.get_bytes(7) or ZERO_ID

                tags = ",".join(tags_list)
                options = ",".join(options_list)

                if superseded_id != ZERO_ID:
                    self._conn.execute(
                        "UPDATE articles SET visibility='superseded', "
                        "replacement_article_id=?, latest_control_seq=? "
                        "WHERE origin=? AND board=? AND article_id=?",
                        (rec.article_id, rec.origin_seq, rec.origin, rec.board, superseded_id),
                    )

                body_state = BODY_UNAVAILABLE

                self._conn.execute(
                    "INSERT OR REPLACE INTO articles "
                    "(origin, board, article_num, article_id, event_id, "
                    "visibility, body_state, pin_state, thread_state, "
                    "subject, tags, options, content_type, "
                    "author_pubkey, author_username, author_registrar, "
                    "created_at, body_hash, body_size, "
                    "root_article_id, reply_to_article_id, latest_control_seq) "
                    "VALUES (?, ?, ?, ?, ?, 'active', ?, 'unpinned', 'open', "
                    "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        rec.origin,
                        rec.board,
                        rec.article_num,
                        rec.article_id,
                        rec.event_id,
                        body_state,
                        subject,
                        tags,
                        options,
                        content_type,
                        rec.actor_pubkey,
                        rec.actor_username,
                        rec.actor_registrar,
                        rec.created_at,
                        rec.body_hash,
                        rec.body_size,
                        root_id,
                        reply_id,
                        rec.origin_seq,
                    ),
                )

                self._replay_pending_for_article(rec.origin, rec.board, rec.article_id)

                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def apply_cancel(self, rec: Record) -> None:
        with self._lock:
            if self.is_applied(rec.event_id):
                return
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if rec.origin != rec.target_origin:
                    self._mark_applied(rec)
                    self._set_checkpoint(rec.origin, rec.origin_seq)
                    self._conn.execute("COMMIT")
                    return

                updated = self._conn.execute(
                    "UPDATE articles SET visibility='cancelled', latest_control_seq=? "
                    "WHERE origin=? AND board=? AND article_id=? "
                    "AND visibility='active'",
                    (rec.origin_seq, rec.target_origin, rec.target_board, rec.target_article_id),
                ).rowcount

                if updated == 0:
                    self._add_pending(rec)

                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def apply_restore(self, rec: Record) -> None:
        with self._lock:
            if self.is_applied(rec.event_id):
                return
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if rec.origin != rec.target_origin:
                    self._mark_applied(rec)
                    self._set_checkpoint(rec.origin, rec.origin_seq)
                    self._conn.execute("COMMIT")
                    return

                updated = self._conn.execute(
                    "UPDATE articles SET visibility='active', latest_control_seq=? "
                    "WHERE origin=? AND board=? AND article_id=? "
                    "AND visibility='cancelled'",
                    (rec.origin_seq, rec.target_origin, rec.target_board, rec.target_article_id),
                ).rowcount

                if updated == 0:
                    self._add_pending(rec)

                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def apply_purge(self, rec: Record) -> None:
        with self._lock:
            if self.is_applied(rec.event_id):
                return
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if rec.origin != rec.target_origin:
                    self._mark_applied(rec)
                    self._set_checkpoint(rec.origin, rec.origin_seq)
                    self._conn.execute("COMMIT")
                    return

                updated = self._conn.execute(
                    "UPDATE articles SET body_state='purged', latest_control_seq=? "
                    "WHERE origin=? AND board=? AND article_id=?",
                    (rec.origin_seq, rec.target_origin, rec.target_board, rec.target_article_id),
                ).rowcount

                if updated == 0:
                    self._add_pending(rec)

                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def apply_pin(self, rec: Record) -> None:
        with self._lock:
            if self.is_applied(rec.event_id):
                return
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if rec.origin != rec.target_origin:
                    self._mark_applied(rec)
                    self._set_checkpoint(rec.origin, rec.origin_seq)
                    self._conn.execute("COMMIT")
                    return

                priority = rec.metadata.get_i64(1) or 0
                updated = self._conn.execute(
                    "UPDATE articles SET pin_state=? WHERE origin=? AND board=? AND article_id=?",
                    (
                        f"pinned({priority})",
                        rec.target_origin,
                        rec.target_board,
                        rec.target_article_id,
                    ),
                ).rowcount

                if updated == 0:
                    self._add_pending(rec)

                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def apply_unpin(self, rec: Record) -> None:
        with self._lock:
            if self.is_applied(rec.event_id):
                return
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if rec.origin != rec.target_origin:
                    self._mark_applied(rec)
                    self._set_checkpoint(rec.origin, rec.origin_seq)
                    self._conn.execute("COMMIT")
                    return

                updated = self._conn.execute(
                    "UPDATE articles SET pin_state='unpinned' "
                    "WHERE origin=? AND board=? AND article_id=?",
                    (rec.target_origin, rec.target_board, rec.target_article_id),
                ).rowcount

                if updated == 0:
                    self._add_pending(rec)

                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def apply_thread_close(self, rec: Record) -> None:
        with self._lock:
            if self.is_applied(rec.event_id):
                return
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if rec.origin != rec.target_origin:
                    self._mark_applied(rec)
                    self._set_checkpoint(rec.origin, rec.origin_seq)
                    self._conn.execute("COMMIT")
                    return

                updated = self._conn.execute(
                    "UPDATE articles SET thread_state='closed' "
                    "WHERE origin=? AND board=? AND article_id=?",
                    (rec.target_origin, rec.target_board, rec.target_article_id),
                ).rowcount

                if updated == 0:
                    self._add_pending(rec)

                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def apply_thread_reopen(self, rec: Record) -> None:
        with self._lock:
            if self.is_applied(rec.event_id):
                return
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if rec.origin != rec.target_origin:
                    self._mark_applied(rec)
                    self._set_checkpoint(rec.origin, rec.origin_seq)
                    self._conn.execute("COMMIT")
                    return

                updated = self._conn.execute(
                    "UPDATE articles SET thread_state='open' "
                    "WHERE origin=? AND board=? AND article_id=?",
                    (rec.target_origin, rec.target_board, rec.target_article_id),
                ).rowcount

                if updated == 0:
                    self._add_pending(rec)

                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def apply_unknown(self, rec: Record) -> None:
        """Record an unknown kind as applied (no projection effect)."""
        with self._lock:
            if self.is_applied(rec.event_id):
                return
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._mark_applied(rec)
                self._set_checkpoint(rec.origin, rec.origin_seq)
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    # ------------------------------------------------------------------
    # Pending controls
    # ------------------------------------------------------------------

    def _add_pending(self, rec: Record) -> None:
        from bonnet.core.record import encode_metadata, encode_record

        self._conn.execute(
            "INSERT OR IGNORE INTO pending_controls "
            "(event_id, origin, origin_seq, kind, target_origin, target_board, "
            "target_article_id, target_event_id, metadata, encoded_record) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                rec.event_id,
                rec.origin,
                rec.origin_seq,
                rec.kind,
                rec.target_origin,
                rec.target_board,
                rec.target_article_id,
                rec.target_event_id,
                encode_metadata(rec.metadata),
                encode_record(rec),
            ),
        )

    def _replay_pending_for_article(self, origin: str, board: str, article_id: bytes) -> None:
        """Replay pending controls for a newly appeared article."""
        from bonnet.core.record import decode_record

        rows = self._conn.execute(
            "SELECT event_id, encoded_record FROM pending_controls "
            "WHERE target_origin=? AND target_board=? AND target_article_id=? "
            "ORDER BY origin, origin_seq ASC",
            (origin, board, article_id),
        ).fetchall()
        for row in rows:
            eid = bytes(row[0])
            encoded = bytes(row[1])
            if encoded:
                pending_rec = decode_record(encoded)
                kind = pending_rec.kind
                if kind == "bonnet.article.cancel":
                    self._apply_cancel_inline(pending_rec)
                elif kind == "bonnet.article.restore":
                    self._apply_restore_inline(pending_rec)
                elif kind == "bonnet.article.purge":
                    self._apply_purge_inline(pending_rec)
                elif kind == "bonnet.article.pin":
                    self._apply_pin_inline(pending_rec)
                elif kind == "bonnet.article.unpin":
                    self._apply_unpin_inline(pending_rec)
                elif kind == "bonnet.thread.close":
                    self._apply_thread_close_inline(pending_rec)
                elif kind == "bonnet.thread.reopen":
                    self._apply_thread_reopen_inline(pending_rec)
            self._conn.execute("DELETE FROM pending_controls WHERE event_id=?", (eid,))

    def _apply_cancel_inline(self, rec: Record) -> None:
        self._conn.execute(
            "UPDATE articles SET visibility='cancelled', latest_control_seq=? "
            "WHERE origin=? AND board=? AND article_id=?",
            (rec.origin_seq, rec.target_origin, rec.target_board, rec.target_article_id),
        )

    def _apply_restore_inline(self, rec: Record) -> None:
        self._conn.execute(
            "UPDATE articles SET visibility='active', latest_control_seq=? "
            "WHERE origin=? AND board=? AND article_id=?",
            (rec.origin_seq, rec.target_origin, rec.target_board, rec.target_article_id),
        )

    def _apply_purge_inline(self, rec: Record) -> None:
        self._conn.execute(
            "UPDATE articles SET body_state='purged', latest_control_seq=? "
            "WHERE origin=? AND board=? AND article_id=?",
            (rec.origin_seq, rec.target_origin, rec.target_board, rec.target_article_id),
        )

    def _apply_pin_inline(self, rec: Record) -> None:
        priority = rec.metadata.get_i64(1) or 0
        self._conn.execute(
            "UPDATE articles SET pin_state=? WHERE origin=? AND board=? AND article_id=?",
            (f"pinned({priority})", rec.target_origin, rec.target_board, rec.target_article_id),
        )

    def _apply_unpin_inline(self, rec: Record) -> None:
        self._conn.execute(
            "UPDATE articles SET pin_state='unpinned' WHERE origin=? AND board=? AND article_id=?",
            (rec.target_origin, rec.target_board, rec.target_article_id),
        )

    def _apply_thread_close_inline(self, rec: Record) -> None:
        self._conn.execute(
            "UPDATE articles SET thread_state='closed' WHERE origin=? AND board=? AND article_id=?",
            (rec.target_origin, rec.target_board, rec.target_article_id),
        )

    def _apply_thread_reopen_inline(self, rec: Record) -> None:
        self._conn.execute(
            "UPDATE articles SET thread_state='open' WHERE origin=? AND board=? AND article_id=?",
            (rec.target_origin, rec.target_board, rec.target_article_id),
        )

    def pending_count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM pending_controls").fetchone()
            return row[0]

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_article_by_num(
        self, origin: str, board: str, article_num: int
    ) -> ArticleProjection | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT origin, board, article_num, article_id, event_id, "
                "visibility, body_state, pin_state, thread_state, "
                "subject, tags, options, content_type, "
                "author_pubkey, author_username, author_registrar, "
                "created_at, body_hash, body_size, "
                "root_article_id, reply_to_article_id, replacement_article_id, "
                "latest_control_seq "
                "FROM articles WHERE origin=? AND board=? AND article_num=?",
                (origin, board, article_num),
            ).fetchone()
            if not row:
                return None
            return ArticleProjection(
                origin=row[0],
                board=row[1],
                article_num=row[2],
                article_id=bytes(row[3]),
                event_id=bytes(row[4]),
                visibility=row[5],
                body_state=row[6],
                pin_state=row[7],
                thread_state=row[8],
                subject=row[9],
                tags=row[10],
                options=row[11],
                content_type=row[12],
                author_pubkey=bytes(row[13]),
                author_username=row[14],
                author_registrar=row[15],
                created_at=row[16],
                body_hash=bytes(row[17]),
                body_size=row[18],
                root_article_id=bytes(row[19]),
                reply_to_article_id=bytes(row[20]),
                replacement_article_id=bytes(row[21]) if row[21] else None,
                latest_control_seq=row[22],
            )

    def get_article_by_id(
        self, origin: str, board: str, article_id: bytes
    ) -> ArticleProjection | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT origin, board, article_num, article_id, event_id, "
                "visibility, body_state, pin_state, thread_state, "
                "subject, tags, options, content_type, "
                "author_pubkey, author_username, author_registrar, "
                "created_at, body_hash, body_size, "
                "root_article_id, reply_to_article_id, replacement_article_id, "
                "latest_control_seq "
                "FROM articles WHERE origin=? AND board=? AND article_id=?",
                (origin, board, article_id),
            ).fetchone()
            if not row:
                return None
            return ArticleProjection(
                origin=row[0],
                board=row[1],
                article_num=row[2],
                article_id=bytes(row[3]),
                event_id=bytes(row[4]),
                visibility=row[5],
                body_state=row[6],
                pin_state=row[7],
                thread_state=row[8],
                subject=row[9],
                tags=row[10],
                options=row[11],
                content_type=row[12],
                author_pubkey=bytes(row[13]),
                author_username=row[14],
                author_registrar=row[15],
                created_at=row[16],
                body_hash=bytes(row[17]),
                body_size=row[18],
                root_article_id=bytes(row[19]),
                reply_to_article_id=bytes(row[20]),
                replacement_article_id=bytes(row[21]) if row[21] else None,
                latest_control_seq=row[22],
            )

    def list_articles(
        self,
        origin: str,
        board: str,
        offset: int = 0,
        limit: int = 100,
        include_cancelled: bool = False,
        include_superseded: bool = False,
        include_purged: bool = False,
    ) -> list[ArticleProjection]:
        states = [VISIBILITY_ACTIVE]
        if include_cancelled:
            states.append(VISIBILITY_CANCELLED)
        if include_superseded:
            states.append(VISIBILITY_SUPERSEDED)
        placeholders = ",".join("?" * len(states))
        where_extra = ""
        if not include_purged:
            where_extra = " AND body_state != 'purged'"
        with self._lock:
            rows = self._conn.execute(
                f"SELECT origin, board, article_num, article_id, event_id, "
                f"visibility, body_state, pin_state, thread_state, "
                f"subject, tags, options, content_type, "
                f"author_pubkey, author_username, author_registrar, "
                f"created_at, body_hash, body_size, "
                f"root_article_id, reply_to_article_id, replacement_article_id, "
                f"latest_control_seq "
                f"FROM articles WHERE origin=? AND board=? "
                f"AND visibility IN ({placeholders}){where_extra} "
                f"ORDER BY created_at DESC, article_num ASC LIMIT ? OFFSET ?",
                [origin, board] + states + [limit, offset],
            ).fetchall()
            return [
                ArticleProjection(
                    origin=r[0],
                    board=r[1],
                    article_num=r[2],
                    article_id=bytes(r[3]),
                    event_id=bytes(r[4]),
                    visibility=r[5],
                    body_state=r[6],
                    pin_state=r[7],
                    thread_state=r[8],
                    subject=r[9],
                    tags=r[10],
                    options=r[11],
                    content_type=r[12],
                    author_pubkey=bytes(r[13]),
                    author_username=r[14],
                    author_registrar=r[15],
                    created_at=r[16],
                    body_hash=bytes(r[17]),
                    body_size=r[18],
                    root_article_id=bytes(r[19]),
                    reply_to_article_id=bytes(r[20]),
                    replacement_article_id=bytes(r[21]) if r[21] else None,
                    latest_control_seq=r[22],
                )
                for r in rows
            ]

    def search_metadata(
        self,
        origin: str,
        board: str,
        text_query: str = "",
        actor_pubkey: bytes = None,
        offset: int = 0,
        limit: int = 100,
        include_cancelled: bool = False,
        include_superseded: bool = False,
    ) -> tuple[list[ArticleProjection], int]:
        """Search articles with SQL-level filtering. Returns (results, total_count)."""
        states = [VISIBILITY_ACTIVE]
        if include_cancelled:
            states.append(VISIBILITY_CANCELLED)
        if include_superseded:
            states.append(VISIBILITY_SUPERSEDED)
        placeholders = ",".join("?" * len(states))

        where_parts = [
            "origin=?",
            "board=?",
            f"visibility IN ({placeholders})",
            "body_state != 'purged'",
        ]
        params = [origin, board] + states

        if text_query:
            where_parts.append("(subject LIKE ? OR tags LIKE ?)")
            like = f"%{text_query}%"
            params.extend([like, like])

        if actor_pubkey is not None:
            where_parts.append("author_pubkey=?")
            params.append(actor_pubkey)

        where_clause = " AND ".join(where_parts)

        with self._lock:
            count_row = self._conn.execute(
                f"SELECT COUNT(*) FROM articles WHERE {where_clause}",
                params,
            ).fetchone()
            total = count_row[0]

            rows = self._conn.execute(
                f"SELECT origin, board, article_num, article_id, event_id, "
                f"visibility, body_state, pin_state, thread_state, "
                f"subject, tags, options, content_type, "
                f"author_pubkey, author_username, author_registrar, "
                f"created_at, body_hash, body_size, "
                f"root_article_id, reply_to_article_id, replacement_article_id, "
                f"latest_control_seq "
                f"FROM articles WHERE {where_clause} "
                f"ORDER BY created_at DESC, article_num ASC LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()

            results = [
                ArticleProjection(
                    origin=r[0],
                    board=r[1],
                    article_num=r[2],
                    article_id=bytes(r[3]),
                    event_id=bytes(r[4]),
                    visibility=r[5],
                    body_state=r[6],
                    pin_state=r[7],
                    thread_state=r[8],
                    subject=r[9],
                    tags=r[10],
                    options=r[11],
                    content_type=r[12],
                    author_pubkey=bytes(r[13]),
                    author_username=r[14],
                    author_registrar=r[15],
                    created_at=r[16],
                    body_hash=bytes(r[17]),
                    body_size=r[18],
                    root_article_id=bytes(r[19]),
                    reply_to_article_id=bytes(r[20]),
                    replacement_article_id=bytes(r[21]) if r[21] else None,
                    latest_control_seq=r[22],
                )
                for r in rows
            ]
            return results, total

    def article_count(self, origin: str, board: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM articles WHERE origin=? AND board=?",
                (origin, board),
            ).fetchone()
            return row[0]

    # ------------------------------------------------------------------
    # Structured query
    # ------------------------------------------------------------------

    def query_articles(
        self,
        origin: str,
        board: str,
        filters: list,
        offset: int = 0,
        limit: int = 100,
    ) -> list[ArticleProjection]:
        """Query articles with structured field filters.

        filters: list of (field_id, operator, value) tuples.
            field_id: 0x01=author_pubkey, 0x02=author_username,
                      0x03=author_registrar, 0x04=tags, 0x05=created_at,
                      0x06=visibility, 0x07=thread_root, 0x08=reply_to,
                      0x09=pin_state
            operator: 0x01=EQ, 0x02=NE, 0x03=GT, 0x04=LT, 0x05=LIKE, 0x06=IN
            value: bytes, str, int, or bool depending on field

        All filters are AND'd. Purged articles excluded unless visibility=purged.
        """
        where_parts = ["origin=?", "board=?"]
        params = [origin, board]

        has_visibility_filter = False
        query_purged = False

        for field_id, op, value in filters:
            if field_id == 0x01:
                col = "author_pubkey"
                if op == 0x01:
                    where_parts.append(f"{col}=?")
                    params.append(value)
                elif op == 0x02:
                    where_parts.append(f"{col}!=?")
                    params.append(value)
            elif field_id == 0x02:
                col = "author_username"
                if op == 0x01:
                    where_parts.append(f"{col}=?")
                    params.append(value)
                elif op == 0x02:
                    where_parts.append(f"{col}!=?")
                    params.append(value)
                elif op == 0x05:
                    where_parts.append(f"{col} LIKE ?")
                    params.append(f"%{value}%")
            elif field_id == 0x03:
                col = "author_registrar"
                if op == 0x01:
                    where_parts.append(f"{col}=?")
                    params.append(value)
                elif op == 0x05:
                    where_parts.append(f"{col} LIKE ?")
                    params.append(f"%{value}%")
            elif field_id == 0x04:
                col = "tags"
                if op == 0x05:
                    where_parts.append(f"{col} LIKE ?")
                    params.append(f"%{value}%")
                elif op == 0x06:
                    for tag in value.split(","):
                        tag = tag.strip()
                        if tag:
                            where_parts.append(f"{col} LIKE ?")
                            params.append(f"%{tag}%")
            elif field_id == 0x05:
                col = "created_at"
                if op == 0x03:
                    where_parts.append(f"{col} > ?")
                    params.append(int(value))
                elif op == 0x04:
                    where_parts.append(f"{col} < ?")
                    params.append(int(value))
                elif op == 0x01:
                    where_parts.append(f"{col} = ?")
                    params.append(int(value))
            elif field_id == 0x06:
                if value == "purged":
                    has_visibility_filter = True
                    query_purged = True
                    where_parts.append("body_state = 'purged'")
                else:
                    col = "visibility"
                    if op == 0x01:
                        has_visibility_filter = True
                        where_parts.append(f"{col}=?")
                        params.append(value)
                    elif op == 0x02:
                        has_visibility_filter = True
                        where_parts.append(f"{col}!=?")
                        params.append(value)
            elif field_id == 0x07:
                if op == 0x01:
                    if value:
                        where_parts.append(
                            "root_article_id = x'0000000000000000000000000000000000000000000000000000000000000000'"
                        )
                    else:
                        where_parts.append(
                            "root_article_id != x'0000000000000000000000000000000000000000000000000000000000000000'"
                        )
            elif field_id == 0x08:
                col = "reply_to_article_id"
                if op == 0x01:
                    where_parts.append(f"{col}=?")
                    params.append(value)
            elif field_id == 0x09:
                col = "pin_state"
                if op == 0x01:
                    if value:
                        where_parts.append(f"{col} != 'unpinned'")
                    else:
                        where_parts.append(f"{col} = 'unpinned'")

        if not has_visibility_filter:
            where_parts.append("visibility = 'active'")

        if not query_purged:
            where_parts.append("body_state != 'purged'")

        where_clause = " AND ".join(where_parts)

        with self._lock:
            rows = self._conn.execute(
                f"SELECT origin, board, article_num, article_id, event_id, "
                f"visibility, body_state, pin_state, thread_state, "
                f"subject, tags, options, content_type, "
                f"author_pubkey, author_username, author_registrar, "
                f"created_at, body_hash, body_size, "
                f"root_article_id, reply_to_article_id, replacement_article_id, "
                f"latest_control_seq "
                f"FROM articles WHERE {where_clause} "
                f"ORDER BY article_num ASC LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()
            return [
                ArticleProjection(
                    origin=r[0],
                    board=r[1],
                    article_num=r[2],
                    article_id=bytes(r[3]),
                    event_id=bytes(r[4]),
                    visibility=r[5],
                    body_state=r[6],
                    pin_state=r[7],
                    thread_state=r[8],
                    subject=r[9],
                    tags=r[10],
                    options=r[11],
                    content_type=r[12],
                    author_pubkey=bytes(r[13]),
                    author_username=r[14],
                    author_registrar=r[15],
                    created_at=r[16],
                    body_hash=bytes(r[17]),
                    body_size=r[18],
                    root_article_id=bytes(r[19]),
                    reply_to_article_id=bytes(r[20]),
                    replacement_article_id=bytes(r[21]) if r[21] else None,
                    latest_control_seq=r[22],
                )
                for r in rows
            ]

    # ------------------------------------------------------------------
    # Rebuild
    # ------------------------------------------------------------------

    def clear(self) -> None:
        """Delete all projection data for a full rebuild."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("DELETE FROM articles")
                self._conn.execute("DELETE FROM pending_controls")
                self._conn.execute("DELETE FROM applied_events")
                self._conn.execute("DELETE FROM projection_checkpoint")
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def update_body_state(self, origin: str, board: str, article_num: int, state: str) -> None:
        """Update body availability state for an article."""
        with self._lock:
            self._conn.execute(
                "UPDATE articles SET body_state=? WHERE origin=? AND board=? AND article_num=?",
                (state, origin, board, article_num),
            )
            self._conn.commit()
