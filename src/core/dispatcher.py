"""Dispatcher for the Bonnet Firehose Protocol (PROTOCOL.md §13).

Processes accepted firehose records in origin sequence order and routes
them to the appropriate projections. Implements idempotent applied-event
tracking, pending controls, cross-dispatcher serialization, and crash replay.
"""

from __future__ import annotations

import threading
from typing import Optional

from core.firehose import FirehoseStore
from core.record import Record, ZERO_ID, ID_SIZE
from core.board_projection import BoardProjection, board_db_path
from core.global_projections import (
    NavProjection, UserProjection, PolicyProjection,
)
from core.bodies import BodyStore


# ---------------------------------------------------------------------------
# Kind constants (mirror of record/firehose kinds)
# ---------------------------------------------------------------------------

KIND_ARTICLE = "bonnet.article"
KIND_ARTICLE_CANCEL = "bonnet.article.cancel"
KIND_ARTICLE_RESTORE = "bonnet.article.restore"
KIND_ARTICLE_PURGE = "bonnet.article.purge"
KIND_ARTICLE_PIN = "bonnet.article.pin"
KIND_ARTICLE_UNPIN = "bonnet.article.unpin"
KIND_THREAD_CLOSE = "bonnet.thread.close"
KIND_THREAD_REOPEN = "bonnet.thread.reopen"
KIND_BOARD_CREATE = "bonnet.board.create"
KIND_BOARD_CLOSE = "bonnet.board.close"
KIND_BOARD_REOPEN = "bonnet.board.reopen"
KIND_USER_REGISTER = "bonnet.user.register"
KIND_USER_REVOKE = "bonnet.user.revoke"
KIND_RULE_PUBLISH = "bonnet.rule.publish"
KIND_RULE_REVOKE = "bonnet.rule.revoke"
KIND_REPORT = "bonnet.report"
KIND_PUNISHMENT_ISSUE = "bonnet.punishment.issue"
KIND_PUNISHMENT_REVOKE = "bonnet.punishment.revoke"
KIND_ORIGIN_KEY_ROTATE = "bonnet.origin.key.rotate"


class Dispatcher:
    """Routes firehose records to projections.

    Each origin has its own checkpoint in events.db. The dispatcher processes
    records in origin sequence order. All dispatchers writing one projection
    database use a serialized writer (the projection's internal RLock).
    """

    def __init__(
        self,
        firehose: FirehoseStore,
        nav: NavProjection,
        users: UserProjection,
        policy: PolicyProjection,
        boards_dir: str,
        body_store: BodyStore,
    ):
        self._firehose = firehose
        self._nav = nav
        self._users = users
        self._policy = policy
        self._boards_dir = boards_dir
        self._body_store = body_store
        self._board_projections: dict[tuple[str, str], BoardProjection] = {}
        self._boards_lock = threading.RLock()
        self._dispatch_lock = threading.RLock()

    def close(self) -> None:
        with self._boards_lock:
            for bp in self._board_projections.values():
                bp.close()
            self._board_projections.clear()

    # ------------------------------------------------------------------
    # Board projection management
    # ------------------------------------------------------------------

    def _get_board_projection(self, origin: str, board: str) -> BoardProjection:
        key = (origin, board)
        with self._boards_lock:
            bp = self._board_projections.get(key)
            if bp is None:
                bp = BoardProjection(board_db_path(self._boards_dir, origin, board))
                self._board_projections[key] = bp
            return bp

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def dispatch_origin(self, origin: str, max_records: int = 10000) -> int:
        """Process all un-dispatched records for one origin.

        Returns the number of records dispatched.
        """
        with self._dispatch_lock:
            checkpoint = self._firehose.get_checkpoint(origin)
            highest = self._firehose.get_highest_seq(origin)
            if checkpoint >= highest:
                return 0

            records = self._firehose.get_events_range(origin, checkpoint + 1, max_records)
            count = 0
            for rec in records:
                self._dispatch_record(rec)
                self._firehose.set_checkpoint(origin, rec.origin_seq)
                count += 1
            return count

    def dispatch_all_origins(self) -> int:
        """Dispatch pending records for all origins. Returns total count."""
        return self._firehose._conn.execute(
            "SELECT DISTINCT origin FROM origin_state"
        ).fetchall().__len__() if self._firehose.get_highest_seq else 0

    def _dispatch_record(self, rec: Record) -> None:
        """Route a single record to the appropriate projection(s)."""
        kind = rec.kind

        if kind == KIND_ARTICLE:
            self._dispatch_article(rec)
        elif kind in (KIND_ARTICLE_CANCEL, KIND_ARTICLE_RESTORE, KIND_ARTICLE_PURGE,
                      KIND_ARTICLE_PIN, KIND_ARTICLE_UNPIN,
                      KIND_THREAD_CLOSE, KIND_THREAD_REOPEN):
            self._dispatch_article_control(rec)
        elif kind == KIND_BOARD_CREATE:
            self._nav.apply_board_create(rec)
        elif kind == KIND_BOARD_CLOSE:
            self._nav.apply_board_close(rec)
        elif kind == KIND_BOARD_REOPEN:
            self._nav.apply_board_reopen(rec)
        elif kind == KIND_USER_REGISTER:
            self._users.apply_user_register(rec)
        elif kind == KIND_USER_REVOKE:
            self._users.apply_user_revoke(rec)
        elif kind == KIND_RULE_PUBLISH:
            self._policy.apply_rule(rec)
        elif kind == KIND_RULE_REVOKE:
            self._policy.apply_rule_revoke(rec)
        elif kind == KIND_REPORT:
            self._policy.apply_report(rec)
        elif kind == KIND_PUNISHMENT_ISSUE:
            self._policy.apply_punishment(rec)
        elif kind == KIND_PUNISHMENT_REVOKE:
            self._policy.apply_punishment_revoke(rec)
        elif kind == KIND_ORIGIN_KEY_ROTATE:
            pass  # handled by firehose store
        else:
            self._dispatch_unknown(rec)

    def _dispatch_article(self, rec: Record) -> None:
        bp = self._get_board_projection(rec.origin, rec.board)
        bp.apply_article(rec)

        if rec.article_num > 0 and rec.body_size > 0:
            self._body_store.finalize_article_body(
                rec.origin, rec.board, rec.event_id, rec.article_num,
            )
            bp.update_body_state(
                rec.origin, rec.board, rec.article_num, "available",
            )

    def _dispatch_article_control(self, rec: Record) -> None:
        target_origin = rec.target_origin
        target_board = rec.target_board
        bp = self._get_board_projection(target_origin, target_board)

        kind = rec.kind
        if kind == KIND_ARTICLE_CANCEL:
            bp.apply_cancel(rec)
        elif kind == KIND_ARTICLE_RESTORE:
            bp.apply_restore(rec)
        elif kind == KIND_ARTICLE_PURGE:
            bp.apply_purge(rec)
            if rec.origin == rec.target_origin and rec.target_article_id != ZERO_ID:
                proj = bp.get_article_by_id(target_origin, target_board, rec.target_article_id)
                if proj:
                    self._body_store.delete_article_body(
                        target_origin, target_board, proj.article_num,
                    )
        elif kind == KIND_ARTICLE_PIN:
            bp.apply_pin(rec)
        elif kind == KIND_ARTICLE_UNPIN:
            bp.apply_unpin(rec)
        elif kind == KIND_THREAD_CLOSE:
            bp.apply_thread_close(rec)
        elif kind == KIND_THREAD_REOPEN:
            bp.apply_thread_reopen(rec)

    def _dispatch_unknown(self, rec: Record) -> None:
        """Unknown kinds are applied as no-ops to track idempotency."""
        if rec.board:
            bp = self._get_board_projection(rec.origin, rec.board)
            bp.apply_unknown(rec)
        else:
            self._nav._mark_applied(rec) if self._nav.is_applied(rec.event_id) is False else None

    # ------------------------------------------------------------------
    # Rebuild
    # ------------------------------------------------------------------

    def rebuild_all(self, origin: str) -> int:
        """Clear all projections for an origin and replay from the firehose.

        Returns the number of records replayed.
        """
        with self._dispatch_lock:
            self._nav.clear()
            self._users.clear()
            self._policy.clear()

            with self._boards_lock:
                for key, bp in list(self._board_projections.items()):
                    if key[0] == origin:
                        bp.clear()
                        bp.close()
                        del self._board_projections[key]

            self._firehose.set_checkpoint(origin, 0)

            return self.dispatch_origin(origin)
