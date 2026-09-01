"""Dispatcher for the firehose protocol.

Processes accepted firehose records in origin sequence order and routes
them to the appropriate projections. Implements idempotent applied-event
tracking, pending controls, cross-dispatcher serialization, and crash replay.
"""

from __future__ import annotations

import threading
from collections.abc import Callable

from bonnet.core.board_projection import (
    AUTHOR_FOREIGN,
    AUTHOR_REGISTRY,
    AUTHOR_UNCHECKED,
    AUTHOR_UNREGISTERED,
    BoardProjection,
    board_db_path,
    delete_board_dbs,
)
from bonnet.core.bodies import BodyStore
from bonnet.core.firehose import FirehoseStore
from bonnet.core.global_projections import (
    NavProjection,
    PolicyProjection,
    UserProjection,
)
from bonnet.core.kinds import (
    ARTICLE_CONTROL_KINDS,
    KIND_ARTICLE,
    KIND_ARTICLE_CANCEL,
    KIND_ARTICLE_PIN,
    KIND_ARTICLE_PURGE,
    KIND_ARTICLE_RESTORE,
    KIND_ARTICLE_UNPIN,
    KIND_BOARD_CLOSE,
    KIND_BOARD_CREATE,
    KIND_BOARD_REOPEN,
    KIND_ORIGIN_KEY_ROTATE,
    KIND_PUNISHMENT_ACK,
    KIND_PUNISHMENT_REVOKE,
    KIND_REPORT,
    KIND_RULE_PUBLISH,
    KIND_RULE_REVOKE,
    KIND_THREAD_CLOSE,
    KIND_THREAD_REOPEN,
    KIND_USER_KEY_ROTATE,
    KIND_USER_REGISTER,
    KIND_USER_REVOKE,
    PUNISHMENT_ISSUE_KINDS,
    PUNISHMENT_TYPE_BY_KIND,
)
from bonnet.core.logging import log_msg
from bonnet.core.record import ZERO_ID, Record


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
        allowed_origins: set = None,
        local_origin: str = "",
        punishment_import_policy: dict = None,
    ):
        self._firehose = firehose
        self._nav = nav
        self._users = users
        self._policy = policy
        self._boards_dir = boards_dir
        self._body_store = body_store
        self._allowed_origins = allowed_origins or set()
        self._local_origin = local_origin
        # origin -> set of imported punishment type names. Types from
        # origins not present in the map are never applied locally.
        self._punishment_import_policy = punishment_import_policy or {}
        self._board_projections: dict[tuple[str, str], BoardProjection] = {}
        self._boards_lock = threading.RLock()
        self._dispatch_lock = threading.RLock()

        # Registry (kind -> handler) built once here rather than an inline
        # elif chain, so a new kind is added in one place: a KIND_* constant
        # in kinds.py and one line registering its handler.
        self._dispatch_table: dict[str, Callable[[Record], None]] = {
            KIND_ARTICLE: self._dispatch_article,
            KIND_BOARD_CREATE: self._nav.apply_board_create,
            KIND_BOARD_CLOSE: self._nav.apply_board_close,
            KIND_BOARD_REOPEN: self._nav.apply_board_reopen,
            KIND_USER_REGISTER: self._users.apply_user_register,
            KIND_USER_REVOKE: self._users.apply_user_revoke,
            # Unlike KIND_ORIGIN_KEY_ROTATE below, this one does real work
            # here: an actor key is carried inside the records it signed, so
            # nothing in the store needs to know about the succession.
            KIND_USER_KEY_ROTATE: self._users.apply_user_key_rotate,
            KIND_RULE_PUBLISH: self._policy.apply_rule,
            KIND_RULE_REVOKE: self._policy.apply_rule_revoke,
            KIND_REPORT: self._policy.apply_report,
            KIND_PUNISHMENT_REVOKE: self._policy.apply_punishment_revoke,
            KIND_PUNISHMENT_ACK: self._policy.apply_punishment_ack,
            KIND_ORIGIN_KEY_ROTATE: lambda rec: None,  # handled by firehose store
        }
        for kind in ARTICLE_CONTROL_KINDS:
            self._dispatch_table[kind] = self._dispatch_article_control
        for kind in PUNISHMENT_ISSUE_KINDS:
            self._dispatch_table[kind] = self._dispatch_punishment_issue

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
        if self._allowed_origins and origin not in self._allowed_origins:
            return 0

        with self._dispatch_lock:
            checkpoint = self._firehose.get_checkpoint(origin)
            highest = self._firehose.get_highest_seq(origin)
            if checkpoint >= highest:
                return 0

            records = self._firehose.get_events_range(origin, checkpoint + 1, max_records)
            count = 0
            for rec in records:
                try:
                    self._dispatch_record(rec)
                except Exception as e:
                    # Skip and log rather than halt: one bad record must not
                    # block every later record for this origin forever. The
                    # checkpoint still advances past it, same as a successful
                    # dispatch, so the origin doesn't get stuck retrying it.
                    log_msg(
                        f"DISPATCH: origin='{origin}' seq={rec.origin_seq} kind='{rec.kind}' "
                        f"FAILED, skipping: {e}"
                    )
                self._firehose.set_checkpoint(origin, rec.origin_seq)
                # Punishment import relies on the policy checkpoint tracking overall
                # dispatch progress, not just policy-kind records, so that
                # _policy_current() can't be fooled by intervening
                # non-policy records into believing the projection is stale.
                self._policy.set_checkpoint(origin, rec.origin_seq)
                count += 1
            return count

    def _dispatch_record(self, rec: Record) -> None:
        """Route a single record to the appropriate projection(s)."""
        handler = self._dispatch_table.get(rec.kind)
        if handler is None:
            self._dispatch_unknown(rec)
        else:
            handler(rec)

    def _dispatch_punishment_issue(self, rec: Record) -> None:
        if self._punishment_import_allowed(rec):
            self._policy.apply_punishment(rec)

    def _punishment_import_allowed(self, rec: Record) -> bool:
        """Per-type, per-origin punishment import filtering.

        Local punishments always apply. Federated ones apply only when the
        origin is configured with that type imported. Rejected records stay
        in the firehose for relay; they are simply not enforced locally.
        """
        if rec.origin == self._local_origin:
            return True
        imported = self._punishment_import_policy.get(rec.origin, frozenset())
        punishment_type = PUNISHMENT_TYPE_BY_KIND.get(rec.kind)
        if punishment_type not in imported:
            log_msg(
                f"DISPATCH: origin='{rec.origin}' seq={rec.origin_seq} kind='{rec.kind}' "
                "not imported — stored for relay only"
            )
            return False
        return True

    def _resolve_author_check(self, rec: Record) -> str:
        """Did the naming origin issue `actor_username` to `actor_pubkey`?

        Purely local, by design. The only case that would need the network is a
        record naming *another* origin as registrar, and that one is answered
        `foreign` without asking: the named origin may be gone, may be refusing
        us, and by the protocol's own reasoning those two are indistinguishable
        from the outside — so a failed lookup could never be told apart from a
        false claim. Reporting "not ours to check" is the honest answer.

        The same-origin case needs no network either, and is complete rather
        than best-effort: sync fetches a prefix beginning at seq 1 and
        `dispatch_origin` walks strictly in sequence, so by the time this runs
        for seq N every `bonnet.user.register` below N from that origin has
        already been applied. A legitimate name can therefore never read as
        `unregistered` merely because this relay is behind.
        """
        if not rec.actor_username:
            return AUTHOR_UNCHECKED
        if rec.actor_registrar != rec.origin:
            return AUTHOR_FOREIGN
        user = self._users.get_user_by_pubkey(rec.origin, rec.actor_pubkey)
        if user is not None and user["username"] == rec.actor_username:
            return AUTHOR_REGISTRY
        return AUTHOR_UNREGISTERED

    def _dispatch_article(self, rec: Record) -> None:
        bp = self._get_board_projection(rec.origin, rec.board)
        bp.apply_article(rec, author_check=self._resolve_author_check(rec))

        if rec.article_num > 0 and rec.body_size > 0:
            if self._body_store.finalize_article_body(
                rec.origin,
                rec.board,
                rec.event_id,
                rec.article_num,
            ):
                bp.update_body_state(
                    rec.origin,
                    rec.board,
                    rec.article_num,
                    "available",
                )
            elif self._body_store.article_body_exists(
                rec.origin,
                rec.board,
                rec.article_num,
            ):
                bp.update_body_state(
                    rec.origin,
                    rec.board,
                    rec.article_num,
                    "available",
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
                        target_origin,
                        target_board,
                        proj.article_num,
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
            self._nav.apply_unknown(rec)

    # ------------------------------------------------------------------
    # Rebuild
    # ------------------------------------------------------------------

    def rebuild_all(self, origin: str) -> int:
        """Clear all projections for an origin and replay from the firehose.

        Board projection databases are deleted from disk rather than cleared
        in place, so replay is deterministic even for boards whose projections
        were never opened by this process and cannot be suppressed by stale
        applied-event tracking.

        Returns the number of records replayed.
        """
        with self._dispatch_lock:
            with self._boards_lock:
                for key, bp in list(self._board_projections.items()):
                    if key[0] == origin:
                        bp.close()
                        del self._board_projections[key]

            delete_board_dbs(self._boards_dir, origin)

            self._nav.clear_origin(origin)
            self._users.clear_origin(origin)
            self._policy.clear_origin(origin)

            self._firehose.set_checkpoint(origin, 0)

            return self.dispatch_origin(origin)
