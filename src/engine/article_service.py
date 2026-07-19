"""Article feed service — engine-layer projection semantics over ArticleFeedStore.

Implements Phase 2 of ARTICLE_FEED_PROTOCOL_V3_IMPLEMENTATION_PLAN.md:
  - ARTICLE publication via feed append
  - CANCEL / RESTORE / PURGE / SUPERSEDE control events
  - Projection-aware article get / list / search
  - Body availability tracking

This service wraps ArticleFeedStore and adds authorization-aware validation
and projection orchestration. It does NOT handle wire protocol commands —
that is Phase 3 (net/commands.py). The store handles mechanical projection
state transitions within atomic transactions; this service handles:
  - Target validation (exists, same feed, not already in terminal state)
  - Author vs moderator authorization for control events
  - Read-side orchestration (joining projection + body + control events)
  - Search/list query construction
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from core.article_feed import (
    EVENT_ARTICLE,
    EVENT_CANCEL,
    EVENT_RESTORE,
    EVENT_PURGE,
    EVENT_RULE,
    EVENT_RULE_REVOKE,
    EVENT_REPORT,
    EVENT_PUNISHMENT,
    EVENT_PUNISHMENT_REVOKE,
    SCHEME_V3,
    ZERO_MESSAGE_ID,
    ZERO_HASH,
    Submission,
    Event,
    FeedHead,
    ArticleHeaders,
    RuleHeaders,
    ReportHeaders,
    PunishmentHeaders,
    ArticleFeedStore,
    compute_body_hash,
    encode_event,
    decode_event,
    verify_author_signature,
    sign_author,
    sign_origin,
    sign_head,
    compute_event_hash,
    compute_head_hash,
    encode_head,
    AcceptResult,
    MessageIdCollision,
    FeedAcceptanceError,
)
from core.crypto import Identity


@dataclass
class ArticleView:
    """Projection-aware article read result."""
    event: Event
    projected_state: str  # 'active', 'cancelled', 'superseded', 'purged'
    control_event_ids: list  # list[bytes] — message IDs of applicable controls
    body_available: bool
    body: Optional[bytes]  # None if not requested or unavailable


class ArticleService:
    """Engine-level article feed service with projection semantics."""

    def __init__(self, store: ArticleFeedStore, origin: str,
                 identity: Identity):
        self._store = store
        self._origin = origin
        self._identity = identity

    @property
    def store(self) -> ArticleFeedStore:
        return self._store

    # ------------------------------------------------------------------
    # Publication
    # ------------------------------------------------------------------

    def publish_article(
        self,
        submission: Submission,
        body: bytes,
        author_signature: bytes,
    ) -> tuple:
        """Publish an ARTICLE event to the local authoritative feed.

        The submission must have event_type=ARTICLE, origin=local origin.
        Returns (Event, FeedHead).
        """
        self._validate_local_submission(submission, EVENT_ARTICLE)
        return self._store.append_authoritative(
            submission, body, SCHEME_V3, author_signature,
            self._identity, expected_origin=self._origin,
        )

    def publish_article_raw(
        self,
        event_type: int,
        submission: Submission,
        body: bytes,
        author_signature: bytes,
    ) -> tuple:
        """Publish any event type (ARTICLE or control) to the local feed.

        Validates the submission origin and author signature, then delegates
        to the store's atomic append. Returns (Event, FeedHead).
        """
        self._validate_local_submission(submission, event_type)
        return self._store.append_authoritative(
            submission, body, SCHEME_V3, author_signature,
            self._identity, expected_origin=self._origin,
        )

    # ------------------------------------------------------------------
    # Control events
    # ------------------------------------------------------------------

    def cancel_article(
        self,
        submission: Submission,
        author_signature: bytes,
    ) -> tuple:
        """Publish a CANCEL control event targeting an article.

        Validates that the target exists in the same feed. Authorization
        (author vs moderator) is checked by the caller — this method
        validates structural correctness only.
        """
        self._validate_local_submission(submission, EVENT_CANCEL)
        self._validate_target_exists(submission)
        return self._store.append_authoritative(
            submission, b"", SCHEME_V3, author_signature,
            self._identity, expected_origin=self._origin,
        )

    def restore_article(
        self,
        submission: Submission,
        author_signature: bytes,
    ) -> tuple:
        """Publish a RESTORE control event targeting an article."""
        self._validate_local_submission(submission, EVENT_RESTORE)
        self._validate_target_exists(submission)
        return self._store.append_authoritative(
            submission, b"", SCHEME_V3, author_signature,
            self._identity, expected_origin=self._origin,
        )

    def purge_article(
        self,
        submission: Submission,
        author_signature: bytes,
    ) -> tuple:
        """Publish a PURGE control event targeting an article.

        After the purge event is committed, the target's body ref is marked
        not retained and the local body blob may be deleted. The article
        metadata and event history remain.
        """
        self._validate_local_submission(submission, EVENT_PURGE)
        self._validate_target_exists(submission)
        return self._store.append_authoritative(
            submission, b"", SCHEME_V3, author_signature,
            self._identity, expected_origin=self._origin,
        )

    def supersede_article(
        self,
        submission: Submission,
        body: bytes,
        author_signature: bytes,
    ) -> tuple:
        """Publish an ARTICLE event that supersedes an existing article.

        The submission must have event_type=ARTICLE and
        supersedes_message_id set to the target article's message_id.
        The target is marked 'superseded' with replacement_message_id
        pointing to the new article.
        """
        self._validate_local_submission(submission, EVENT_ARTICLE)
        if submission.supersedes_message_id == ZERO_MESSAGE_ID:
            raise FeedAcceptanceError("supersede requires non-zero supersedes_message_id")
        self._validate_target_exists_by_id(submission.supersedes_message_id,
                                           submission.origin, submission.board)
        return self._store.append_authoritative(
            submission, body, SCHEME_V3, author_signature,
            self._identity, expected_origin=self._origin,
        )

    # ------------------------------------------------------------------
    # Moderation control events (Phase 5)
    # ------------------------------------------------------------------

    def publish_rule(
        self,
        submission: Submission,
        body: bytes,
        author_signature: bytes,
    ) -> tuple:
        """Publish a RULE event to the configured moderation.rules board.

        The submission must have event_type=RULE and headers=RuleHeaders.
        Authorization (administrator role) is checked by the caller.
        """
        self._validate_local_submission(submission, EVENT_RULE)
        if not isinstance(submission.headers, RuleHeaders):
            raise FeedAcceptanceError("RULE requires RuleHeaders")
        return self._store.append_authoritative(
            submission, body, SCHEME_V3, author_signature,
            self._identity, expected_origin=self._origin,
        )

    def publish_rule_revoke(
        self,
        submission: Submission,
        author_signature: bytes,
    ) -> tuple:
        """Publish a RULE_REVOKE event targeting an existing rule."""
        self._validate_local_submission(submission, EVENT_RULE_REVOKE)
        self._validate_target_event_exists(submission)
        return self._store.append_authoritative(
            submission, b"", SCHEME_V3, author_signature,
            self._identity, expected_origin=self._origin,
        )

    def publish_report(
        self,
        submission: Submission,
        body: bytes,
        author_signature: bytes,
    ) -> tuple:
        """Publish a REPORT event to the configured moderation.reports board.

        The submission must have event_type=REPORT and headers=ReportHeaders.
        Reports are author-signed audit records; importing does not punish.
        """
        self._validate_local_submission(submission, EVENT_REPORT)
        if not isinstance(submission.headers, ReportHeaders):
            raise FeedAcceptanceError("REPORT requires ReportHeaders")
        return self._store.append_authoritative(
            submission, body, SCHEME_V3, author_signature,
            self._identity, expected_origin=self._origin,
        )

    def publish_punishment(
        self,
        submission: Submission,
        body: bytes,
        author_signature: bytes,
    ) -> tuple:
        """Publish a PUNISHMENT event to the configured moderation.actions board.

        The submission must have event_type=PUNISHMENT and
        headers=PunishmentHeaders. Authorization (moderator/admin role) is
        checked by the caller.
        """
        self._validate_local_submission(submission, EVENT_PUNISHMENT)
        if not isinstance(submission.headers, PunishmentHeaders):
            raise FeedAcceptanceError("PUNISHMENT requires PunishmentHeaders")
        return self._store.append_authoritative(
            submission, body, SCHEME_V3, author_signature,
            self._identity, expected_origin=self._origin,
        )

    def publish_punishment_revoke(
        self,
        submission: Submission,
        author_signature: bytes,
    ) -> tuple:
        """Publish a PUNISHMENT_REVOKE event targeting an existing punishment."""
        self._validate_local_submission(submission, EVENT_PUNISHMENT_REVOKE)
        self._validate_target_event_exists(submission)
        return self._store.append_authoritative(
            submission, b"", SCHEME_V3, author_signature,
            self._identity, expected_origin=self._origin,
        )

    def get_article(
        self,
        origin: str,
        board: str,
        selector_type: int,
        selector: bytes | int,
        include_body: bool = True,
    ) -> Optional[ArticleView]:
        """Get a single article with lifecycle state and controls.

        selector_type: 0x01 (article_num, selector is int) or
                       0x02 (message_id, selector is 32-byte bytes).
        Returns None if the article is unknown.
        """
        if selector_type == 0x01:
            proj = self._store.get_article_projection(origin, board, selector)
        elif selector_type == 0x02:
            proj = self._store.get_article_projection_by_message_id(
                origin, board, selector)
        else:
            raise ValueError(f"invalid selector_type {selector_type}")

        if proj is None:
            return None

        event = self._store.get_event_by_message_id(proj["message_id"])
        if event is None:
            return None

        control_events = self._store.get_control_events_for_article(
            origin, board, proj["message_id"])
        control_ids = [e.message_id for e in control_events
                       if e.event_type in (EVENT_CANCEL, EVENT_RESTORE, EVENT_PURGE)
                       or (e.event_type == EVENT_ARTICLE
                           and e.supersedes_message_id == proj["message_id"])]

        body_available = self._store.is_body_available(
            proj["body_hash"], proj["message_id"])

        body = None
        if include_body and body_available:
            body = self._store.get_body(proj["body_hash"])

        return ArticleView(
            event=event,
            projected_state=proj["current_state"],
            control_event_ids=control_ids,
            body_available=body_available,
            body=body,
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
        include_body: bool = False,
    ) -> list:
        """List articles with projection state filtering.

        Default: only 'active' articles. Flags include other states.
        Returns list[ArticleView].
        """
        projections = self._store.list_article_projections(
            origin, board, offset, limit,
            include_cancelled=include_cancelled,
            include_superseded=include_superseded,
            include_purged=include_purged,
        )
        results = []
        for proj in projections:
            event = self._store.get_event_by_message_id(proj["message_id"])
            if event is None:
                continue
            control_events = self._store.get_control_events_for_article(
                origin, board, proj["message_id"])
            control_ids = [e.message_id for e in control_events
                           if e.event_type in (EVENT_CANCEL, EVENT_RESTORE, EVENT_PURGE)
                           or (e.event_type == EVENT_ARTICLE
                               and e.supersedes_message_id == proj["message_id"])]
            body_available = self._store.is_body_available(
                proj["body_hash"], proj["message_id"])
            body = None
            if include_body and body_available:
                body = self._store.get_body(proj["body_hash"])
            results.append(ArticleView(
                event=event,
                projected_state=proj["current_state"],
                control_event_ids=control_ids,
                body_available=body_available,
                body=body,
            ))
        return results

    def search_articles(
        self,
        origin: str,
        board: str,
        event_type_mask: int = 0,
        actor_pubkey: bytes = None,
        subject_pubkey: bytes = None,
        target_message_id: bytes = None,
        created_after: int = 0,
        created_before: int = 0,
        text_query: str = "",
        offset: int = 0,
        limit: int = 100,
        include_cancelled: bool = False,
        include_superseded: bool = False,
        include_purged: bool = False,
    ) -> list:
        """Search articles with structured filters.

        event_type_mask: bitmask selecting event types (bit (type-1) set).
        actor_pubkey: filter by actor/author public key.
        subject_pubkey: filter by typed subject (culprit/punished key).
        target_message_id: filter by target_message_id field.
        created_after/created_before: time window (0 = unbounded).
        text_query: substring search over subject/tags.
        """
        # For Phase 2, implement a projection-based search over article_projection.
        # A full event-type-mask search across all event types is Phase 5.
        states = ["active"]
        if include_cancelled:
            states.append("cancelled")
        if include_superseded:
            states.append("superseded")
        if include_purged:
            states.append("purged")

        projections = self._store.search_article_projections(
            origin, board, states,
            actor_pubkey=actor_pubkey,
            created_after=created_after,
            created_before=created_before,
            text_query=text_query,
            offset=offset,
            limit=limit,
        )

        results = []
        for proj in projections:
            event = self._store.get_event_by_message_id(proj["message_id"])
            if event is None:
                continue
            control_events = self._store.get_control_events_for_article(
                origin, board, proj["message_id"])
            control_ids = [e.message_id for e in control_events
                           if e.event_type in (EVENT_CANCEL, EVENT_RESTORE, EVENT_PURGE)
                           or (e.event_type == EVENT_ARTICLE
                               and e.supersedes_message_id == proj["message_id"])]
            body_available = self._store.is_body_available(
                proj["body_hash"], proj["message_id"])
            results.append(ArticleView(
                event=event,
                projected_state=proj["current_state"],
                control_event_ids=control_ids,
                body_available=body_available,
                body=None,
            ))
        return results

    def get_control_events(
        self,
        origin: str,
        board: str,
        target_message_id: bytes,
    ) -> list:
        """Get all control events targeting an article."""
        return self._store.get_control_events_for_article(
            origin, board, target_message_id)

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    def _validate_local_submission(
        self, submission: Submission, expected_event_type: int,
    ) -> None:
        """Validate that a submission is for the local origin and correct type."""
        if submission.event_type != expected_event_type:
            raise FeedAcceptanceError(
                f"event_type {submission.event_type:#04x} != expected {expected_event_type:#04x}")
        if submission.origin != self._origin:
            raise FeedAcceptanceError(
                f"submission origin {submission.origin!r} != local origin {self._origin!r}")

    def _validate_target_exists(self, submission: Submission) -> None:
        """Validate that target_message_id refers to an article in this feed."""
        if submission.target_message_id == ZERO_MESSAGE_ID:
            raise FeedAcceptanceError("control event requires non-zero target_message_id")
        self._validate_target_exists_by_id(
            submission.target_message_id, submission.origin, submission.board)

    def _validate_target_event_exists(self, submission: Submission) -> None:
        """Validate that target_message_id refers to any event in this feed.

        Used for moderation control events (PUNISHMENT_REVOKE, RULE_REVOKE)
        that target non-ARTICLE events.
        """
        if submission.target_message_id == ZERO_MESSAGE_ID:
            raise FeedAcceptanceError("control event requires non-zero target_message_id")
        event = self._store.get_event_by_message_id(submission.target_message_id)
        if event is None:
            raise FeedAcceptanceError(
                f"target event {submission.target_message_id.hex()[:16]}... "
                f"not found in feed ({submission.origin}, {submission.board})")
        if event.origin != submission.origin or event.board != submission.board:
            raise FeedAcceptanceError(
                f"target event {submission.target_message_id.hex()[:16]}... "
                f"is in a different feed ({event.origin}, {event.board})")

    def _validate_target_exists_by_id(
        self, message_id: bytes, origin: str, board: str,
    ) -> None:
        """Check that an article with this message_id exists in the feed."""
        proj = self._store.get_article_projection_by_message_id(
            origin, board, message_id)
        if proj is None:
            raise FeedAcceptanceError(
                f"target article {message_id.hex()} not found in feed "
                f"({origin}, {board})")
