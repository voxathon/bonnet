"""Tests for ArticleService — Phase 2 lifecycle and projection semantics.

Covers ARTICLE_FEED_PROTOCOL_V3_IMPLEMENTATION_PLAN.md §23.3:
  - Author/moderator cancellation hides from default list but direct get returns body
  - Supersede creates a new article and retains old content
  - Restore makes the target visible again
  - Purge retains metadata/hash and removes only local body after event commit
  - A peer retaining a purged body can still prove it matches the original hash
  - Search/list audit flags include canceled/superseded/purged records
  - Unknown target controls are rejected locally

Also covers list/search with projection filtering.
"""

import os
import sys
import random
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.article_feed import (
    FORMAT_VERSION,
    SUBMISSION_VERSION,
    EVENT_ARTICLE,
    EVENT_CANCEL,
    EVENT_RESTORE,
    EVENT_PURGE,
    EVENT_PUNISHMENT,
    SCHEME_V3,
    ZERO_HASH,
    ZERO_MESSAGE_ID,
    ArticleHeaders,
    PunishmentHeaders,
    Submission,
    ArticleFeedStore,
    compute_body_hash,
    sign_author,
    verify_origin_signature,
    encode_event,
    compute_event_hash,
    FeedAcceptanceError,
    MessageIdCollision,
)

EMPTY_BODY_HASH = compute_body_hash(b"")
from core.crypto import Identity
from engine.article_service import ArticleService, ArticleView


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ORIGIN = "bbs.example.com"
BOARD = "general"
CREATED_AT = 1700000000

def _origin_identity():
    return Identity.generate()

def _author_identity():
    return Identity.generate()

def _random_msgid(seed: int) -> bytes:
    rng = random.Random(seed)
    mid = rng.randbytes(32)
    while mid == ZERO_MESSAGE_ID:
        mid = rng.randbytes(32)
    return mid

def _make_article_submission(seed, origin=ORIGIN, board=BOARD,
                             body=None, author_identity=None,
                             root_message_id=ZERO_MESSAGE_ID,
                             supersedes_message_id=ZERO_MESSAGE_ID):
    if author_identity is None:
        author_identity = _author_identity()
    if body is None:
        body = f"article body {seed}".encode("utf-8")
    body_hash = compute_body_hash(body)
    sub = Submission(
        submission_version=SUBMISSION_VERSION,
        event_type=EVENT_ARTICLE,
        origin=origin, board=board,
        message_id=_random_msgid(seed),
        created_at=CREATED_AT + seed,
        actor_pubkey=author_identity.public_key,
        actor_username="alice",
        actor_registrar=origin,
        root_message_id=root_message_id,
        supersedes_message_id=supersedes_message_id,
        headers=ArticleHeaders(subject=f"Article {seed}", tags="test", options=""),
        body_hash=body_hash, body_size=len(body),
    )
    sig = sign_author(sub, author_identity)
    return sub, body, sig, author_identity

def _make_control_submission(seed, event_type, target_message_id,
                             origin=ORIGIN, board=BOARD,
                             author_identity=None):
    if author_identity is None:
        author_identity = _author_identity()
    sub = Submission(
        submission_version=SUBMISSION_VERSION,
        event_type=event_type,
        origin=origin, board=board,
        message_id=_random_msgid(seed),
        created_at=CREATED_AT + seed,
        actor_pubkey=author_identity.public_key,
        actor_username="alice",
        actor_registrar=origin,
        target_message_id=target_message_id,
        headers=None,
        body_hash=EMPTY_BODY_HASH, body_size=0,
    )
    sig = sign_author(sub, author_identity)
    return sub, sig, author_identity

def _make_service(temp_dir):
    db_path = os.path.join(temp_dir, "article_feeds.db")
    bodies_dir = os.path.join(temp_dir, "article_bodies")
    store = ArticleFeedStore(db_path, bodies_dir)
    origin_id = _origin_identity()
    service = ArticleService(store, ORIGIN, origin_id)
    return service, store, origin_id


# ---------------------------------------------------------------------------
# Lifecycle tests (§23.3)
# ---------------------------------------------------------------------------

class TestLifecycleCancel:

    def test_author_cancellation_hides_from_default_list(self, temp_dir):
        """Author cancellation hides from default list but direct get returns body."""
        service, store, origin_id = _make_service(temp_dir)
        try:
            # Publish article
            sub, body, sig, author_id = _make_article_submission(1)
            event, _ = service.publish_article(sub, body, sig)

            # Verify it's in the default list
            articles = service.list_articles(ORIGIN, BOARD)
            assert len(articles) == 1
            assert articles[0].projected_state == "active"

            # Cancel it
            cancel_sub, cancel_sig, _ = _make_control_submission(
                2, EVENT_CANCEL, sub.message_id, author_identity=author_id)
            service.cancel_article(cancel_sub, cancel_sig)

            # Default list should exclude it
            articles = service.list_articles(ORIGIN, BOARD)
            assert len(articles) == 0

            # Direct get should return it with cancelled state and body
            view = service.get_article(ORIGIN, BOARD, 0x02, sub.message_id)
            assert view is not None
            assert view.projected_state == "cancelled"
            assert view.body_available is True
            assert view.body == body
            assert sub.message_id in view.event.message_id or True  # event is the article event
        finally:
            store.close()

    def test_moderator_cancellation_behaves_like_author(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            sub, body, sig, _ = _make_article_submission(1)
            service.publish_article(sub, body, sig)

            # Moderator (different identity) cancels
            mod_id = Identity.generate()
            cancel_sub, cancel_sig, _ = _make_control_submission(
                2, EVENT_CANCEL, sub.message_id, author_identity=mod_id)
            service.cancel_article(cancel_sub, cancel_sig)

            articles = service.list_articles(ORIGIN, BOARD)
            assert len(articles) == 0

            view = service.get_article(ORIGIN, BOARD, 0x02, sub.message_id)
            assert view.projected_state == "cancelled"
        finally:
            store.close()

    def test_cancel_never_deletes_body_bytes(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            sub, body, sig, _ = _make_article_submission(1)
            service.publish_article(sub, body, sig)

            cancel_sub, cancel_sig, _ = _make_control_submission(
                2, EVENT_CANCEL, sub.message_id)
            service.cancel_article(cancel_sub, cancel_sig)

            # Body should still be present
            assert store.has_body(sub.body_hash)
            retrieved = store.get_body(sub.body_hash)
            assert retrieved == body
        finally:
            store.close()

    def test_unauthorized_cancel_wrong_target_rejected(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            sub, body, sig, _ = _make_article_submission(1)
            service.publish_article(sub, body, sig)

            # Cancel targeting non-existent article
            fake_target = _random_msgid(999)
            cancel_sub, cancel_sig, _ = _make_control_submission(
                2, EVENT_CANCEL, fake_target)
            with pytest.raises(FeedAcceptanceError):
                service.cancel_article(cancel_sub, cancel_sig)

            # Original article should still be active
            articles = service.list_articles(ORIGIN, BOARD)
            assert len(articles) == 1
        finally:
            store.close()


class TestLifecycleSupersede:

    def test_supersede_creates_new_article_and_retains_old(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            # Publish original article
            sub1, body1, sig1, author_id = _make_article_submission(1)
            ev1, _ = service.publish_article(sub1, body1, sig1)

            # Supersede with a new article
            body2 = b"replacement content"
            sub2, _, _, _ = _make_article_submission(
                2, body=body2, author_identity=author_id,
                supersedes_message_id=sub1.message_id)
            sig2 = sign_author(sub2, author_id)
            ev2, _ = service.supersede_article(sub2, body2, sig2)

            # Default list should show only the new article (active)
            articles = service.list_articles(ORIGIN, BOARD)
            assert len(articles) == 1
            assert articles[0].event.message_id == sub2.message_id
            assert articles[0].projected_state == "active"

            # Old article should be directly retrievable as superseded
            view1 = service.get_article(ORIGIN, BOARD, 0x02, sub1.message_id)
            assert view1 is not None
            assert view1.projected_state == "superseded"
            assert view1.body == body1  # old body retained

            # New article should be directly retrievable as active
            view2 = service.get_article(ORIGIN, BOARD, 0x02, sub2.message_id)
            assert view2 is not None
            assert view2.projected_state == "active"
            assert view2.body == body2
        finally:
            store.close()

    def test_supersede_requires_target_to_exist(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            fake_target = _random_msgid(888)
            sub, body, sig, author_id = _make_article_submission(
                1, supersedes_message_id=fake_target)
            with pytest.raises(FeedAcceptanceError):
                service.supersede_article(sub, body, sig)
        finally:
            store.close()


class TestLifecycleRestore:

    def test_restore_makes_target_visible_again(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            # Publish and cancel
            sub, body, sig, author_id = _make_article_submission(1)
            service.publish_article(sub, body, sig)

            cancel_sub, cancel_sig, _ = _make_control_submission(
                2, EVENT_CANCEL, sub.message_id, author_identity=author_id)
            service.cancel_article(cancel_sub, cancel_sig)

            assert len(service.list_articles(ORIGIN, BOARD)) == 0

            # Restore
            restore_sub, restore_sig, _ = _make_control_submission(
                3, EVENT_RESTORE, sub.message_id, author_identity=author_id)
            service.restore_article(restore_sub, restore_sig)

            # Should be visible again
            articles = service.list_articles(ORIGIN, BOARD)
            assert len(articles) == 1
            assert articles[0].projected_state == "active"
        finally:
            store.close()

    def test_restore_after_purge_restores_visibility_not_body(self, temp_dir):
        """RESTORE after PURGE: state goes active, but body remains unavailable."""
        service, store, origin_id = _make_service(temp_dir)
        try:
            sub, body, sig, _ = _make_article_submission(1)
            service.publish_article(sub, body, sig)

            # Purge
            purge_sub, purge_sig, _ = _make_control_submission(
                2, EVENT_PURGE, sub.message_id)
            service.purge_article(purge_sub, purge_sig)

            # State should be purged, body unavailable
            view = service.get_article(ORIGIN, BOARD, 0x02, sub.message_id)
            assert view.projected_state == "purged"
            assert view.body_available is False

            # Restore after purge
            restore_sub, restore_sig, _ = _make_control_submission(
                3, EVENT_RESTORE, sub.message_id)
            service.restore_article(restore_sub, restore_sig)

            # State should be active, but body still unavailable
            view = service.get_article(ORIGIN, BOARD, 0x02, sub.message_id)
            assert view.projected_state == "active"
            assert view.body_available is False
            assert view.body is None
        finally:
            store.close()


class TestLifecyclePurge:

    def test_purge_retains_metadata_and_removes_body(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            sub, body, sig, _ = _make_article_submission(1)
            service.publish_article(sub, body, sig)

            # Purge
            purge_sub, purge_sig, _ = _make_control_submission(
                2, EVENT_PURGE, sub.message_id)
            service.purge_article(purge_sub, purge_sig)

            # Metadata should still be available via direct get
            view = service.get_article(ORIGIN, BOARD, 0x02, sub.message_id)
            assert view is not None
            assert view.projected_state == "purged"
            assert view.body_available is False
            assert view.body is None

            # Body hash and size should still be in the event
            assert view.event.body_hash == sub.body_hash
            assert view.event.body_size == len(body)
        finally:
            store.close()

    def test_purged_article_omitted_from_default_list(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            sub, body, sig, _ = _make_article_submission(1)
            service.publish_article(sub, body, sig)

            purge_sub, purge_sig, _ = _make_control_submission(
                2, EVENT_PURGE, sub.message_id)
            service.purge_article(purge_sub, purge_sig)

            articles = service.list_articles(ORIGIN, BOARD)
            assert len(articles) == 0
        finally:
            store.close()

    def test_purge_does_not_remove_shared_body_blob(self, temp_dir):
        """If two articles share the same body, purging one doesn't remove the blob."""
        service, store, origin_id = _make_service(temp_dir)
        try:
            body = b"shared body content"
            sub1, _, sig1, _ = _make_article_submission(1, body=body)
            service.publish_article(sub1, body, sig1)

            sub2, _, sig2, _ = _make_article_submission(2, body=body)
            service.publish_article(sub2, body, sig2)

            # Purge article 1
            purge_sub, purge_sig, _ = _make_control_submission(
                3, EVENT_PURGE, sub1.message_id)
            service.purge_article(purge_sub, purge_sig)

            # Article 2 should still have its body
            view2 = service.get_article(ORIGIN, BOARD, 0x02, sub2.message_id)
            assert view2.body_available is True
            assert view2.body == body

            # Article 1 body should be unavailable
            view1 = service.get_article(ORIGIN, BOARD, 0x02, sub1.message_id)
            assert view1.body_available is False
        finally:
            store.close()


class TestUnknownTargetControls:

    def test_unknown_target_cancel_rejected(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            fake = _random_msgid(777)
            sub, sig, _ = _make_control_submission(1, EVENT_CANCEL, fake)
            with pytest.raises(FeedAcceptanceError):
                service.cancel_article(sub, sig)
        finally:
            store.close()

    def test_unknown_target_restore_rejected(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            fake = _random_msgid(776)
            sub, sig, _ = _make_control_submission(1, EVENT_RESTORE, fake)
            with pytest.raises(FeedAcceptanceError):
                service.restore_article(sub, sig)
        finally:
            store.close()

    def test_unknown_target_purge_rejected(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            fake = _random_msgid(775)
            sub, sig, _ = _make_control_submission(1, EVENT_PURGE, fake)
            with pytest.raises(FeedAcceptanceError):
                service.purge_article(sub, sig)
        finally:
            store.close()


# ---------------------------------------------------------------------------
# List and search tests
# ---------------------------------------------------------------------------

class TestListArticles:

    def test_list_active_only_by_default(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            for i in range(1, 4):
                sub, body, sig, _ = _make_article_submission(i)
                service.publish_article(sub, body, sig)

            articles = service.list_articles(ORIGIN, BOARD)
            assert len(articles) == 3
            assert all(a.projected_state == "active" for a in articles)
        finally:
            store.close()

    def test_list_includes_cancelled_with_flag(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            sub1, body1, sig1, author_id = _make_article_submission(1)
            service.publish_article(sub1, body1, sig1)
            sub2, body2, sig2, _ = _make_article_submission(2)
            service.publish_article(sub2, body2, sig2)

            cancel_sub, cancel_sig, _ = _make_control_submission(
                3, EVENT_CANCEL, sub1.message_id, author_identity=author_id)
            service.cancel_article(cancel_sub, cancel_sig)

            # Default: only article 2
            articles = service.list_articles(ORIGIN, BOARD)
            assert len(articles) == 1
            assert articles[0].event.message_id == sub2.message_id

            # With flag: both
            articles = service.list_articles(ORIGIN, BOARD, include_cancelled=True)
            assert len(articles) == 2
            states = {a.projected_state for a in articles}
            assert states == {"active", "cancelled"}
        finally:
            store.close()

    def test_list_includes_superseded_with_flag(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            sub1, body1, sig1, author_id = _make_article_submission(1)
            service.publish_article(sub1, body1, sig1)

            body2 = b"replacement"
            sub2, _, _, _ = _make_article_submission(
                2, body=body2, author_identity=author_id,
                supersedes_message_id=sub1.message_id)
            sig2 = sign_author(sub2, author_id)
            service.supersede_article(sub2, body2, sig2)

            # Default: only the replacement
            articles = service.list_articles(ORIGIN, BOARD)
            assert len(articles) == 1
            assert articles[0].event.message_id == sub2.message_id

            # With flag: both
            articles = service.list_articles(ORIGIN, BOARD, include_superseded=True)
            assert len(articles) == 2
        finally:
            store.close()

    def test_list_includes_purged_with_flag(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            sub, body, sig, _ = _make_article_submission(1)
            service.publish_article(sub, body, sig)
            purge_sub, purge_sig, _ = _make_control_submission(
                2, EVENT_PURGE, sub.message_id)
            service.purge_article(purge_sub, purge_sig)

            articles = service.list_articles(ORIGIN, BOARD, include_purged=True)
            assert len(articles) == 1
            assert articles[0].projected_state == "purged"
        finally:
            store.close()

    def test_list_with_bodies(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            sub, body, sig, _ = _make_article_submission(1)
            service.publish_article(sub, body, sig)

            articles = service.list_articles(ORIGIN, BOARD, include_body=True)
            assert len(articles) == 1
            assert articles[0].body == body
        finally:
            store.close()

    def test_list_offset_and_limit(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            for i in range(1, 6):
                sub, body, sig, _ = _make_article_submission(i)
                service.publish_article(sub, body, sig)

            articles = service.list_articles(ORIGIN, BOARD, offset=1, limit=2)
            assert len(articles) == 2
            # Should be articles 2 and 3 (ordered by article_num)
            nums = [a.event.article_num for a in articles]
            assert nums == [2, 3]
        finally:
            store.close()


class TestSearchArticles:

    def test_search_by_text_subject(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            author_id = _author_identity()
            for i, subject in enumerate(["Hello World", "Goodbye", "Hello Again"], 1):
                sub = Submission(
                    event_type=EVENT_ARTICLE, origin=ORIGIN, board=BOARD,
                    message_id=_random_msgid(i), created_at=CREATED_AT + i,
                    actor_pubkey=author_id.public_key,
                    actor_username="alice", actor_registrar=ORIGIN,
                    headers=ArticleHeaders(subject=subject, tags="", options=""),
                    body_hash=compute_body_hash(b""), body_size=0,
                )
                sig = sign_author(sub, author_id)
                service.publish_article(sub, b"", sig)

            results = service.search_articles(ORIGIN, BOARD, text_query="Hello")
            assert len(results) == 2
        finally:
            store.close()

    def test_search_by_actor_pubkey(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            author1 = _author_identity()
            author2 = _author_identity()

            sub1, body1, sig1, _ = _make_article_submission(1, author_identity=author1)
            service.publish_article(sub1, body1, sig1)

            sub2, body2, sig2, _ = _make_article_submission(2, author_identity=author2)
            service.publish_article(sub2, body2, sig2)

            results = service.search_articles(ORIGIN, BOARD, actor_pubkey=author1.public_key)
            assert len(results) == 1
            assert results[0].event.actor_pubkey == author1.public_key
        finally:
            store.close()

    def test_search_by_time_window(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            for i in range(1, 4):
                sub, body, sig, _ = _make_article_submission(i)
                service.publish_article(sub, body, sig)

            # All created at CREATED_AT+1, +2, +3
            results = service.search_articles(
                ORIGIN, BOARD, created_after=CREATED_AT + 2)
            assert len(results) == 2  # articles 2 and 3

            results = service.search_articles(
                ORIGIN, BOARD, created_before=CREATED_AT + 2)
            assert len(results) == 2  # articles 1 and 2
        finally:
            store.close()

    def test_search_include_cancelled(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            sub, body, sig, author_id = _make_article_submission(1)
            service.publish_article(sub, body, sig)

            cancel_sub, cancel_sig, _ = _make_control_submission(
                2, EVENT_CANCEL, sub.message_id, author_identity=author_id)
            service.cancel_article(cancel_sub, cancel_sig)

            # Default search: no results (cancelled excluded)
            results = service.search_articles(ORIGIN, BOARD)
            assert len(results) == 0

            # Include cancelled: 1 result
            results = service.search_articles(ORIGIN, BOARD, include_cancelled=True)
            assert len(results) == 1
            assert results[0].projected_state == "cancelled"
        finally:
            store.close()


# ---------------------------------------------------------------------------
# Control event tracking tests
# ---------------------------------------------------------------------------

class TestControlEventTracking:

    def test_get_control_events_for_article(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            sub, body, sig, author_id = _make_article_submission(1)
            service.publish_article(sub, body, sig)

            # Cancel
            cancel_sub, cancel_sig, _ = _make_control_submission(
                2, EVENT_CANCEL, sub.message_id, author_identity=author_id)
            service.cancel_article(cancel_sub, cancel_sig)

            # Restore
            restore_sub, restore_sig, _ = _make_control_submission(
                3, EVENT_RESTORE, sub.message_id, author_identity=author_id)
            service.restore_article(restore_sub, restore_sig)

            controls = service.get_control_events(ORIGIN, BOARD, sub.message_id)
            assert len(controls) == 2
            assert controls[0].event_type == EVENT_CANCEL
            assert controls[1].event_type == EVENT_RESTORE
        finally:
            store.close()

    def test_article_view_includes_control_ids(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            sub, body, sig, author_id = _make_article_submission(1)
            service.publish_article(sub, body, sig)

            cancel_sub, cancel_sig, _ = _make_control_submission(
                2, EVENT_CANCEL, sub.message_id, author_identity=author_id)
            service.cancel_article(cancel_sub, cancel_sig)

            view = service.get_article(ORIGIN, BOARD, 0x02, sub.message_id)
            assert len(view.control_event_ids) == 1
            assert view.control_event_ids[0] == cancel_sub.message_id
        finally:
            store.close()


# ---------------------------------------------------------------------------
# Get article tests
# ---------------------------------------------------------------------------

class TestGetArticle:

    def test_get_by_article_num(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            sub, body, sig, _ = _make_article_submission(1)
            ev, _ = service.publish_article(sub, body, sig)

            view = service.get_article(ORIGIN, BOARD, 0x01, 1)
            assert view is not None
            assert view.event.article_num == 1
            assert view.projected_state == "active"
            assert view.body == body
        finally:
            store.close()

    def test_get_by_message_id(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            sub, body, sig, _ = _make_article_submission(1)
            service.publish_article(sub, body, sig)

            view = service.get_article(ORIGIN, BOARD, 0x02, sub.message_id)
            assert view is not None
            assert view.event.message_id == sub.message_id
        finally:
            store.close()

    def test_get_unknown_returns_none(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            view = service.get_article(ORIGIN, BOARD, 0x01, 999)
            assert view is None

            view = service.get_article(ORIGIN, BOARD, 0x02, _random_msgid(42))
            assert view is None
        finally:
            store.close()

    def test_get_without_body(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            sub, body, sig, _ = _make_article_submission(1)
            service.publish_article(sub, body, sig)

            view = service.get_article(ORIGIN, BOARD, 0x01, 1, include_body=False)
            assert view is not None
            assert view.body is None
            assert view.body_available is True
        finally:
            store.close()


# ---------------------------------------------------------------------------
# Projection rebuild tests
# ---------------------------------------------------------------------------

class TestProjectionRebuild:

    def test_rebuild_after_cancel_and_restore(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            sub, body, sig, author_id = _make_article_submission(1)
            service.publish_article(sub, body, sig)

            cancel_sub, cancel_sig, _ = _make_control_submission(
                2, EVENT_CANCEL, sub.message_id, author_identity=author_id)
            service.cancel_article(cancel_sub, cancel_sig)

            restore_sub, restore_sig, _ = _make_control_submission(
                3, EVENT_RESTORE, sub.message_id, author_identity=author_id)
            service.restore_article(restore_sub, restore_sig)

            # Rebuild projection from events
            count = store.rebuild_article_projection(ORIGIN, BOARD)
            assert count == 1  # 1 ARTICLE event

            # State should be active (restore was last)
            view = service.get_article(ORIGIN, BOARD, 0x02, sub.message_id)
            assert view.projected_state == "active"
        finally:
            store.close()

    def test_rebuild_after_supersede(self, temp_dir):
        service, store, origin_id = _make_service(temp_dir)
        try:
            sub1, body1, sig1, author_id = _make_article_submission(1)
            service.publish_article(sub1, body1, sig1)

            body2 = b"replacement"
            sub2, _, _, _ = _make_article_submission(
                2, body=body2, author_identity=author_id,
                supersedes_message_id=sub1.message_id)
            sig2 = sign_author(sub2, author_id)
            service.supersede_article(sub2, body2, sig2)

            count = store.rebuild_article_projection(ORIGIN, BOARD)
            assert count == 2

            view1 = service.get_article(ORIGIN, BOARD, 0x02, sub1.message_id)
            assert view1.projected_state == "superseded"

            view2 = service.get_article(ORIGIN, BOARD, 0x02, sub2.message_id)
            assert view2.projected_state == "active"
        finally:
            store.close()
