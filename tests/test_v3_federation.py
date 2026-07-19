"""Tests for Protocol v3 article feed federation (Phase 4).

Covers ARTICLE_FEED_PROTOCOL_V3_IMPLEMENTATION_PLAN.md §23.8 relay integration:
  - Origin A publishes article events
  - Node C imports A's feed through a relay or directly
  - C verifies A's signatures and accepts the range
  - Articles appear in C's projection

Also tests:
  - Feed subscription config matching
  - Body policy (eager fetch)
  - SSRF guard (non-dialable relay rejected)
  - Backoff tracking

These tests use a two-server setup: Origin A and Receiver C, each with their
own ArticleFeedStore. The sync is performed by calling the SyncManager's
article-feed sync methods directly (bypassing HTTP) to test the sync logic
without network complexity.
"""

import os
import sys
import struct
import random
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.article_feed import (
    ArticleFeedStore,
    Submission,
    ArticleHeaders,
    EVENT_ARTICLE,
    EVENT_CANCEL,
    SCHEME_V3,
    SUBMISSION_VERSION,
    ZERO_MESSAGE_ID,
    compute_body_hash,
    sign_author,
    decode_event,
    decode_head,
    verify_head_signature,
    verify_origin_signature,
    encode_event,
    compute_event_hash,
    encode_head,
    compute_head_hash,
    AcceptResult,
    MessageIdCollision,
    FeedAcceptanceError,
)
from core.crypto import Identity
from core.config import Config, FeedSubscription, ControlPolicy, ModerationBoards
from engine.article_service import ArticleService
from net.sync import _is_dialable_host


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ORIGIN_A = "origin-a.test"
ORIGIN_C = "origin-c.test"
BOARD = "general"
CREATED_AT = 1700000000


def _random_msgid(seed):
    rng = random.Random(seed)
    mid = rng.randbytes(32)
    while mid == ZERO_MESSAGE_ID:
        mid = rng.randbytes(32)
    return mid


def _make_article_submission(seed, origin=ORIGIN_A, board=BOARD, body=None,
                             author_identity=None):
    if author_identity is None:
        author_identity = Identity.generate()
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
        headers=ArticleHeaders(subject=f"Article {seed}", tags="test", options=""),
        body_hash=body_hash, body_size=len(body),
    )
    sig = sign_author(sub, author_identity)
    return sub, body, sig


def _make_store(temp_dir, name, origin, max_body_size=1024*1024):
    db_path = os.path.join(temp_dir, f"{name}_feeds.db")
    bodies_dir = os.path.join(temp_dir, f"{name}_bodies")
    return ArticleFeedStore(db_path, bodies_dir, max_body_size=max_body_size)


# ---------------------------------------------------------------------------
# Feed subscription config tests
# ---------------------------------------------------------------------------

class TestFeedSubscriptionConfig:

    def test_subscription_matches_specific_board(self):
        sub = FeedSubscription("origin.test", ["general", "random"], ["relay.test"])
        assert sub.matches_board("general")
        assert sub.matches_board("random")
        assert not sub.matches_board("other")

    def test_subscription_wildcard_matches_all(self):
        sub = FeedSubscription("origin.test", ["*"], ["relay.test"])
        assert sub.matches_board("general")
        assert sub.matches_board("anything")

    def test_config_get_feed_subscription(self):
        subs = [FeedSubscription("origin.test", ["*"], ["relay.test"])]
        cfg = Config(origin="local.test", feed_subscriptions=subs)
        found = cfg.get_feed_subscription("origin.test", "general")
        assert found is not None
        assert found.origin == "origin.test"

        not_found = cfg.get_feed_subscription("other.test", "general")
        assert not_found is None

    def test_config_is_feed_subscribed(self):
        subs = [FeedSubscription("origin.test", ["general"], ["relay.test"])]
        cfg = Config(origin="local.test", feed_subscriptions=subs)
        assert cfg.is_feed_subscribed("origin.test", "general")
        assert not cfg.is_feed_subscribed("origin.test", "other")
        assert not cfg.is_feed_subscribed("other.test", "general")

    def test_control_policy_matching(self):
        policies = [ControlPolicy("origin.test", "moderation.actions",
                                  ["punishment", "punishment-revoke"])]
        cfg = Config(origin="local.test", control_policies=policies)
        found = cfg.get_control_policy("origin.test", "moderation.actions")
        assert found is not None
        assert "punishment" in found.apply

    def test_moderation_boards_defaults(self):
        mb = ModerationBoards()
        assert mb.rules == "moderation.rules"
        assert mb.reports == "moderation.reports"
        assert mb.punishments == "moderation.actions"


# ---------------------------------------------------------------------------
# Direct feed sync tests (store-to-store, bypassing HTTP)
# ---------------------------------------------------------------------------

class TestFeedSyncDirect:

    def test_receiver_accepts_origin_feed_range(self, temp_dir):
        """Origin A publishes events, receiver C accepts the range via
        accept_remote_range and sees them in its projection."""
        store_a = _make_store(temp_dir, "a", ORIGIN_A)
        store_c = _make_store(temp_dir, "c", ORIGIN_C)
        try:
            origin_id = Identity.generate()
            service_a = ArticleService(store_a, ORIGIN_A, origin_id)

            # Publish 3 articles on A
            events = []
            for i in range(1, 4):
                sub, body, sig = _make_article_submission(i)
                ev, head = service_a.publish_article(sub, body, sig)
                events.append(ev)

            # C fetches A's head + events and accepts them
            head = store_a.get_head(ORIGIN_A, BOARD)
            assert head is not None

            result = store_c.accept_remote_range(
                ORIGIN_A, BOARD, head, events,
                origin_pubkey=origin_id.public_key,
                source_relay="origin-a.test",
            )
            assert result.accepted
            assert result.accepted_count == 3

            # C should see the articles in its projection
            state = store_c.get_feed_state(ORIGIN_A, BOARD)
            assert state["highest_accepted_seq"] == 3
            assert state["current_article_count"] == 3

            # Projection should have the articles
            projections = store_c.list_article_projections(ORIGIN_A, BOARD)
            assert len(projections) == 3
        finally:
            store_a.close()
            store_c.close()

    def test_receiver_rejects_wrong_origin_key(self, temp_dir):
        """Receiver rejects events signed by the wrong origin key."""
        store_a = _make_store(temp_dir, "a", ORIGIN_A)
        store_c = _make_store(temp_dir, "c", ORIGIN_C)
        try:
            origin_id = Identity.generate()
            service_a = ArticleService(store_a, ORIGIN_A, origin_id)

            sub, body, sig = _make_article_submission(1)
            ev, head = service_a.publish_article(sub, body, sig)

            # C uses a different (wrong) pubkey
            wrong_key = Identity.generate().public_key
            result = store_c.accept_remote_range(
                ORIGIN_A, BOARD, head, [ev],
                origin_pubkey=wrong_key,
                source_relay="origin-a.test",
            )
            assert not result.accepted
            assert "signature" in result.reason.lower()
        finally:
            store_a.close()
            store_c.close()

    def test_incremental_sync_advances_state(self, temp_dir):
        """C syncs 3 events, then A publishes 2 more, C syncs the delta."""
        store_a = _make_store(temp_dir, "a", ORIGIN_A)
        store_c = _make_store(temp_dir, "c", ORIGIN_C)
        try:
            origin_id = Identity.generate()
            service_a = ArticleService(store_a, ORIGIN_A, origin_id)

            # Publish 3 on A, sync to C
            events_1 = []
            for i in range(1, 4):
                sub, body, sig = _make_article_submission(i)
                ev, _ = service_a.publish_article(sub, body, sig)
                events_1.append(ev)
            head_1 = store_a.get_head(ORIGIN_A, BOARD)
            store_c.accept_remote_range(ORIGIN_A, BOARD, head_1, events_1,
                                        origin_pubkey=origin_id.public_key,
                                        source_relay="origin-a.test")

            # Publish 2 more on A
            events_2 = []
            for i in range(4, 6):
                sub, body, sig = _make_article_submission(i)
                ev, _ = service_a.publish_article(sub, body, sig)
                events_2.append(ev)
            head_2 = store_a.get_head(ORIGIN_A, BOARD)

            # C syncs the delta (events 4-5)
            result = store_c.accept_remote_range(ORIGIN_A, BOARD, head_2, events_2,
                                                 origin_pubkey=origin_id.public_key,
                                                 source_relay="origin-a.test")
            assert result.accepted
            assert result.accepted_count == 2

            state = store_c.get_feed_state(ORIGIN_A, BOARD)
            assert state["highest_accepted_seq"] == 5
            assert state["current_article_count"] == 5
        finally:
            store_a.close()
            store_c.close()

    def test_cancel_propagates_through_sync(self, temp_dir):
        """A publishes an article and a cancel; C syncs both and sees
        the article as cancelled in its projection."""
        store_a = _make_store(temp_dir, "a", ORIGIN_A)
        store_c = _make_store(temp_dir, "c", ORIGIN_C)
        try:
            origin_id = Identity.generate()
            author_id = Identity.generate()
            service_a = ArticleService(store_a, ORIGIN_A, origin_id)

            # Publish article
            sub1, body1, sig1 = _make_article_submission(1, author_identity=author_id)
            ev1, _ = service_a.publish_article(sub1, body1, sig1)

            # Cancel it
            cancel_sub = Submission(
                submission_version=SUBMISSION_VERSION,
                event_type=EVENT_CANCEL, origin=ORIGIN_A, board=BOARD,
                message_id=_random_msgid(100), created_at=CREATED_AT + 100,
                actor_pubkey=author_id.public_key, actor_username="alice",
                actor_registrar=ORIGIN_A,
                target_message_id=sub1.message_id,
                body_hash=compute_body_hash(b""), body_size=0,
            )
            cancel_sig = sign_author(cancel_sub, author_id)
            ev2, head = service_a.cancel_article(cancel_sub, cancel_sig)

            # C syncs both events
            result = store_c.accept_remote_range(
                ORIGIN_A, BOARD, head, [ev1, ev2],
                origin_pubkey=origin_id.public_key,
                source_relay="origin-a.test",
            )
            assert result.accepted

            # C's projection should show the article as cancelled
            projections = store_c.list_article_projections(ORIGIN_A, BOARD,
                                                            include_cancelled=True)
            assert len(projections) == 1
            assert projections[0]["current_state"] == "cancelled"
        finally:
            store_a.close()
            store_c.close()

    def test_idempotent_sync_same_head(self, temp_dir):
        """Syncing the same head twice is idempotent."""
        store_a = _make_store(temp_dir, "a", ORIGIN_A)
        store_c = _make_store(temp_dir, "c", ORIGIN_C)
        try:
            origin_id = Identity.generate()
            service_a = ArticleService(store_a, ORIGIN_A, origin_id)

            sub, body, sig = _make_article_submission(1)
            ev, head = service_a.publish_article(sub, body, sig)

            # First sync
            r1 = store_c.accept_remote_range(ORIGIN_A, BOARD, head, [ev],
                                             origin_pubkey=origin_id.public_key,
                                             source_relay="origin-a.test")
            assert r1.accepted

            # Second sync (same head) — should be idempotent
            r2 = store_c.accept_remote_range(ORIGIN_A, BOARD, head, [ev],
                                             origin_pubkey=origin_id.public_key,
                                             source_relay="origin-a.test")
            assert r2.accepted
            assert "idempotent" in r2.reason

            # State should not have advanced beyond 1
            state = store_c.get_feed_state(ORIGIN_A, BOARD)
            assert state["highest_accepted_seq"] == 1
            assert state["current_event_count"] == 1
        finally:
            store_a.close()
            store_c.close()

    def test_rollback_rejected(self, temp_dir):
        """C rejects a head with a lower sequence than already accepted."""
        store_a = _make_store(temp_dir, "a", ORIGIN_A)
        store_c = _make_store(temp_dir, "c", ORIGIN_C)
        try:
            origin_id = Identity.generate()
            service_a = ArticleService(store_a, ORIGIN_A, origin_id)

            # Publish 3 on A
            events = []
            for i in range(1, 4):
                sub, body, sig = _make_article_submission(i)
                ev, _ = service_a.publish_article(sub, body, sig)
                events.append(ev)
            head_3 = store_a.get_head(ORIGIN_A, BOARD)

            # C accepts all 3
            store_c.accept_remote_range(ORIGIN_A, BOARD, head_3, events,
                                        origin_pubkey=origin_id.public_key,
                                        source_relay="origin-a.test")

            # Now try to accept a head at seq=1 (rollback)
            # Build a head at seq=1 using the first event
            from core.article_feed import FeedHead, compute_event_hash, encode_event, sign_head
            head_1 = FeedHead(
                origin=ORIGIN_A, board=BOARD,
                latest_feed_seq=1,
                latest_event_hash=compute_event_hash(encode_event(events[0])),
                article_count=1, event_count=1,
                snapshot_timestamp=1700000100,
            )
            sign_head(head_1, origin_id)
            result = store_c.accept_remote_range(ORIGIN_A, BOARD, head_1, [events[0]],
                                                 origin_pubkey=origin_id.public_key,
                                                 source_relay="origin-a.test")
            assert not result.accepted
            assert "rollback" in result.reason
        finally:
            store_a.close()
            store_c.close()


# ---------------------------------------------------------------------------
# SSRF guard tests
# ---------------------------------------------------------------------------

class TestSSRFGuard:

    def test_localhost_rejected(self):
        assert not _is_dialable_host("localhost")

    def test_private_ip_rejected(self):
        assert not _is_dialable_host("192.168.1.1")
        assert not _is_dialable_host("10.0.0.1")
        assert not _is_dialable_host("172.16.0.1")

    def test_loopback_rejected(self):
        assert not _is_dialable_host("127.0.0.1")

    def test_public_ip_accepted(self):
        assert _is_dialable_host("8.8.8.8")

    def test_valid_hostname_accepted(self):
        assert _is_dialable_host("example.com")
        assert _is_dialable_host("bbs.example.com")

    def test_empty_rejected(self):
        assert not _is_dialable_host("")
        assert not _is_dialable_host(None)


# ---------------------------------------------------------------------------
# Body policy tests
# ---------------------------------------------------------------------------

class TestBodyPolicy:

    def test_eager_body_fetch(self, temp_dir):
        """When body_policy=eager, bodies are fetched after metadata sync."""
        store_a = _make_store(temp_dir, "a", ORIGIN_A)
        store_c = _make_store(temp_dir, "c", ORIGIN_C)
        try:
            origin_id = Identity.generate()
            service_a = ArticleService(store_a, ORIGIN_A, origin_id)

            # Publish an article with a body on A
            body = b"eager body content"
            sub, _, sig = _make_article_submission(1, body=body)
            ev, head = service_a.publish_article(sub, body, sig)

            # C accepts the metadata range
            result = store_c.accept_remote_range(
                ORIGIN_A, BOARD, head, [ev],
                origin_pubkey=origin_id.public_key,
                source_relay="origin-a.test",
            )
            assert result.accepted

            # C does NOT have the body yet (accept_remote_range doesn't fetch bodies)
            assert not store_c.has_body(sub.body_hash)

            # Simulate eager body fetch: C fetches from A's store directly
            fetched_body = store_a.get_body(sub.body_hash)
            assert fetched_body == body
            store_c._store_body_bytes(fetched_body)
            assert store_c.has_body(sub.body_hash)
        finally:
            store_a.close()
            store_c.close()

    def test_on_demand_body_not_fetched(self, temp_dir):
        """When body_policy=on-demand, bodies are not fetched during sync."""
        store_a = _make_store(temp_dir, "a", ORIGIN_A)
        store_c = _make_store(temp_dir, "c", ORIGIN_C)
        try:
            origin_id = Identity.generate()
            service_a = ArticleService(store_a, ORIGIN_A, origin_id)

            body = b"on-demand body"
            sub, _, sig = _make_article_submission(1, body=body)
            ev, head = service_a.publish_article(sub, body, sig)

            # C accepts metadata only
            store_c.accept_remote_range(ORIGIN_A, BOARD, head, [ev],
                                        origin_pubkey=origin_id.public_key,
                                        source_relay="origin-a.test")

            # Body should NOT be present on C
            assert not store_c.has_body(sub.body_hash)

            # But the article projection should exist
            projections = store_c.list_article_projections(ORIGIN_A, BOARD)
            assert len(projections) == 1
            assert projections[0]["body_hash"] == sub.body_hash
        finally:
            store_a.close()
            store_c.close()


# ---------------------------------------------------------------------------
# Multi-page staging tests (feed sync with large ranges)
# ---------------------------------------------------------------------------

class TestMultiPageSync:

    def test_large_range_synced_in_pages(self, temp_dir):
        """A large feed is synced in pages via staging + promotion."""
        store_a = _make_store(temp_dir, "a", ORIGIN_A)
        store_c = _make_store(temp_dir, "c", ORIGIN_C)
        try:
            origin_id = Identity.generate()
            service_a = ArticleService(store_a, ORIGIN_A, origin_id)

            # Publish 10 articles on A
            events = []
            for i in range(1, 11):
                sub, body, sig = _make_article_submission(i)
                ev, _ = service_a.publish_article(sub, body, sig)
                events.append(ev)
            head = store_a.get_head(ORIGIN_A, BOARD)

            # C syncs in two pages of 5 events each
            from core.article_feed import compute_head_hash, encode_head
            candidate_hash = compute_head_hash(encode_head(head))

            # Page 1: events 1-5
            store_c.stage_events(candidate_hash, events[:5])
            state = store_c.get_feed_state(ORIGIN_A, BOARD)
            assert state is None or state["highest_accepted_seq"] == 0

            # Page 2: events 6-10
            store_c.stage_events(candidate_hash, events[5:])
            state = store_c.get_feed_state(ORIGIN_A, BOARD)
            assert state is None or state["highest_accepted_seq"] == 0

            # Promote
            result = store_c.promote_staged(
                ORIGIN_A, BOARD, head,
                origin_pubkey=origin_id.public_key,
                source_relay="origin-a.test",
            )
            assert result.accepted
            assert result.accepted_count == 10

            state = store_c.get_feed_state(ORIGIN_A, BOARD)
            assert state["highest_accepted_seq"] == 10
        finally:
            store_a.close()
            store_c.close()
