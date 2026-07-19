"""Load tests for v3 first sync and body fetch limits (Phase 8).

Tests that the feed sync and body fetch infrastructure handles:
  - Large feed first-sync (100+ events)
  - Body fetch with bounded response sizes
  - Concurrent sync operations
  - Byte-bounded FEED_EVENTS responses
"""

import os
import sys
import time
import random
import pytest
from concurrent.futures import ThreadPoolExecutor

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
    ZERO_HASH,
    compute_body_hash,
    sign_author,
    encode_event,
    decode_event,
    compute_event_hash,
    compute_head_hash,
    encode_head,
    decode_head,
    verify_head_signature,
    verify_origin_signature,
)
from core.crypto import Identity
from engine.article_service import ArticleService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ORIGIN_A = "origin-a.test"
ORIGIN_C = "origin-c.test"
BOARD = "loadtest"
CREATED_AT = 1700000000


def _random_msgid(seed):
    rng = random.Random(seed)
    mid = rng.randbytes(32)
    while mid == ZERO_MESSAGE_ID:
        mid = rng.randbytes(32)
    return mid


def _make_article_submission(seed, origin=ORIGIN_A, board=BOARD, body=None):
    author_id = Identity.generate()
    if body is None:
        body = f"load test body {seed}".encode("utf-8")
    body_hash = compute_body_hash(body)
    sub = Submission(
        submission_version=SUBMISSION_VERSION,
        event_type=EVENT_ARTICLE,
        origin=origin, board=board,
        message_id=_random_msgid(seed),
        created_at=CREATED_AT + seed,
        actor_pubkey=author_id.public_key,
        actor_username="loadtest",
        actor_registrar=origin,
        headers=ArticleHeaders(subject=f"Load Test {seed}", tags="test", options=""),
        body_hash=body_hash, body_size=len(body),
    )
    sig = sign_author(sub, author_id)
    return sub, body, sig


def _make_store(temp_dir, name):
    db_path = os.path.join(temp_dir, f"{name}_feeds.db")
    bodies_dir = os.path.join(temp_dir, f"{name}_bodies")
    return ArticleFeedStore(db_path, bodies_dir)


# ---------------------------------------------------------------------------
# Load tests
# ---------------------------------------------------------------------------

class TestFirstSyncLoad:

    def test_first_sync_100_events(self, temp_dir):
        """First sync of 100 events completes and all events are accepted."""
        store_a = _make_store(temp_dir, "a")
        store_c = _make_store(temp_dir, "c")
        try:
            origin_id = Identity.generate()
            service_a = ArticleService(store_a, ORIGIN_A, origin_id)

            # Publish 100 articles on A
            events = []
            for i in range(1, 101):
                sub, body, sig = _make_article_submission(i)
                ev, _ = service_a.publish_article(sub, body, sig)
                events.append(ev)

            head = store_a.get_head(ORIGIN_A, BOARD)
            assert head.latest_feed_seq == 100

            # C syncs all 100 events
            result = store_c.accept_remote_range(
                ORIGIN_A, BOARD, head, events,
                origin_pubkey=origin_id.public_key,
                source_relay="origin-a.test",
            )
            assert result.accepted
            assert result.accepted_count == 100

            state = store_c.get_feed_state(ORIGIN_A, BOARD)
            assert state["highest_accepted_seq"] == 100
            assert state["current_article_count"] == 100
        finally:
            store_a.close()
            store_c.close()

    def test_first_sync_500_events(self, temp_dir):
        """First sync of 500 events completes within reasonable time."""
        store_a = _make_store(temp_dir, "a")
        store_c = _make_store(temp_dir, "c")
        try:
            origin_id = Identity.generate()
            service_a = ArticleService(store_a, ORIGIN_A, origin_id)

            events = []
            for i in range(1, 501):
                sub, body, sig = _make_article_submission(i)
                ev, _ = service_a.publish_article(sub, body, sig)
                events.append(ev)

            head = store_a.get_head(ORIGIN_A, BOARD)

            start = time.time()
            result = store_c.accept_remote_range(
                ORIGIN_A, BOARD, head, events,
                origin_pubkey=origin_id.public_key,
                source_relay="origin-a.test",
            )
            elapsed = time.time() - start

            assert result.accepted
            assert result.accepted_count == 500
            # Should complete in under 10 seconds
            assert elapsed < 10.0, f"Sync took {elapsed:.1f}s, expected < 10s"
        finally:
            store_a.close()
            store_c.close()

    def test_paged_sync_1000_events(self, temp_dir):
        """Sync 1000 events in pages of 50, using staging + promotion."""
        store_a = _make_store(temp_dir, "a")
        store_c = _make_store(temp_dir, "c")
        try:
            origin_id = Identity.generate()
            service_a = ArticleService(store_a, ORIGIN_A, origin_id)

            events = []
            for i in range(1, 1001):
                sub, body, sig = _make_article_submission(i)
                ev, _ = service_a.publish_article(sub, body, sig)
                events.append(ev)

            head = store_a.get_head(ORIGIN_A, BOARD)
            candidate_hash = compute_head_hash(encode_head(head))

            # Stage in pages of 50
            for page_start in range(0, 1000, 50):
                page = events[page_start:page_start + 50]
                store_c.stage_events(candidate_hash, page)

            # Promote
            result = store_c.promote_staged(
                ORIGIN_A, BOARD, head,
                origin_pubkey=origin_id.public_key,
                source_relay="origin-a.test",
            )
            assert result.accepted
            assert result.accepted_count == 1000

            state = store_c.get_feed_state(ORIGIN_A, BOARD)
            assert state["highest_accepted_seq"] == 1000
        finally:
            store_a.close()
            store_c.close()


class TestBodyFetchLimits:

    def test_body_fetch_oversized_rejected(self, temp_dir):
        """Body exceeding max_body_size is rejected before buffering."""
        store = _make_store(temp_dir, "a")
        try:
            store._max_body_size = 100  # 100 byte limit
            big_body = b"x" * 200
            with pytest.raises(Exception):
                store._store_body_bytes(big_body)
        finally:
            store.close()

    def test_byte_bounded_events_range(self, temp_dir):
        """FEED_EVENTS with byte limit returns fewer events than max_count."""
        store = _make_store(temp_dir, "a")
        try:
            origin_id = Identity.generate()
            service = ArticleService(store, ORIGIN_A, origin_id)

            # Publish 20 articles with large bodies
            for i in range(1, 21):
                body = f"body content {i} with lots of padding to make the event encoding larger than usual xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".encode()
                sub, _, sig = _make_article_submission(i, body=body)
                sub.actor_pubkey = origin_id.public_key
                sig = sign_author(sub, origin_id)
                service.publish_article(sub, body, sig)

            # Query with max_count=20 but max_bytes=2000 (should get fewer)
            events = store.get_events_range(ORIGIN_A, BOARD, 1, max_count=20, max_bytes=2000)
            # Should return fewer than 20 due to byte limit
            assert len(events) < 20
            assert len(events) > 0
        finally:
            store.close()


class TestConcurrentSync:

    def test_concurrent_appends_dont_corrupt(self, temp_dir):
        """20 concurrent appends produce 20 distinct contiguous events."""
        store = _make_store(temp_dir, "a")
        try:
            origin_id = Identity.generate()
            service = ArticleService(store, ORIGIN_A, origin_id)

            def append_one(seed):
                sub, body, sig = _make_article_submission(seed)
                return service.publish_article(sub, body, sig)

            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(append_one, range(1, 21)))

            seqs = sorted(r[0].feed_seq for r in results)
            assert seqs == list(range(1, 21))
            article_nums = sorted(r[0].article_num for r in results)
            assert article_nums == list(range(1, 21))

            state = store.get_feed_state(ORIGIN_A, BOARD)
            assert state["highest_accepted_seq"] == 20
        finally:
            store.close()
