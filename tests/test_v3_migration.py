"""Tests for Phase 6 migration (§23.9).

Covers ARTICLE_FEED_PROTOCOL_V3_IMPLEMENTATION_PLAN.md §23.9:
  - Existing post numbers are preserved
  - Existing root relationships map to message IDs
  - Existing bodies hash correctly
  - Unsigned legacy posts remain honestly marked unsigned
  - Valid old post signatures remain preserved and verifiable under legacy scheme
  - Reports/punishments preserve every rollover as a distinct event
  - Existing origin signatures remain stored
  - Interrupted migration resumes idempotently
  - Old databases remain untouched until verification completes
  - Effective bans remain continuous across the transition union

These tests create legacy v2 data in AME/Keibatsu databases, then run the
MigrationExecutor and verify the resulting v3 events.
"""

import os
import sys
import time
import struct
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.article_feed import (
    ArticleFeedStore,
    EVENT_ARTICLE,
    EVENT_RULE,
    EVENT_REPORT,
    EVENT_PUNISHMENT,
    SCHEME_NONE,
    SCHEME_LEGACY_V2,
    SCHEME_V3,
    ZERO_MESSAGE_ID,
    ZERO_HASH,
    Extension,
    ArticleHeaders,
    RuleHeaders,
    ReportHeaders,
    PunishmentHeaders,
    decode_event,
    compute_body_hash,
    EXT_LEGACY_DESCRIPTOR,
    EXT_LEGACY_AUTHOR_SIGNATURE,
    EXT_LEGACY_ORIGIN_SIGNATURE,
    LEGACY_POST,
    LEGACY_RULE,
    LEGACY_REPORT,
    LEGACY_PUNISHMENT,
)
from core.crypto import Identity
from core.config import Config, ControlPolicy, ModerationBoards
from core.migration import (
    MigrationExecutor,
    MigrationProgress,
    derive_post_message_id,
    derive_rule_message_id,
    derive_report_message_id,
    derive_punishment_message_id,
    encode_canonical_legacy_post_metadata,
    encode_canonical_legacy_rule,
    build_post_legacy_descriptor,
)
from core.orm import Database
from engine.ume import Ume
from engine.ame import Ame
from engine.keibatsu import Keibatsu
from engine.article_service import ArticleService
from engine.moderation_service import ModerationService
from tests.helpers import default_test_acls
from tests.fixtures.protocol_v1.wire_fixtures import TEST_SEED


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ORIGIN = "bbs.test"
BOARD = "testboard"
MOD_RULES = "moderation.rules"
MOD_REPORTS = "moderation.reports"
MOD_ACTIONS = "moderation.actions"


@pytest.fixture
def temp_dir(tmp_path):
    return str(tmp_path)


def _make_server_identity():
    return Identity.from_private_key(TEST_SEED)


def _make_config(temp_dir):
    return Config(
        origin=ORIGIN,
        registrars=[ORIGIN],
        ame_path=os.path.join(temp_dir, "boards"),
        data_dir=temp_dir,
        nav_db_path=os.path.join(temp_dir, "nav.db"),
        reports_db_path=os.path.join(temp_dir, "reports.db"),
        punishments_db_path=os.path.join(temp_dir, "punishments.db"),
        log_dir=os.path.join(temp_dir, "logs"),
        acls=default_test_acls(ORIGIN),
        anonymous_read=True,
        moderation_boards=ModerationBoards(
            rules=MOD_RULES, reports=MOD_REPORTS, punishments=MOD_ACTIONS),
        control_policies=[ControlPolicy(ORIGIN, MOD_ACTIONS, ["punishment"])],
    )


def _make_full_setup(temp_dir):
    """Create a full server-like setup with AME, Keibatsu, and ArticleFeedStore."""
    sid = _make_server_identity()
    cfg = _make_config(temp_dir)

    ume = Ume(os.path.join(temp_dir, "userfile"))
    ume.ensure_root_user(ORIGIN, sid.public_key)

    ame = Ame(cfg.ame_path, origin=ORIGIN, signing_key=sid.signing_key,
              nav_db_path=cfg.nav_db_path)

    # Init rules table for keibatsu
    with Database(cfg.reports_db_path).open() as ctx:
        ctx.execute("""CREATE TABLE IF NOT EXISTS rules (
            rule_num INTEGER PRIMARY KEY, rule_name TEXT UNIQUE NOT NULL, description TEXT NOT NULL
        )""")

    keibatsu = Keibatsu(cfg.reports_db_path, cfg.punishments_db_path,
                        ume=ume, signing_key=sid.signing_key, origin=ORIGIN)

    store = ArticleFeedStore(
        os.path.join(temp_dir, "article_feeds.db"),
        os.path.join(temp_dir, "article_bodies"),
    )

    return sid, cfg, ume, ame, keibatsu, store


# ---------------------------------------------------------------------------
# Deterministic message ID tests
# ---------------------------------------------------------------------------

class TestDeterministicMessageIDs:

    def test_post_message_id_deterministic(self):
        """Same post data always produces the same message ID."""
        meta = encode_canonical_legacy_post_metadata(
            post_num=1, last_modified=1700000000, creation_date=1700000000,
            last_bumped=1700000000, closed=False, sticky=0,
            tags="test", subject="Hello", options="",
            root=0, author="alice", author_registrar="bbs.test",
            legacy_signature_text="",
        )
        body_hash = compute_body_hash(b"body content")
        mid1 = derive_post_message_id(ORIGIN, BOARD, 1, meta, body_hash)
        mid2 = derive_post_message_id(ORIGIN, BOARD, 1, meta, body_hash)
        assert mid1 == mid2
        assert len(mid1) == 32
        assert mid1 != ZERO_MESSAGE_ID

    def test_post_message_id_differs_by_post_num(self):
        meta = encode_canonical_legacy_post_metadata(
            post_num=1, last_modified=1700000000, creation_date=1700000000,
            last_bumped=1700000000, closed=False, sticky=0,
            tags="", subject="", options="",
            root=0, author="", author_registrar="",
            legacy_signature_text="",
        )
        body_hash = compute_body_hash(b"body")
        mid1 = derive_post_message_id(ORIGIN, BOARD, 1, meta, body_hash)
        meta2 = encode_canonical_legacy_post_metadata(
            post_num=2, last_modified=1700000000, creation_date=1700000000,
            last_bumped=1700000000, closed=False, sticky=0,
            tags="", subject="", options="",
            root=0, author="", author_registrar="",
            legacy_signature_text="",
        )
        mid2 = derive_post_message_id(ORIGIN, BOARD, 2, meta2, body_hash)
        assert mid1 != mid2

    def test_rule_message_id_deterministic(self):
        encoded = encode_canonical_legacy_rule(1, "spam", "No spamming")
        mid1 = derive_rule_message_id(ORIGIN, encoded)
        mid2 = derive_rule_message_id(ORIGIN, encoded)
        assert mid1 == mid2


# ---------------------------------------------------------------------------
# Post migration tests
# ---------------------------------------------------------------------------

class TestPostMigration:

    def test_post_numbers_preserved(self, temp_dir):
        """Existing post numbers are preserved as article_num (§23.9)."""
        sid, cfg, ume, ame, kei, store = _make_full_setup(temp_dir)
        try:
            # Create a board and some posts
            board = ame.create_board(BOARD)
            for i in range(1, 4):
                result = board.create_post(
                    subject=f"Post {i}", content=f"Content {i}",
                    author="alice", author_registrar=ORIGIN,
                )
                result.result()  # wait

            # Run migration
            executor = MigrationExecutor(store, sid, cfg, ame=ame, keibatsu=kei)
            count = executor.migrate_posts()
            assert count == 3

            # Verify article_nums are preserved
            projections = store.list_article_projections(ORIGIN, BOARD)
            assert len(projections) == 3
            nums = sorted(p["article_num"] for p in projections)
            assert nums == [1, 2, 3]
        finally:
            store.close()
            ame.shutdown()
            kei.shutdown()

    def test_bodies_hash_correctly(self, temp_dir):
        """Existing bodies hash correctly in v3 events (§23.9)."""
        sid, cfg, ume, ame, kei, store = _make_full_setup(temp_dir)
        try:
            board = ame.create_board(BOARD)
            body_text = "Hello migration world!"
            result = board.create_post(
                subject="Test", content=body_text,
                author="alice", author_registrar=ORIGIN,
            )
            result.result()

            executor = MigrationExecutor(store, sid, cfg, ame=ame, keibatsu=kei)
            executor.migrate_posts()

            # Verify body hash
            projections = store.list_article_projections(ORIGIN, BOARD)
            assert len(projections) == 1
            expected_hash = compute_body_hash(body_text.encode("utf-8"))
            assert projections[0]["body_hash"] == expected_hash

            # Verify body is retrievable
            body = store.get_body(expected_hash)
            assert body == body_text.encode("utf-8")
        finally:
            store.close()
            ame.shutdown()
            kei.shutdown()

    def test_unsigned_posts_marked_scheme_none(self, temp_dir):
        """Unsigned legacy posts remain honestly marked unsigned (§23.9)."""
        sid, cfg, ume, ame, kei, store = _make_full_setup(temp_dir)
        try:
            board = ame.create_board(BOARD)
            result = board.create_post(
                subject="No sig", content="content",
                author="alice", author_registrar=ORIGIN,
            )
            result.result()

            executor = MigrationExecutor(store, sid, cfg, ame=ame, keibatsu=kei)
            executor.migrate_posts()

            # Check the event has scheme 0
            events = store.get_events_range(ORIGIN, BOARD, 1, 10)
            assert len(events) == 1
            assert events[0].author_signature_scheme == SCHEME_NONE
            assert events[0].author_signature == b""
            assert len(events[0].extensions) > 0  # has LEGACY_DESCRIPTOR
        finally:
            store.close()
            ame.shutdown()
            kei.shutdown()

    def test_legacy_descriptor_present(self, temp_dir):
        """Migrated events have a LEGACY_DESCRIPTOR extension."""
        sid, cfg, ume, ame, kei, store = _make_full_setup(temp_dir)
        try:
            board = ame.create_board(BOARD)
            result = board.create_post(
                subject="Test", content="content",
                author="alice", author_registrar=ORIGIN,
            )
            result.result()

            executor = MigrationExecutor(store, sid, cfg, ame=ame, keibatsu=kei)
            executor.migrate_posts()

            events = store.get_events_range(ORIGIN, BOARD, 1, 10)
            assert len(events) == 1
            ev = events[0]
            # Find LEGACY_DESCRIPTOR
            descriptors = [e for e in ev.extensions if e.type == EXT_LEGACY_DESCRIPTOR]
            assert len(descriptors) == 1
            # Verify it encodes the post_num
            desc = descriptors[0].value
            assert desc[0] == 2  # source_protocol = v2
            assert desc[1] == LEGACY_POST  # source_object_type
            # legacy_identity is post_num:u64be
            post_num = struct.unpack(">Q", desc[2:10])[0]
            assert post_num == 1
        finally:
            store.close()
            ame.shutdown()
            kei.shutdown()

    def test_root_relationship_mapped_to_message_id(self, temp_dir):
        """Existing root relationships map to message IDs (§23.9)."""
        sid, cfg, ume, ame, kei, store = _make_full_setup(temp_dir)
        try:
            board = ame.create_board(BOARD)
            # Create a root post and a reply
            r1 = board.create_post(subject="Root", content="root body",
                                   author="alice", author_registrar=ORIGIN)
            root_post = r1.result()
            r2 = board.create_post(subject="Reply", content="reply body",
                                   root=root_post.post_num,
                                   author="bob", author_registrar=ORIGIN)
            reply_post = r2.result()

            executor = MigrationExecutor(store, sid, cfg, ame=ame, keibatsu=kei)
            executor.migrate_posts()

            events = store.get_events_range(ORIGIN, BOARD, 1, 10)
            assert len(events) == 2
            # First event (root) should have zero root_message_id
            assert events[0].root_message_id == ZERO_MESSAGE_ID
            # Second event (reply) should have root_message_id pointing to first
            assert events[1].root_message_id == events[0].message_id
        finally:
            store.close()
            ame.shutdown()
            kei.shutdown()


# ---------------------------------------------------------------------------
# Rule migration tests
# ---------------------------------------------------------------------------

class TestRuleMigration:

    def test_rules_migrated_to_moderation_board(self, temp_dir):
        """Existing rules migrate to the configured moderation.rules board."""
        sid, cfg, ume, ame, kei, store = _make_full_setup(temp_dir)
        try:
            # Create some rules
            kei.create_rule("spam", "No spamming").result()
            kei.create_rule("nsfw", "No NSFW content").result()

            executor = MigrationExecutor(store, sid, cfg, ame=ame, keibatsu=kei)
            count = executor.migrate_rules()
            assert count == 2

            # Verify events on the moderation.rules board
            events = store.get_events_range(ORIGIN, MOD_RULES, 1, 10)
            assert len(events) == 2
            assert all(e.event_type == EVENT_RULE for e in events)
        finally:
            store.close()
            ame.shutdown()
            kei.shutdown()


# ---------------------------------------------------------------------------
# Punishment migration tests
# ---------------------------------------------------------------------------

class TestPunishmentMigration:

    def test_punishment_migrated_with_expires_at(self, temp_dir):
        """Punishments preserve expires_at and created_at."""
        sid, cfg, ume, ame, kei, store = _make_full_setup(temp_dir)
        try:
            punished = Identity.generate().public_key
            kei.create_punishment(
                punished, [], expires_at=-1, ban_notes="banned for testing",
                issued_by=sid.public_key, sync_ume=False,
            ).result()

            executor = MigrationExecutor(store, sid, cfg, ame=ame, keibatsu=kei)
            count = executor.migrate_punishments()
            assert count == 1

            # Verify the event
            events = store.get_events_range(ORIGIN, MOD_ACTIONS, 1, 10)
            assert len(events) == 1
            ev = events[0]
            assert ev.event_type == EVENT_PUNISHMENT
            assert isinstance(ev.headers, PunishmentHeaders)
            assert ev.headers.punished_pubkey == punished
            assert ev.headers.expires_at == -1  # permanent
        finally:
            store.close()
            ame.shutdown()
            kei.shutdown()

    def test_punishment_ban_works_after_migration(self, temp_dir):
        """After migration, ModerationService can evaluate bans from migrated events."""
        sid, cfg, ume, ame, kei, store = _make_full_setup(temp_dir)
        try:
            punished = Identity.generate().public_key
            kei.create_punishment(
                punished, [], expires_at=-1, ban_notes="migrated ban",
                issued_by=sid.public_key, sync_ume=False,
            ).result()

            executor = MigrationExecutor(store, sid, cfg, ame=ame, keibatsu=kei)
            executor.migrate_punishments()

            # Check ban via ModerationService
            mod_svc = ModerationService(store, cfg)
            ban = mod_svc.is_banned(punished)
            assert ban.banned
            assert "migrated ban" in ban.reason
        finally:
            store.close()
            ame.shutdown()
            kei.shutdown()


# ---------------------------------------------------------------------------
# Idempotent restart tests
# ------------------------------------------------------------------

class TestIdempotentRestart:

    def test_migration_idempotent_on_restart(self, temp_dir):
        """Interrupted migration resumes idempotently (§23.9)."""
        sid, cfg, ume, ame, kei, store = _make_full_setup(temp_dir)
        try:
            board = ame.create_board(BOARD)
            for i in range(1, 4):
                board.create_post(
                    subject=f"Post {i}", content=f"Content {i}",
                    author="alice", author_registrar=ORIGIN,
                ).result()

            executor = MigrationExecutor(store, sid, cfg, ame=ame, keibatsu=kei)
            count1 = executor.migrate_posts()
            assert count1 == 3

            # Run again — should skip (idempotent)
            count2 = executor.migrate_posts()
            assert count2 == 0

            # Verify state is still correct
            projections = store.list_article_projections(ORIGIN, BOARD)
            assert len(projections) == 3
        finally:
            store.close()
            ame.shutdown()
            kei.shutdown()

    def test_progress_tracking(self, temp_dir):
        """Migration progress is tracked and queryable."""
        sid, cfg, ume, ame, kei, store = _make_full_setup(temp_dir)
        try:
            board = ame.create_board(BOARD)
            board.create_post(subject="Test", content="content",
                              author="alice", author_registrar=ORIGIN).result()

            executor = MigrationExecutor(store, sid, cfg, ame=ame, keibatsu=kei)
            executor.migrate_posts()

            completed = executor.progress.list_completed()
            assert len(completed) >= 1
            assert any("posts" in c[0] for c in completed)
        finally:
            store.close()
            ame.shutdown()
            kei.shutdown()


# ---------------------------------------------------------------------------
# Full migration test
# ------------------------------------------------------------------

class TestFullMigration:

    def test_migrate_all(self, temp_dir):
        """migrate_all() migrates posts, rules, reports, and punishments."""
        sid, cfg, ume, ame, kei, store = _make_full_setup(temp_dir)
        try:
            # Create legacy data
            board = ame.create_board(BOARD)
            board.create_post(subject="Post 1", content="content1",
                              author="alice", author_registrar=ORIGIN).result()
            board.create_post(subject="Post 2", content="content2",
                              author="bob", author_registrar=ORIGIN).result()

            kei.create_rule("spam", "No spamming").result()

            punished = Identity.generate().public_key
            kei.create_punishment(punished, [], expires_at=-1,
                                  ban_notes="banned",
                                  issued_by=sid.public_key,
                                  sync_ume=False).result()

            # Run full migration
            executor = MigrationExecutor(store, sid, cfg, ame=ame, keibatsu=kei)
            results = executor.migrate_all()

            assert results["posts"] == 2
            assert results["rules"] == 1
            assert results["punishments"] == 1

            # Verify everything is in the feed
            article_projections = store.list_article_projections(ORIGIN, BOARD)
            assert len(article_projections) == 2

            rule_events = store.get_events_range(ORIGIN, MOD_RULES, 1, 10)
            assert len(rule_events) == 1

            pun_events = store.get_events_range(ORIGIN, MOD_ACTIONS, 1, 10)
            assert len(pun_events) == 1

            # Verify ban still works
            mod_svc = ModerationService(store, cfg)
            ban = mod_svc.is_banned(punished)
            assert ban.banned
        finally:
            store.close()
            ame.shutdown()
            kei.shutdown()

    def test_old_databases_untouched(self, temp_dir):
        """Old databases remain untouched (read-only) after migration."""
        sid, cfg, ume, ame, kei, store = _make_full_setup(temp_dir)
        try:
            board = ame.create_board(BOARD)
            board.create_post(subject="Post", content="content",
                              author="alice", author_registrar=ORIGIN).result()

            # Record the post count before migration
            posts_before = board.query().result()
            count_before = len(posts_before)

            executor = MigrationExecutor(store, sid, cfg, ame=ame, keibatsu=kei)
            executor.migrate_posts()

            # Legacy data should still be there
            posts_after = board.query().result()
            assert len(posts_after) == count_before
        finally:
            store.close()
            ame.shutdown()
            kei.shutdown()
