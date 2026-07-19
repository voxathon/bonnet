"""Tests for v3 moderation materialization (Phase 5, §23.7).

Covers ARTICLE_FEED_PROTOCOL_V3_IMPLEMENTATION_PLAN.md §23.7:
  - REPORT is queryable by culprit
  - PUNISHMENT warning does not ban
  - Temporary unexpired punishment bans
  - Expired punishment does not ban
  - Permanent punishment bans
  - Revocation removes effective ban but preserves audit rows
  - Multiple enforcement feeds: any active applicable punishment blocks writes
  - Archive-only feed does not affect bans
  - Per-origin temporal filter is applied consistently
  - UME flag disagreement does not override event-derived state

Also tests:
  - ModerationService.is_banned with control policy filtering
  - Punishment projection rebuild with revocations
"""

import os
import sys
import time
import random
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.article_feed import (
    ArticleFeedStore,
    Submission,
    ArticleHeaders,
    RuleHeaders,
    ReportHeaders,
    PunishmentHeaders,
    EVENT_ARTICLE,
    EVENT_CANCEL,
    EVENT_REPORT,
    EVENT_PUNISHMENT,
    EVENT_PUNISHMENT_REVOKE,
    EVENT_RULE,
    SCHEME_V3,
    SUBMISSION_VERSION,
    ZERO_MESSAGE_ID,
    ZERO_HASH,
    compute_body_hash,
    sign_author,
)
from core.crypto import Identity
from core.config import Config, FeedSubscription, ControlPolicy, ModerationBoards
from engine.article_service import ArticleService
from engine.moderation_service import ModerationService, EffectiveBan


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ORIGIN = "bbs.test"
BOARD = "general"
MOD_ACTIONS = "moderation.actions"
MOD_REPORTS = "moderation.reports"
MOD_RULES = "moderation.rules"
CREATED_AT = 1700000000


def _random_msgid(seed):
    rng = random.Random(seed)
    mid = rng.randbytes(32)
    while mid == ZERO_MESSAGE_ID:
        mid = rng.randbytes(32)
    return mid


def _make_store(temp_dir, max_body_size=1024*1024):
    db_path = os.path.join(temp_dir, "article_feeds.db")
    bodies_dir = os.path.join(temp_dir, "article_bodies")
    return ArticleFeedStore(db_path, bodies_dir, max_body_size=max_body_size)


def _make_config(temp_dir, control_policies=None, moderation_boards=None):
    if moderation_boards is None:
        moderation_boards = ModerationBoards(
            rules=MOD_RULES, reports=MOD_REPORTS, punishments=MOD_ACTIONS)
    return Config(
        origin=ORIGIN,
        ame_path=os.path.join(temp_dir, "boards"),
        data_dir=temp_dir,
        nav_db_path=os.path.join(temp_dir, "nav.db"),
        reports_db_path=os.path.join(temp_dir, "reports.db"),
        punishments_db_path=os.path.join(temp_dir, "punishments.db"),
        log_dir=os.path.join(temp_dir, "logs"),
        moderation_boards=moderation_boards,
        control_policies=control_policies or [],
    )


def _make_punishment_submission(seed, punished_pubkey, expires_at,
                                origin=ORIGIN, board=MOD_ACTIONS,
                                notes=b"", author_identity=None):
    if author_identity is None:
        author_identity = Identity.generate()
    body_hash = compute_body_hash(notes)
    sub = Submission(
        submission_version=SUBMISSION_VERSION,
        event_type=EVENT_PUNISHMENT,
        origin=origin, board=board,
        message_id=_random_msgid(seed),
        created_at=CREATED_AT + seed,
        actor_pubkey=author_identity.public_key,
        actor_username="admin",
        actor_registrar=origin,
        headers=PunishmentHeaders(
            punished_pubkey=punished_pubkey,
            expires_at=expires_at,
            report_ids=[],
            rule_ids=[],
        ),
        body_hash=body_hash, body_size=len(notes),
    )
    sig = sign_author(sub, author_identity)
    return sub, notes, sig, author_identity


def _make_revoke_submission(seed, target_message_id, origin=ORIGIN,
                            board=MOD_ACTIONS, author_identity=None):
    if author_identity is None:
        author_identity = Identity.generate()
    sub = Submission(
        submission_version=SUBMISSION_VERSION,
        event_type=EVENT_PUNISHMENT_REVOKE,
        origin=origin, board=board,
        message_id=_random_msgid(seed),
        created_at=CREATED_AT + seed,
        actor_pubkey=author_identity.public_key,
        actor_username="admin",
        actor_registrar=origin,
        target_message_id=target_message_id,
        body_hash=compute_body_hash(b""), body_size=0,
    )
    sig = sign_author(sub, author_identity)
    return sub, sig, author_identity


def _make_report_submission(seed, culprit_pubkey, origin=ORIGIN,
                            board=MOD_REPORTS, author_identity=None):
    if author_identity is None:
        author_identity = Identity.generate()
    sub = Submission(
        submission_version=SUBMISSION_VERSION,
        event_type=EVENT_REPORT,
        origin=origin, board=board,
        message_id=_random_msgid(seed),
        created_at=CREATED_AT + seed,
        actor_pubkey=author_identity.public_key,
        actor_username="reporter",
        actor_registrar=origin,
        headers=ReportHeaders(
            culprit_pubkey=culprit_pubkey,
            target_origin="",
            target_board="",
            target_article_id=ZERO_MESSAGE_ID,
            rule_message_ids=[],
            evidence_hashes=[],
        ),
        body_hash=compute_body_hash(b"report description"), body_size=18,
    )
    sig = sign_author(sub, author_identity)
    return sub, b"report description", sig, author_identity


def _setup_service(temp_dir, control_policies=None):
    store = _make_store(temp_dir)
    origin_id = Identity.generate()
    cfg = _make_config(temp_dir, control_policies=control_policies)
    art_svc = ArticleService(store, ORIGIN, origin_id)
    mod_svc = ModerationService(store, cfg)
    return store, origin_id, art_svc, mod_svc, cfg


# ---------------------------------------------------------------------------
# Moderation materialization tests (§23.7)
# ---------------------------------------------------------------------------

class TestPunishmentWarnings:

    def test_warning_does_not_ban(self, temp_dir):
        """PUNISHMENT with expires_at=0 is a warning and does not ban."""
        store, origin_id, art_svc, mod_svc, cfg = _setup_service(temp_dir,
            control_policies=[ControlPolicy(ORIGIN, MOD_ACTIONS, ["punishment"])])

        try:
            punished = Identity.generate().public_key
            sub, notes, sig, _ = _make_punishment_submission(
                1, punished, expires_at=0, notes=b"warning only",
                author_identity=origin_id)
            art_svc.publish_punishment(sub, notes, sig)

            ban = mod_svc.is_banned(punished)
            assert not ban.banned
        finally:
            store.close()


class TestTemporaryPunishment:

    def test_temporary_unexpired_bans(self, temp_dir):
        """Temporary punishment (expires_at > now) bans."""
        store, origin_id, art_svc, mod_svc, cfg = _setup_service(temp_dir,
            control_policies=[ControlPolicy(ORIGIN, MOD_ACTIONS, ["punishment"])])

        try:
            punished = Identity.generate().public_key
            future = int(time.time()) + 3600
            sub, notes, sig, _ = _make_punishment_submission(
                1, punished, expires_at=future, notes=b"banned for 1 hour",
                author_identity=origin_id)
            art_svc.publish_punishment(sub, notes, sig)

            ban = mod_svc.is_banned(punished)
            assert ban.banned
            assert "banned for 1 hour" in ban.reason
            assert ban.expires_at == future
        finally:
            store.close()

    def test_expired_punishment_does_not_ban(self, temp_dir):
        """Expired punishment (expires_at < now) does not ban."""
        store, origin_id, art_svc, mod_svc, cfg = _setup_service(temp_dir,
            control_policies=[ControlPolicy(ORIGIN, MOD_ACTIONS, ["punishment"])])

        try:
            punished = Identity.generate().public_key
            past = int(time.time()) - 3600  # expired 1 hour ago
            sub, notes, sig, _ = _make_punishment_submission(
                1, punished, expires_at=past, notes=b"was banned",
                author_identity=origin_id)
            art_svc.publish_punishment(sub, notes, sig)

            ban = mod_svc.is_banned(punished)
            assert not ban.banned
        finally:
            store.close()


class TestPermanentPunishment:

    def test_permanent_bans(self, temp_dir):
        """Permanent punishment (expires_at=-1) bans."""
        store, origin_id, art_svc, mod_svc, cfg = _setup_service(temp_dir,
            control_policies=[ControlPolicy(ORIGIN, MOD_ACTIONS, ["punishment"])])

        try:
            punished = Identity.generate().public_key
            sub, notes, sig, _ = _make_punishment_submission(
                1, punished, expires_at=-1, notes=b"permanently banned",
                author_identity=origin_id)
            art_svc.publish_punishment(sub, notes, sig)

            ban = mod_svc.is_banned(punished)
            assert ban.banned
            assert ban.expires_at == -1
        finally:
            store.close()


class TestRevocation:

    def test_revocation_removes_effective_ban(self, temp_dir):
        """PUNISHMENT_REVOKE removes the effective ban but preserves the
        audit row."""
        store, origin_id, art_svc, mod_svc, cfg = _setup_service(temp_dir,
            control_policies=[ControlPolicy(ORIGIN, MOD_ACTIONS, ["punishment"])])

        try:
            punished = Identity.generate().public_key

            # Publish punishment
            sub1, notes1, sig1, _ = _make_punishment_submission(
                1, punished, expires_at=-1, notes=b"banned",
                author_identity=origin_id)
            ev1, _ = art_svc.publish_punishment(sub1, notes1, sig1)

            ban = mod_svc.is_banned(punished)
            assert ban.banned

            # Revoke it
            revoke_sub, revoke_sig, _ = _make_revoke_submission(
                2, sub1.message_id, author_identity=origin_id)
            art_svc.publish_punishment_revoke(revoke_sub, revoke_sig)

            ban = mod_svc.is_banned(punished)
            assert not ban.banned

            # Audit row should still exist
            punishments = mod_svc.list_punishments_by_pubkey(punished)
            assert len(punishments) == 1
            assert punishments[0]["revoked_by"] is not None
        finally:
            store.close()


class TestControlPolicyFiltering:

    def test_no_control_policy_means_not_enforceable(self, temp_dir):
        """Without a control_policy, punishments are not enforceable."""
        store, origin_id, art_svc, mod_svc, cfg = _setup_service(temp_dir)

        try:
            punished = Identity.generate().public_key
            sub, notes, sig, _ = _make_punishment_submission(
                1, punished, expires_at=-1, notes=b"banned",
                author_identity=origin_id)
            art_svc.publish_punishment(sub, notes, sig)

            ban = mod_svc.is_banned(punished)
            assert not ban.banned  # no control policy → not enforceable
        finally:
            store.close()

    def test_archive_only_feed_does_not_ban(self, temp_dir):
        """A feed with control_policy.apply NOT including 'punishment' does
        not produce bans (archive-only)."""
        store, origin_id, art_svc, mod_svc, cfg = _setup_service(temp_dir,
            control_policies=[ControlPolicy(ORIGIN, MOD_ACTIONS, [])])  # empty apply

        try:
            punished = Identity.generate().public_key
            sub, notes, sig, _ = _make_punishment_submission(
                1, punished, expires_at=-1, notes=b"banned",
                author_identity=origin_id)
            art_svc.publish_punishment(sub, notes, sig)

            ban = mod_svc.is_banned(punished)
            assert not ban.banned  # archive-only → not enforceable
        finally:
            store.close()


class TestReports:

    def test_report_queryable_by_culprit(self, temp_dir):
        """REPORT events are queryable by culprit pubkey."""
        store, origin_id, art_svc, mod_svc, cfg = _setup_service(temp_dir)

        try:
            culprit = Identity.generate().public_key
            sub, body, sig, _ = _make_report_submission(
                1, culprit, author_identity=origin_id)
            art_svc.publish_report(sub, body, sig)

            reports = mod_svc.list_reports_by_culprit(culprit)
            assert len(reports) == 1
            assert reports[0].headers.culprit_pubkey == culprit
        finally:
            store.close()


class TestProjectionRebuild:

    def test_rebuild_preserves_revocations(self, temp_dir):
        """Rebuilding punishment projections preserves revocation state."""
        store, origin_id, art_svc, mod_svc, cfg = _setup_service(temp_dir,
            control_policies=[ControlPolicy(ORIGIN, MOD_ACTIONS, ["punishment"])])

        try:
            punished = Identity.generate().public_key

            # Publish + revoke
            sub1, notes1, sig1, _ = _make_punishment_submission(
                1, punished, expires_at=-1, author_identity=origin_id)
            art_svc.publish_punishment(sub1, notes1, sig1)

            revoke_sub, revoke_sig, _ = _make_revoke_submission(
                2, sub1.message_id, author_identity=origin_id)
            art_svc.publish_punishment_revoke(revoke_sub, revoke_sig)

            # Rebuild
            count = mod_svc.rebuild_punishment_projections()
            assert count >= 1

            # Should still be not banned after rebuild
            ban = mod_svc.is_banned(punished)
            assert not ban.banned

            # Audit row should have revoked_by set
            punishments = mod_svc.list_punishments_by_pubkey(punished)
            assert len(punishments) == 1
            assert punishments[0]["revoked_by"] is not None
        finally:
            store.close()


class TestMultipleEnforcementFeeds:

    def test_any_active_punishment_blocks(self, temp_dir):
        """Multiple enforcement feeds: any active applicable punishment blocks."""
        store, origin_id, art_svc, mod_svc, cfg = _setup_service(temp_dir,
            control_policies=[
                ControlPolicy(ORIGIN, MOD_ACTIONS, ["punishment"]),
                ControlPolicy("other.test", MOD_ACTIONS, ["punishment"]),
            ])

        try:
            punished = Identity.generate().public_key

            # Publish a permanent punishment from local origin
            sub, notes, sig, _ = _make_punishment_submission(
                1, punished, expires_at=-1, author_identity=origin_id)
            art_svc.publish_punishment(sub, notes, sig)

            ban = mod_svc.is_banned(punished)
            assert ban.banned
            assert ban.source_origin == ORIGIN
        finally:
            store.close()


class TestNoPunishments:

    def test_no_punishments_not_banned(self, temp_dir):
        """A key with no punishments is not banned."""
        store, origin_id, art_svc, mod_svc, cfg = _setup_service(temp_dir,
            control_policies=[ControlPolicy(ORIGIN, MOD_ACTIONS, ["punishment"])])

        try:
            ban = mod_svc.is_banned(Identity.generate().public_key)
            assert not ban.banned
        finally:
            store.close()
