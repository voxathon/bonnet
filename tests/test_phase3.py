# -*- coding: utf-8 -*-
"""Phase 3 tests: compositional ACL, kind validation, and search.

Tests PROTOCOL.md §12 (kind schemas), §15 (search), §16 (ACL model).
"""

import os
import pytest

from core.crypto import Identity
from core.record import (
    Intent, MetadataMap, ZERO_ID,
    metadata_text, metadata_text_list, metadata_bytes, metadata_u64, metadata_i64,
    compute_body_hash,
)
from core.acl import (
    ACLEvaluator, ACLRule, PrincipalMatcher, AuthContext,
    default_rules_for_admin,
)
from core.kind_validator import KindValidator, ValidationError
from core.board_projection import BoardProjection
from core.bodies import BodyStore
from core.search import SearchService


# ---------------------------------------------------------------------------
# Test identities
# ---------------------------------------------------------------------------

ADMIN_PUB = bytes(range(1, 33))
USER_PUB = bytes(range(10, 42))
ANON_PUB = bytes(range(20, 52))


def _rid(seed: int) -> bytes:
    return bytes([(seed + i) % 256 for i in range(32)])


# ---------------------------------------------------------------------------
# ACL Tests (§16)
# ---------------------------------------------------------------------------

class TestACLEvaluator:
    def _admin_ctx(self):
        return AuthContext(pubkey=ADMIN_PUB, role="administrator", origin="bbs.test",
                           is_registered=True)

    def _user_ctx(self):
        return AuthContext(pubkey=USER_PUB, role="", origin="bbs.test",
                           is_registered=True)

    def _anon_ctx(self):
        return AuthContext(pubkey=ANON_PUB, is_anonymous=True)

    def _unknown_ctx(self):
        return AuthContext(pubkey=USER_PUB, is_unknown=True)

    def test_admin_full_access(self):
        rules = default_rules_for_admin(ADMIN_PUB.hex())
        acl = ACLEvaluator(rules)
        ctx = self._admin_ctx()
        assert acl.check(ctx, "read", command="PUBLISH_RECORD")
        assert acl.check(ctx, "write", command="PUBLISH_RECORD", kind="bonnet.article", board="general")

    def test_no_implicit_admin_bypass(self):
        """Admin with no rules is denied everything."""
        acl = ACLEvaluator([])
        ctx = self._admin_ctx()
        assert not acl.check(ctx, "read", command="PUBLISH_RECORD")

    def test_deny_overrides_allow(self):
        rules = [
            ACLRule(
                effect="allow",
                matcher=PrincipalMatcher(role="administrator"),
                actions=["read", "write"],
                commands=["*"],
            ),
            ACLRule(
                effect="deny",
                matcher=PrincipalMatcher(role="administrator"),
                actions=["write"],
                commands=["PUBLISH_RECORD"],
            ),
        ]
        acl = ACLEvaluator(rules)
        ctx = self._admin_ctx()
        assert acl.check(ctx, "read", command="PUBLISH_RECORD")
        assert not acl.check(ctx, "write", command="PUBLISH_RECORD")

    def test_conjunctive_dimensions(self):
        """All dimensions must pass."""
        rules = [
            ACLRule(
                effect="allow",
                matcher=PrincipalMatcher(role="administrator"),
                actions=["write"],
                commands=["*"],
                kinds=["*"],
                boards=["general"],
                objects=["*"],
            ),
        ]
        acl = ACLEvaluator(rules)
        ctx = self._admin_ctx()
        assert acl.check(ctx, "write", command="PUBLISH_RECORD", kind="bonnet.article", board="general")
        assert not acl.check(ctx, "write", command="PUBLISH_RECORD", kind="bonnet.article", board="other")

    def test_no_match_means_deny(self):
        rules = [
            ACLRule(
                effect="allow",
                matcher=PrincipalMatcher(role="administrator"),
                actions=["read"],
                commands=["ARTICLE_GET"],
            ),
        ]
        acl = ACLEvaluator(rules)
        ctx = self._admin_ctx()
        assert acl.check(ctx, "read", command="ARTICLE_GET")
        assert not acl.check(ctx, "read", command="PUBLISH_RECORD")

    def test_wildcard_selector(self):
        rules = [
            ACLRule(
                effect="allow",
                matcher=PrincipalMatcher(wildcard=True),
                actions=["read"],
                commands=["*"],
                boards=["*"],
                objects=["*"],
            ),
        ]
        acl = ACLEvaluator(rules)
        ctx = self._user_ctx()
        assert acl.check(ctx, "read", command="ARTICLE_GET", board="general", object_name="articles")
        assert not acl.check(ctx, "write", command="ARTICLE_GET")

    def test_pubkey_matcher(self):
        rules = [
            ACLRule(
                effect="allow",
                matcher=PrincipalMatcher(pubkey=USER_PUB),
                actions=["read", "write"],
                commands=["*"],
                kinds=["*"],
                boards=["*"],
            ),
        ]
        acl = ACLEvaluator(rules)
        ctx = self._user_ctx()
        assert acl.check(ctx, "write", command="PUBLISH_RECORD", kind="bonnet.article", board="general")

    def test_anonymous_matcher(self):
        rules = [
            ACLRule(
                effect="allow",
                matcher=PrincipalMatcher(anonymous=True),
                actions=["read"],
                commands=["ARTICLE_GET", "ARTICLE_LIST", "BOARD_LIST"],
                boards=["*"],
                objects=["articles"],
            ),
        ]
        acl = ACLEvaluator(rules)
        ctx = self._anon_ctx()
        assert acl.check(ctx, "read", command="ARTICLE_GET", board="general", object_name="articles")
        assert not acl.check(ctx, "write", command="ARTICLE_GET")
        assert not acl.check(ctx, "read", command="PUBLISH_RECORD")

    def test_unknown_matcher(self):
        rules = [
            ACLRule(
                effect="allow",
                matcher=PrincipalMatcher(unknown=True),
                actions=["write"],
                commands=["REGISTER"],
            ),
        ]
        acl = ACLEvaluator(rules)
        ctx = self._unknown_ctx()
        assert acl.check(ctx, "write", command="REGISTER")

    def test_origin_matcher(self):
        rules = [
            ACLRule(
                effect="allow",
                matcher=PrincipalMatcher(origin="bbs.test"),
                actions=["read", "write"],
                commands=["*"],
                kinds=["*"],
                boards=["*"],
            ),
        ]
        acl = ACLEvaluator(rules)
        ctx = self._user_ctx()
        assert acl.check(ctx, "write", command="PUBLISH_RECORD", kind="bonnet.article", board="general")

    def test_deny_in_one_dimension_rejects(self):
        """A deny in the board dimension kills a write even if command is allowed."""
        rules = [
            ACLRule(
                effect="allow",
                matcher=PrincipalMatcher(wildcard=True),
                actions=["write"],
                commands=["PUBLISH_RECORD"],
                kinds=["*"],
                boards=["general"],
            ),
            ACLRule(
                effect="deny",
                matcher=PrincipalMatcher(wildcard=True),
                actions=["write"],
                boards=["secret"],
            ),
        ]
        acl = ACLEvaluator(rules)
        ctx = self._user_ctx()
        assert acl.check(ctx, "write", command="PUBLISH_RECORD", kind="bonnet.article", board="general")
        assert not acl.check(ctx, "write", command="PUBLISH_RECORD", kind="bonnet.article", board="secret")

    def test_from_toml(self):
        data = {
            "acl": [
                {
                    "effect": "allow",
                    "match": {"role": "administrator"},
                    "actions": ["read", "write"],
                    "commands": ["*"],
                    "kinds": ["*"],
                    "boards": ["*"],
                    "objects": ["*"],
                },
                {
                    "effect": "deny",
                    "match": {"anonymous": True},
                    "actions": ["write"],
                    "commands": ["*"],
                },
            ]
        }
        acl = ACLEvaluator.from_toml(data)
        ctx = self._admin_ctx()
        assert acl.check(ctx, "write", command="PUBLISH_RECORD", kind="bonnet.article", board="general")
        ctx2 = self._anon_ctx()
        assert not acl.check(ctx2, "write", command="PUBLISH_RECORD")

    def test_glob_pattern_matching(self):
        rules = [
            ACLRule(
                effect="allow",
                matcher=PrincipalMatcher(wildcard=True),
                actions=["read"],
                commands=["ARTICLE_*"],
                boards=["*"],
            ),
        ]
        acl = ACLEvaluator(rules)
        ctx = self._user_ctx()
        assert acl.check(ctx, "read", command="ARTICLE_GET", board="general")
        assert acl.check(ctx, "read", command="ARTICLE_LIST", board="general")
        assert not acl.check(ctx, "read", command="PUBLISH_RECORD", board="general")


# ---------------------------------------------------------------------------
# Kind Validation Tests (§12)
# ---------------------------------------------------------------------------

class TestKindValidator:
    def setup_method(self):
        self.validator = KindValidator()

    def _intent(self, kind="bonnet.article", **kwargs):
        defaults = dict(
            event_id=_rid(1), kind=kind, origin="bbs.test",
            actor_pubkey=USER_PUB,
        )
        defaults.update(kwargs)
        return Intent(**defaults)

    def test_article_valid(self):
        intent = self._intent(
            board="general", article_id=_rid(2),
            metadata=MetadataMap([
                metadata_text(1, "Subject"),
                metadata_text(4, "text/plain"),
            ]),
        )
        self.validator.validate(intent)

    def test_article_missing_subject(self):
        intent = self._intent(
            board="general", article_id=_rid(2),
            metadata=MetadataMap([metadata_text(4, "text/plain")]),
        )
        with pytest.raises(ValidationError, match="subject"):
            self.validator.validate(intent)

    def test_article_missing_content_type(self):
        intent = self._intent(
            board="general", article_id=_rid(2),
            metadata=MetadataMap([metadata_text(1, "Subject")]),
        )
        with pytest.raises(ValidationError, match="content type"):
            self.validator.validate(intent)

    def test_article_zero_article_id(self):
        intent = self._intent(
            board="general", article_id=ZERO_ID,
            metadata=MetadataMap([
                metadata_text(1, "Subject"),
                metadata_text(4, "text/plain"),
            ]),
        )
        with pytest.raises(ValidationError, match="article_id"):
            self.validator.validate(intent)

    def test_article_empty_board(self):
        intent = self._intent(
            board="", article_id=_rid(2),
            metadata=MetadataMap([
                metadata_text(1, "Subject"),
                metadata_text(4, "text/plain"),
            ]),
        )
        with pytest.raises(ValidationError, match="board"):
            self.validator.validate(intent)

    def test_cancel_valid(self):
        intent = self._intent(
            kind="bonnet.article.cancel",
            target_origin="bbs.test", target_board="general",
            target_article_id=_rid(5),
        )
        self.validator.validate(intent)

    def test_cancel_missing_target(self):
        intent = self._intent(kind="bonnet.article.cancel")
        with pytest.raises(ValidationError, match="target_origin"):
            self.validator.validate(intent)

    def test_cancel_with_event_target(self):
        intent = self._intent(
            kind="bonnet.article.cancel",
            target_origin="bbs.test", target_board="general",
            target_article_id=_rid(5), target_event_id=_rid(6),
        )
        with pytest.raises(ValidationError, match="target_event_id"):
            self.validator.validate(intent)

    def test_pin_valid(self):
        intent = self._intent(
            kind="bonnet.article.pin",
            target_origin="bbs.test", target_board="general",
            target_article_id=_rid(5),
            metadata=MetadataMap([metadata_i64(1, 42)]),
        )
        self.validator.validate(intent)

    def test_pin_missing_priority(self):
        intent = self._intent(
            kind="bonnet.article.pin",
            target_origin="bbs.test", target_board="general",
            target_article_id=_rid(5),
        )
        with pytest.raises(ValidationError, match="priority"):
            self.validator.validate(intent)

    def test_board_create_valid(self):
        intent = self._intent(
            kind="bonnet.board.create", board="newboard",
            metadata=MetadataMap([
                metadata_bytes(1, USER_PUB),
                metadata_text(2, "New Board"),
            ]),
        )
        self.validator.validate(intent)

    def test_board_create_missing_owner(self):
        intent = self._intent(
            kind="bonnet.board.create", board="newboard",
            metadata=MetadataMap([metadata_text(2, "New Board")]),
        )
        with pytest.raises(ValidationError, match="owner"):
            self.validator.validate(intent)

    def test_user_register_valid(self):
        intent = self._intent(
            kind="bonnet.user.register",
            metadata=MetadataMap([
                metadata_text(1, "alice"),
                metadata_bytes(2, USER_PUB),
                metadata_u64(3, 0x01),
            ]),
        )
        self.validator.validate(intent)

    def test_user_register_reserved_flags(self):
        intent = self._intent(
            kind="bonnet.user.register",
            metadata=MetadataMap([
                metadata_text(1, "alice"),
                metadata_bytes(2, USER_PUB),
                metadata_u64(3, 0x04),
            ]),
        )
        with pytest.raises(ValidationError, match="reserved"):
            self.validator.validate(intent)

    def test_user_revoke_valid(self):
        intent = self._intent(
            kind="bonnet.user.revoke",
            target_origin="bbs.test", target_event_id=_rid(10),
            metadata=MetadataMap([metadata_bytes(1, USER_PUB)]),
        )
        self.validator.validate(intent)

    def test_punishment_issue_valid(self):
        intent = self._intent(
            kind="bonnet.punishment.issue", board="moderation.actions",
            metadata=MetadataMap([
                metadata_bytes(1, _rid(30)),
                metadata_i64(2, -1),
            ]),
        )
        self.validator.validate(intent)

    def test_punishment_issue_missing_expiration(self):
        intent = self._intent(
            kind="bonnet.punishment.issue", board="moderation.actions",
            metadata=MetadataMap([metadata_bytes(1, _rid(30))]),
        )
        with pytest.raises(ValidationError, match="expiration"):
            self.validator.validate(intent)

    def test_report_with_article_target(self):
        intent = self._intent(
            kind="bonnet.report", board="moderation.reports",
            target_origin="bbs.test", target_board="general",
            target_article_id=_rid(5),
            metadata=MetadataMap([metadata_bytes(1, _rid(40))]),
        )
        self.validator.validate(intent)

    def test_report_with_event_target(self):
        intent = self._intent(
            kind="bonnet.report", board="moderation.reports",
            target_origin="bbs.test", target_event_id=_rid(6),
            metadata=MetadataMap([metadata_bytes(1, _rid(40))]),
        )
        self.validator.validate(intent)

    def test_report_mixed_target_rejected(self):
        intent = self._intent(
            kind="bonnet.report", board="moderation.reports",
            target_origin="bbs.test", target_board="general",
            target_article_id=_rid(5), target_event_id=_rid(6),
            metadata=MetadataMap([metadata_bytes(1, _rid(40))]),
        )
        with pytest.raises(ValidationError, match="target"):
            self.validator.validate(intent)

    def test_report_no_target_ok(self):
        intent = self._intent(
            kind="bonnet.report", board="moderation.reports",
            metadata=MetadataMap([metadata_bytes(1, _rid(40))]),
        )
        self.validator.validate(intent)

    def test_key_rotation_valid(self):
        intent = self._intent(
            kind="bonnet.origin.key.rotate",
            metadata=MetadataMap([
                metadata_bytes(1, _rid(50)),
                metadata_bytes(2, _rid(51)),
            ]),
        )
        self.validator.validate(intent)

    def test_unknown_kind_passes(self):
        intent = self._intent(kind="bonnet.unknown.future", board="general")
        self.validator.validate(intent)


# ---------------------------------------------------------------------------
# Search Tests (§15)
# ---------------------------------------------------------------------------

class TestSearchService:
    @pytest.fixture
    def search_env(self, tmp_path):
        boards_dir = str(tmp_path / "boards")
        body_store = BodyStore(
            boards_dir=boards_dir,
            events_dir=str(tmp_path / "events"),
        )
        bp = BoardProjection(str(tmp_path / "test_board.db"))
        search = SearchService(
            boards_dir=boards_dir,
            body_store=body_store,
            max_count=100, timeout_seconds=5, result_limit=50,
        )
        yield bp, body_store, search
        bp.close()

    def _make_article_rec(self, seq, article_num, subject="Test", tags="", body=b"hello world"):
        from core.record import Record, encode_unsigned_record, sign_record
        from core.crypto import Identity

        origin = Identity.from_private_key(bytes(range(1, 33)))
        aid = _rid(seq + 10)
        eid = _rid(seq)

        from core.record import metadata_text_list
        m = MetadataMap([
            metadata_text(1, subject),
            metadata_text(4, "text/plain"),
        ])
        if tags:
            m.fields.append(metadata_text_list(2, tags.split(",")))

        rec = Record(
            origin="bbs.test", origin_seq=seq, event_id=eid,
            kind="bonnet.article", actor_pubkey=USER_PUB,
            board="general", article_id=aid, article_num=article_num,
            metadata=m, body_hash=compute_body_hash(body), body_size=len(body),
        )
        return rec

    def test_metadata_search_by_subject(self, search_env):
        bp, body_store, search = search_env
        rec1 = self._make_article_rec(1, 1, subject="Hello World", tags="news")
        rec2 = self._make_article_rec(2, 2, subject="Goodbye", tags="tech")
        bp.apply_article(rec1)
        bp.apply_article(rec2)

        results = search.search_metadata(bp, "bbs.test", "general", text_query="hello")
        assert len(results.results) == 1
        assert results.results[0].subject == "Hello World"

    def test_metadata_search_by_tags(self, search_env):
        bp, body_store, search = search_env
        rec1 = self._make_article_rec(1, 1, subject="Article 1", tags="news,tech")
        rec2 = self._make_article_rec(2, 2, subject="Article 2", tags="sports")
        bp.apply_article(rec1)
        bp.apply_article(rec2)

        results = search.search_metadata(bp, "bbs.test", "general", text_query="tech")
        assert len(results.results) == 1
        assert results.results[0].subject == "Article 1"

    def test_metadata_search_excludes_purged(self, search_env):
        bp, body_store, search = search_env
        rec1 = self._make_article_rec(1, 1, subject="Keep me")
        rec2 = self._make_article_rec(2, 2, subject="Purge me")
        bp.apply_article(rec1)
        bp.apply_article(rec2)

        from core.record import Record
        purge_rec = Record(
            origin="bbs.test", origin_seq=3, event_id=_rid(3),
            kind="bonnet.article.purge", actor_pubkey=USER_PUB,
            board="general", target_origin="bbs.test", target_board="general",
            target_article_id=rec2.article_id,
        )
        bp.apply_purge(purge_rec)

        results = search.search_metadata(bp, "bbs.test", "general")
        assert len(results.results) == 1
        assert results.results[0].subject == "Keep me"

    def test_metadata_search_filter_by_actor(self, search_env):
        bp, body_store, search = search_env
        from core.record import Record, encode_unsigned_record, sign_record
        from core.crypto import Identity

        origin = Identity.from_private_key(bytes(range(1, 33)))
        other_pub = bytes(range(50, 82))

        rec1 = self._make_article_rec(1, 1, subject="By user")
        rec2 = Record(
            origin="bbs.test", origin_seq=2, event_id=_rid(2),
            kind="bonnet.article", actor_pubkey=other_pub,
            board="general", article_id=_rid(12), article_num=2,
            metadata=MetadataMap([
                metadata_text(1, "By other"),
                metadata_text(4, "text/plain"),
            ]),
            body_hash=compute_body_hash(b""), body_size=0,
        )
        bp.apply_article(rec1)
        bp.apply_article(rec2)

        results = search.search_metadata(
            bp, "bbs.test", "general", actor_pubkey=USER_PUB
        )
        assert len(results.results) == 1
        assert results.results[0].subject == "By user"

    def test_body_search_finds_text(self, search_env):
        bp, body_store, search = search_env
        body1 = b"The quick brown fox jumps over the lazy dog"
        body2 = b"A completely different article about cats"

        rec1 = self._make_article_rec(1, 1, subject="Fox", body=body1)
        rec2 = self._make_article_rec(2, 2, subject="Cats", body=body2)
        bp.apply_article(rec1)
        bp.apply_article(rec2)

        body_store.write_article_body("bbs.test", "general", 1, body1, compute_body_hash(body1), len(body1))
        body_store.write_article_body("bbs.test", "general", 2, body2, compute_body_hash(body2), len(body2))

        results = search.search_bodies(bp, "bbs.test", "general", "fox")
        assert len(results.results) == 1
        assert results.results[0].subject == "Fox"
        assert "fox" in results.results[0].excerpt.lower()

    def test_body_search_excludes_purged(self, search_env):
        bp, body_store, search = search_env
        body1 = b"Keep this article about dogs"
        body2 = b"Purge this article about cats"

        rec1 = self._make_article_rec(1, 1, subject="Dogs", body=body1)
        rec2 = self._make_article_rec(2, 2, subject="Cats", body=body2)
        bp.apply_article(rec1)
        bp.apply_article(rec2)

        body_store.write_article_body("bbs.test", "general", 1, body1, compute_body_hash(body1), len(body1))
        body_store.write_article_body("bbs.test", "general", 2, body2, compute_body_hash(body2), len(body2))

        from core.record import Record
        purge_rec = Record(
            origin="bbs.test", origin_seq=3, event_id=_rid(3),
            kind="bonnet.article.purge", actor_pubkey=USER_PUB,
            board="general", target_origin="bbs.test", target_board="general",
            target_article_id=rec2.article_id,
        )
        bp.apply_purge(purge_rec)

        results = search.search_bodies(bp, "bbs.test", "general", "article")
        subjects = [r.subject for r in results.results]
        assert "Dogs" in subjects
        assert "Cats" not in subjects

    def test_body_search_excludes_cancelled_by_default(self, search_env):
        bp, body_store, search = search_env
        body1 = b"Active article about programming"
        body2 = b"Cancelled article about programming"

        rec1 = self._make_article_rec(1, 1, subject="Active", body=body1)
        rec2 = self._make_article_rec(2, 2, subject="Cancelled", body=body2)
        bp.apply_article(rec1)
        bp.apply_article(rec2)

        body_store.write_article_body("bbs.test", "general", 1, body1, compute_body_hash(body1), len(body1))
        body_store.write_article_body("bbs.test", "general", 2, body2, compute_body_hash(body2), len(body2))

        from core.record import Record
        cancel_rec = Record(
            origin="bbs.test", origin_seq=3, event_id=_rid(3),
            kind="bonnet.article.cancel", actor_pubkey=USER_PUB,
            board="general", target_origin="bbs.test", target_board="general",
            target_article_id=rec2.article_id,
        )
        bp.apply_cancel(cancel_rec)

        results = search.search_bodies(bp, "bbs.test", "general", "programming")
        subjects = [r.subject for r in results.results]
        assert "Active" in subjects
        assert "Cancelled" not in subjects

        results_all = search.search_bodies(
            bp, "bbs.test", "general", "programming", include_cancelled=True
        )
        subjects_all = [r.subject for r in results_all.results]
        assert "Active" in subjects_all
        assert "Cancelled" in subjects_all

    def test_body_search_empty_board(self, search_env):
        bp, body_store, search = search_env
        results = search.search_bodies(bp, "bbs.test", "empty", "anything")
        assert len(results.results) == 0
