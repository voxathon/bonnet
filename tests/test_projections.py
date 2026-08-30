"""Body storage, board projections, global projections, and state reduction."""

import time

import pytest

from bonnet.core.board_projection import BoardProjection
from bonnet.core.bodies import BodyError, BodyStore
from bonnet.core.crypto import Identity
from bonnet.core.dispatcher import Dispatcher
from bonnet.core.firehose import FirehoseStore
from bonnet.core.global_projections import (
    NavProjection,
    PolicyProjection,
    UserProjection,
)
from bonnet.core.record import (
    ZERO_HASH,
    Intent,
    MetadataMap,
    Record,
    compute_body_hash,
    encode_intent,
    encode_unsigned_record,
    metadata_bytes,
    metadata_i64,
    metadata_text,
    metadata_u64,
    sign_intent,
    sign_key_rotation_proof,
    sign_record,
)

# ---------------------------------------------------------------------------
# Test identities
# ---------------------------------------------------------------------------

ORIGIN_A = Identity.from_private_key(bytes(range(1, 33)))
ACTOR = Identity.from_private_key(bytes(range(10, 42)))
ORIGIN_A_PUB = ORIGIN_A.public_key
ACTOR_PUB = ACTOR.public_key


def _rid(seed: int) -> bytes:
    return bytes([(seed + i) % 256 for i in range(32)])


def _make_article_intent(origin, eid, aid, board="general", body=b"hello world"):
    return Intent(
        event_id=eid,
        kind="bonnet.article",
        origin=origin,
        actor_pubkey=ACTOR_PUB,
        board=board,
        article_id=aid,
        metadata=MetadataMap(
            [
                metadata_text(1, "Test Article"),
                metadata_text(4, "text/plain"),
            ]
        ),
        body_hash=compute_body_hash(body),
        body_size=len(body),
    )


def _make_record(origin, seq, prev_hash, eid, kind, actor=ACTOR, **kwargs):
    intent = Intent(event_id=eid, kind=kind, origin=origin, actor_pubkey=actor.public_key, **kwargs)
    actor_sig = sign_intent(actor, encode_intent(intent))
    rec = Record(
        origin=origin,
        origin_seq=seq,
        previous_event_hash=prev_hash,
        event_id=eid,
        kind=kind,
        actor_pubkey=actor.public_key,
        actor_signature=actor_sig,
        **kwargs,
    )
    unsigned = encode_unsigned_record(rec)
    rec.origin_signature = sign_record(ORIGIN_A, unsigned)
    return rec, intent


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def body_store(tmp_path):
    return BodyStore(
        boards_dir=str(tmp_path / "boards"),
        events_dir=str(tmp_path / "events"),
    )


@pytest.fixture
def board_proj(tmp_path):
    bp = BoardProjection(str(tmp_path / "board_test.db"))
    yield bp
    bp.close()


@pytest.fixture
def nav_proj(tmp_path):
    n = NavProjection(str(tmp_path / "nav.db"))
    yield n
    n.close()


@pytest.fixture
def user_proj(tmp_path):
    u = UserProjection(str(tmp_path / "users.db"))
    yield u
    u.close()


@pytest.fixture
def policy_proj(tmp_path):
    p = PolicyProjection(str(tmp_path / "policy.db"))
    yield p
    p.close()


@pytest.fixture
def firehose(tmp_path):
    f = FirehoseStore(str(tmp_path / "events.db"))
    yield f
    f.close()


@pytest.fixture
def dispatcher(tmp_path, firehose):
    nav = NavProjection(str(tmp_path / "nav.db"))
    users = UserProjection(str(tmp_path / "users.db"))
    policy = PolicyProjection(str(tmp_path / "policy.db"))
    bs = BodyStore(
        boards_dir=str(tmp_path / "boards"),
        events_dir=str(tmp_path / "events_bodies"),
    )
    d = Dispatcher(
        firehose=firehose,
        nav=nav,
        users=users,
        policy=policy,
        boards_dir=str(tmp_path / "boards"),
        body_store=bs,
        allowed_origins={"bbs.a"},
        local_origin="bbs.a",
    )
    yield d, firehose, nav, users, policy, bs
    d.close()
    nav.close()
    users.close()
    policy.close()


# ---------------------------------------------------------------------------
# Body storage tests
# ---------------------------------------------------------------------------


class TestBodyStore:
    def test_write_and_read_article_body(self, body_store):
        body = b"hello article body"
        body_hash = compute_body_hash(body)
        body_store.write_article_body("bbs.a", "general", 1, body, body_hash, len(body))
        result = body_store.get_article_body("bbs.a", "general", 1, body_hash, len(body))
        assert result == body

    def test_read_corrupt_article_body_returns_none(self, body_store):
        body = b"hello article body"
        body_hash = compute_body_hash(body)
        body_store.write_article_body("bbs.a", "general", 1, body, body_hash, len(body))
        # Corrupt the file
        path = body_store._article_body_path("bbs.a", "general", 1)
        with open(path, "wb") as f:
            f.write(b"corrupted data")
        result = body_store.get_article_body("bbs.a", "general", 1, body_hash, len(body))
        assert result is None

    def test_missing_article_body_returns_none(self, body_store):
        result = body_store.get_article_body("bbs.a", "general", 99, b"\x00" * 32, 0)
        assert result is None

    def test_delete_article_body(self, body_store):
        body = b"delete me"
        body_hash = compute_body_hash(body)
        body_store.write_article_body("bbs.a", "general", 1, body, body_hash, len(body))
        assert body_store.article_body_exists("bbs.a", "general", 1)
        assert body_store.delete_article_body("bbs.a", "general", 1)
        assert not body_store.article_body_exists("bbs.a", "general", 1)

    def test_stage_and_finalize_article_body(self, body_store):
        body = b"staged content"
        body_hash = compute_body_hash(body)
        eid = _rid(1)
        body_store.stage_article_body("bbs.a", "general", eid, body, body_hash, len(body))
        assert body_store.finalize_article_body("bbs.a", "general", eid, 1)
        result = body_store.get_article_body("bbs.a", "general", 1, body_hash, len(body))
        assert result == body

    def test_finalize_without_staging_returns_false(self, body_store):
        eid = _rid(99)
        assert not body_store.finalize_article_body("bbs.a", "general", eid, 1)

    def test_stage_wrong_hash_rejected(self, body_store):
        with pytest.raises(BodyError):
            body_store.stage_article_body(
                "bbs.a",
                "general",
                _rid(1),
                b"body",
                b"\xff" * 32,
                4,
            )

    def test_write_and_read_event_body(self, body_store):
        body = b"event body content"
        body_hash = compute_body_hash(body)
        eid = _rid(5)
        body_store.write_event_body("bbs.a", eid, body, body_hash, len(body))
        result = body_store.get_event_body("bbs.a", eid, body_hash, len(body))
        assert result == body

    def test_delete_event_body(self, body_store):
        body = b"delete me"
        body_hash = compute_body_hash(body)
        eid = _rid(5)
        body_store.write_event_body("bbs.a", eid, body, body_hash, len(body))
        assert body_store.event_body_exists("bbs.a", eid)
        assert body_store.delete_event_body("bbs.a", eid)
        assert not body_store.event_body_exists("bbs.a", eid)

    def test_corrupt_event_body_returns_none(self, body_store):
        body = b"event body"
        body_hash = compute_body_hash(body)
        eid = _rid(5)
        body_store.write_event_body("bbs.a", eid, body, body_hash, len(body))
        path = body_store._event_body_path("bbs.a", eid)
        with open(path, "wb") as f:
            f.write(b"corrupt")
        result = body_store.get_event_body("bbs.a", eid, body_hash, len(body))
        assert result is None


# ---------------------------------------------------------------------------
# Board projection tests
# ---------------------------------------------------------------------------


class TestBoardProjection:
    def _make_article_record(self, origin="bbs.a", seq=1, eid=None, aid=None, board="general"):
        eid = eid or _rid(seq)
        aid = aid or _rid(seq + 10)
        body = b"article body"
        intent = _make_article_intent(origin, eid, aid, board, body)
        actor_sig = sign_intent(ACTOR, encode_intent(intent))
        rec = Record(
            origin=origin,
            origin_seq=seq,
            previous_event_hash=ZERO_HASH,
            event_id=eid,
            kind="bonnet.article",
            actor_pubkey=ACTOR_PUB,
            board=board,
            article_id=aid,
            article_num=seq,
            metadata=intent.metadata,
            body_hash=intent.body_hash,
            body_size=intent.body_size,
            actor_signature=actor_sig,
        )
        unsigned = encode_unsigned_record(rec)
        rec.origin_signature = sign_record(ORIGIN_A, unsigned)
        return rec

    def test_apply_article(self, board_proj):
        rec = self._make_article_record()
        board_proj.apply_article(rec)
        art = board_proj.get_article_by_num("bbs.a", "general", 1)
        assert art is not None
        assert art.article_num == 1
        assert art.visibility == "active"
        assert art.body_state == "unavailable"
        assert art.subject == "Test Article"
        assert art.content_type == "text/plain"

    def test_apply_article_idempotent(self, board_proj):
        rec = self._make_article_record()
        board_proj.apply_article(rec)
        board_proj.apply_article(rec)
        assert board_proj.article_count("bbs.a", "general") == 1

    def test_cancel_and_restore(self, board_proj):
        rec = self._make_article_record()
        board_proj.apply_article(rec)

        cancel_rec = Record(
            origin="bbs.a",
            origin_seq=2,
            event_id=_rid(2),
            kind="bonnet.article.cancel",
            actor_pubkey=ACTOR_PUB,
            board="general",
            target_origin="bbs.a",
            target_board="general",
            target_article_id=rec.article_id,
        )
        board_proj.apply_cancel(cancel_rec)
        art = board_proj.get_article_by_id("bbs.a", "general", rec.article_id)
        assert art.visibility == "cancelled"

        restore_rec = Record(
            origin="bbs.a",
            origin_seq=3,
            event_id=_rid(3),
            kind="bonnet.article.restore",
            actor_pubkey=ACTOR_PUB,
            board="general",
            target_origin="bbs.a",
            target_board="general",
            target_article_id=rec.article_id,
        )
        board_proj.apply_restore(restore_rec)
        art = board_proj.get_article_by_id("bbs.a", "general", rec.article_id)
        assert art.visibility == "active"

    def test_purge(self, board_proj):
        rec = self._make_article_record()
        board_proj.apply_article(rec)

        purge_rec = Record(
            origin="bbs.a",
            origin_seq=2,
            event_id=_rid(2),
            kind="bonnet.article.purge",
            actor_pubkey=ACTOR_PUB,
            board="general",
            target_origin="bbs.a",
            target_board="general",
            target_article_id=rec.article_id,
        )
        board_proj.apply_purge(purge_rec)
        art = board_proj.get_article_by_id("bbs.a", "general", rec.article_id)
        assert art.body_state == "purged"

    def test_foreign_origin_control_no_effect(self, board_proj):
        rec = self._make_article_record()
        board_proj.apply_article(rec)

        cancel_rec = Record(
            origin="bbs.evil",
            origin_seq=99,
            event_id=_rid(99),
            kind="bonnet.article.cancel",
            actor_pubkey=ACTOR_PUB,
            board="general",
            target_origin="bbs.a",
            target_board="general",
            target_article_id=rec.article_id,
        )
        board_proj.apply_cancel(cancel_rec)
        art = board_proj.get_article_by_id("bbs.a", "general", rec.article_id)
        assert art.visibility == "active"

    def test_control_before_target_is_pending(self, board_proj):
        aid = _rid(50)
        cancel_rec = Record(
            origin="bbs.a",
            origin_seq=1,
            event_id=_rid(1),
            kind="bonnet.article.cancel",
            actor_pubkey=ACTOR_PUB,
            board="general",
            target_origin="bbs.a",
            target_board="general",
            target_article_id=aid,
        )
        board_proj.apply_cancel(cancel_rec)
        assert board_proj.pending_count() == 1

        article_rec = self._make_article_record(seq=2, aid=aid)
        board_proj.apply_article(article_rec)
        art = board_proj.get_article_by_id("bbs.a", "general", aid)
        assert art.visibility == "cancelled"
        assert board_proj.pending_count() == 0

    def test_list_articles_default_active_only(self, board_proj):
        for i in range(3):
            rec = self._make_article_record(seq=i + 1, eid=_rid(i + 1), aid=_rid(i + 11))
            board_proj.apply_article(rec)

        cancel_rec = Record(
            origin="bbs.a",
            origin_seq=4,
            event_id=_rid(4),
            kind="bonnet.article.cancel",
            actor_pubkey=ACTOR_PUB,
            board="general",
            target_origin="bbs.a",
            target_board="general",
            target_article_id=_rid(11),
        )
        board_proj.apply_cancel(cancel_rec)

        active = board_proj.list_articles("bbs.a", "general")
        assert len(active) == 2

        all_articles = board_proj.list_articles("bbs.a", "general", include_cancelled=True)
        assert len(all_articles) == 3

    def test_pin_and_unpin(self, board_proj):
        rec = self._make_article_record()
        board_proj.apply_article(rec)

        pin_rec = Record(
            origin="bbs.a",
            origin_seq=2,
            event_id=_rid(2),
            kind="bonnet.article.pin",
            actor_pubkey=ACTOR_PUB,
            board="general",
            target_origin="bbs.a",
            target_board="general",
            target_article_id=rec.article_id,
            metadata=MetadataMap([metadata_i64(1, 42)]),
        )
        board_proj.apply_pin(pin_rec)
        art = board_proj.get_article_by_id("bbs.a", "general", rec.article_id)
        assert "pinned" in art.pin_state
        assert "42" in art.pin_state

        unpin_rec = Record(
            origin="bbs.a",
            origin_seq=3,
            event_id=_rid(3),
            kind="bonnet.article.unpin",
            actor_pubkey=ACTOR_PUB,
            board="general",
            target_origin="bbs.a",
            target_board="general",
            target_article_id=rec.article_id,
        )
        board_proj.apply_unpin(unpin_rec)
        art = board_proj.get_article_by_id("bbs.a", "general", rec.article_id)
        assert art.pin_state == "unpinned"

    def test_thread_close_and_reopen(self, board_proj):
        rec = self._make_article_record()
        board_proj.apply_article(rec)

        close_rec = Record(
            origin="bbs.a",
            origin_seq=2,
            event_id=_rid(2),
            kind="bonnet.thread.close",
            actor_pubkey=ACTOR_PUB,
            board="general",
            target_origin="bbs.a",
            target_board="general",
            target_article_id=rec.article_id,
        )
        board_proj.apply_thread_close(close_rec)
        art = board_proj.get_article_by_id("bbs.a", "general", rec.article_id)
        assert art.thread_state == "closed"

        reopen_rec = Record(
            origin="bbs.a",
            origin_seq=3,
            event_id=_rid(3),
            kind="bonnet.thread.reopen",
            actor_pubkey=ACTOR_PUB,
            board="general",
            target_origin="bbs.a",
            target_board="general",
            target_article_id=rec.article_id,
        )
        board_proj.apply_thread_reopen(reopen_rec)
        art = board_proj.get_article_by_id("bbs.a", "general", rec.article_id)
        assert art.thread_state == "open"

    def test_checkpoint(self, board_proj):
        assert board_proj.get_checkpoint("bbs.a") == 0
        board_proj.set_checkpoint("bbs.a", 42)
        assert board_proj.get_checkpoint("bbs.a") == 42

    def test_clear_for_rebuild(self, board_proj):
        rec = self._make_article_record()
        board_proj.apply_article(rec)
        assert board_proj.article_count("bbs.a", "general") == 1
        board_proj.clear()
        assert board_proj.article_count("bbs.a", "general") == 0
        assert board_proj.get_checkpoint("bbs.a") == 0


class TestQueryArticlesVisibilityFilter:
    """internal/BUGS.md #2 as originally filed claimed an unsupported
    operator on the visibility field (0x06) disabled the default
    visibility='active' fallback and leaked cancelled/superseded articles.
    Traced and reproduced against real data: that claim does not hold — the
    fallback only depends on has_visibility_filter, which stays False for an
    unsupported op, so the default still applies. What's actually broken is
    narrower: the 'purged' sentinel value (op is meant to select EQ vs NE)
    ignores op entirely, so a caller asking to EXCLUDE purged articles
    (op=NE) gets treated as asking to include ONLY purged ones."""

    def _make_article_record(self, seq, aid):
        eid = _rid(seq)
        body = b"article body"
        intent = _make_article_intent("bbs.a", eid, aid, "general", body)
        actor_sig = sign_intent(ACTOR, encode_intent(intent))
        rec = Record(
            origin="bbs.a",
            origin_seq=seq,
            previous_event_hash=ZERO_HASH,
            event_id=eid,
            kind="bonnet.article",
            actor_pubkey=ACTOR_PUB,
            board="general",
            article_id=aid,
            article_num=seq,
            metadata=intent.metadata,
            body_hash=intent.body_hash,
            body_size=intent.body_size,
            actor_signature=actor_sig,
        )
        rec.origin_signature = sign_record(ORIGIN_A, encode_unsigned_record(rec))
        return rec

    def _seed(self, board_proj):
        active = self._make_article_record(seq=1, aid=_rid(11))
        board_proj.apply_article(active)
        other = self._make_article_record(seq=2, aid=_rid(12))
        board_proj.apply_article(other)
        board_proj.apply_cancel(
            Record(
                origin="bbs.a",
                origin_seq=3,
                event_id=_rid(3),
                kind="bonnet.article.cancel",
                actor_pubkey=ACTOR_PUB,
                board="general",
                target_origin="bbs.a",
                target_board="general",
                target_article_id=other.article_id,
            )
        )
        return active, other

    def test_unsupported_operator_still_defaults_to_active_only(self, board_proj):
        """The originally-filed scenario: an unsupported operator (GT) on
        the visibility field must not disable the safe default."""
        self._seed(board_proj)
        results = board_proj.query_articles("bbs.a", "general", [(0x06, 0x03, "active")])
        assert [r.article_num for r in results] == [1]

    def test_no_filter_defaults_to_active_only(self, board_proj):
        self._seed(board_proj)
        results = board_proj.query_articles("bbs.a", "general", [])
        assert [r.article_num for r in results] == [1]

    def test_explicit_ne_active_returns_cancelled(self, board_proj):
        self._seed(board_proj)
        results = board_proj.query_articles("bbs.a", "general", [(0x06, 0x02, "active")])
        assert [(r.article_num, r.visibility) for r in results] == [(2, "cancelled")]

    def test_eq_purged_returns_only_purged(self, board_proj):
        self._seed(board_proj)
        results = board_proj.query_articles("bbs.a", "general", [(0x06, 0x01, "purged")])
        assert results == []

    def test_ne_purged_excludes_purged_not_includes_it(self, board_proj):
        """The real bug: NE 'purged' must mean 'exclude purged', not get
        treated as EQ 'purged'. Neither seeded article is purged, so the
        default active-only visibility filter still applies on top —
        NE 'purged' doesn't by itself widen visibility, only body_state."""
        self._seed(board_proj)
        results = board_proj.query_articles("bbs.a", "general", [(0x06, 0x02, "purged")])
        assert [r.article_num for r in results] == [1]


# ---------------------------------------------------------------------------
# Nav projection tests
# ---------------------------------------------------------------------------


class TestNavProjection:
    def test_board_create(self, nav_proj):
        rec = Record(
            origin="bbs.a",
            origin_seq=1,
            event_id=_rid(1),
            kind="bonnet.board.create",
            actor_pubkey=ACTOR_PUB,
            board="general",
            metadata=MetadataMap(
                [
                    metadata_bytes(1, ACTOR_PUB),
                    metadata_text(2, "General Discussion"),
                ]
            ),
        )
        nav_proj.apply_board_create(rec)
        board = nav_proj.get_board("bbs.a", "general")
        assert board is not None
        assert board["owner_pubkey"] == ACTOR_PUB
        assert board["display_name"] == "General Discussion"
        assert board["closed"] is False

    def test_board_close_and_reopen(self, nav_proj):
        create_rec = Record(
            origin="bbs.a",
            origin_seq=1,
            event_id=_rid(1),
            kind="bonnet.board.create",
            actor_pubkey=ACTOR_PUB,
            board="general",
            metadata=MetadataMap([metadata_bytes(1, ACTOR_PUB)]),
        )
        nav_proj.apply_board_create(create_rec)

        close_rec = Record(
            origin="bbs.a",
            origin_seq=2,
            event_id=_rid(2),
            kind="bonnet.board.close",
            actor_pubkey=ACTOR_PUB,
            board="general",
        )
        nav_proj.apply_board_close(close_rec)
        assert nav_proj.get_board("bbs.a", "general")["closed"] is True

        reopen_rec = Record(
            origin="bbs.a",
            origin_seq=3,
            event_id=_rid(3),
            kind="bonnet.board.reopen",
            actor_pubkey=ACTOR_PUB,
            board="general",
        )
        nav_proj.apply_board_reopen(reopen_rec)
        assert nav_proj.get_board("bbs.a", "general")["closed"] is False

    def test_list_boards(self, nav_proj):
        for i in range(3):
            rec = Record(
                origin="bbs.a",
                origin_seq=i + 1,
                event_id=_rid(i + 1),
                kind="bonnet.board.create",
                actor_pubkey=ACTOR_PUB,
                board=f"board{i}",
                metadata=MetadataMap([metadata_bytes(1, ACTOR_PUB)]),
            )
            nav_proj.apply_board_create(rec)
        boards = nav_proj.list_boards("bbs.a")
        assert len(boards) == 3


# ---------------------------------------------------------------------------
# User projection tests
# ---------------------------------------------------------------------------


class TestUserProjection:
    def test_register_and_get(self, user_proj):
        user_pubkey = _rid(20)
        rec = Record(
            origin="bbs.a",
            origin_seq=1,
            event_id=_rid(1),
            kind="bonnet.user.register",
            actor_pubkey=ACTOR_PUB,
            metadata=MetadataMap(
                [
                    metadata_text(1, "alice"),
                    metadata_bytes(2, user_pubkey),
                    metadata_u64(3, 0),
                ]
            ),
        )
        user_proj.apply_user_register(rec)
        user = user_proj.get_user_by_pubkey("bbs.a", user_pubkey)
        assert user is not None
        assert user["username"] == "alice"
        assert user["revoked"] is False

    def test_revoke(self, user_proj):
        user_pubkey = _rid(20)
        reg_rec = Record(
            origin="bbs.a",
            origin_seq=1,
            event_id=_rid(1),
            kind="bonnet.user.register",
            actor_pubkey=ACTOR_PUB,
            metadata=MetadataMap(
                [
                    metadata_text(1, "bob"),
                    metadata_bytes(2, user_pubkey),
                    metadata_u64(3, 0),
                ]
            ),
        )
        user_proj.apply_user_register(reg_rec)

        revoke_rec = Record(
            origin="bbs.a",
            origin_seq=2,
            event_id=_rid(2),
            kind="bonnet.user.revoke",
            actor_pubkey=ACTOR_PUB,
            target_origin="bbs.a",
            target_event_id=_rid(1),
            metadata=MetadataMap([metadata_bytes(1, user_pubkey)]),
        )
        user_proj.apply_user_revoke(revoke_rec)

        user = user_proj.get_user_by_pubkey("bbs.a", user_pubkey)
        assert user["revoked"] is True

    def test_revoke_rejects_cross_origin(self, user_proj):
        """A remote origin cannot revoke a user it doesn't own, even via
        replication — same guard class as the article control kinds."""
        user_pubkey = _rid(21)
        reg_rec = Record(
            origin="bbs.a",
            origin_seq=1,
            event_id=_rid(1),
            kind="bonnet.user.register",
            actor_pubkey=ACTOR_PUB,
            metadata=MetadataMap(
                [
                    metadata_text(1, "carol"),
                    metadata_bytes(2, user_pubkey),
                    metadata_u64(3, 0),
                ]
            ),
        )
        user_proj.apply_user_register(reg_rec)

        cross_origin_revoke = Record(
            origin="bbs.attacker",
            origin_seq=1,
            event_id=_rid(200),
            kind="bonnet.user.revoke",
            actor_pubkey=ACTOR_PUB,
            target_origin="bbs.a",
            target_event_id=_rid(1),
            metadata=MetadataMap([metadata_bytes(1, user_pubkey)]),
        )
        user_proj.apply_user_revoke(cross_origin_revoke)

        user = user_proj.get_user_by_pubkey("bbs.a", user_pubkey)
        assert user["revoked"] is False

        same_origin_revoke = Record(
            origin="bbs.a",
            origin_seq=2,
            event_id=_rid(2),
            kind="bonnet.user.revoke",
            actor_pubkey=ACTOR_PUB,
            target_origin="bbs.a",
            target_event_id=_rid(1),
            metadata=MetadataMap([metadata_bytes(1, user_pubkey)]),
        )
        user_proj.apply_user_revoke(same_origin_revoke)
        assert user_proj.get_user_by_pubkey("bbs.a", user_pubkey)["revoked"] is True

    # ------------------------------------------------------------------
    # Actor key rotation
    # ------------------------------------------------------------------

    @staticmethod
    def _register(user_proj, pubkey, username="dave", flags=0, origin="bbs.a", seq=1):
        user_proj.apply_user_register(
            Record(
                origin=origin,
                origin_seq=seq,
                event_id=_rid(seq),
                kind="bonnet.user.register",
                actor_pubkey=ACTOR_PUB,
                metadata=MetadataMap(
                    [
                        metadata_text(1, username),
                        metadata_bytes(2, pubkey),
                        metadata_u64(3, flags),
                    ]
                ),
            )
        )

    @staticmethod
    def _rotate_rec(old_identity, new_identity, origin="bbs.a", seq=2, proof=None):
        if proof is None:
            proof = sign_key_rotation_proof(
                new_identity, origin, old_identity.public_key, new_identity.public_key
            )
        return Record(
            origin=origin,
            origin_seq=seq,
            event_id=_rid(seq),
            kind="bonnet.user.key.rotate",
            actor_pubkey=old_identity.public_key,
            metadata=MetadataMap(
                [
                    metadata_bytes(1, new_identity.public_key),
                    metadata_bytes(2, proof),
                ]
            ),
        )

    def test_rotate_carries_identity_forward(self, user_proj):
        old, new = Identity.generate(), Identity.generate()
        self._register(user_proj, old.public_key, username="dave", flags=2)

        user_proj.apply_user_key_rotate(self._rotate_rec(old, new))

        carried = user_proj.get_user_by_pubkey("bbs.a", new.public_key)
        assert carried is not None
        assert carried["username"] == "dave"
        assert carried["flags"] == 2
        assert carried["superseded_by"] is None

    def test_rotate_retires_the_old_key(self, user_proj):
        old, new = Identity.generate(), Identity.generate()
        self._register(user_proj, old.public_key)

        user_proj.apply_user_key_rotate(self._rotate_rec(old, new))

        retired = user_proj.get_user_by_pubkey("bbs.a", old.public_key)
        # The row survives, so records signed by the old key still resolve a
        # username — but the successor is what stops it authenticating.
        assert retired is not None
        assert retired["username"] == "dave"
        assert retired["superseded_by"] == new.public_key
        # Retirement is not revocation; the two must stay distinguishable.
        assert retired["revoked"] is False
        assert user_proj.get_key_successor("bbs.a", old.public_key) == new.public_key

    def test_rotate_rejects_a_proof_signed_by_the_wrong_key(self, user_proj):
        old, new, impostor = Identity.generate(), Identity.generate(), Identity.generate()
        self._register(user_proj, old.public_key)

        # Correctly shaped proof over the right pair, signed by neither party.
        bad_proof = sign_key_rotation_proof(impostor, "bbs.a", old.public_key, new.public_key)
        user_proj.apply_user_key_rotate(self._rotate_rec(old, new, proof=bad_proof))

        assert user_proj.get_user_by_pubkey("bbs.a", new.public_key) is None
        assert user_proj.get_key_successor("bbs.a", old.public_key) is None

    def test_rotate_rejects_a_proof_bound_to_another_origin(self, user_proj):
        """The proof commits to the origin, so it cannot be lifted between them."""
        old, new = Identity.generate(), Identity.generate()
        self._register(user_proj, old.public_key)

        elsewhere = sign_key_rotation_proof(new, "bbs.elsewhere", old.public_key, new.public_key)
        user_proj.apply_user_key_rotate(self._rotate_rec(old, new, proof=elsewhere))

        assert user_proj.get_key_successor("bbs.a", old.public_key) is None

    def test_rotate_ignores_a_key_this_origin_never_registered(self, user_proj):
        """Scoped by lookup: an origin can only rotate keys registered with it."""
        old, new = Identity.generate(), Identity.generate()
        self._register(user_proj, old.public_key, origin="bbs.a")

        # Same keys, but the record was published by a different origin.
        user_proj.apply_user_key_rotate(self._rotate_rec(old, new, origin="bbs.attacker"))

        assert user_proj.get_key_successor("bbs.a", old.public_key) is None
        assert user_proj.get_user_by_pubkey("bbs.a", old.public_key)["superseded_by"] is None

    def test_rotate_is_idempotent(self, user_proj):
        old, new = Identity.generate(), Identity.generate()
        self._register(user_proj, old.public_key)
        rec = self._rotate_rec(old, new)

        user_proj.apply_user_key_rotate(rec)
        user_proj.apply_user_key_rotate(rec)

        assert user_proj.get_key_successor("bbs.a", old.public_key) == new.public_key

    def test_rotations_survive_reopening_the_store(self, tmp_path):
        """Write, close, reopen — a fresh-DB test cannot see a destructive
        _init_schema, which is exactly what a migration here would introduce."""
        old, new = Identity.generate(), Identity.generate()
        path = str(tmp_path / "users.db")

        proj = UserProjection(path)
        self._register(proj, old.public_key, username="erin")
        proj.apply_user_key_rotate(self._rotate_rec(old, new))
        proj.close()

        reopened = UserProjection(path)
        try:
            assert reopened.get_key_successor("bbs.a", old.public_key) == new.public_key
            assert reopened.get_user_by_pubkey("bbs.a", new.public_key)["username"] == "erin"
        finally:
            reopened.close()

    def test_clear_origin_drops_rotations(self, user_proj):
        """Otherwise a rebuild replays registrations while stale successors
        keep retiring the keys it just recreated."""
        old, new = Identity.generate(), Identity.generate()
        self._register(user_proj, old.public_key)
        user_proj.apply_user_key_rotate(self._rotate_rec(old, new))

        user_proj.clear_origin("bbs.a")

        assert user_proj.get_key_successor("bbs.a", old.public_key) is None

    def test_list_users_excludes_revoked(self, user_proj):
        for i in range(3):
            user_pubkey = _rid(20 + i)
            rec = Record(
                origin="bbs.a",
                origin_seq=i + 1,
                event_id=_rid(i + 1),
                kind="bonnet.user.register",
                actor_pubkey=ACTOR_PUB,
                metadata=MetadataMap(
                    [
                        metadata_text(1, f"user{i}"),
                        metadata_bytes(2, user_pubkey),
                        metadata_u64(3, 0),
                    ]
                ),
            )
            user_proj.apply_user_register(rec)

        revoke_rec = Record(
            origin="bbs.a",
            origin_seq=4,
            event_id=_rid(4),
            kind="bonnet.user.revoke",
            actor_pubkey=ACTOR_PUB,
            target_origin="bbs.a",
            target_event_id=_rid(1),
            metadata=MetadataMap([metadata_bytes(1, _rid(20))]),
        )
        user_proj.apply_user_revoke(revoke_rec)

        active = user_proj.list_users("bbs.a")
        assert len(active) == 2

        all_users = user_proj.list_users("bbs.a", include_revoked=True)
        assert len(all_users) == 3


# ---------------------------------------------------------------------------
# Policy projection tests
# ---------------------------------------------------------------------------


class TestPolicyProjection:
    def test_rule_publish_and_list(self, policy_proj):
        rec = Record(
            origin="bbs.a",
            origin_seq=1,
            event_id=_rid(1),
            kind="bonnet.rule.publish",
            actor_pubkey=ACTOR_PUB,
            board="moderation.rules",
            metadata=MetadataMap([metadata_text(1, "no-spam")]),
            body_hash=_rid(99),
            body_size=100,
            created_at=1700000000,
        )
        policy_proj.apply_rule(rec)
        rules = policy_proj.list_rules("bbs.a")
        assert len(rules) == 1
        assert rules[0]["rule_name"] == "no-spam"

    def test_rule_revoke_rejects_cross_origin(self, policy_proj):
        """A remote origin cannot revoke a rule it doesn't own, even via
        replication — same guard class as punishment.revoke."""
        rec = Record(
            origin="bbs.a",
            origin_seq=1,
            event_id=_rid(1),
            kind="bonnet.rule.publish",
            actor_pubkey=ACTOR_PUB,
            board="moderation.rules",
            metadata=MetadataMap([metadata_text(1, "no-spam")]),
            body_hash=_rid(99),
            body_size=100,
            created_at=1700000000,
        )
        policy_proj.apply_rule(rec)

        cross_origin_revoke = Record(
            origin="bbs.attacker",
            origin_seq=1,
            event_id=_rid(200),
            kind="bonnet.rule.revoke",
            actor_pubkey=ACTOR_PUB,
            target_origin="bbs.a",
            target_event_id=_rid(1),
            created_at=1700000100,
        )
        policy_proj.apply_rule_revoke(cross_origin_revoke)

        rules = policy_proj.list_rules("bbs.a")
        assert len(rules) == 1
        assert rules[0]["revoked"] is False

        same_origin_revoke = Record(
            origin="bbs.a",
            origin_seq=2,
            event_id=_rid(2),
            kind="bonnet.rule.revoke",
            actor_pubkey=ACTOR_PUB,
            target_origin="bbs.a",
            target_event_id=_rid(1),
            created_at=1700000200,
        )
        policy_proj.apply_rule_revoke(same_origin_revoke)
        assert policy_proj.list_rules("bbs.a", include_revoked=True)[0]["revoked"] is True

    def _punish_rec(self, seq, kind, punished, event_id=None, **kwargs):
        return Record(
            origin="bbs.a",
            origin_seq=seq,
            event_id=event_id or _rid(seq),
            kind=kind,
            actor_pubkey=ACTOR_PUB,
            board="moderation.actions",
            metadata=kwargs.pop("metadata", MetadataMap([metadata_bytes(1, punished)])),
            created_at=1700000000,
            **kwargs,
        )

    def test_punishment_and_revoke(self, policy_proj):
        punished = _rid(30)
        issue_rec = self._punish_rec(
            1,
            "bonnet.punishment.permaban",
            punished,
            metadata=MetadataMap([metadata_bytes(1, punished)]),
        )
        policy_proj.apply_punishment(issue_rec)

        puns = policy_proj.list_punishments_for_pubkey(punished)
        assert len(puns) == 1
        assert puns[0]["type"] == "permaban"
        assert puns[0]["expires_at"] == 0

        revoke_rec = self._punish_rec(
            2,
            "bonnet.punishment.revoke",
            punished,
            target_origin="bbs.a",
            target_event_id=_rid(1),
        )
        policy_proj.apply_punishment_revoke(revoke_rec)

        active = policy_proj.list_punishments_for_pubkey(punished)
        assert len(active) == 0

        all_puns = policy_proj.list_punishments_for_pubkey(punished, include_revoked=True)
        assert len(all_puns) == 1
        assert all_puns[0]["revoked"] is True

    def test_punishment_revoke_rejects_cross_origin(self, policy_proj):
        """A remote origin cannot revoke a punishment it doesn't own, even
        via replication — matching board_projection.py's control-kind
        guard. Without this, any origin could publish a punishment.revoke
        naming another origin's punishment as the target and silently lift
        that origin's ban once the record propagates and is dispatched."""
        punished = _rid(33)
        future = int(time.time()) + 3600
        issue_rec = self._punish_rec(
            1,
            "bonnet.punishment.ban",
            punished,
            metadata=MetadataMap([metadata_bytes(1, punished), metadata_i64(2, future)]),
        )
        policy_proj.apply_punishment(issue_rec)
        assert len(policy_proj.list_pending_for_pubkey(punished)) == 1

        cross_origin_revoke = Record(
            origin="bbs.attacker",
            origin_seq=1,
            event_id=_rid(200),
            kind="bonnet.punishment.revoke",
            actor_pubkey=ACTOR_PUB,
            target_origin="bbs.a",
            target_event_id=_rid(1),
            created_at=1700000100,
        )
        policy_proj.apply_punishment_revoke(cross_origin_revoke)

        assert len(policy_proj.list_pending_for_pubkey(punished)) == 1, (
            "cross-origin revoke must be a no-op — the ban must still be pending"
        )

        same_origin_revoke = self._punish_rec(
            2,
            "bonnet.punishment.revoke",
            punished,
            target_origin="bbs.a",
            target_event_id=_rid(1),
        )
        policy_proj.apply_punishment_revoke(same_origin_revoke)
        assert policy_proj.list_pending_for_pubkey(punished) == []

    def test_apply_punishment_rejects_unknown_kind(self, policy_proj):
        rec = self._punish_rec(1, "bonnet.punishment.issue", _rid(30))
        with pytest.raises(ValueError, match="not a punishment kind"):
            policy_proj.apply_punishment(rec)

    def test_pending_warning_blocks_until_acked(self, policy_proj):
        punished = _rid(31)
        warn_rec = self._punish_rec(1, "bonnet.punishment.warn", punished)
        policy_proj.apply_punishment(warn_rec)

        pending = policy_proj.list_pending_for_pubkey(punished)
        assert len(pending) == 1
        assert pending[0]["type"] == "warning"
        assert pending[0]["event_id"] == _rid(1)

        ack_rec = Record(
            origin="bbs.a",
            origin_seq=2,
            event_id=_rid(2),
            kind="bonnet.punishment.ack",
            actor_pubkey=punished,
            metadata=MetadataMap([metadata_bytes(1, _rid(1))]),
            created_at=1700000100,
        )
        policy_proj.apply_punishment_ack(ack_rec)

        assert policy_proj.list_pending_for_pubkey(punished) == []
        # Ack is idempotent at the pending level even if re-acknowledged.
        dup_ack = Record(
            origin="bbs.a",
            origin_seq=3,
            event_id=_rid(3),
            kind="bonnet.punishment.ack",
            actor_pubkey=punished,
            metadata=MetadataMap([metadata_bytes(1, _rid(1))]),
            created_at=1700000200,
        )
        policy_proj.apply_punishment_ack(dup_ack)
        assert policy_proj.list_pending_for_pubkey(punished) == []

    def test_pending_ban_respects_expiry(self, policy_proj):
        punished = _rid(32)
        future = int(time.time()) + 3600
        past = int(time.time()) - 3600

        active_rec = self._punish_rec(
            1,
            "bonnet.punishment.ban",
            punished,
            event_id=_rid(1),
            metadata=MetadataMap([metadata_bytes(1, punished), metadata_i64(2, future)]),
        )
        policy_proj.apply_punishment(active_rec)

        expired_rec = self._punish_rec(
            2,
            "bonnet.punishment.ban",
            punished,
            event_id=_rid(2),
            metadata=MetadataMap([metadata_bytes(1, punished), metadata_i64(2, past)]),
        )
        policy_proj.apply_punishment(expired_rec)

        pending = policy_proj.list_pending_for_pubkey(punished)
        assert len(pending) == 1
        assert pending[0]["event_id"] == _rid(1)
        assert pending[0]["expires_at"] == future

    def test_pending_permaban_and_revocation(self, policy_proj):
        punished = _rid(33)
        rec = self._punish_rec(1, "bonnet.punishment.permaban", punished)
        policy_proj.apply_punishment(rec)
        assert len(policy_proj.list_pending_for_pubkey(punished)) == 1

        revoke_rec = self._punish_rec(
            2,
            "bonnet.punishment.revoke",
            punished,
            target_origin="bbs.a",
            target_event_id=_rid(1),
        )
        policy_proj.apply_punishment_revoke(revoke_rec)
        assert policy_proj.list_pending_for_pubkey(punished) == []

    def test_pending_filters_by_allowed_origins(self, policy_proj):
        punished = _rid(34)
        local_rec = self._punish_rec(1, "bonnet.punishment.warn", punished, event_id=_rid(1))
        policy_proj.apply_punishment(local_rec)

        remote_rec = Record(
            origin="bbs.remote",
            origin_seq=1,
            event_id=_rid(2),
            kind="bonnet.punishment.warn",
            actor_pubkey=ACTOR_PUB,
            board="moderation.actions",
            metadata=MetadataMap([metadata_bytes(1, punished)]),
            created_at=1700000000,
        )
        policy_proj.apply_punishment(remote_rec)

        both = policy_proj.list_pending_for_pubkey(
            punished, allowed_origins={"bbs.a", "bbs.remote"}
        )
        assert len(both) == 2
        only_local = policy_proj.list_pending_for_pubkey(punished, allowed_origins={"bbs.a"})
        assert len(only_local) == 1
        assert only_local[0]["origin"] == "bbs.a"

    def test_pending_stores_body_reference(self, policy_proj):
        punished = _rid(35)
        rec = self._punish_rec(
            1,
            "bonnet.punishment.warn",
            punished,
            body_hash=b"\x22" * 32,
            body_size=42,
        )
        policy_proj.apply_punishment(rec)

        pending = policy_proj.list_pending_for_pubkey(punished)
        assert pending[0]["body_hash"] == b"\x22" * 32
        assert pending[0]["body_size"] == 42


# ---------------------------------------------------------------------------
# Dispatcher tests
# ---------------------------------------------------------------------------


class TestDispatcher:
    def test_dispatch_article_and_query(self, dispatcher):
        d, firehose, nav, users, policy, bs = dispatcher
        firehose.init_origin_key("bbs.a", ORIGIN_A_PUB)

        body = b"hello world"
        intent = _make_article_intent("bbs.a", _rid(1), _rid(2), body=body)
        sig = sign_intent(ACTOR, encode_intent(intent))
        bs.stage_article_body(
            "bbs.a", "general", intent.event_id, body, intent.body_hash, intent.body_size
        )
        _rec = firehose.append_record(ORIGIN_A, intent, sig, body)

        count = d.dispatch_origin("bbs.a")
        assert count == 1

        bp = d._get_board_projection("bbs.a", "general")
        art = bp.get_article_by_num("bbs.a", "general", 1)
        assert art is not None
        assert art.subject == "Test Article"
        assert art.body_state == "available"

        body_data = bs.get_article_body("bbs.a", "general", 1, intent.body_hash, len(body))
        assert body_data == body

    def test_dispatch_cancel_after_article(self, dispatcher):
        d, firehose, nav, users, policy, bs = dispatcher
        firehose.init_origin_key("bbs.a", ORIGIN_A_PUB)

        aid = _rid(2)
        intent = _make_article_intent("bbs.a", _rid(1), aid)
        sig = sign_intent(ACTOR, encode_intent(intent))
        firehose.append_record(ORIGIN_A, intent, sig, b"hello world")

        cancel_intent = Intent(
            event_id=_rid(3),
            kind="bonnet.article.cancel",
            origin="bbs.a",
            actor_pubkey=ACTOR_PUB,
            board="general",
            target_origin="bbs.a",
            target_board="general",
            target_article_id=aid,
        )
        cancel_sig = sign_intent(ACTOR, encode_intent(cancel_intent))
        firehose.append_record(ORIGIN_A, cancel_intent, cancel_sig, b"")

        d.dispatch_origin("bbs.a")

        bp = d._get_board_projection("bbs.a", "general")
        art = bp.get_article_by_id("bbs.a", "general", aid)
        assert art.visibility == "cancelled"

    def test_dispatch_control_before_target(self, dispatcher):
        d, firehose, nav, users, policy, bs = dispatcher
        firehose.init_origin_key("bbs.a", ORIGIN_A_PUB)

        aid = _rid(50)
        cancel_intent = Intent(
            event_id=_rid(1),
            kind="bonnet.article.cancel",
            origin="bbs.a",
            actor_pubkey=ACTOR_PUB,
            board="general",
            target_origin="bbs.a",
            target_board="general",
            target_article_id=aid,
        )
        cancel_sig = sign_intent(ACTOR, encode_intent(cancel_intent))
        firehose.append_record(ORIGIN_A, cancel_intent, cancel_sig, b"")

        article_intent = _make_article_intent("bbs.a", _rid(2), aid)
        article_sig = sign_intent(ACTOR, encode_intent(article_intent))
        firehose.append_record(ORIGIN_A, article_intent, article_sig, b"hello world")

        d.dispatch_origin("bbs.a")

        bp = d._get_board_projection("bbs.a", "general")
        art = bp.get_article_by_id("bbs.a", "general", aid)
        assert art.visibility == "cancelled"
        assert bp.pending_count() == 0

    def test_dispatch_board_create(self, dispatcher):
        d, firehose, nav, users, policy, bs = dispatcher
        firehose.init_origin_key("bbs.a", ORIGIN_A_PUB)

        board_intent = Intent(
            event_id=_rid(1),
            kind="bonnet.board.create",
            origin="bbs.a",
            actor_pubkey=ACTOR_PUB,
            board="newboard",
            metadata=MetadataMap(
                [
                    metadata_bytes(1, ACTOR_PUB),
                    metadata_text(2, "New Board"),
                ]
            ),
        )
        sig = sign_intent(ACTOR, encode_intent(board_intent))
        firehose.append_record(ORIGIN_A, board_intent, sig, b"")

        d.dispatch_origin("bbs.a")

        board = nav.get_board("bbs.a", "newboard")
        assert board is not None
        assert board["display_name"] == "New Board"

    def test_dispatch_user_register(self, dispatcher):
        d, firehose, nav, users, policy, bs = dispatcher
        firehose.init_origin_key("bbs.a", ORIGIN_A_PUB)

        user_pubkey = _rid(20)
        reg_intent = Intent(
            event_id=_rid(1),
            kind="bonnet.user.register",
            origin="bbs.a",
            actor_pubkey=ACTOR_PUB,
            metadata=MetadataMap(
                [
                    metadata_text(1, "alice"),
                    metadata_bytes(2, user_pubkey),
                    metadata_u64(3, 0),
                ]
            ),
        )
        sig = sign_intent(ACTOR, encode_intent(reg_intent))
        firehose.append_record(ORIGIN_A, reg_intent, sig, b"")

        d.dispatch_origin("bbs.a")

        user = users.get_user_by_pubkey("bbs.a", user_pubkey)
        assert user is not None
        assert user["username"] == "alice"

    def test_dispatch_punishment(self, dispatcher):
        d, firehose, nav, users, policy, bs = dispatcher
        firehose.init_origin_key("bbs.a", ORIGIN_A_PUB)

        punished_user = Identity.from_private_key(bytes(range(50, 82)))
        pun_intent = Intent(
            event_id=_rid(1),
            kind="bonnet.punishment.ban",
            origin="bbs.a",
            actor_pubkey=ACTOR_PUB,
            board="moderation.actions",
            metadata=MetadataMap(
                [
                    metadata_bytes(1, punished_user.public_key),
                    metadata_i64(2, 1800000000),
                ]
            ),
            body_hash=compute_body_hash(b"banned for spam"),
            body_size=len(b"banned for spam"),
        )
        sig = sign_intent(ACTOR, encode_intent(pun_intent))
        firehose.append_record(ORIGIN_A, pun_intent, sig, b"banned for spam")

        ack_intent = Intent(
            event_id=_rid(2),
            kind="bonnet.punishment.ack",
            origin="bbs.a",
            actor_pubkey=punished_user.public_key,
            metadata=MetadataMap([metadata_bytes(1, _rid(1))]),
        )
        ack_sig = sign_intent(punished_user, encode_intent(ack_intent))
        firehose.append_record(ORIGIN_A, ack_intent, ack_sig, b"")

        d.dispatch_origin("bbs.a")

        puns = policy.list_punishments_for_pubkey(punished_user.public_key)
        assert len(puns) == 1
        assert puns[0]["type"] == "ban"
        assert puns[0]["expires_at"] == 1800000000

        # Ban with an ack still gates — only expiry or revoke lifts it.
        pending_after_ack = policy.list_pending_for_pubkey(punished_user.public_key)
        assert len(pending_after_ack) == 1

    def test_dispatch_idempotent(self, dispatcher):
        d, firehose, nav, users, policy, bs = dispatcher
        firehose.init_origin_key("bbs.a", ORIGIN_A_PUB)

        intent = _make_article_intent("bbs.a", _rid(1), _rid(2))
        sig = sign_intent(ACTOR, encode_intent(intent))
        firehose.append_record(ORIGIN_A, intent, sig, b"hello world")

        count1 = d.dispatch_origin("bbs.a")
        count2 = d.dispatch_origin("bbs.a")
        assert count1 == 1
        assert count2 == 0

    def test_rebuild_projections(self, dispatcher):
        d, firehose, nav, users, policy, bs = dispatcher
        firehose.init_origin_key("bbs.a", ORIGIN_A_PUB)

        body = b"rebuild me"
        intent = _make_article_intent("bbs.a", _rid(1), _rid(2), body=body)
        sig = sign_intent(ACTOR, encode_intent(intent))
        bs.stage_article_body(
            "bbs.a", "general", intent.event_id, body, intent.body_hash, intent.body_size
        )
        firehose.append_record(ORIGIN_A, intent, sig, body)

        d.dispatch_origin("bbs.a")
        bp = d._get_board_projection("bbs.a", "general")
        assert bp.article_count("bbs.a", "general") == 1

        count = d.rebuild_all("bbs.a")
        assert count == 1

        bp2 = d._get_board_projection("bbs.a", "general")
        assert bp2.article_count("bbs.a", "general") == 1
        art = bp2.get_article_by_num("bbs.a", "general", 1)
        assert art is not None
        assert art.subject == "Test Article"

    def test_crash_recovery_replay(self, dispatcher):
        d, firehose, nav, users, policy, bs = dispatcher
        firehose.init_origin_key("bbs.a", ORIGIN_A_PUB)

        for i in range(3):
            body = f"body{i}".encode()
            intent = _make_article_intent("bbs.a", _rid(i + 1), _rid(i + 10), body=body)
            sig = sign_intent(ACTOR, encode_intent(intent))
            bs.stage_article_body(
                "bbs.a", "general", intent.event_id, body, intent.body_hash, intent.body_size
            )
            firehose.append_record(ORIGIN_A, intent, sig, body)

        # Dispatch record 1, then simulate crash before dispatching 2 and 3
        d.dispatch_origin("bbs.a")

        # Reset checkpoint to 1 to simulate crash after first dispatch
        firehose.set_checkpoint("bbs.a", 1)

        count = d.dispatch_origin("bbs.a")
        assert count == 2  # records 2 and 3

        bp = d._get_board_projection("bbs.a", "general")
        assert bp.article_count("bbs.a", "general") == 3

    def test_purge_deletes_body(self, dispatcher):
        d, firehose, nav, users, policy, bs = dispatcher
        firehose.init_origin_key("bbs.a", ORIGIN_A_PUB)

        body = b"purge me"
        aid = _rid(2)
        intent = _make_article_intent("bbs.a", _rid(1), aid, body=body)
        sig = sign_intent(ACTOR, encode_intent(intent))
        bs.stage_article_body(
            "bbs.a", "general", intent.event_id, body, intent.body_hash, intent.body_size
        )
        firehose.append_record(ORIGIN_A, intent, sig, body)

        purge_intent = Intent(
            event_id=_rid(3),
            kind="bonnet.article.purge",
            origin="bbs.a",
            actor_pubkey=ACTOR_PUB,
            board="general",
            target_origin="bbs.a",
            target_board="general",
            target_article_id=aid,
        )
        purge_sig = sign_intent(ACTOR, encode_intent(purge_intent))
        firehose.append_record(ORIGIN_A, purge_intent, purge_sig, b"")

        d.dispatch_origin("bbs.a")

        bp = d._get_board_projection("bbs.a", "general")
        art = bp.get_article_by_id("bbs.a", "general", aid)
        assert art.body_state == "purged"
        assert not bs.article_body_exists("bbs.a", "general", 1)


def test_reopening_a_policy_projection_preserves_derived_state(tmp_path):
    """Opening an existing projection must not wipe it.

    A schema migration here clears `applied_events` and
    `projection_checkpoint` deliberately, to force the dispatcher to replay
    from the authoritative firehose. Those clears are shared by every table in
    this projection, so one left running unconditionally turns every startup
    into a full replay — correct in the end, but silently expensive, and
    invisible to tests that only ever build fresh databases. That is exactly
    how it slipped in once.
    """
    path = str(tmp_path / "policy.db")

    p = PolicyProjection(path)
    p._conn.execute(
        "INSERT INTO reports (event_id, origin, origin_seq, culprit_pubkey, target_origin,"
        " target_board, target_article_id, target_event_id, body_hash, body_size, created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (bytes(32), "o", 1, bytes(32), "", "", bytes(32), bytes(32), bytes(32), 4, 1),
    )
    p._conn.execute(
        "INSERT INTO applied_events (event_id, origin, origin_seq, kind, applied_at)"
        " VALUES (?,?,?,?,?)",
        (bytes(32), "o", 1, "bonnet.report", 1),
    )
    p._conn.commit()
    p.close()

    reopened = PolicyProjection(path)
    try:
        assert len(reopened.list_reports()) == 1
        applied = reopened._conn.execute("SELECT COUNT(*) FROM applied_events").fetchone()[0]
        assert applied == 1, "reopening cleared applied_events — every start would replay"
    finally:
        reopened.close()
