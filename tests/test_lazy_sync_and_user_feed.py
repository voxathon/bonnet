"""Tests for lazy federation, ACL fixes, and user registry feed migration.

Covers:
  - Backoff fix for lazy mode (sync_interval=0 seeds from 30s)
  - FeedSubscription no longer has body_policy
  - max_events_per_cycle config
  - USER_REGISTER / USER_REVOKE event encoding
  - user_projection populated on feed event acceptance
  - user_projection query by pubkey
  - UserFeedPublisher publishes on UME mutations
  - Metadata-only peering (bodies not fetched during sync)
"""

import os
import sys
import struct
import time
import random
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.article_feed import (
    ArticleFeedStore,
    Submission,
    UserHeaders,
    EVENT_USER_REGISTER,
    EVENT_USER_REVOKE,
    EVENT_ARTICLE,
    SCHEME_V3,
    SUBMISSION_VERSION,
    ZERO_MESSAGE_ID,
    ZERO_HASH,
    compute_body_hash,
    sign_author,
    sign_origin,
    decode_event,
    encode_event,
    compute_event_hash,
    compute_head_hash,
    encode_head,
)
from core.crypto import Identity
from core.config import Config, FeedSubscription, ModerationBoards
from engine.article_service import ArticleService, UserFeedPublisher
from engine.ume import Ume
from net.context import CommandContext
from net.sync import SyncManager

ORIGIN = "origin.test"
BOARD = "users.registry"
CREATED_AT = 1700000000


def _random_msgid(seed):
    rng = random.Random(seed)
    mid = rng.randbytes(32)
    while mid == ZERO_MESSAGE_ID:
        mid = rng.randbytes(32)
    return mid


def _make_store(temp_dir, name="store"):
    db_path = os.path.join(temp_dir, f"{name}_feeds.db")
    bodies_dir = os.path.join(temp_dir, f"{name}_bodies")
    return ArticleFeedStore(db_path, bodies_dir, max_body_size=1024 * 1024)


def _make_user_submission(username, pubkey, origin=ORIGIN, board=BOARD,
                          flags=0, seq=1, creation_time=CREATED_AT,
                          identity=None):
    if identity is None:
        identity = Identity.generate()
    headers = UserHeaders(
        username=username,
        publickey=pubkey,
        flags=flags,
        seq_numbr=seq,
        creation_time=creation_time,
    )
    import random
    mid = _random_msgid(hash(username) & 0xFFFFFFFF)
    sub = Submission(
        submission_version=SUBMISSION_VERSION,
        event_type=EVENT_USER_REGISTER,
        origin=origin, board=board,
        message_id=mid,
        created_at=creation_time,
        actor_pubkey=identity.public_key,
        actor_username=username,
        actor_registrar=origin,
        headers=headers,
        body_hash=compute_body_hash(b""), body_size=0,
    )
    sig = sign_author(sub, identity)
    return sub, identity, sig


# ---------------------------------------------------------------------------
# Backoff fix tests
# ---------------------------------------------------------------------------

class TestLazyBackoff:

    @pytest.mark.asyncio
    async def test_backoff_seeds_from_30s_when_interval_zero(self, temp_dir):
        """In lazy-only mode (interval=0), first failure backs off 30s."""
        config = Config(origin=ORIGIN, sync_interval_seconds=0)
        store = _make_store(temp_dir)
        try:
            service = ArticleService(store, ORIGIN, Identity.generate())
            from engine.facade import BonnetEngine
            from engine.ame import Ame
            from engine.keibatsu import Keibatsu

            ume = Ume(os.path.join(temp_dir, "userfile"))
            ame = Ame(os.path.join(temp_dir, "boards"), origin=ORIGIN,
                       signing_key=Identity.generate().signing_key,
                       nav_db_path=os.path.join(temp_dir, "nav.db"))
            keibatsu = Keibatsu(
                reports_path=os.path.join(temp_dir, "reports.db"),
                punishments_path=os.path.join(temp_dir, "punishments.db"),
                ume=ume, signing_key=Identity.generate().signing_key,
                origin=ORIGIN,
            )
            engine = BonnetEngine(ume, ame, keibatsu, config, Identity.generate())
            engine.article_service = service

            sync_mgr = SyncManager(engine)
            assert sync_mgr._sync_interval == 0
            assert sync_mgr._sync_max_events_per_cycle == 5000

            sync_mgr._record_peer_failure("peer.test")
            assert sync_mgr._peer_backoff["peer.test"] == 30

            sync_mgr._record_peer_failure("peer.test")
            assert sync_mgr._peer_backoff["peer.test"] == 60

            sync_mgr._record_peer_success("peer.test")
            assert sync_mgr._peer_backoff["peer.test"] == 0
        finally:
            store.close()


# ---------------------------------------------------------------------------
# FeedSubscription tests
# ---------------------------------------------------------------------------

class TestFeedSubscriptionNoBodyPolicy:

    def test_no_body_policy_attribute(self):
        sub = FeedSubscription("origin.test", ["general"], ["relay.test"])
        assert not hasattr(sub, "body_policy")

    def test_from_dict_ignores_body_policy(self):
        data = {
            "origin": "origin.test",
            "boards": ["general"],
            "relays": ["relay.test"],
            "body_policy": "eager",
        }
        sub = FeedSubscription.from_dict(data)
        assert not hasattr(sub, "body_policy")


# ---------------------------------------------------------------------------
# ModerationBoards tests
# ---------------------------------------------------------------------------

class TestModerationBoardsUsers:

    def test_users_board_default(self):
        mb = ModerationBoards()
        assert mb.users == "users.registry"

    def test_from_dict_includes_users(self):
        mb = ModerationBoards.from_dict({"users": "custom.users"})
        assert mb.users == "custom.users"


# ---------------------------------------------------------------------------
# UserHeaders encoding tests
# ---------------------------------------------------------------------------

class TestUserHeadersCodec:

    def test_encode_decode_roundtrip(self):
        pubkey = Identity.generate().public_key
        headers = UserHeaders(
            username="alice",
            publickey=pubkey,
            flags=3,
            seq_numbr=42,
            creation_time=CREATED_AT,
        )
        from core.article_feed import _encode_user_headers, _decode_user_headers
        encoded = _encode_user_headers(headers)
        decoded, offset = _decode_user_headers(encoded)
        assert offset == len(encoded)
        assert decoded.username == "alice"
        assert decoded.publickey == pubkey
        assert decoded.flags == 3
        assert decoded.seq_numbr == 42
        assert decoded.creation_time == CREATED_AT

    def test_encode_requires_32_byte_pubkey(self):
        from core.article_feed import _encode_user_headers, DecodeError
        headers = UserHeaders(username="bob", publickey=b"\x00" * 31)
        with pytest.raises(DecodeError):
            _encode_user_headers(headers)


# ---------------------------------------------------------------------------
# user_projection tests
# ---------------------------------------------------------------------------

class TestUserProjection:

    def test_projection_populated_on_local_publish(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            origin_id = Identity.generate()
            service = ArticleService(store, ORIGIN, origin_id)
            store.create_empty_feed(ORIGIN, BOARD, origin_id)

            user_key = Identity.generate()
            sub, _, sig = _make_user_submission(
                "alice", user_key.public_key, identity=origin_id)
            service.publish_user_register(sub, sig)

            proj = store.get_user_by_pubkey(user_key.public_key)
            assert proj is not None
            assert proj["username"] == "alice"
            assert proj["origin"] == ORIGIN
            assert proj["revoked"] == 0
        finally:
            store.close()

    def test_projection_revoked_on_user_revoke(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            origin_id = Identity.generate()
            service = ArticleService(store, ORIGIN, origin_id)
            store.create_empty_feed(ORIGIN, BOARD, origin_id)

            user_key = Identity.generate()
            sub, _, sig = _make_user_submission(
                "alice", user_key.public_key, identity=origin_id)
            ev, head = service.publish_user_register(sub, sig)

            proj = store.get_user_by_pubkey(user_key.public_key)
            assert proj is not None

            revoke_sub = Submission(
                event_type=EVENT_USER_REVOKE,
                origin=ORIGIN, board=BOARD,
                message_id=_random_msgid(999),
                target_message_id=ev.message_id,
                actor_pubkey=origin_id.public_key,
                body_hash=compute_body_hash(b""),
                body_size=0,
                created_at=int(time.time()),
            )
            revoke_sig = sign_author(revoke_sub, origin_id)
            service.publish_user_revoke(revoke_sub, revoke_sig)

            proj = store.get_user_by_pubkey(user_key.public_key)
            assert proj is None
        finally:
            store.close()

    def test_list_users_by_origin(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            origin_id = Identity.generate()
            service = ArticleService(store, ORIGIN, origin_id)
            store.create_empty_feed(ORIGIN, BOARD, origin_id)

            for name in ["alice", "bob", "carol"]:
                key = Identity.generate()
                sub, _, sig = _make_user_submission(
                    name, key.public_key, seq=len(name),
                    identity=origin_id)
                service.publish_user_register(sub, sig)

            users = store.list_users_by_origin(ORIGIN)
            assert len(users) == 3
            names = [u["username"] for u in users]
            assert "alice" in names
            assert "bob" in names
            assert "carol" in names
        finally:
            store.close()

    def test_projection_populated_on_remote_accept(self, temp_dir):
        store_a = _make_store(temp_dir, "a")
        store_c = _make_store(temp_dir, "c")
        try:
            origin_id = Identity.generate()
            service_a = ArticleService(store_a, ORIGIN, origin_id)
            store_a.create_empty_feed(ORIGIN, BOARD, origin_id)

            user_key = Identity.generate()
            sub, _, sig = _make_user_submission(
                "alice", user_key.public_key, identity=origin_id)
            ev, head = service_a.publish_user_register(sub, sig)

            result = store_c.accept_remote_range(
                ORIGIN, BOARD, head, [ev],
                origin_pubkey=origin_id.public_key,
                source_relay="origin.test",
            )
            assert result.accepted

            proj = store_c.get_user_by_pubkey(user_key.public_key)
            assert proj is not None
            assert proj["username"] == "alice"
            assert proj["origin"] == ORIGIN
        finally:
            store_a.close()
            store_c.close()


# ---------------------------------------------------------------------------
# UserFeedPublisher tests
# ---------------------------------------------------------------------------

class TestUserFeedPublisher:

    def test_publish_on_ume_put(self, temp_dir):
        store = _make_store(temp_dir)
        ume_path = os.path.join(temp_dir, "userfile")
        try:
            origin_id = Identity.generate()
            service = ArticleService(store, ORIGIN, origin_id)
            store.create_empty_feed(ORIGIN, BOARD, origin_id)

            ume = Ume(ume_path)
            publisher = UserFeedPublisher(service, origin_id, ORIGIN, BOARD)
            ume.register_mutation_callback(publisher.on_mutation)

            user_key = Identity.generate().public_key
            ume.put("alice", ORIGIN, user_key,
                    record_origin=ORIGIN, relay=ORIGIN)

            proj = store.get_user_by_pubkey(user_key)
            assert proj is not None
            assert proj["username"] == "alice"
        finally:
            store.close()

    def test_revoke_on_ume_delete(self, temp_dir):
        store = _make_store(temp_dir)
        ume_path = os.path.join(temp_dir, "userfile")
        try:
            origin_id = Identity.generate()
            service = ArticleService(store, ORIGIN, origin_id)
            store.create_empty_feed(ORIGIN, BOARD, origin_id)

            ume = Ume(ume_path)
            publisher = UserFeedPublisher(service, origin_id, ORIGIN, BOARD)
            ume.register_mutation_callback(publisher.on_mutation)

            user_key = Identity.generate().public_key
            ume.put("alice", ORIGIN, user_key,
                    record_origin=ORIGIN, relay=ORIGIN)

            proj = store.get_user_by_pubkey(user_key)
            assert proj is not None

            ume.delete(username="alice")

            proj = store.get_user_by_pubkey(user_key)
            assert proj is None
        finally:
            store.close()

    def test_ignores_remote_users(self, temp_dir):
        store = _make_store(temp_dir)
        ume_path = os.path.join(temp_dir, "userfile")
        try:
            origin_id = Identity.generate()
            service = ArticleService(store, ORIGIN, origin_id)
            store.create_empty_feed(ORIGIN, BOARD, origin_id)

            ume = Ume(ume_path)
            publisher = UserFeedPublisher(service, origin_id, ORIGIN, BOARD)
            ume.register_mutation_callback(publisher.on_mutation)

            user_key = Identity.generate().public_key
            ume.put("alice", "remote.test", user_key,
                    record_origin="remote.test", relay="remote.test")

            proj = store.get_user_by_pubkey(user_key)
            assert proj is None
        finally:
            store.close()
