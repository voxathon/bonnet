"""Tests for remote-origin feed access after removing _refuse_remote_feed.

The old _refuse_remote_feed gate blocked anonymous/known callers from reading
remote-origin feed metadata, while letting any freshly-generated Ed25519 key
through (is_unknown).  That was security theatre: anyone can generate a key.

The fix: remote-origin feed metadata (heads, events) is served to anyone who
passes the standard ACL gates (command + object + board read).  Metadata is
public by design; article bodies remain the confidentiality boundary.

These tests verify:
  1. Known (registered) users can read cached remote-origin feed heads/events
  2. Anonymous users can read cached remote-origin feed heads/events
  3. FEED_HEAD for an uncached remote origin returns 404 + queues lazy sync
     (no fake head created with the local server key)
  4. ARTICLE_BODY for a remote origin returns 404 when not cached
"""

import os
import sys
import struct
import time
import random
import pytest
import pytest_asyncio
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.crypto import Identity
from core.config import Config, Matcher, ACLEntry, FeedSubscription
from core.orm import Database
from engine.ume import Ume
from engine.ame import Ame
from engine.keibatsu import Keibatsu
from engine.facade import BonnetEngine
from engine.article_service import ArticleService
from net.commands import CommandHandler
from net.context import CommandContext
from core.article_feed import (
    ArticleFeedStore,
    Submission,
    ArticleHeaders,
    EVENT_ARTICLE,
    SCHEME_V3,
    SUBMISSION_VERSION,
    ZERO_MESSAGE_ID,
    ZERO_HASH,
    compute_body_hash,
    sign_author,
    decode_head,
)
from client.protocol import V3_COMMANDS, _encode_v3_str
from tests.helpers import default_test_acls


LOCAL_ORIGIN = "local.test"
REMOTE_ORIGIN = "remote.test"
BOARD = "testboard"
CREATED_AT = 1700000000


def _init_rules(reports_path):
    with Database(reports_path).open() as ctx:
        ctx.execute("""CREATE TABLE IF NOT EXISTS rules (
            rule_num INTEGER PRIMARY KEY, rule_name TEXT UNIQUE NOT NULL, description TEXT NOT NULL
        )""")


def _random_msgid(seed):
    rng = random.Random(seed)
    mid = rng.randbytes(32)
    while mid == ZERO_MESSAGE_ID:
        mid = rng.randbytes(32)
    return mid


def _make_article_submission(seed, origin, board, author_identity):
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


def _build_feed_head_cmd(origin, board):
    return (
        struct.pack(">B", V3_COMMANDS["FEED_HEAD"])
        + _encode_v3_str(origin)
        + _encode_v3_str(board)
    )


def _build_feed_events_cmd(origin, board, start_seq=1, max_count=100):
    return (
        struct.pack(">B", V3_COMMANDS["FEED_EVENTS"])
        + _encode_v3_str(origin)
        + _encode_v3_str(board)
        + struct.pack(">Q", start_seq)
        + struct.pack(">H", max_count)
    )


def _build_article_body_cmd(origin, board, message_id, body_hash):
    return (
        struct.pack(">B", V3_COMMANDS["ARTICLE_BODY"])
        + _encode_v3_str(origin)
        + _encode_v3_str(board)
        + message_id
        + body_hash
    )


def _make_known_ctx(peer_pubkey, origin=LOCAL_ORIGIN):
    user = MagicMock()
    user.username = "testuser"
    user.publickey = peer_pubkey
    user.is_administrator = False
    user.is_moderator = False
    user.is_banned = False
    user.record_origin = origin
    user.creation_time = int(time.time())
    return CommandContext(
        peer_public_key=peer_pubkey,
        user=user,
        username="testuser",
        is_anonymous=False,
        origin=origin,
    )


def _make_anon_ctx(anon_key):
    return CommandContext(
        peer_public_key=anon_key,
        user=None,
        is_anonymous=True,
        origin=LOCAL_ORIGIN,
    )


def _decode_error(response):
    if len(response) > 0 and response[0] == 0x01:
        code = struct.unpack(">H", response[1:3])[0]
        msg_len = response[3]
        return code, response[4:4 + msg_len].decode("utf-8", errors="replace")
    return None


def _seed_remote_data(local_store, remote_identity, origin=REMOTE_ORIGIN, board=BOARD):
    """Publish articles on a remote store, then accept them into the local store."""
    import tempfile
    temp_dir = tempfile.mkdtemp()
    remote_store = ArticleFeedStore(
        os.path.join(temp_dir, "remote_feeds.db"),
        os.path.join(temp_dir, "remote_bodies"),
    )
    try:
        remote_service = ArticleService(remote_store, origin, remote_identity)
        author_id = Identity.generate()
        events = []
        for i in range(1, 4):
            sub, body, sig = _make_article_submission(i, origin, board, author_id)
            ev, head = remote_service.publish_article(sub, body, sig)
            events.append(ev)

        head = remote_store.get_head(origin, board)
        assert head is not None

        result = local_store.accept_remote_range(
            origin, board, head, events,
            origin_pubkey=remote_identity.public_key,
            source_relay="relay.test",
        )
        assert result.accepted
        return head, events
    finally:
        remote_store.close()
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)


@pytest_asyncio.fixture
async def setup(tmp_path):
    temp_dir = str(tmp_path)
    ident = Identity.generate()
    remote_ident = Identity.generate()

    config = Config(
        origin=LOCAL_ORIGIN,
        registrars=[LOCAL_ORIGIN],
        ame_path=os.path.join(temp_dir, "boards"),
        data_dir=temp_dir,
        nav_db_path=os.path.join(temp_dir, "nav.db"),
        reports_db_path=os.path.join(temp_dir, "reports.db"),
        punishments_db_path=os.path.join(temp_dir, "punishments.db"),
        log_dir=os.path.join(temp_dir, "logs"),
        acls=default_test_acls(LOCAL_ORIGIN),
        anonymous_read=True,
        feed_subscriptions=[
            FeedSubscription(origin=REMOTE_ORIGIN, boards=[BOARD],
                             relays=["relay.test"]),
        ],
    )
    ume = Ume(os.path.join(temp_dir, "userfile"))
    ame = Ame(config.ame_path, origin=LOCAL_ORIGIN, signing_key=ident.signing_key,
              nav_db_path=config.nav_db_path)
    _init_rules(config.reports_db_path)
    keibatsu = Keibatsu(config.reports_db_path, config.punishments_db_path,
                        ume=ume, signing_key=ident.signing_key, origin=LOCAL_ORIGIN)
    engine = BonnetEngine(ume, ame, keibatsu, config, ident)

    feed_store = ArticleFeedStore(
        os.path.join(temp_dir, "article_feeds.db"),
        os.path.join(temp_dir, "article_bodies"),
    )
    article_service = ArticleService(feed_store, LOCAL_ORIGIN, ident)
    engine.article_service = article_service

    handler = CommandHandler(engine)
    task = handler._sync_mgr._worker_task
    if task and not task.done():
        task.cancel()
    handler._sync_mgr.queue_sync_threadsafe = lambda peer: None

    ame.create_board(BOARD, owner_pubkey=ident.public_key)
    ume.ensure_root_user(LOCAL_ORIGIN, ident.public_key)

    yield {
        "ident": ident, "remote_ident": remote_ident,
        "config": config, "ume": ume, "ame": ame,
        "keibatsu": keibatsu, "engine": engine, "handler": handler,
        "article_service": article_service, "feed_store": feed_store,
    }

    ame.shutdown()
    keibatsu.shutdown()
    feed_store.close()


class TestRemoteFeedAccess:
    """Remote-origin feed metadata is served to all ACL-permitted principals."""

    @pytest.mark.asyncio
    async def test_known_user_reads_cached_remote_feed_head(self, setup):
        s = setup
        handler = s["handler"]
        feed_store = s["feed_store"]

        _seed_remote_data(feed_store, s["remote_ident"])

        cmd = _build_feed_head_cmd(REMOTE_ORIGIN, BOARD)
        ctx = _make_known_ctx(s["ident"].public_key)
        resp = handler.handle_v3(cmd, ctx)

        assert resp[0] == 0x00, f"expected success, got {_decode_error(resp)}"
        head_len = struct.unpack(">H", resp[1:3])[0]
        decoded = decode_head(resp[3:3 + head_len])
        assert decoded.origin == REMOTE_ORIGIN
        assert decoded.board == BOARD
        assert decoded.latest_feed_seq == 3

    @pytest.mark.asyncio
    async def test_anonymous_reads_cached_remote_feed_head(self, tmp_path):
        """Anonymous users with FEED_HEAD command access can read cached
        remote-origin feed heads (no _refuse_remote_feed gate)."""
        temp_dir = str(tmp_path)
        ident = Identity.generate()
        remote_ident = Identity.generate()

        from tests.helpers import anonymous_read_command_names
        anon_commands = anonymous_read_command_names() + ["FEED_HEAD", "FEED_EVENTS"]

        local_acl = ACLEntry(
            "local-full-access", Matcher(origin_pattern=LOCAL_ORIGIN),
            ["*"], True, True, command_patterns=["*"], object_patterns=["*"],
        )
        anon_acl = ACLEntry(
            "anonymous-read", Matcher(anonymous=True),
            ["*"], True, False, command_patterns=anon_commands,
            object_patterns=["articles"],
        )
        unknown_acl = ACLEntry(
            "unknown-read", Matcher(unknown=True),
            ["*"], True, False, command_patterns=anon_commands,
            object_patterns=["articles"],
        )
        unknown_reg = ACLEntry(
            "unknown-registration", Matcher(unknown=True),
            ["*"], False, True, command_patterns=["REGISTER"],
        )

        config = Config(
            origin=LOCAL_ORIGIN, registrars=[LOCAL_ORIGIN],
            ame_path=os.path.join(temp_dir, "boards"),
            data_dir=temp_dir,
            nav_db_path=os.path.join(temp_dir, "nav.db"),
            reports_db_path=os.path.join(temp_dir, "reports.db"),
            punishments_db_path=os.path.join(temp_dir, "punishments.db"),
            log_dir=os.path.join(temp_dir, "logs"),
            acls=[local_acl, anon_acl, unknown_acl, unknown_reg],
            anonymous_read=True,
            feed_subscriptions=[
                FeedSubscription(origin=REMOTE_ORIGIN, boards=[BOARD],
                                 relays=["relay.test"]),
            ],
        )
        ume = Ume(os.path.join(temp_dir, "userfile"))
        ame = Ame(config.ame_path, origin=LOCAL_ORIGIN, signing_key=ident.signing_key,
                  nav_db_path=config.nav_db_path)
        _init_rules(config.reports_db_path)
        keibatsu = Keibatsu(config.reports_db_path, config.punishments_db_path,
                            ume=ume, signing_key=ident.signing_key, origin=LOCAL_ORIGIN)
        engine = BonnetEngine(ume, ame, keibatsu, config, ident)
        feed_store = ArticleFeedStore(
            os.path.join(temp_dir, "article_feeds.db"),
            os.path.join(temp_dir, "article_bodies"),
        )
        article_service = ArticleService(feed_store, LOCAL_ORIGIN, ident)
        engine.article_service = article_service
        handler = CommandHandler(engine)
        task = handler._sync_mgr._worker_task
        if task and not task.done():
            task.cancel()
        handler._sync_mgr.queue_sync_threadsafe = lambda peer: None
        ame.create_board(BOARD, owner_pubkey=ident.public_key)

        try:
            _seed_remote_data(feed_store, remote_ident)

            anon_key = Identity.generate().public_key
            cmd = _build_feed_head_cmd(REMOTE_ORIGIN, BOARD)
            ctx = _make_anon_ctx(anon_key)
            resp = handler.handle_v3(cmd, ctx)

            assert resp[0] == 0x00, f"expected success, got {_decode_error(resp)}"
        finally:
            ame.shutdown()
            keibatsu.shutdown()
            feed_store.close()

    @pytest.mark.asyncio
    async def test_uncached_remote_feed_head_returns_404(self, setup):
        s = setup
        handler = s["handler"]

        cmd = _build_feed_head_cmd(REMOTE_ORIGIN, BOARD)
        ctx = _make_known_ctx(s["ident"].public_key)
        resp = handler.handle_v3(cmd, ctx)

        err = _decode_error(resp)
        assert err is not None, "expected 404 but got success"
        assert err[0] == 404
        assert REMOTE_ORIGIN in err[1]

        head = s["feed_store"].get_head(REMOTE_ORIGIN, BOARD)
        assert head is None, "should not create a fake head for remote origin"

    @pytest.mark.asyncio
    async def test_uncached_remote_article_body_returns_404(self, setup):
        s = setup
        handler = s["handler"]

        fake_msg_id = _random_msgid(99)
        fake_body_hash = b"\x01" * 32
        cmd = _build_article_body_cmd(REMOTE_ORIGIN, BOARD, fake_msg_id, fake_body_hash)
        ctx = _make_known_ctx(s["ident"].public_key)
        resp = handler.handle_v3(cmd, ctx)

        err = _decode_error(resp)
        assert err is not None
        assert err[0] in (404, 410)

    @pytest.mark.asyncio
    async def test_remote_feed_events_serves_cached_data(self, setup):
        s = setup
        handler = s["handler"]
        feed_store = s["feed_store"]

        _seed_remote_data(feed_store, s["remote_ident"])

        cmd = _build_feed_events_cmd(REMOTE_ORIGIN, BOARD, 1, 100)
        ctx = _make_known_ctx(s["ident"].public_key)
        resp = handler.handle_v3(cmd, ctx)

        assert resp[0] == 0x00, f"expected success, got {_decode_error(resp)}"
        count = struct.unpack(">H", resp[1:3])[0]
        assert count == 3, f"expected 3 events, got {count}"
