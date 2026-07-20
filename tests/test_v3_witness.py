"""Tests for advisory witness metadata (accepted_at, source_relay) in v3 feed responses.

Verifies that:
  1. FEED_HEAD response includes accepted_at + source_relay after the head
  2. FEED_EVENTS response includes accepted_at + source_relay per event
  3. FEED_HEADS response includes accepted_at + source_relay per entry
  4. Local-origin data has source_relay == local origin
  5. Remote-origin data has source_relay == relay hostname
  6. Parsers handle old-format responses (no trailing witness) gracefully
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
    decode_event,
)
from client.protocol import (
    V3_COMMANDS, _encode_v3_str,
    parse_feed_head_resp, parse_feed_events_resp, parse_feed_heads_resp,
)
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


def _build_feed_heads_cmd(offset=0, limit=100):
    return (
        struct.pack(">B", V3_COMMANDS["FEED_HEADS"])
        + struct.pack(">I", offset)
        + struct.pack(">H", limit)
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


def _decode_error(response):
    if len(response) > 0 and response[0] == 0x01:
        code = struct.unpack(">H", response[1:3])[0]
        msg_len = response[3]
        return code, response[4:4 + msg_len].decode("utf-8", errors="replace")
    return None


def _seed_remote_data(local_store, remote_identity, origin=REMOTE_ORIGIN, board=BOARD):
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


class TestWitnessInFeedHead:
    """FEED_HEAD response includes accepted_at + source_relay."""

    @pytest.mark.asyncio
    async def test_local_head_has_origin_as_source_relay(self, setup):
        s = setup
        handler = s["handler"]
        author_id = Identity.generate()
        sub, body, sig = _make_article_submission(1, LOCAL_ORIGIN, BOARD, author_id)
        s["article_service"].publish_article(sub, body, sig)

        cmd = _build_feed_head_cmd("", BOARD)  # empty origin = local
        ctx = _make_known_ctx(s["ident"].public_key)
        resp = handler.handle_v3(cmd, ctx)

        assert resp[0] == 0x00, f"failed: {_decode_error(resp)}"
        result = parse_feed_head_resp(resp[1:])
        assert result["source_relay"] == LOCAL_ORIGIN
        assert result["accepted_at"] > 0

    @pytest.mark.asyncio
    async def test_remote_head_has_relay_as_source_relay(self, setup):
        s = setup
        handler = s["handler"]
        _seed_remote_data(s["feed_store"], s["remote_ident"])

        cmd = _build_feed_head_cmd(REMOTE_ORIGIN, BOARD)
        ctx = _make_known_ctx(s["ident"].public_key)
        resp = handler.handle_v3(cmd, ctx)

        assert resp[0] == 0x00, f"failed: {_decode_error(resp)}"
        result = parse_feed_head_resp(resp[1:])
        assert result["source_relay"] == "relay.test"
        assert result["accepted_at"] > 0


class TestWitnessInFeedEvents:
    """FEED_EVENTS response includes accepted_at + source_relay per event."""

    @pytest.mark.asyncio
    async def test_local_events_have_origin_as_source_relay(self, setup):
        s = setup
        handler = s["handler"]
        author_id = Identity.generate()
        for i in range(1, 4):
            sub, body, sig = _make_article_submission(i, LOCAL_ORIGIN, BOARD, author_id)
            s["article_service"].publish_article(sub, body, sig)

        cmd = _build_feed_events_cmd("", BOARD, 1, 10)
        ctx = _make_known_ctx(s["ident"].public_key)
        resp = handler.handle_v3(cmd, ctx)

        assert resp[0] == 0x00, f"failed: {_decode_error(resp)}"
        events = parse_feed_events_resp(resp[1:])
        assert len(events) == 3
        for entry in events:
            assert entry["source_relay"] == LOCAL_ORIGIN
            assert entry["accepted_at"] > 0

    @pytest.mark.asyncio
    async def test_remote_events_have_relay_as_source_relay(self, setup):
        s = setup
        handler = s["handler"]
        _seed_remote_data(s["feed_store"], s["remote_ident"])

        cmd = _build_feed_events_cmd(REMOTE_ORIGIN, BOARD, 1, 10)
        ctx = _make_known_ctx(s["ident"].public_key)
        resp = handler.handle_v3(cmd, ctx)

        assert resp[0] == 0x00, f"failed: {_decode_error(resp)}"
        events = parse_feed_events_resp(resp[1:])
        assert len(events) == 3
        for entry in events:
            assert entry["source_relay"] == "relay.test"
            assert entry["accepted_at"] > 0


class TestWitnessInFeedHeads:
    """FEED_HEADS response includes accepted_at + source_relay per entry."""

    @pytest.mark.asyncio
    async def test_feed_heads_includes_witness(self, setup):
        s = setup
        handler = s["handler"]
        author_id = Identity.generate()
        sub, body, sig = _make_article_submission(1, LOCAL_ORIGIN, BOARD, author_id)
        s["article_service"].publish_article(sub, body, sig)

        cmd = _build_feed_heads_cmd(0, 100)
        ctx = _make_known_ctx(s["ident"].public_key)
        resp = handler.handle_v3(cmd, ctx)

        assert resp[0] == 0x00, f"failed: {_decode_error(resp)}"
        entries = parse_feed_heads_resp(resp[1:])
        assert len(entries) >= 1
        for entry in entries:
            assert entry["accepted_at"] > 0
            assert entry["source_relay"] == LOCAL_ORIGIN


class TestParserBackwardCompat:
    """Parsers handle old-format responses (no trailing witness) gracefully."""

    def test_parse_feed_head_resp_old_format(self):
        """Old format: head_len:u16 + head_bytes (no trailing witness)."""
        from core.article_feed import make_empty_head, sign_head, encode_head, compute_head_hash
        ident = Identity.generate()
        head = make_empty_head("old.test", "board")
        sign_head(head, ident)
        encoded = encode_head(head)
        old_payload = struct.pack(">H", len(encoded)) + encoded

        result = parse_feed_head_resp(old_payload)
        assert result["head_bytes"] == encoded
        assert result["accepted_at"] == 0
        assert result["source_relay"] == ""

    def test_parse_feed_events_resp_old_format(self):
        """Old format: count:u16 + [event_len:u32 + event_bytes]* (no witness)."""
        fake_event = b"\x00" * 100
        old_payload = struct.pack(">H", 1) + struct.pack(">I", len(fake_event)) + fake_event

        events = parse_feed_events_resp(old_payload)
        assert len(events) == 1
        assert events[0]["event_bytes"] == fake_event
        assert events[0]["accepted_at"] == 0
        assert events[0]["source_relay"] == ""

    def test_parse_feed_heads_resp_old_format(self):
        """Old format: count:u16 + [origin:u16 + board:u16 + head_len:u16 + head]* (no witness)."""
        from core.article_feed import make_empty_head, sign_head, encode_head
        ident = Identity.generate()
        head = make_empty_head("old.test", "board")
        sign_head(head, ident)
        encoded = encode_head(head)
        origin_b = "old.test".encode("utf-8")
        board_b = "board".encode("utf-8")
        old_payload = struct.pack(">H", 1)
        old_payload += struct.pack(">H", len(origin_b)) + origin_b
        old_payload += struct.pack(">H", len(board_b)) + board_b
        old_payload += struct.pack(">H", len(encoded)) + encoded

        entries = parse_feed_heads_resp(old_payload)
        assert len(entries) == 1
        assert entries[0]["origin"] == "old.test"
        assert entries[0]["board"] == "board"
        assert entries[0]["head_bytes"] == encoded
        assert entries[0]["accepted_at"] == 0
        assert entries[0]["source_relay"] == ""
