"""Integration tests for Bonnet protocol v3 article feed commands.

Tests the full ASGI request/response cycle through /v3/command:
  - ARTICLE_PUBLISH: publish an article and verify the response
  - ARTICLE_GET: retrieve an article by article_num and message_id
  - ARTICLE_LIST: list articles with projection filtering
  - ARTICLE_SEARCH: search articles by text
  - FEED_HEAD: get the signed feed head
  - FEED_EVENTS: fetch a contiguous event range
  - FEED_HEADS: list feed heads across boards
  - BAN_STATUS: check ban status

These tests set up a minimal server with ArticleFeedStore + ArticleService
wired into the BonnetEngine facade, then send signed v3 commands through
httpx ASGITransport.
"""

import os
import sys
import struct
import time
import random
import base64
import pytest
import pytest_asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import httpx
from httpx import AsyncClient, ASGITransport

from core.crypto import Identity
from core.config import Config
from engine.ume import Ume
from engine.ame import Ame
from engine.keibatsu import Keibatsu
from engine.facade import BonnetEngine
from core.user_registry import UserRegistryStore, RegistryService
from core.article_feed import (
    ArticleFeedStore,
    Submission,
    ArticleHeaders,
    EVENT_ARTICLE,
    EVENT_CANCEL,
    SCHEME_V3,
    ZERO_MESSAGE_ID,
    ZERO_HASH,
    FORMAT_VERSION,
    SUBMISSION_VERSION,
    encode_submission,
    decode_submission,
    decode_event,
    decode_head,
    compute_body_hash,
    sign_author,
    verify_author_signature,
    verify_origin_signature,
    compute_event_hash,
    encode_event,
    compute_head_hash,
    encode_head,
    STATE_ACTIVE,
    STATE_CANCELLED,
    BODY_INCLUDED,
    BODY_AVAILABLE_NOT_INCLUDED,
    BODY_UNAVAILABLE,
    FLAG_INCLUDE_CANCELLED,
)
from engine.article_service import ArticleService
from net.commands import CommandHandler
from net.http_server import BonnetHTTPServer
from net.http_auth import (
    BonnetSigner, BonnetVerifier, KeyResolver, HTTPMessage,
    compute_content_digest,
)
from net.replay import ReplayLedger
from net.rate_limiter import RateLimiter

from tests.helpers import default_test_acls
from tests.fixtures.protocol_v1.wire_fixtures import TEST_SEED


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def temp_dir(tmp_path):
    return str(tmp_path)

ORIGIN = "bbs.test"
BOARD = "testboard"

class V3ServerSetup:
    """Server setup with ArticleFeedStore + ArticleService wired in."""

    def __init__(self, temp_dir):
        self.temp_dir = temp_dir
        self.server_identity = Identity.from_private_key(TEST_SEED)
        self.config = Config(
            origin=ORIGIN,
            registrars=[ORIGIN],
            ame_path=os.path.join(temp_dir, "boards"),
            data_dir=temp_dir,
            nav_db_path=os.path.join(temp_dir, "nav.db"),
            reports_db_path=os.path.join(temp_dir, "reports.db"),
            punishments_db_path=os.path.join(temp_dir, "punishments.db"),
            log_dir=os.path.join(temp_dir, "logs"),
            identity_path=os.path.join(temp_dir, "identity"),
            userfile_path=os.path.join(temp_dir, "userfile"),
            acls=default_test_acls(ORIGIN),
            anonymous_read=True,
            max_request_size=10 * 1024 * 1024,
            rate_limit_requests=100,
            rate_limit_window=1,
            signature_lifetime_seconds=60,
            clock_skew_seconds=30,
            search_per_identity_concurrency=1,
            search_rate_limit=10,
            search_rate_window_seconds=60,
        )

        self.ume = Ume(os.path.join(temp_dir, "userfile"))
        self.ame = Ame(self.config.ame_path, origin=ORIGIN,
                       signing_key=self.server_identity.signing_key,
                       nav_db_path=self.config.nav_db_path)

        # Init rules table (needed by Keibatsu init)
        from core.orm import Database
        with Database(self.config.reports_db_path).open() as ctx:
            ctx.execute("""CREATE TABLE IF NOT EXISTS rules (
                rule_num INTEGER PRIMARY KEY, rule_name TEXT UNIQUE NOT NULL, description TEXT NOT NULL
            )""")

        self.keibatsu = Keibatsu(self.config.reports_db_path, self.config.punishments_db_path,
                                  ume=self.ume, signing_key=self.server_identity.signing_key,
                                  origin=ORIGIN)

        self.engine = BonnetEngine(self.ume, self.ame, self.keibatsu, self.config, self.server_identity)

        # Article feed store + service
        self.article_feed_store = ArticleFeedStore(
            os.path.join(temp_dir, "article_feeds.db"),
            os.path.join(temp_dir, "article_bodies"),
        )
        self.article_service = ArticleService(
            self.article_feed_store, ORIGIN, self.server_identity,
        )
        self.engine.article_service = self.article_service

        # User registry
        self.registry_store = UserRegistryStore(os.path.join(temp_dir, "user_registry.db"))
        self.registry_service = RegistryService(
            self.registry_store, self.ume, self.server_identity, ORIGIN
        )
        self.ume.register_mutation_callback(self.registry_service.mark_dirty)
        self.engine.registry_store = self.registry_store
        self.engine.registry_service = self.registry_service

        self.handler = CommandHandler(self.engine)

        # Cancel sync worker
        task = self.handler._sync_mgr._worker_task
        if task and not task.done():
            task.cancel()

        self.anonymous_identity = Identity.generate()
        self.replay_ledger = ReplayLedger(
            os.path.join(temp_dir, "replay.db"), clock_skew_seconds=30
        )
        self.rate_limiter = RateLimiter(max_requests=100, window_seconds=1)

        self.app = BonnetHTTPServer(
            command_handler=self.handler,
            server_identity=self.server_identity,
            config=self.config,
            ume=self.ume,
            anonymous_identity=self.anonymous_identity,
            replay_ledger=self.replay_ledger,
            rate_limiter=self.rate_limiter,
        )

        # Register the server identity as a local user for write access
        self.ume.ensure_root_user(ORIGIN, self.server_identity.public_key)

    def cleanup(self):
        self.ame.shutdown()
        self.keibatsu.shutdown()
        self.replay_ledger.close()
        self.registry_store.close()
        self.article_feed_store.close()

    def make_client(self):
        transport = ASGITransport(app=self.app)
        return AsyncClient(transport=transport, base_url=f"https://{ORIGIN}")


@pytest_asyncio.fixture
async def setup(temp_dir):
    s = V3ServerSetup(temp_dir)
    yield s
    s.cleanup()


def _make_nonce():
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()


async def _sign_v3_request(identity, body, anonymous_identity=None):
    """Build signed HTTP headers for a v3 command request."""
    if anonymous_identity:
        priv = anonymous_identity.private_key
        pub = anonymous_identity.public_key
    else:
        priv = identity.private_key
        pub = identity.public_key

    cd = compute_content_digest(body)
    nonce = _make_nonce()
    now = int(time.time())
    expires = now + 60

    msg = HTTPMessage(
        method="POST",
        url=f"https://{ORIGIN}/v3/command",
        headers={
            "Content-Type": "application/vnd.bonnet.command",
            "Content-Digest": cd,
            "Bonnet-Version": "3",
            "Bonnet-Nonce": nonce,
        },
        body=body,
    )

    signer = BonnetSigner(private_key=priv, key_id=f"ed25519:{pub.hex()}")
    await signer.sign_request(msg, nonce=nonce, created=now, expires=expires,
                              include_username=False)

    return dict(msg.headers)


def _random_msgid(seed):
    rng = random.Random(seed)
    mid = rng.randbytes(32)
    while mid == ZERO_MESSAGE_ID:
        mid = rng.randbytes(32)
    return mid


def _make_article_submission(seed, body=None, origin=ORIGIN, board=BOARD,
                             author_identity=None):
    """Build an ARTICLE submission + author signature for v3 publishing."""
    if author_identity is None:
        author_identity = Identity.generate()
    if body is None:
        body = f"v3 article body {seed}".encode("utf-8")
    body_hash = compute_body_hash(body)
    sub = Submission(
        submission_version=SUBMISSION_VERSION,
        event_type=EVENT_ARTICLE,
        origin=origin, board=board,
        message_id=_random_msgid(seed),
        created_at=1700000000 + seed,
        actor_pubkey=author_identity.public_key,
        actor_username="root",
        actor_registrar=origin,
        root_message_id=ZERO_MESSAGE_ID,
        headers=ArticleHeaders(subject=f"V3 Article {seed}", tags="test", options=""),
        body_hash=body_hash, body_size=len(body),
    )
    encoded_sub = encode_submission(sub)
    author_sig = sign_author(sub, author_identity)
    return sub, encoded_sub, body, author_sig, author_identity


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestV3ArticlePublish:

    @pytest.mark.asyncio
    async def test_publish_and_get_article(self, setup):
        """ARTICLE_PUBLISH followed by ARTICLE_GET round-trips correctly."""
        async with setup.make_client() as client:
            # Use server identity as author (it's the registered root user)
            author_id = setup.server_identity
            sub, encoded_sub, body, author_sig, _ = _make_article_submission(
                1, author_identity=author_id)

            # Build ARTICLE_PUBLISH request — sign HTTP with server identity
            from client.protocol import build_article_publish, parse_article_publish_resp
            cmd = build_article_publish(encoded_sub, body, SCHEME_V3, author_sig)
            headers = await _sign_v3_request(setup.server_identity, cmd)
            resp = await client.post("/v3/command", content=cmd, headers=headers)
            assert resp.status_code == 200

            # Parse response
            status = resp.content[0]
            assert status == 0x00  # success
            result = parse_article_publish_resp(resp.content[1:])
            event = decode_event(result["event_bytes"])
            assert event.event_type == EVENT_ARTICLE
            assert event.origin == ORIGIN
            assert event.board == BOARD
            assert event.article_num == 1
            assert event.feed_seq == 1

            # ARTICLE_GET by article_num
            from client.protocol import build_article_get, parse_article_get_resp
            cmd2 = build_article_get(BOARD, 0x01, 1, include_body=True)
            headers2 = await _sign_v3_request(setup.server_identity, cmd2)
            resp2 = await client.post("/v3/command", content=cmd2, headers=headers2)
            assert resp2.status_code == 200
            assert resp2.content[0] == 0x00
            result2 = parse_article_get_resp(resp2.content[1:])
            assert result2["projected_state"] == STATE_ACTIVE
            assert result2["body_status"] == BODY_INCLUDED
            assert result2["body"] == body

    @pytest.mark.asyncio
    async def test_publish_multiple_articles(self, setup):
        """Publish 3 articles and verify article_nums are contiguous."""
        async with setup.make_client() as client:
            from client.protocol import build_article_publish
            author_id = setup.server_identity
            for i in range(1, 4):
                sub, encoded_sub, body, author_sig, _ = _make_article_submission(
                    i, author_identity=author_id)
                cmd = build_article_publish(encoded_sub, body, SCHEME_V3, author_sig)
                headers = await _sign_v3_request(setup.server_identity, cmd)
                resp = await client.post("/v3/command", content=cmd, headers=headers)
                assert resp.status_code == 200
                assert resp.content[0] == 0x00


class TestV3ArticleList:

    @pytest.mark.asyncio
    async def test_list_articles_default(self, setup):
        """ARTICLE_LIST returns only active articles by default."""
        async with setup.make_client() as client:
            # Publish 3 articles directly through the service (bypassing HTTP)
            for i in range(1, 4):
                sub, _, body, author_sig, _ = _make_article_submission(
                    i, author_identity=setup.server_identity)
                setup.article_service.publish_article(sub, body, author_sig)

            from client.protocol import build_article_list, parse_article_list_resp
            cmd = build_article_list(BOARD)
            headers = await _sign_v3_request(setup.server_identity, cmd)
            resp = await client.post("/v3/command", content=cmd, headers=headers)
            assert resp.status_code == 200
            assert resp.content[0] == 0x00
            entries = parse_article_list_resp(resp.content[1:])
            assert len(entries) == 3
            for e in entries:
                assert e["projected_state"] == STATE_ACTIVE


class TestV3ArticleSearch:

    @pytest.mark.asyncio
    async def test_search_by_text(self, setup):
        """ARTICLE_SEARCH finds articles by subject text."""
        async with setup.make_client() as client:
            # Publish articles with different subjects using server identity
            for i, subject in enumerate(["Hello World", "Goodbye", "Hello Again"], 1):
                body = f"body {i}".encode("utf-8")
                sub = Submission(
                    submission_version=SUBMISSION_VERSION,
                    event_type=EVENT_ARTICLE, origin=ORIGIN, board=BOARD,
                    message_id=_random_msgid(i), created_at=1700000000 + i,
                    actor_pubkey=setup.server_identity.public_key,
                    actor_username="root", actor_registrar=ORIGIN,
                    headers=ArticleHeaders(subject=subject, tags="", options=""),
                    body_hash=compute_body_hash(body), body_size=len(body),
                )
                sig = sign_author(sub, setup.server_identity)
                setup.article_service.publish_article(sub, body, sig)

            from client.protocol import build_article_search, parse_article_search_resp
            cmd = build_article_search(BOARD, text_query="Hello")
            headers = await _sign_v3_request(setup.server_identity, cmd)
            resp = await client.post("/v3/command", content=cmd, headers=headers)
            assert resp.status_code == 200
            assert resp.content[0] == 0x00
            result = parse_article_search_resp(resp.content[1:])
            assert result["body_search_complete"] == 1
            assert len(result["entries"]) == 2


class TestV3FeedHead:

    @pytest.mark.asyncio
    async def test_feed_head_after_publish(self, setup):
        """FEED_HEAD returns the signed head after articles are published."""
        async with setup.make_client() as client:
            sub, _, body, author_sig, _ = _make_article_submission(
                1, author_identity=setup.server_identity)
            setup.article_service.publish_article(sub, body, author_sig)

            from client.protocol import build_feed_head, parse_feed_head_resp
            cmd = build_feed_head(BOARD)
            headers = await _sign_v3_request(setup.server_identity, cmd)
            resp = await client.post("/v3/command", content=cmd, headers=headers)
            assert resp.status_code == 200
            assert resp.content[0] == 0x00
            head_bytes = parse_feed_head_resp(resp.content[1:])
            head = decode_head(head_bytes)
            assert head.origin == ORIGIN
            assert head.board == BOARD
            assert head.latest_feed_seq == 1
            assert head.article_count == 1

    @pytest.mark.asyncio
    async def test_feed_head_empty_feed(self, setup):
        """FEED_HEAD returns an empty head for a feed with no events."""
        async with setup.make_client() as client:
            from client.protocol import build_feed_head, parse_feed_head_resp
            cmd = build_feed_head("emptyboard")
            headers = await _sign_v3_request(setup.server_identity, cmd)
            resp = await client.post("/v3/command", content=cmd, headers=headers)
            assert resp.status_code == 200
            assert resp.content[0] == 0x00
            head_bytes = parse_feed_head_resp(resp.content[1:])
            head = decode_head(head_bytes)
            assert head.latest_feed_seq == 0
            assert head.article_count == 0


class TestV3FeedEvents:

    @pytest.mark.asyncio
    async def test_feed_events_returns_range(self, setup):
        """FEED_EVENTS returns a contiguous range of encoded events."""
        async with setup.make_client() as client:
            for i in range(1, 4):
                sub, _, body, author_sig, _ = _make_article_submission(
                    i, author_identity=setup.server_identity)
                setup.article_service.publish_article(sub, body, author_sig)

            from client.protocol import build_feed_events, parse_feed_events_resp
            cmd = build_feed_events(BOARD, start_seq=1, max_count=10)
            headers = await _sign_v3_request(setup.server_identity, cmd)
            resp = await client.post("/v3/command", content=cmd, headers=headers)
            assert resp.status_code == 200
            assert resp.content[0] == 0x00
            events = parse_feed_events_resp(resp.content[1:])
            assert len(events) == 3
            for i, ev_bytes in enumerate(events):
                ev = decode_event(ev_bytes)
                assert ev.feed_seq == i + 1
                assert ev.event_type == EVENT_ARTICLE


class TestV3FeedHeads:

    @pytest.mark.asyncio
    async def test_feed_heads_lists_all(self, setup):
        """FEED_HEADS lists heads across all boards."""
        async with setup.make_client() as client:
            # Publish to two boards with different seeds
            for i, board in enumerate([BOARD, "another"], 1):
                sub, _, body, author_sig, _ = _make_article_submission(
                    i, board=board, author_identity=setup.server_identity)
                setup.article_service.publish_article(sub, body, author_sig)

            from client.protocol import build_feed_heads, parse_feed_heads_resp
            cmd = build_feed_heads()
            headers = await _sign_v3_request(setup.server_identity, cmd)
            resp = await client.post("/v3/command", content=cmd, headers=headers)
            assert resp.status_code == 200
            assert resp.content[0] == 0x00
            entries = parse_feed_heads_resp(resp.content[1:])
            assert len(entries) >= 2
            boards = {e["board"] for e in entries}
            assert BOARD in boards
            assert "another" in boards

    @pytest.mark.asyncio
    async def test_empty_board_visible_in_feed_heads(self, setup):
        """BOARD_CREATE creates a stored empty feed head, so an empty board
        is visible in FEED_HEADS immediately (§9 lines 707-716)."""
        async with setup.make_client() as client:
            # Create a board via the v3 command endpoint
            from client.protocol import build_board_create
            cmd = build_board_create("emptyboard")
            headers = await _sign_v3_request(setup.server_identity, cmd)
            resp = await client.post("/v3/command", content=cmd, headers=headers)
            assert resp.status_code == 200
            assert resp.content[0] == 0x00  # success

            # The empty board should appear in FEED_HEADS
            from client.protocol import build_feed_heads, parse_feed_heads_resp
            cmd2 = build_feed_heads()
            headers2 = await _sign_v3_request(setup.server_identity, cmd2)
            resp2 = await client.post("/v3/command", content=cmd2, headers=headers2)
            assert resp2.status_code == 200
            assert resp2.content[0] == 0x00
            entries = parse_feed_heads_resp(resp2.content[1:])
            boards = {e["board"] for e in entries}
            assert "emptyboard" in boards

            # The head should report seq=0, article_count=0
            from client.protocol import build_feed_head, parse_feed_head_resp
            cmd3 = build_feed_head("emptyboard")
            headers3 = await _sign_v3_request(setup.server_identity, cmd3)
            resp3 = await client.post("/v3/command", content=cmd3, headers=headers3)
            assert resp3.status_code == 200
            assert resp3.content[0] == 0x00
            head_bytes = parse_feed_head_resp(resp3.content[1:])
            head = decode_head(head_bytes)
            assert head.latest_feed_seq == 0
            assert head.article_count == 0
            assert head.origin == ORIGIN
            assert head.board == "emptyboard"

    @pytest.mark.asyncio
    async def test_feed_head_stable_across_requests(self, setup):
        """The stored empty head is stable — same bytes on repeated requests."""
        async with setup.make_client() as client:
            # Create a board
            from client.protocol import build_board_create
            cmd = build_board_create("stableboard")
            headers = await _sign_v3_request(setup.server_identity, cmd)
            await client.post("/v3/command", content=cmd, headers=headers)

            # Request FEED_HEAD twice — should get the same encoded head
            from client.protocol import build_feed_head, parse_feed_head_resp
            cmd2 = build_feed_head("stableboard")
            headers2 = await _sign_v3_request(setup.server_identity, cmd2)
            resp1 = await client.post("/v3/command", content=cmd2, headers=headers2)
            head_bytes_1 = parse_feed_head_resp(resp1.content[1:])

            headers3 = await _sign_v3_request(setup.server_identity, cmd2)
            resp2 = await client.post("/v3/command", content=cmd2, headers=headers3)
            head_bytes_2 = parse_feed_head_resp(resp2.content[1:])

            assert head_bytes_1 == head_bytes_2  # stable, not ephemeral


class TestV3BanStatus:

    @pytest.mark.asyncio
    async def test_ban_status_not_banned(self, setup):
        """BAN_STATUS returns not-banned for an unregistered key."""
        async with setup.make_client() as client:
            from client.protocol import build_ban_status, parse_ban_status_resp
            pubkey = Identity.generate().public_key
            cmd = build_ban_status(pubkey)
            headers = await _sign_v3_request(setup.server_identity, cmd)
            resp = await client.post("/v3/command", content=cmd, headers=headers)
            assert resp.status_code == 200
            assert resp.content[0] == 0x00
            result = parse_ban_status_resp(resp.content[1:])
            assert result["banned"] is False


class TestV3ArticleBody:

    @pytest.mark.asyncio
    async def test_article_body_fetch(self, setup):
        """ARTICLE_BODY fetches a body by hash."""
        async with setup.make_client() as client:
            sub, _, body, author_sig, _ = _make_article_submission(
                1, author_identity=setup.server_identity)
            event, _ = setup.article_service.publish_article(sub, body, author_sig)

            from client.protocol import build_article_body, parse_article_body_resp
            cmd = build_article_body(BOARD, sub.message_id, sub.body_hash)
            headers = await _sign_v3_request(setup.server_identity, cmd)
            resp = await client.post("/v3/command", content=cmd, headers=headers)
            assert resp.status_code == 200
            assert resp.content[0] == 0x00
            fetched = parse_article_body_resp(resp.content[1:])
            assert fetched == body


class TestV3BoardSetState:

    def _make_board_state_submission(self, seed, event_type, board=BOARD,
                                     origin=ORIGIN, author_identity=None,
                                     body_text=b"closing the board"):
        """Build a BOARD_CLOSE or BOARD_REOPEN submission."""
        from core.article_feed import (
            EVENT_BOARD_CLOSE, EVENT_BOARD_REOPEN, ZERO_MESSAGE_ID,
        )
        if author_identity is None:
            author_identity = Identity.generate()
        body_hash = compute_body_hash(body_text)
        sub = Submission(
            submission_version=SUBMISSION_VERSION,
            event_type=event_type,
            origin=origin, board=board,
            message_id=_random_msgid(seed),
            created_at=1700000000 + seed,
            actor_pubkey=author_identity.public_key,
            actor_username="admin",
            actor_registrar=origin,
            headers=None,
            body_hash=body_hash,
            body_size=len(body_text),
        )
        sig = sign_author(sub, author_identity)
        return sub, body_text, sig, author_identity

    def _build_board_set_state_cmd(self, encoded_sub, body, author_sig):
        """Build a BOARD_SET_STATE command (opcode 0x1A) with ARTICLE_PUBLISH framing."""
        from client.protocol import V3_COMMANDS
        return (
            struct.pack(">B", V3_COMMANDS["BOARD_SET_STATE"])
            + struct.pack(">I", len(encoded_sub)) + encoded_sub
            + struct.pack(">I", len(body)) + body
            + struct.pack(">B", SCHEME_V3)
            + struct.pack(">H", len(author_sig)) + author_sig
        )

    @pytest.mark.asyncio
    async def test_board_close(self, setup):
        """BOARD_SET_STATE with BOARD_CLOSE publishes a close event and updates nav."""
        async with setup.make_client() as client:
            # Create a board first
            setup.ame.create_board(BOARD)

            from client.protocol import parse_article_publish_resp
            from core.article_feed import EVENT_BOARD_CLOSE
            sub, body, sig, _ = self._make_board_state_submission(
                1, EVENT_BOARD_CLOSE, author_identity=setup.server_identity)
            encoded_sub = encode_submission(sub)
            cmd = self._build_board_set_state_cmd(encoded_sub, body, sig)
            headers = await _sign_v3_request(setup.server_identity, cmd)
            resp = await client.post("/v3/command", content=cmd, headers=headers)
            assert resp.status_code == 200
            assert resp.content[0] == 0x00
            result = parse_article_publish_resp(resp.content[1:])
            event = decode_event(result["event_bytes"])
            assert event.event_type == EVENT_BOARD_CLOSE
            assert event.board == BOARD

            # Verify nav closed flag is set
            nav_entry = setup.ame.get_nav().get(BOARD)
            assert nav_entry['closed'] is True

    @pytest.mark.asyncio
    async def test_board_reopen(self, setup):
        """BOARD_SET_STATE with BOARD_REOPEN publishes a reopen event and clears nav."""
        async with setup.make_client() as client:
            setup.ame.create_board(BOARD)
            # Close it first
            setup.ame.close_board(BOARD)

            from client.protocol import parse_article_publish_resp
            from core.article_feed import EVENT_BOARD_REOPEN
            sub, body, sig, _ = self._make_board_state_submission(
                2, EVENT_BOARD_REOPEN, author_identity=setup.server_identity,
                body_text=b"reopening")
            encoded_sub = encode_submission(sub)
            cmd = self._build_board_set_state_cmd(encoded_sub, body, sig)
            headers = await _sign_v3_request(setup.server_identity, cmd)
            resp = await client.post("/v3/command", content=cmd, headers=headers)
            assert resp.status_code == 200
            assert resp.content[0] == 0x00
            result = parse_article_publish_resp(resp.content[1:])
            event = decode_event(result["event_bytes"])
            assert event.event_type == EVENT_BOARD_REOPEN

            # Verify nav closed flag is cleared
            nav_entry = setup.ame.get_nav().get(BOARD)
            assert nav_entry['closed'] is False

    @pytest.mark.asyncio
    async def test_board_close_already_closed_returns_409(self, setup):
        """BOARD_CLOSE on an already-closed board returns 409."""
        async with setup.make_client() as client:
            setup.ame.create_board(BOARD)
            setup.ame.close_board(BOARD)

            from core.article_feed import EVENT_BOARD_CLOSE
            sub, body, sig, _ = self._make_board_state_submission(
                3, EVENT_BOARD_CLOSE, author_identity=setup.server_identity)
            encoded_sub = encode_submission(sub)
            cmd = self._build_board_set_state_cmd(encoded_sub, body, sig)
            headers = await _sign_v3_request(setup.server_identity, cmd)
            resp = await client.post("/v3/command", content=cmd, headers=headers)
            assert resp.status_code == 200
            assert resp.content[0] == 0x01  # error
            code = struct.unpack(">H", resp.content[1:3])[0]
            assert code == 409

    @pytest.mark.asyncio
    async def test_board_set_state_rejects_wrong_event_type(self, setup):
        """BOARD_SET_STATE rejects ARTICLE submissions with 400."""
        async with setup.make_client() as client:
            setup.ame.create_board(BOARD)

            # Build an ARTICLE submission but send it via BOARD_SET_STATE opcode
            sub, encoded_sub, body, sig, _ = _make_article_submission(
                4, author_identity=setup.server_identity)
            cmd = self._build_board_set_state_cmd(encoded_sub, body, sig)
            headers = await _sign_v3_request(setup.server_identity, cmd)
            resp = await client.post("/v3/command", content=cmd, headers=headers)
            assert resp.status_code == 200
            assert resp.content[0] == 0x01  # error
            code = struct.unpack(">H", resp.content[1:3])[0]
            assert code == 400
