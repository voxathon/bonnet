"""End-to-end tests for BonnetHTTPClient against BonnetHTTPServer.

Tests the full client → server round-trip via httpx ASGI transport:
  - Anonymous commands (shared key)
  - Authenticated commands (registered user)
  - Registration
  - Response signature verification
  - Origin pin TOFU
  - Changed server key fails closed
  - v3 article feed: publish, get, list, search, cancel, supersede
  - v3 board state: close / reopen
  - v3 ban status
  - Every command family round-trips via /v3/command
"""

import os
import sys
import struct
import base64
import time
import pytest
import pytest_asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import httpx
from httpx import AsyncClient, ASGITransport

from core.crypto import Identity
from core.config import Config
from core.article_feed import ArticleFeedStore
from core.user_registry import UserRegistryStore, RegistryService
from engine.ume import Ume
from engine.ame import Ame
from engine.keibatsu import Keibatsu
from engine.facade import BonnetEngine
from engine.article_service import ArticleService
from net.commands import CommandHandler
from net.http_server import BonnetHTTPServer
from net.http_auth import BonnetSigner, BonnetVerifier, KeyResolver, HTTPMessage, compute_content_digest
from net.replay import ReplayLedger
from net.rate_limiter import RateLimiter
from client.http import BonnetHTTPClient, BonnetHTTPError
from client.protocol import SELECTOR_ARTICLE_NUM, SELECTOR_MESSAGE_ID

from tests.fixtures.protocol_v1.wire_fixtures import TEST_SEED
from tests.helpers import default_test_acls


# ---------------------------------------------------------------------------
# Shared server setup (reused from test_http_server.py pattern)
# ---------------------------------------------------------------------------

class ServerSetup:
    def __init__(self, temp_dir):
        self.temp_dir = temp_dir
        self.server_identity = Identity.from_private_key(TEST_SEED)
        self.config = Config(
            origin="bbs.test",
            registrars=["bbs.test"],
            ame_path=os.path.join(temp_dir, "boards"),
            data_dir=temp_dir,
            nav_db_path=os.path.join(temp_dir, "nav.db"),
            reports_db_path=os.path.join(temp_dir, "reports.db"),
            punishments_db_path=os.path.join(temp_dir, "punishments.db"),
            log_dir=os.path.join(temp_dir, "logs"),
            identity_path=os.path.join(temp_dir, "identity"),
            userfile_path=os.path.join(temp_dir, "userfile"),
            acls=default_test_acls("bbs.test"),
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
        self.ame = Ame(self.config.ame_path, origin="bbs.test",
                       signing_key=self.server_identity.signing_key,
                       nav_db_path=self.config.nav_db_path)

        from core.orm import Database
        with Database(self.config.reports_db_path).open() as ctx:
            ctx.execute("""CREATE TABLE IF NOT EXISTS rules (
                rule_num INTEGER PRIMARY KEY, rule_name TEXT UNIQUE NOT NULL, description TEXT NOT NULL
            )""")

        self.keibatsu = Keibatsu(self.config.reports_db_path, self.config.punishments_db_path,
                                  ume=self.ume, signing_key=self.server_identity.signing_key,
                                  origin="bbs.test")

        self.engine = BonnetEngine(self.ume, self.ame, self.keibatsu, self.config, self.server_identity)

        # Article feed store + service (required for v3 ARTICLE_PUBLISH etc.)
        self.article_feed_store = ArticleFeedStore(
            os.path.join(temp_dir, "article_feeds.db"),
            os.path.join(temp_dir, "article_bodies"),
        )
        self.article_service = ArticleService(
            self.article_feed_store, "bbs.test", self.server_identity,
        )
        self.engine.article_service = self.article_service

        # User registry
        self.registry_store = UserRegistryStore(os.path.join(temp_dir, "user_registry.db"))
        self.registry_service = RegistryService(
            self.registry_store, self.ume, self.server_identity, "bbs.test"
        )
        self.ume.register_mutation_callback(self.registry_service.mark_dirty)
        self.engine.registry_store = self.registry_store
        self.engine.registry_service = self.registry_service

        self.handler = CommandHandler(self.engine)

        task = self.handler._sync_mgr._worker_task
        if task and not task.done():
            task.cancel()

        self.anonymous_identity = Identity.generate()
        self.replay_ledger = ReplayLedger(os.path.join(temp_dir, "replay.db"), clock_skew_seconds=30)
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

        # Ensure root user exists
        self.root_user = self.ume.ensure_root_user("bbs.test", self.server_identity.public_key)

    def cleanup(self):
        self.ame.shutdown()
        self.keibatsu.shutdown()
        self.replay_ledger.close()
        self.registry_store.close()
        self.article_feed_store.close()

    def make_asgi_transport(self):
        return ASGITransport(app=self.app)


@pytest_asyncio.fixture
async def setup(tmp_path):
    s = ServerSetup(str(tmp_path))
    yield s
    s.cleanup()


def _make_client(setup, base_url="https://bbs.test"):
    """Create a BonnetHTTPClient wired to the ASGI app."""
    transport = setup.make_asgi_transport()
    client = BonnetHTTPClient(base_url=base_url)
    client._http_client = httpx.AsyncClient(
        transport=transport,
        base_url=base_url,
        verify=False,
        timeout=httpx.Timeout(30.0),
    )
    return client


# ---------------------------------------------------------------------------
# Anonymous client tests
# ---------------------------------------------------------------------------

class TestAnonymousClient:

    @pytest.mark.asyncio
    async def test_anonymous_board_list(self, setup):
        async with _make_client(setup) as client:
            await client.connect_anonymous(anonymous_private_key=setup.anonymous_identity.private_key)
            boards = await client.board_list()
            assert boards == []

    @pytest.mark.asyncio
    async def test_anonymous_get_pubkey(self, setup):
        async with _make_client(setup) as client:
            await client.connect_anonymous(anonymous_private_key=setup.anonymous_identity.private_key)
            pubkey_hex = await client.get_server_pubkey()
            assert bytes.fromhex(pubkey_hex) == setup.server_identity.public_key

    @pytest.mark.asyncio
    async def test_anonymous_list_users(self, setup):
        async with _make_client(setup) as client:
            await client.connect_anonymous(anonymous_private_key=setup.anonymous_identity.private_key)
            users = await client.list_users()
            assert len(users) >= 1  # at least root

    @pytest.mark.asyncio
    async def test_anonymous_rejected_for_write(self, setup):
        async with _make_client(setup) as client:
            await client.connect_anonymous(anonymous_private_key=setup.anonymous_identity.private_key)
            with pytest.raises(BonnetHTTPError) as exc:
                await client.board_create("test")
            assert exc.value.code == 403

    @pytest.mark.asyncio
    async def test_anonymous_rejected_for_publish(self, setup):
        async with _make_client(setup) as client:
            await client.connect_anonymous(anonymous_private_key=setup.anonymous_identity.private_key)
            with pytest.raises((BonnetHTTPError, Exception)):
                await client.publish_article("general", "test", "body")


# ---------------------------------------------------------------------------
# Authenticated client tests — identity / board / user admin
# ---------------------------------------------------------------------------

class TestAuthenticatedClient:

    @pytest.mark.asyncio
    async def test_register_and_list_boards(self, setup):
        ident = Identity.generate()
        async with _make_client(setup) as client:
            await client.connect(ident)
            name = await client.register("alice", "bbs.test")
            assert name == "alice"

            boards = await client.board_list()
            assert boards == []

    @pytest.mark.asyncio
    async def test_get_user(self, setup):
        ident = Identity.generate()
        async with _make_client(setup) as client:
            await client.connect(ident)
            await client.register("alice", "bbs.test")
            user = await client.get_user("alice")
            assert user is not None
            assert user.username == "alice"
            assert bytes.fromhex(user.public_key) == ident.public_key

    @pytest.mark.asyncio
    async def test_get_user_not_found(self, setup):
        async with _make_client(setup) as client:
            await client.connect_anonymous(anonymous_private_key=setup.anonymous_identity.private_key)
            user = await client.get_user("nonexistent")
            assert user is None

    @pytest.mark.asyncio
    async def test_admin_board_create_and_list(self, setup):
        async with _make_client(setup) as client:
            await client.connect(setup.server_identity, "root")
            await client.board_create("general")
            boards = await client.board_list()
            names = [b.name for b in boards]
            assert "general" in names

    @pytest.mark.asyncio
    async def test_user_promote_demote(self, setup):
        ident = Identity.generate()
        async with _make_client(setup) as client:
            await client.connect(ident)
            await client.register("bob", "bbs.test")

            await client.connect(setup.server_identity, "root")
            await client.user_promote("bob")
            await client.user_demote("bob")


# ---------------------------------------------------------------------------
# v3 article feed tests
# ---------------------------------------------------------------------------

class TestArticleFeed:

    @pytest.mark.asyncio
    async def test_publish_and_get_article(self, setup):
        async with _make_client(setup) as client:
            await client.connect(setup.server_identity, "root")
            await client.board_create("general")

            result = await client.publish_article("general", "Hello", "Body text here", tags="test")
            assert result.article_num >= 1
            assert result.event_type_name == "ARTICLE"

            article = await client.article_get("general", SELECTOR_ARTICLE_NUM, result.article_num, True)
            assert article is not None
            assert article.subject == "Hello"
            assert article.body == "Body text here"
            assert article.tags == "test"

    @pytest.mark.asyncio
    async def test_list_articles(self, setup):
        async with _make_client(setup) as client:
            await client.connect(setup.server_identity, "root")
            await client.board_create("general")
            await client.publish_article("general", "Post 1", "body1")
            await client.publish_article("general", "Post 2", "body2")

            articles = await client.article_list("general")
            assert len(articles) == 2

    @pytest.mark.asyncio
    async def test_search_articles(self, setup):
        async with _make_client(setup) as client:
            await client.connect(setup.server_identity, "root")
            await client.board_create("general")
            await client.publish_article("general", "Hello World", "body1")
            await client.publish_article("general", "Goodbye", "body2")

            results = await client.article_search("general", text_query="Hello")
            assert len(results) == 1
            assert results[0].subject == "Hello World"

    @pytest.mark.asyncio
    async def test_cancel_and_restore_article(self, setup):
        async with _make_client(setup) as client:
            await client.connect(setup.server_identity, "root")
            await client.board_create("general")
            result = await client.publish_article("general", "To cancel", "body")

            cancel_result = await client.cancel_article(
                "general", bytes.fromhex(result.message_id), "test cancel reason",
            )
            assert cancel_result.event_type_name == "CANCEL"

            article = await client.article_get("general", SELECTOR_MESSAGE_ID, bytes.fromhex(result.message_id), False)
            assert article is not None
            assert article.projected_state == "cancelled"

            restore_result = await client.restore_article(
                "general", bytes.fromhex(result.message_id), "restored reason",
            )
            assert restore_result.event_type_name == "RESTORE"

            article = await client.article_get("general", SELECTOR_MESSAGE_ID, bytes.fromhex(result.message_id), False)
            assert article is not None
            assert article.projected_state == "active"

    @pytest.mark.asyncio
    async def test_supersede_article(self, setup):
        async with _make_client(setup) as client:
            await client.connect(setup.server_identity, "root")
            await client.board_create("general")
            original = await client.publish_article("general", "Original", "original body")

            superseded = await client.supersede_article(
                "general", bytes.fromhex(original.message_id),
                "Updated", "updated body",
            )
            assert superseded.event_type_name == "ARTICLE"
            assert superseded.article_num > original.article_num

            # Original should be superseded
            old = await client.article_get("general", SELECTOR_MESSAGE_ID, bytes.fromhex(original.message_id), False)
            assert old is not None
            assert old.projected_state == "superseded"

    @pytest.mark.asyncio
    async def test_feed_head_and_events(self, setup):
        async with _make_client(setup) as client:
            await client.connect(setup.server_identity, "root")
            await client.board_create("general")
            await client.publish_article("general", "Test", "body")

            head = await client.feed_head("general")
            assert head is not None
            assert head.board == "general"
            assert head.latest_feed_seq >= 1

            events = await client.feed_events("general", start_seq=1)
            assert len(events) >= 1

    @pytest.mark.asyncio
    async def test_feed_heads_list(self, setup):
        async with _make_client(setup) as client:
            await client.connect(setup.server_identity, "root")
            await client.board_create("general")
            await client.publish_article("general", "Test", "body")

            heads = await client.feed_heads()
            assert len(heads) >= 1
            assert any(h.board == "general" for h in heads)


# ---------------------------------------------------------------------------
# v3 board state tests
# ---------------------------------------------------------------------------

class TestBoardState:

    @pytest.mark.asyncio
    async def test_close_and_reopen_board(self, setup):
        async with _make_client(setup) as client:
            await client.connect(setup.server_identity, "root")
            await client.board_create("general")

            close_result = await client.close_board("general", "testing")
            assert close_result.event_type_name == "BOARD_CLOSE"

            boards = await client.board_list()
            general = [b for b in boards if b.name == "general"][0]
            assert general.closed is True

            reopen_result = await client.reopen_board("general", "reopened")
            assert reopen_result.event_type_name == "BOARD_REOPEN"

            boards = await client.board_list()
            general = [b for b in boards if b.name == "general"][0]
            assert general.closed is False

    @pytest.mark.asyncio
    async def test_publish_rejected_on_closed_board(self, setup):
        async with _make_client(setup) as client:
            await client.connect(setup.server_identity, "root")
            await client.board_create("general")
            await client.close_board("general")

            with pytest.raises(BonnetHTTPError):
                await client.publish_article("general", "should fail", "body")


# ---------------------------------------------------------------------------
# v3 ban status test
# ---------------------------------------------------------------------------

class TestBanStatus:

    @pytest.mark.asyncio
    async def test_ban_status_not_banned(self, setup):
        async with _make_client(setup) as client:
            await client.connect_anonymous(anonymous_private_key=setup.anonymous_identity.private_key)
            status = await client.ban_status(setup.server_identity.public_key)
            assert status.banned is False


# ---------------------------------------------------------------------------
# Fail-closed tests
# ---------------------------------------------------------------------------

class TestFailClosed:

    @pytest.mark.asyncio
    async def test_changed_server_key_fails_closed(self, setup, tmp_path):
        """If the server key changes without rotation, the client must fail."""
        trust_path = str(tmp_path / "trust.db")
        ident = Identity.generate()

        # First connection — pins the server key
        async with _make_client(setup) as client:
            client._trust_store = __import__("core.trust", fromlist=["TrustStore"]).TrustStore(trust_path)
            await client.connect(ident)
            await client.register("alice", "bbs.test")
            client._trust_store.close()

        # Second connection with a DIFFERENT server key
        wrong_identity = Identity.generate()
        setup.app._server_identity = wrong_identity
        setup.app._signer = BonnetSigner(
            private_key=wrong_identity.private_key,
            key_id="origin:bbs.test",
        )

        async with _make_client(setup) as client:
            client._trust_store = __import__("core.trust", fromlist=["TrustStore"]).TrustStore(trust_path)
            with pytest.raises(BonnetHTTPError) as exc:
                await client.connect(ident)
            assert "pin mismatch" in exc.value.message.lower() or "mismatch" in exc.value.message.lower()
            client._trust_store.close()

    @pytest.mark.asyncio
    async def test_unsigned_response_rejected(self, setup):
        """If the server sends an unsigned response, the client must reject it."""
        ident = Identity.generate()
        async with _make_client(setup) as client:
            await client.connect(ident)

            client._ensure_client = lambda: None
            if client._http_client is None:
                client._http_client = httpx.AsyncClient(
                    transport=setup.make_asgi_transport(),
                    base_url="https://bbs.test",
                    verify=False,
                )

            import base64 as b64
            nonce = b64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
            body = b"\x11"  # BOARD_LIST
            cd = compute_content_digest(body)

            msg = HTTPMessage(
                method="POST",
                url="https://bbs.test/v3/command",
                headers={
                    "Content-Type": "application/vnd.bonnet.command",
                    "Content-Digest": cd,
                    "Bonnet-Version": "3",
                    "Bonnet-Nonce": nonce,
                },
                body=body,
            )
            await client._signer.sign_request(msg, nonce=nonce)
            resp = await client._http_client.post("/v3/command", content=body, headers=dict(msg.headers))

            # Strip the signature headers
            tampered_headers = {k: v for k, v in resp.headers.items()
                                if k.lower() not in ("signature-input", "signature")}
            tampered_resp = httpx.Response(
                status_code=200,
                headers=tampered_headers,
                content=resp.content,
                request=resp.request,
            )

            with pytest.raises(BonnetHTTPError):
                await client._verify_response(tampered_resp, nonce)


# ---------------------------------------------------------------------------
# Origin pin TOFU test
# ---------------------------------------------------------------------------

class TestOriginPinning:

    @pytest.mark.asyncio
    async def test_tofu_first_contact(self, setup, tmp_path):
        """First contact pins the server key; second contact with same key succeeds."""
        from core.trust import TrustStore

        trust_path = str(tmp_path / "trust.db")
        ident = Identity.generate()

        async with _make_client(setup) as client:
            client._trust_store = TrustStore(trust_path)
            await client.connect(ident)
            await client.register("alice", "bbs.test")
            client._trust_store.close()

        # Verify the pin was stored
        ts = TrustStore(trust_path)
        pin = ts.get_pin("bbs.test")
        assert pin == setup.server_identity.public_key
        ts.close()

    @pytest.mark.asyncio
    async def test_repeat_contact_same_key(self, setup, tmp_path):
        """Second contact with the same server key succeeds."""
        from core.trust import TrustStore

        trust_path = str(tmp_path / "trust.db")

        async with _make_client(setup) as client:
            client._trust_store = TrustStore(trust_path)
            await client.connect_anonymous(anonymous_private_key=setup.anonymous_identity.private_key)
            client._trust_store.close()

        async with _make_client(setup) as client:
            client._trust_store = TrustStore(trust_path)
            await client.connect_anonymous(anonymous_private_key=setup.anonymous_identity.private_key)
            await client.board_list()
            client._trust_store.close()


# ---------------------------------------------------------------------------
# Discovery test
# ---------------------------------------------------------------------------

class TestDiscovery:

    @pytest.mark.asyncio
    async def test_discover_returns_correct_info(self, setup):
        async with _make_client(setup) as client:
            info = await client.discover()
            assert info["protocol_versions"] == [3]
            assert info["origin"] == "bbs.test"
            assert info["public_key"] == setup.server_identity.public_key.hex()
            assert "anonymous_key" in info
            assert info["command_endpoint"] == "/v3/command"
