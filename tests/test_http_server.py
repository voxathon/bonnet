"""Integration tests for the Bonnet v2 HTTP server.

Tests the full ASGI request/response cycle via httpx ASGITransport:
  - Discovery endpoint
  - Anonymous command (shared key)
  - Authenticated command
  - Registration (unregistered key)
  - Malformed traffic rejection
  - Replay detection
  - Rate limiting
  - Response signature verification

Run: PYTHONPATH=src uv run pytest tests/test_http_server.py -v
"""

import os
import sys
import json
import base64
import struct
import time
import pytest
import pytest_asyncio
from unittest.mock import MagicMock, AsyncMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import httpx
from httpx import AsyncClient, ASGITransport

from core.crypto import Identity
from core.config import Config
from engine.ume import Ume
from engine.ame import Ame
from engine.keibatsu import Keibatsu
from engine.facade import BonnetEngine
from net.commands import CommandHandler
from net.http_server import BonnetHTTPServer
from net.http_auth import (
    BonnetSigner, BonnetVerifier, KeyResolver, HTTPMessage,
    compute_content_digest, BONNET_TAG,
)
from net.replay import ReplayLedger
from net.rate_limiter import RateLimiter
from net.context import CommandContext

from tests.fixtures.protocol_v1.wire_fixtures import TEST_SEED


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def temp_dir(tmp_path):
    return str(tmp_path)


class ServerSetup:
    """Reusable server setup for integration tests."""

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
            acls=[],
            anonymous_read=True,
            max_request_size=10 * 1024 * 1024,
            rate_limit_requests=100,
            rate_limit_window=1,
            public_commands={0x02, 0x03, 0x04, 0x11, 0x13, 0x14, 0x19, 0x30,
                             0x41, 0x42, 0x43, 0x51, 0x52, 0x54, 0x61, 0x62, 0x63, 0x71},
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

        # Init rules table
        from core.orm import Database
        with Database(self.config.reports_db_path).open() as ctx:
            ctx.execute("""CREATE TABLE IF NOT EXISTS rules (
                rule_num INTEGER PRIMARY KEY, rule_name TEXT UNIQUE NOT NULL, description TEXT NOT NULL
            )""")

        self.keibatsu = Keibatsu(self.config.reports_db_path, self.config.punishments_db_path,
                                  ume=self.ume, signing_key=self.server_identity.signing_key,
                                  origin="bbs.test")

        self.engine = BonnetEngine(self.ume, self.ame, self.keibatsu, self.config, self.server_identity)
        self.handler = CommandHandler(self.engine)

        # Cancel sync worker to avoid lingering tasks
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

    def cleanup(self):
        self.ame.shutdown()
        self.keibatsu.shutdown()
        self.replay_ledger.close()

    def make_client(self):
        transport = ASGITransport(app=self.app)
        return AsyncClient(transport=transport, base_url="https://bbs.test")


@pytest_asyncio.fixture
async def setup(temp_dir):
    s = ServerSetup(temp_dir)
    yield s
    s.cleanup()


def _make_nonce():
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()


async def _sign_request(client_identity, url, body, anonymous_identity=None, username=None):
    """Build a signed HTTP request dict for httpx."""
    if anonymous_identity:
        priv = anonymous_identity.private_key
        pub = anonymous_identity.public_key
    else:
        priv = client_identity.private_key
        pub = client_identity.public_key

    cd = compute_content_digest(body)
    nonce = _make_nonce()
    now = int(time.time())
    expires = now + 60

    msg = HTTPMessage(
        method="POST",
        url=url,
        headers={
            "Content-Type": "application/vnd.bonnet.command",
            "Content-Digest": cd,
            "Bonnet-Version": "2",
            "Bonnet-Nonce": nonce,
        },
        body=body,
    )
    if username:
        msg.set_header("Bonnet-Username", username)

    signer = BonnetSigner(private_key=priv, key_id=f"ed25519:{pub.hex()}")
    await signer.sign_request(msg, nonce=nonce, created=now, expires=expires,
                              include_username=bool(username))

    headers = dict(msg.headers)
    return headers


# ---------------------------------------------------------------------------
# Discovery tests
# ---------------------------------------------------------------------------

class TestDiscovery:

    @pytest.mark.asyncio
    async def test_discovery_returns_json(self, setup):
        async with setup.make_client() as client:
            resp = await client.get("/.well-known/bonnet")

        assert resp.status_code == 200
        data = resp.json()
        assert data["protocol_versions"] == [2]
        assert data["origin"] == "bbs.test"
        assert data["public_key"] == setup.server_identity.public_key.hex()
        assert data["command_endpoint"] == "/v2/command"
        assert "anonymous_key" in data
        assert data["anonymous_key"] == setup.anonymous_identity.public_key.hex()

    @pytest.mark.asyncio
    async def test_discovery_response_signed(self, setup):
        async with setup.make_client() as client:
            resp = await client.get("/.well-known/bonnet")

        assert "signature-input" in resp.headers
        assert "signature" in resp.headers
        assert "bonnet-version" in resp.headers
        assert resp.headers["bonnet-version"] == "2"
        assert resp.headers["bonnet-origin"] == "bbs.test"

    @pytest.mark.asyncio
    async def test_discovery_anonymous_key_matches_server(self, setup):
        async with setup.make_client() as client:
            resp = await client.get("/.well-known/bonnet")

        data = resp.json()
        assert bytes.fromhex(data["anonymous_key"]) == setup.app.anonymous_public_key


# ---------------------------------------------------------------------------
# Anonymous command tests (shared key)
# ---------------------------------------------------------------------------

class TestAnonymousCommand:

    @pytest.mark.asyncio
    async def test_anonymous_board_list(self, setup):
        """Anonymous request signed with shared key can run BOARD_LIST (public command)."""
        body = b"\x11"  # BOARD_LIST
        headers = await _sign_request(
            None, "https://bbs.test/v2/command", body,
            anonymous_identity=setup.anonymous_identity
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200
        assert resp.headers["bonnet-version"] == "2"
        assert resp.headers["bonnet-origin"] == "bbs.test"
        assert "signature-input" in resp.headers
        # Response body starts with status byte
        assert resp.content[0] == 0x00  # SUCCESS

    @pytest.mark.asyncio
    async def test_anonymous_get_pubkey(self, setup):
        """Anonymous GET_PUBKEY returns server public key."""
        body = b"\x30"  # GET_PUBKEY
        headers = await _sign_request(
            None, "https://bbs.test/v2/command", body,
            anonymous_identity=setup.anonymous_identity
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200
        assert resp.content[0] == 0x00  # SUCCESS
        assert resp.content[1:33] == setup.server_identity.public_key

    @pytest.mark.asyncio
    async def test_anonymous_rejected_for_private_command(self, setup):
        """Anonymous cannot run BOARD_CREATE (not in public_commands)."""
        body = b"\x10" + bytes([7]) + b"general"  # BOARD_CREATE
        headers = await _sign_request(
            None, "https://bbs.test/v2/command", body,
            anonymous_identity=setup.anonymous_identity
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200
        assert resp.content[0] == 0x01  # ERROR
        code = struct.unpack(">H", resp.content[1:3])[0]
        assert code == 401


# ---------------------------------------------------------------------------
# Authenticated command tests
# ---------------------------------------------------------------------------

class TestAuthenticatedCommand:

    @pytest.mark.asyncio
    async def test_register_new_user(self, setup):
        """An unregistered key can REGISTER."""
        client_ident = Identity.generate()
        body = bytes([0x01]) + bytes([5]) + b"alice" + bytes([8]) + b"bbs.test"
        headers = await _sign_request(
            client_ident, "https://bbs.test/v2/command", body
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200
        if resp.content[0] != 0x00:
            code = struct.unpack(">H", resp.content[1:3])[0]
            msg_len = resp.content[3]
            msg = resp.content[4:4+msg_len].decode("utf-8", errors="replace")
            pytest.fail(f"Registration failed: code={code}, msg={msg}")
        assert resp.content[0] == 0x00  # SUCCESS

    @pytest.mark.asyncio
    async def test_registered_user_board_create(self, setup):
        """A registered user can create a board (needs admin — root user)."""
        root_user = setup.ume.ensure_root_user("bbs.test", setup.server_identity.public_key)
        body = bytes([0x10]) + bytes([7]) + b"general"
        headers = await _sign_request(
            setup.server_identity, "https://bbs.test/v2/command", body
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200
        assert resp.content[0] == 0x00  # SUCCESS

    @pytest.mark.asyncio
    async def test_unknown_key_rejected(self, setup):
        """An unknown (non-anonymous, non-registered) key is rejected for non-REGISTER commands."""
        client_ident = Identity.generate()
        body = b"\x11"  # BOARD_LIST
        headers = await _sign_request(
            client_ident, "https://bbs.test/v2/command", body
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 403
        assert b"Unknown key" in resp.content or b"register" in resp.content


# ---------------------------------------------------------------------------
# Malformed traffic tests
# ---------------------------------------------------------------------------

class TestMalformedTraffic:

    @pytest.mark.asyncio
    async def test_missing_bonnet_version(self, setup):
        body = b"\x11"
        headers = await _sign_request(
            None, "https://bbs.test/v2/command", body,
            anonymous_identity=setup.anonymous_identity
        )
        # Remove the header regardless of case
        for k in list(headers.keys()):
            if k.lower() == "bonnet-version":
                del headers[k]

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 426

    @pytest.mark.asyncio
    async def test_wrong_content_type(self, setup):
        body = b"\x11"
        headers = await _sign_request(
            None, "https://bbs.test/v2/command", body,
            anonymous_identity=setup.anonymous_identity
        )
        headers["content-type"] = "application/json"

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 415

    @pytest.mark.asyncio
    async def test_missing_signature(self, setup):
        body = b"\x11"
        headers = {
            "Content-Type": "application/vnd.bonnet.command",
            "Content-Digest": compute_content_digest(body),
            "Bonnet-Version": "2",
        }

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_tampered_body(self, setup):
        body = b"\x11"
        headers = await _sign_request(
            None, "https://bbs.test/v2/command", body,
            anonymous_identity=setup.anonymous_identity
        )
        # Tamper body but keep the old Content-Digest
        tampered_body = b"\x12"

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=tampered_body, headers=headers)

        assert resp.status_code == 400
        assert b"digest" in resp.content.lower() or b"Digest" in resp.content

    @pytest.mark.asyncio
    async def test_empty_body(self, setup):
        headers = await _sign_request(
            None, "https://bbs.test/v2/command", b"\x11",
            anonymous_identity=setup.anonymous_identity
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=b"", headers=headers)

        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_oversized_body(self, setup):
        body = b"\x11" + b"\x00" * (10 * 1024 * 1024 + 1)
        headers = await _sign_request(
            None, "https://bbs.test/v2/command", b"\x11",
            anonymous_identity=setup.anonymous_identity
        )
        headers["content-digest"] = compute_content_digest(body)

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 413

    @pytest.mark.asyncio
    async def test_unknown_route(self, setup):
        async with setup.make_client() as client:
            resp = await client.get("/unknown")

        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Replay detection
# ---------------------------------------------------------------------------

class TestReplayDetection:

    @pytest.mark.asyncio
    async def test_replay_rejected(self, setup):
        """The same (pubkey, nonce) pair must be rejected on second submission."""
        client_ident = Identity.generate()
        body = bytes([0x01]) + bytes([5]) + b"alice" + bytes([8]) + b"bbs.test"

        # Build headers once with a fixed nonce
        nonce = _make_nonce()
        now = int(time.time())
        cd = compute_content_digest(body)

        msg = HTTPMessage(
            method="POST",
            url="https://bbs.test/v2/command",
            headers={
                "Content-Type": "application/vnd.bonnet.command",
                "Content-Digest": cd,
                "Bonnet-Version": "2",
                "Bonnet-Nonce": nonce,
            },
            body=body,
        )
        signer = BonnetSigner(
            private_key=client_ident.private_key,
            key_id=f"ed25519:{client_ident.public_key.hex()}",
        )
        await signer.sign_request(msg, nonce=nonce, created=now, expires=now + 60)
        headers = dict(msg.headers)

        # First request — should succeed (REGISTER)
        async with setup.make_client() as client:
            resp1 = await client.post("/v2/command", content=body, headers=headers)

        assert resp1.status_code == 200

        # Second request with same nonce — should be rejected as replay
        # But REGISTER already created the user, so this would fail anyway.
        # Use a different body (BOARD_LIST) with the same nonce to isolate the replay check.
        body2 = b"\x11"  # BOARD_LIST
        cd2 = compute_content_digest(body2)
        msg2 = HTTPMessage(
            method="POST",
            url="https://bbs.test/v2/command",
            headers={
                "Content-Type": "application/vnd.bonnet.command",
                "Content-Digest": cd2,
                "Bonnet-Version": "2",
                "Bonnet-Nonce": nonce,
            },
            body=body2,
        )
        await signer.sign_request(msg2, nonce=nonce, created=now, expires=now + 60)
        headers2 = dict(msg2.headers)

        async with setup.make_client() as client:
            resp2 = await client.post("/v2/command", content=body2, headers=headers2)

        assert resp2.status_code == 409
        assert b"Replay" in resp2.content


# ---------------------------------------------------------------------------
# Response signature verification
# ---------------------------------------------------------------------------

class TestResponseSignature:

    @pytest.mark.asyncio
    async def test_response_can_be_verified(self, setup):
        """The response signature can be verified with the server's public key."""
        body = b"\x11"  # BOARD_LIST
        headers = await _sign_request(
            None, "https://bbs.test/v2/command", body,
            anonymous_identity=setup.anonymous_identity
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200

        # Verify the response signature
        resp_msg = HTTPMessage(
            method="POST",
            url="https://bbs.test/v2/command",
            headers=dict(resp.headers),
            status_code=resp.status_code,
            body=resp.content,
        )

        class ServerKeyResolver(KeyResolver):
            def resolve_public_key(self, key_id):
                return setup.server_identity.public_key

        verifier = BonnetVerifier(
            key_resolver=ServerKeyResolver(),
            max_lifetime=10**9, clock_skew=10**9,
        )
        result = await verifier.verify_response(
            resp_msg,
            expected_origin="bbs.test",
        )
        assert result.label == "bonnet"
        assert "@status" in result.covered_components

    @pytest.mark.asyncio
    async def test_response_includes_request_nonce(self, setup):
        """The response echoes the request's nonce in Bonnet-Request-Nonce."""
        body = b"\x11"
        nonce = _make_nonce()
        now = int(time.time())

        msg = HTTPMessage(
            method="POST",
            url="https://bbs.test/v2/command",
            headers={
                "Content-Type": "application/vnd.bonnet.command",
                "Content-Digest": compute_content_digest(body),
                "Bonnet-Version": "2",
                "Bonnet-Nonce": nonce,
            },
            body=body,
        )
        signer = BonnetSigner(
            private_key=setup.anonymous_identity.private_key,
            key_id=f"ed25519:{setup.anonymous_identity.public_key.hex()}",
        )
        await signer.sign_request(msg, nonce=nonce, created=now, expires=now + 60)

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=dict(msg.headers))

        assert resp.status_code == 200
        assert resp.headers.get("bonnet-request-nonce") == nonce


# ---------------------------------------------------------------------------
# Rate limiting through HTTP
# ---------------------------------------------------------------------------

class TestRateLimiting:

    @pytest.mark.asyncio
    async def test_rate_limit_survives_connection_churn(self, setup):
        """Rate limits accumulate across HTTP connections (shared limiter)."""
        # Use a low limit
        setup.rate_limiter = RateLimiter(max_requests=2, window_seconds=60)
        setup.app._rate_limiter = setup.rate_limiter

        body = b"\x11"
        responses = []

        for _ in range(3):
            headers = await _sign_request(
                None, "https://bbs.test/v2/command", body,
                anonymous_identity=setup.anonymous_identity
            )
            async with setup.make_client() as client:
                resp = await client.post("/v2/command", content=body, headers=headers)
            responses.append(resp.status_code)

        # First two should succeed, third should be rate-limited
        assert responses[0] == 200
        assert responses[1] == 200
        assert responses[2] == 429
