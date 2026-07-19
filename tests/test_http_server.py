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
from core.user_registry import UserRegistryStore, RegistryService
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


from tests.helpers import default_test_acls


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

        self.registry_store = UserRegistryStore(os.path.join(temp_dir, "user_registry.db"))
        self.registry_service = RegistryService(
            self.registry_store, self.ume, self.server_identity, "bbs.test"
        )
        self.ume.register_mutation_callback(self.registry_service.mark_dirty)
        self.engine.registry_store = self.registry_store
        self.engine.registry_service = self.registry_service

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
        self.registry_store.close()

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
        assert data["protocol_versions"] == [3]
        assert data["origin"] == "bbs.test"
        assert data["public_key"] == setup.server_identity.public_key.hex()
        assert data["command_endpoint"] == "/v3/command"
        assert "anonymous_key" in data
        assert data["anonymous_key"] == setup.anonymous_identity.public_key.hex()
        assert "capabilities" in data
        assert "user-registry-merkle-v1" in data["capabilities"]
        assert "immutable-article-feed-v1" in data["capabilities"]
        assert "moderation_boards" in data
        assert "rules" in data["moderation_boards"]
        assert "reports" in data["moderation_boards"]
        assert "punishments" in data["moderation_boards"]

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
        """Anonymous cannot run BOARD_CREATE (write command, denied by command ACL)."""
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
        assert code == 403  # command ACL denies write for anonymous


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
        """An unknown (non-anonymous, non-registered) key is rejected for write
        commands by the command ACL gate (protocol-level 403 error)."""
        client_ident = Identity.generate()
        body = b"\x10" + bytes([7]) + b"general"  # BOARD_CREATE
        headers = await _sign_request(
            client_ident, "https://bbs.test/v2/command", body
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200
        assert resp.content[0] == 0x01  # ERROR
        code = struct.unpack(">H", resp.content[1:3])[0]
        assert code == 403  # command ACL denies BOARD_CREATE for unknown


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


# ---------------------------------------------------------------------------
# Command ACL: unknown-signer and anonymous access behavior (Phase 1)
# ---------------------------------------------------------------------------


class TestUnknownSignerCommandACL:
    """Phase 1: Unknown (validly-signed but unregistered) signers are subject
    to command ACL evaluation. Under default ACLs, unknown principals can
    call read commands (unknown-read ACL) and REGISTER (unknown-registration
    ACL), but are denied all other write commands.
    """

    @pytest.mark.asyncio
    async def test_unknown_signer_can_call_board_list(self, setup):
        """BOARD_LIST is a read command granted by the unknown-read ACL."""
        unknown_ident = Identity.generate()
        body = b"\x11"  # BOARD_LIST
        headers = await _sign_request(
            unknown_ident, "https://bbs.test/v2/command", body
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200
        assert resp.content[0] == 0x00  # SUCCESS

    @pytest.mark.asyncio
    async def test_unknown_signer_can_call_list_users(self, setup):
        """LIST_USERS is a read command granted by the unknown-read ACL."""
        unknown_ident = Identity.generate()
        body = struct.pack(">BII", 0x03, 0, 100)  # LIST_USERS offset=0 limit=100
        headers = await _sign_request(
            unknown_ident, "https://bbs.test/v2/command", body
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200
        assert resp.content[0] == 0x00  # SUCCESS

    @pytest.mark.asyncio
    async def test_unknown_signer_can_register(self, setup):
        """REGISTER is granted to unknown signers by the unknown-registration
        ACL (match.unknown=true, commands=["REGISTER"], write=true)."""
        from client.protocol import build_register
        unknown_ident = Identity.generate()
        body = build_register("newuser", "bbs.test")
        headers = await _sign_request(
            unknown_ident, "https://bbs.test/v2/command", body
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200
        assert resp.content[0] == 0x00  # SUCCESS

    @pytest.mark.asyncio
    async def test_unknown_signer_denied_for_write_command(self, setup):
        """BOARD_CREATE is a write command — no unknown ACL grants it."""
        unknown_ident = Identity.generate()
        body = b"\x10" + bytes([7]) + b"general"  # BOARD_CREATE
        headers = await _sign_request(
            unknown_ident, "https://bbs.test/v2/command", body
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200
        assert resp.content[0] == 0x01  # ERROR
        code = struct.unpack(">H", resp.content[1:3])[0]
        assert code == 403  # command ACL denies write for unknown


class TestAnonymousCommandACL:
    """Phase 1: Anonymous (shared-key) signers are subject to command ACL
    evaluation. Under default ACLs, anonymous can run read commands but not
    writes or POST_CONTENT_SEARCH.
    """

    @pytest.mark.asyncio
    async def test_anonymous_denied_for_content_search(self, setup):
        """POST_CONTENT_SEARCH is NOT in the anonymous-read default ACL — denied."""
        body = struct.pack(">B", 0x1A) + struct.pack(">B", 3) + b"foo" + struct.pack(">I", 100) + struct.pack(">I", 0)
        headers = await _sign_request(
            None, "https://bbs.test/v2/command", body,
            anonymous_identity=setup.anonymous_identity
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200
        assert resp.content[0] == 0x01  # ERROR

    @pytest.mark.asyncio
    async def test_anonymous_denied_for_write(self, setup):
        """BOARD_CREATE is a write — denied for anonymous."""
        body = b"\x10" + bytes([7]) + b"general"
        headers = await _sign_request(
            None, "https://bbs.test/v2/command", body,
            anonymous_identity=setup.anonymous_identity
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200
        assert resp.content[0] == 0x01  # ERROR


# ---------------------------------------------------------------------------
# Phase 4: Registry command round-trip tests (opcodes 0x05–0x09)
# ---------------------------------------------------------------------------


class TestRegistryCommands:

    @pytest.mark.asyncio
    async def test_registry_head_returns_signed_head(self, setup):
        """USER_REGISTRY_HEAD (0x05) returns a signed head for the local origin."""
        from client.protocol import build_user_registry_head, parse_user_registry_head_resp
        from core.user_registry import decode_head, verify_head

        body = build_user_registry_head("bbs.test")
        headers = await _sign_request(
            None, "https://bbs.test/v2/command", body,
            anonymous_identity=setup.anonymous_identity
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200
        assert resp.content[0] == 0x00
        encoded = parse_user_registry_head_resp(resp.content[1:])
        head = decode_head(encoded)
        assert head.origin == "bbs.test"
        assert head.registry_seq >= 1
        assert verify_head(head, setup.server_identity.public_key)

    @pytest.mark.asyncio
    async def test_registry_head_unknown_origin_returns_404(self, setup):
        from client.protocol import build_user_registry_head

        body = build_user_registry_head("nonexistent.test")
        headers = await _sign_request(
            None, "https://bbs.test/v2/command", body,
            anonymous_identity=setup.anonymous_identity
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200
        assert resp.content[0] == 0x01  # ERROR
        code = struct.unpack(">H", resp.content[1:3])[0]
        assert code == 404

    @pytest.mark.asyncio
    async def test_registry_heads_lists_cached_heads(self, setup):
        """USER_REGISTRY_HEADS (0x08) lists cached heads."""
        from client.protocol import build_user_registry_heads, parse_user_registry_heads_resp
        from core.user_registry import decode_head

        setup.registry_service.build_snapshot()

        body = build_user_registry_heads(offset=0, limit=10)
        headers = await _sign_request(
            None, "https://bbs.test/v2/command", body,
            anonymous_identity=setup.anonymous_identity
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200
        assert resp.content[0] == 0x00
        encoded_heads = parse_user_registry_heads_resp(resp.content[1:])
        assert len(encoded_heads) >= 1
        head = decode_head(encoded_heads[0])
        assert head.origin == "bbs.test"

    @pytest.mark.asyncio
    async def test_registry_records_returns_raw_record(self, setup):
        """USER_REGISTRY_RECORDS (0x07) returns exact raw records."""
        from client.protocol import (
            build_user_registry_records, parse_user_registry_records_resp,
        )
        from core.user_registry import compute_registry_key
        from engine.ume import RECORD_SIZE

        setup.ume.put("testuser", "bbs.test", Identity.generate().public_key,
                      record_origin="bbs.test", relay="bbs.test")
        head = setup.registry_service.build_snapshot()

        key = compute_registry_key("bbs.test", "testuser")
        body = build_user_registry_records("bbs.test", head.registry_seq, [key])
        headers = await _sign_request(
            None, "https://bbs.test/v2/command", body,
            anonymous_identity=setup.anonymous_identity
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200
        assert resp.content[0] == 0x00
        records = parse_user_registry_records_resp(resp.content[1:])
        assert len(records) == 1
        assert records[0]["present"] == 1
        assert len(records[0]["raw_record"]) == RECORD_SIZE

    @pytest.mark.asyncio
    async def test_registry_records_absent_key(self, setup):
        """USER_REGISTRY_RECORDS returns present=0 for absent keys."""
        from client.protocol import build_user_registry_records, parse_user_registry_records_resp

        setup.registry_service.build_snapshot()
        absent_key = b"\xFF" * 32
        body = build_user_registry_records("bbs.test", 0, [absent_key])
        headers = await _sign_request(
            None, "https://bbs.test/v2/command", body,
            anonymous_identity=setup.anonymous_identity
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200
        assert resp.content[0] == 0x00
        records = parse_user_registry_records_resp(resp.content[1:])
        assert records[0]["present"] == 0

    @pytest.mark.asyncio
    async def test_registry_nodes_returns_root_children(self, setup):
        """USER_REGISTRY_NODES (0x06) returns node hashes for requested prefixes."""
        from client.protocol import build_user_registry_nodes, parse_user_registry_nodes_resp

        setup.registry_service.build_snapshot()
        body = build_user_registry_nodes("bbs.test", 0, [(0, b"")])
        headers = await _sign_request(
            None, "https://bbs.test/v2/command", body,
            anonymous_identity=setup.anonymous_identity
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200
        assert resp.content[0] == 0x00
        nodes = parse_user_registry_nodes_resp(resp.content[1:])
        assert len(nodes) == 1
        assert nodes[0]["prefix_bit_length"] == 0
        assert len(nodes[0]["node_hash"]) == 32

    @pytest.mark.asyncio
    async def test_registry_head_chain_returns_linkage(self, setup):
        """USER_REGISTRY_HEAD_CHAIN (0x09) returns descending heads."""
        from client.protocol import build_user_registry_head_chain, parse_user_registry_heads_resp
        from core.user_registry import decode_head

        h1 = setup.registry_service.build_snapshot()
        setup.ume.put("chainuser", "bbs.test", Identity.generate().public_key,
                      record_origin="bbs.test", relay="bbs.test")
        h2 = setup.registry_service.build_snapshot()

        body = build_user_registry_head_chain("bbs.test", h2.registry_seq, 10)
        headers = await _sign_request(
            None, "https://bbs.test/v2/command", body,
            anonymous_identity=setup.anonymous_identity
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200
        assert resp.content[0] == 0x00
        encoded_heads = parse_user_registry_heads_resp(resp.content[1:])
        assert len(encoded_heads) >= 2
        head2 = decode_head(encoded_heads[0])
        head1 = decode_head(encoded_heads[1])
        assert head2.registry_seq == h2.registry_seq
        assert head1.registry_seq == h1.registry_seq
        assert head2.previous_head_hash == head1.head_hash

    @pytest.mark.asyncio
    async def test_registry_head_anonymous_access(self, setup):
        """Registry commands are public — anonymous can call USER_REGISTRY_HEAD."""
        from client.protocol import build_user_registry_head

        body = build_user_registry_head("bbs.test")
        headers = await _sign_request(
            None, "https://bbs.test/v2/command", body,
            anonymous_identity=setup.anonymous_identity
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200
        assert resp.content[0] == 0x00

    @pytest.mark.asyncio
    async def test_registry_head_unknown_valid_signer_access(self, setup):
        """Unknown valid signer can call registry read commands (unknown-read ACL)."""
        from client.protocol import build_user_registry_head

        unknown_ident = Identity.generate()
        body = build_user_registry_head("bbs.test")
        headers = await _sign_request(
            unknown_ident, "https://bbs.test/v2/command", body
        )

        async with setup.make_client() as client:
            resp = await client.post("/v2/command", content=body, headers=headers)

        assert resp.status_code == 200
        assert resp.content[0] == 0x00  # SUCCESS
