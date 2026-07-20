# -*- coding: utf-8 -*-
"""Tests for effective remote enforcement (Phase 6, §6/§17.4/§17.9).

Covers:
  §17.4 — Banned command behavior:
    - Local active punishment blocks writes, permits ACL-authorized reads
    - Remote active punishment blocks writes, permits ACL-authorized reads
    - Out-of-window punishment does not block
    - Expired punishment does not block
    - Multiple origins: any effective active punishment blocks writes
    - UME flag disagreement does not override Keibatsu effective state

  §17.9 — Three-node integration:
    - Origin A issues punishment
    - Relay B imports A (allowlisted), caches and exports A's punishment head
    - Node C imports A through B (A allowlisted, B trusted relay)
    - C blocks writes by the punished known user but permits authorized reads
    - C rejects origin D punishments advertised by B when D is not allowlisted
    - Removing A from C's import allowlist prevents future imports but does not
      delete or automatically deactivate already accepted A punishments
"""

import os
import sys
import struct
import time
import asyncio

import pytest
import pytest_asyncio
from unittest.mock import MagicMock, AsyncMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.crypto import Identity
from core.config import Config, Matcher, ACLEntry
from core.orm import Database
from engine.ume import Ume
from engine.ame import Ame
from engine.keibatsu import Keibatsu
from engine.facade import BonnetEngine
from net.commands import CommandHandler
from net.context import CommandContext
from net.http_server import BonnetHTTPServer
from net.http_auth import BonnetSigner, HTTPMessage, compute_content_digest
from net.replay import ReplayLedger
from net.rate_limiter import RateLimiter
from tests.helpers import default_test_acls, permissive_import_allowlist

import httpx
from httpx import AsyncClient, ASGITransport


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _init_rules(reports_path):
    with Database(reports_path).open() as ctx:
        ctx.execute("""
            CREATE TABLE IF NOT EXISTS rules (
                rule_num INTEGER PRIMARY KEY,
                rule_name TEXT UNIQUE NOT NULL,
                description TEXT NOT NULL
            )
        """)


def _make_engine_setup(temp_dir, origin="local.test"):
    """Create a handler-level setup for banned-command-behavior tests."""
    ident = Identity.generate()
    config = Config(
        origin=origin,
        ame_path=os.path.join(temp_dir, "boards"),
        data_dir=temp_dir,
        nav_db_path=os.path.join(temp_dir, "nav.db"),
        reports_db_path=os.path.join(temp_dir, "reports.db"),
        punishments_db_path=os.path.join(temp_dir, "punishments.db"),
        log_dir=os.path.join(temp_dir, "logs"),
        acls=default_test_acls(origin),
        anonymous_read=True,
        import_allowlist=permissive_import_allowlist([origin, "remote.test", "origin-a.test"]),
    )
    ume = Ume(os.path.join(temp_dir, "userfile"))
    ame = Ame(config.ame_path, origin=origin, signing_key=ident.signing_key,
              nav_db_path=config.nav_db_path)
    _init_rules(config.reports_db_path)
    keibatsu = Keibatsu(config.reports_db_path, config.punishments_db_path,
                        ume=ume, signing_key=ident.signing_key, origin=origin)
    engine = BonnetEngine(ume, ame, keibatsu, config, ident)
    return {
        "ident": ident, "config": config, "ume": ume, "ame": ame,
        "keibatsu": keibatsu, "engine": engine, "origin": origin,
    }


def _make_handler(setup):
    handler = CommandHandler(setup["engine"])
    task = handler._sync_mgr._worker_task
    if task and not task.done():
        task.cancel()
    return handler


def _user_ctx(setup, user_pubkey=None, is_admin=False):
    """Create a CommandContext for a known (registered) user."""
    if user_pubkey is None:
        user_pubkey = setup["ident"].public_key
    user = MagicMock()
    user.username = "testuser"
    user.publickey = user_pubkey
    user.is_administrator = is_admin
    user.is_moderator = False
    user.is_banned = False  # UME flag — must not override Keibatsu
    user.record_origin = setup["config"].origin
    user.creation_time = int(time.time())
    return CommandContext(
        peer_public_key=user_pubkey,
        user=user,
        username="testuser",
        is_anonymous=False,
    )


def _build_post_create(board_name="testboard", root=0, subject="s", content="c"):
    bb = board_name.encode("utf-8")
    out = struct.pack("B", len(bb)) + bb
    out += struct.pack(">Q", root)
    sb = subject.encode("utf-8")
    out += struct.pack("B", len(sb)) + sb
    out += struct.pack("B", 0)  # tags
    out += struct.pack("B", 0)  # options
    cb = content.encode("utf-8")
    out += struct.pack(">I", len(cb)) + cb
    return bytes([0x12]) + out


def _build_board_list():
    return bytes([0x11])


def _decode_error(response):
    if len(response) > 0 and response[0] == 0x01:
        code = struct.unpack(">H", response[1:3])[0]
        msg_len = response[3]
        return code, response[4:4 + msg_len].decode("utf-8", errors="replace")
    return None


# ---------------------------------------------------------------------------
# §17.4 — Banned command behavior
# ---------------------------------------------------------------------------

class TestBannedCommandBehavior:
    """Verify that effectively banned known users are denied writes but
    permitted ACL-authorized reads (§6.2, §17.4)."""

    @pytest_asyncio.fixture
    async def setup(self, tmp_path):
        s = _make_engine_setup(str(tmp_path))
        s["handler"] = _make_handler(s)
        # Create a board for testing
        s["ame"].create_board("testboard", owner_pubkey=s["ident"].public_key)
        yield s
        s["ame"].shutdown()
        s["keibatsu"].shutdown()

    def test_local_punishment_blocks_writes(self, setup):
        """A local active punishment blocks write commands."""
        k = setup["keibatsu"]
        handler = setup["handler"]
        pubkey = setup["ident"].public_key

        k.create_punishment(pubkey, [1], -1, "local ban").result(timeout=5)

        ctx = _user_ctx(setup, pubkey)
        resp = handler.handle(_build_post_create(), ctx)
        code, _ = _decode_error(resp)
        assert code == 403
        assert "banned" in _decode_error(resp)[1].lower()

    def test_local_punishment_permits_reads(self, setup):
        """A local active punishment permits ACL-authorized read commands."""
        k = setup["keibatsu"]
        handler = setup["handler"]
        pubkey = setup["ident"].public_key

        k.create_punishment(pubkey, [1], -1, "local ban").result(timeout=5)

        ctx = _user_ctx(setup, pubkey)
        resp = handler.handle(_build_board_list(), ctx)
        # BOARD_LIST should succeed (read command, ACL grants via local-full-access)
        assert resp[0] == 0x00, f"expected success, got {_decode_error(resp)}"

    def test_out_of_window_punishment_does_not_block(self, setup):
        """An out-of-window punishment does not block writes."""
        k = setup["keibatsu"]
        handler = setup["handler"]
        pubkey = setup["ident"].public_key

        p = k.create_punishment(pubkey, [1], -1, "old ban").result(timeout=5)
        # Set created_at to the past
        with k._punishments_db.open() as ctx:
            ctx.execute("UPDATE punishments SET created_at=? WHERE punishment_id=? AND origin=?",
                        [1000, p.punishment_id, p.origin])
        # Filter: only recent records
        k._record_in_window = lambda origin, t: t > 5000

        ctx = _user_ctx(setup, pubkey)
        resp = handler.handle(_build_post_create(), ctx)
        # Should NOT be banned — write should proceed to handler checks
        err = _decode_error(resp)
        # It may fail at the board ACL or business rule level, but NOT at the ban gate
        if err:
            assert err[0] != 403 or "banned" not in err[1].lower()

    def test_expired_punishment_does_not_block(self, setup):
        """An expired temporary punishment does not block writes."""
        k = setup["keibatsu"]
        handler = setup["handler"]
        pubkey = setup["ident"].public_key

        # Create a temporary ban that already expired
        k.create_punishment(pubkey, [1], int(time.time()) - 3600, "expired ban").result(timeout=5)

        ctx = _user_ctx(setup, pubkey)
        resp = handler.handle(_build_post_create(), ctx)
        err = _decode_error(resp)
        if err:
            assert err[0] != 403 or "banned" not in err[1].lower()

    def test_multiple_origins_any_blocks_writes(self, setup):
        """Any effective active punishment from any origin blocks writes."""
        k = setup["keibatsu"]
        handler = setup["handler"]
        pubkey = setup["ident"].public_key

        # Insert a remote punishment directly
        with k._punishments_db.open() as ctx:
            ctx.execute(
                "INSERT INTO punishments (punishment_id, origin, rollover, punished_pubkey, "
                "report_ids, expires_at, ban_notes, issued_by, created_at, relay, origin_sig) "
                "VALUES (?, ?, 0, ?, ?, -1, 'remote ban', NULL, ?, ?, NULL)",
                [1, "remote.test", pubkey, "[]", int(time.time()), "remote.test"]
            )

        ctx = _user_ctx(setup, pubkey)
        resp = handler.handle(_build_post_create(), ctx)
        code, msg = _decode_error(resp)
        assert code == 403
        assert "banned" in msg.lower()

    def test_ume_flag_disagreement_does_not_override(self, setup):
        """UME is_banned=False does not override Keibatsu effective state."""
        k = setup["keibatsu"]
        handler = setup["handler"]
        pubkey = setup["ident"].public_key

        # Create a punishment (Keibatsu says banned)
        k.create_punishment(pubkey, [1], -1, "real ban").result(timeout=5)

        ctx = _user_ctx(setup, pubkey)
        ctx.user.is_banned = False  # UME says not banned — disagreement

        resp = handler.handle(_build_post_create(), ctx)
        code, msg = _decode_error(resp)
        assert code == 403
        assert "banned" in msg.lower()

    def test_remote_punishment_permits_reads(self, setup):
        """A remote active punishment permits ACL-authorized reads."""
        k = setup["keibatsu"]
        handler = setup["handler"]
        pubkey = setup["ident"].public_key

        # Insert a remote punishment
        with k._punishments_db.open() as ctx:
            ctx.execute(
                "INSERT INTO punishments (punishment_id, origin, rollover, punished_pubkey, "
                "report_ids, expires_at, ban_notes, issued_by, created_at, relay, origin_sig) "
                "VALUES (?, ?, 0, ?, ?, -1, 'remote ban', NULL, ?, ?, NULL)",
                [1, "remote.test", pubkey, "[]", int(time.time()), "remote.test"]
            )

        ctx = _user_ctx(setup, pubkey)
        resp = handler.handle(_build_board_list(), ctx)
        assert resp[0] == 0x00, f"expected success, got {_decode_error(resp)}"

    def test_anonymous_not_gated_by_ban(self, setup):
        """Anonymous principals are not subject to the ban gate (§6.2)."""
        k = setup["keibatsu"]
        handler = setup["handler"]

        # Even if the anonymous key had a punishment, the gate doesn't apply
        # because ctx.user is None for anonymous
        ctx = CommandContext(
            peer_public_key=b"\x00" * 32,
            user=None,
            is_anonymous=True,
        )
        # BOARD_LIST is a read — should succeed
        resp = handler.handle(_build_board_list(), ctx)
        assert resp[0] == 0x00, f"expected success, got {_decode_error(resp)}"


# ---------------------------------------------------------------------------
# §17.9 — Three-node integration test
# ---------------------------------------------------------------------------

class EnforcementTestServer:
    """Full server setup with all registries for enforcement integration tests."""

    _TEST_ORIGINS = ["origin-a.test", "relay-b.test", "node-c.test", "origin-d.test"]

    def __init__(self, temp_dir, origin):
        self.temp_dir = temp_dir
        self.origin = origin
        self.server_identity = Identity.generate()

        _import_allowlist = {
            "boards": list(self._TEST_ORIGINS),
            "users": list(self._TEST_ORIGINS),
            "reports": list(self._TEST_ORIGINS),
            "punishments": list(self._TEST_ORIGINS),
        }

        self.config = Config(
            origin=origin,
            registrars=[origin],
            ame_path=os.path.join(temp_dir, origin, "boards"),
            data_dir=os.path.join(temp_dir, origin),
            nav_db_path=os.path.join(temp_dir, origin, "nav.db"),
            reports_db_path=os.path.join(temp_dir, origin, "reports.db"),
            punishments_db_path=os.path.join(temp_dir, origin, "punishments.db"),
            log_dir=os.path.join(temp_dir, origin, "logs"),
            identity_path=os.path.join(temp_dir, origin, "identity"),
            userfile_path=os.path.join(temp_dir, origin, "userfile"),
            acls=default_test_acls(origin),
            anonymous_read=True,
            max_request_size=10 * 1024 * 1024,
            rate_limit_requests=100,
            rate_limit_window=1,
            signature_lifetime_seconds=60,
            clock_skew_seconds=30,
            search_per_identity_concurrency=1,
            search_rate_limit=10,
            search_rate_window_seconds=60,
            max_creation_time_correction=86400,
            import_allowlist=_import_allowlist,
        )

        os.makedirs(os.path.join(temp_dir, origin), exist_ok=True)

        self.ume = Ume(os.path.join(temp_dir, origin, "userfile"))
        self.ame = Ame(self.config.ame_path, origin=origin,
                       signing_key=self.server_identity.signing_key,
                       nav_db_path=self.config.nav_db_path)

        with Database(self.config.reports_db_path).open() as ctx:
            ctx.execute("""CREATE TABLE IF NOT EXISTS rules (
                rule_num INTEGER PRIMARY KEY, rule_name TEXT UNIQUE NOT NULL, description TEXT NOT NULL
            )""")

        self.keibatsu = Keibatsu(
            self.config.reports_db_path, self.config.punishments_db_path,
            ume=self.ume, signing_key=self.server_identity.signing_key,
            origin=origin,
        )
        self.engine = BonnetEngine(self.ume, self.ame, self.keibatsu, self.config, self.server_identity)

        self.handler = CommandHandler(self.engine)
        task = self.handler._sync_mgr._worker_task
        if task and not task.done():
            task.cancel()

        self.anonymous_identity = Identity.generate()
        self.replay_ledger = ReplayLedger(
            os.path.join(temp_dir, origin, "replay.db"), clock_skew_seconds=30
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
        return AsyncClient(transport=transport, base_url=f"https://{self.origin}")

    def restrict_punishment_allowlist(self, origins):
        """Restrict the punishments import allowlist to specific origins."""
        self.config._import_allowlist["punishments"] = {o.lower() for o in origins}


class ASGISyncClient:
    """Wraps an httpx AsyncClient for sync operations."""

    def __init__(self, http_client, server_identity, anonymous_identity, origin):
        self._http = http_client
        self._server_identity = server_identity
        self._anonymous_identity = anonymous_identity
        self._server_origin = origin
        self.server_public_key = server_identity.public_key
        self._signer = BonnetSigner(
            private_key=server_identity.private_key,
            key_id=f"ed25519:{server_identity.public_key.hex()}",
        )
        import base64
        self._base_url = f"https://{origin}"

    async def _send_command(self, cmd_bytes):
        import base64
        nonce = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        now = int(time.time())
        cd = compute_content_digest(cmd_bytes)

        msg = HTTPMessage(
            method="POST",
            url=f"{self._base_url}/v2/command",
            headers={
                "Content-Type": "application/vnd.bonnet.command",
                "Content-Digest": cd,
                "Bonnet-Version": "2",
                "Bonnet-Nonce": nonce,
            },
            body=cmd_bytes,
        )

        await self._signer.sign_request(msg, nonce=nonce, created=now, expires=now + 60)
        headers = dict(msg.headers)

        resp = await self._http.post("/v2/command", content=cmd_bytes, headers=headers)
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP error: {resp.status_code}")

        from client.protocol import parse_response, ResponseStatus
        status, payload = parse_response(resp.content)
        if status == ResponseStatus.ERROR:
            from client.protocol import parse_error_response
            raise RuntimeError(parse_error_response(payload))
        return payload

    async def connect(self, ident):
        pass

    async def close(self):
        pass


@pytest_asyncio.fixture
async def origin_a(tmp_path):
    s = EnforcementTestServer(str(tmp_path), "origin-a.test")
    yield s
    s.cleanup()


@pytest_asyncio.fixture
async def relay_b(tmp_path):
    s = EnforcementTestServer(str(tmp_path), "relay-b.test")
    yield s
    s.cleanup()


@pytest_asyncio.fixture
async def node_c(tmp_path):
    s = EnforcementTestServer(str(tmp_path), "node-c.test")
    yield s
    s.cleanup()


@pytest_asyncio.fixture
async def origin_d(tmp_path):
    s = EnforcementTestServer(str(tmp_path), "origin-d.test")
    yield s
    s.cleanup()


@pytest.mark.skip(reason="Punishment registry sync removed in v3 Phase 7 — replaced by article feed federation")
class TestThreeNodeEnforcement:
    """§17.9: Three-node integration test for remote enforcement."""

    @pytest.mark.asyncio
    async def test_relayed_punishment_blocks_writes_on_node_c(
        self, origin_a, relay_b, node_c, tmp_path
    ):
        """Origin A issues punishment -> Relay B imports -> Node C imports
        through B -> C blocks writes by the punished user."""
        # 1. Origin A creates a punishment against a user
        punished_pubkey = Identity.generate().public_key
        origin_a.keibatsu.create_punishment(
            punished_pubkey, [1], -1, "banned by A",
            issued_by=origin_a.server_identity.public_key,
        ).result(timeout=5)

        # Build punishment registry snapshot on A
        origin_a.punishment_registry_service.build_snapshot()

        # 2. Relay B syncs punishment registry from origin A
        relay_b.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-a.test", origin_a.server_identity.public_key
        )
        async with origin_a.make_client() as http_client:
            client = ASGISyncClient(
                http_client, relay_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )
            await relay_b.handler._sync_mgr._sync_punishment_registry(client, "origin-a.test")

        # Verify B has A's punishment head
        head_b = relay_b.punishment_registry_store.get_head("origin-a.test")
        assert head_b is not None

        # 3. Node C pins origin A's key and syncs from relay B
        node_c.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-a.test", origin_a.server_identity.public_key
        )
        node_c.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "relay-b.test", relay_b.server_identity.public_key
        )

        async with relay_b.make_client() as http_client:
            client = ASGISyncClient(
                http_client, node_c.server_identity,
                relay_b.anonymous_identity, "relay-b.test"
            )
            await node_c.handler._sync_mgr._sync_punishment_registry(client, "relay-b.test")
            await node_c.handler._sync_mgr._sync_punishment_relayed_origins(client, "relay-b.test")

        # 4. Node C has origin A's punishment head (relayed through B)
        head_c = node_c.punishment_registry_store.get_head("origin-a.test")
        assert head_c is not None
        assert head_c.origin == "origin-a.test"

        # 5. Node C's Keibatsu should have the punishment ingested
        # (The sync path stores records in the registry sidecar, but for
        # enforcement, we need the punishment in Keibatsu's punishments table.
        # In a full implementation, the sync path would normalize records into
        # Keibatsu. For this test, we directly insert to verify enforcement.)
        node_c.keibatsu._upsert_remote_punishment(
            punishment_id=1, origin="origin-a.test", rollover=0,
            punished_pubkey=punished_pubkey, report_ids=[1], expires_at=-1,
            ban_notes="banned by A", issued_by=b'', created_at=int(time.time()),
            relay="relay-b.test", origin_sig=None,
            peer_pubkey_resolver=lambda o: origin_a.server_identity.public_key if o == "origin-a.test" else None,
        )

        # 6. C blocks writes by the punished known user
        is_banned, reason = node_c.keibatsu.is_banned(punished_pubkey).result(timeout=5)
        assert is_banned is True

        # 7. C permits reads (using a handler-level check)
        # Register the user on C with local origin so ACLs grant access
        node_c.ume.put("banned_user", "node-c.test", punished_pubkey,
                        record_origin="node-c.test", relay="node-c.test")
        user = node_c.ume.get(username="banned_user")
        ctx = CommandContext(
            peer_public_key=punished_pubkey,
            user=user,
            username="banned_user",
            is_anonymous=False,
        )
        # BOARD_LIST (read) should succeed
        resp = node_c.handler.handle(bytes([0x11]), ctx)  # BOARD_LIST
        assert resp[0] == 0x00, f"read should succeed, got {_decode_error(resp)}"

        # POST_CREATE (write) should be blocked by ban gate
        resp = node_c.handler.handle(_build_post_create(), ctx)
        code, msg = _decode_error(resp)
        assert code == 403
        assert "banned" in msg.lower()

    @pytest.mark.asyncio
    async def test_disallowed_origin_rejected(
        self, origin_a, origin_d, relay_b, node_c, tmp_path
    ):
        """C rejects origin D punishments when D is not in C's import allowlist."""
        # Origin D creates a punishment
        punished_pubkey = Identity.generate().public_key
        origin_d.keibatsu.create_punishment(
            punished_pubkey, [1], -1, "banned by D",
        ).result(timeout=5)
        origin_d.punishment_registry_service.build_snapshot()

        # Relay B syncs from D
        relay_b.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-d.test", origin_d.server_identity.public_key
        )
        async with origin_d.make_client() as http_client:
            client = ASGISyncClient(
                http_client, relay_b.server_identity,
                origin_d.anonymous_identity, "origin-d.test"
            )
            await relay_b.handler._sync_mgr._sync_punishment_registry(client, "origin-d.test")

        # Node C restricts punishment allowlist to only A (not D)
        node_c.restrict_punishment_allowlist(["origin-a.test"])

        # Node C syncs from B — D should be skipped
        node_c.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "relay-b.test", relay_b.server_identity.public_key
        )
        async with relay_b.make_client() as http_client:
            client = ASGISyncClient(
                http_client, node_c.server_identity,
                relay_b.anonymous_identity, "relay-b.test"
            )
            await node_c.handler._sync_mgr._sync_punishment_relayed_origins(client, "relay-b.test")

        # C should NOT have D's punishment head
        head_c = node_c.punishment_registry_store.get_head("origin-d.test")
        assert head_c is None

    @pytest.mark.asyncio
    async def test_allowlist_removal_preserves_existing(
        self, origin_a, relay_b, node_c, tmp_path
    ):
        """Removing A from C's import allowlist prevents future imports but
        does not delete already accepted punishments."""
        # Setup: A creates punishment, B relays, C imports
        punished_pubkey = Identity.generate().public_key
        origin_a.keibatsu.create_punishment(
            punished_pubkey, [1], -1, "banned by A",
        ).result(timeout=5)
        origin_a.punishment_registry_service.build_snapshot()

        relay_b.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-a.test", origin_a.server_identity.public_key
        )
        async with origin_a.make_client() as http_client:
            client = ASGISyncClient(
                http_client, relay_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )
            await relay_b.handler._sync_mgr._sync_punishment_registry(client, "origin-a.test")

        node_c.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-a.test", origin_a.server_identity.public_key
        )
        node_c.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "relay-b.test", relay_b.server_identity.public_key
        )
        async with relay_b.make_client() as http_client:
            client = ASGISyncClient(
                http_client, node_c.server_identity,
                relay_b.anonymous_identity, "relay-b.test"
            )
            await node_c.handler._sync_mgr._sync_punishment_registry(client, "relay-b.test")
            await node_c.handler._sync_mgr._sync_punishment_relayed_origins(client, "relay-b.test")

        # C has A's head
        assert node_c.punishment_registry_store.get_head("origin-a.test") is not None

        # Now remove A from C's punishment allowlist
        node_c.restrict_punishment_allowlist([])  # deny all

        # The already-accepted head is still there
        assert node_c.punishment_registry_store.get_head("origin-a.test") is not None

        # A new sync attempt would skip A (allowlist denies it)
        # but the existing data is preserved
        state = node_c.punishment_registry_store.get_state("origin-a.test")
        assert state is not None
        assert state["highest_accepted_seq"] >= 1
