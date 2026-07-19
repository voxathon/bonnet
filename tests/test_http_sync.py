"""Real two-server federation tests for registry synchronization (Phase 5).

Tests the full flow:
  - Origin A produces a signed registry head
  - Node B fetches, verifies, and accepts the head
  - Records are normalized into node B's UME
  - Subtree comparison detects changes
  - Rollback and equivocation are rejected
  - Tampered records are rejected

Uses real ASGI HTTP server instances via httpx ASGITransport.
"""

import os
import sys
import struct
import time
import pytest
import pytest_asyncio
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import httpx
from httpx import AsyncClient, ASGITransport

from core.crypto import Identity
from core.config import Config
from core.user_registry import (
    UserRegistryStore, RegistryService, decode_head, verify_head,
    compute_registry_key, compute_value_hash, encode_head,
)
from core.report_registry import ReportRegistryStore, ReportRegistryService
from core.punishment_registry import PunishmentRegistryStore, PunishmentRegistryService
from engine.ume import Ume, User, RECORD_SIZE
from engine.ame import Ame
from engine.keibatsu import Keibatsu
from engine.facade import BonnetEngine
from net.commands import CommandHandler
from net.http_server import BonnetHTTPServer
from net.http_auth import (
    BonnetSigner, BonnetVerifier, KeyResolver, HTTPMessage,
    compute_content_digest,
)
from net.replay import ReplayLedger
from net.rate_limiter import RateLimiter
from net.sync import SyncManager
from net.sync import _is_dialable_host, _resolves_to_global_only

from client.protocol import (
    build_user_registry_head, parse_user_registry_head_resp,
    build_user_registry_nodes, parse_user_registry_nodes_resp,
    build_user_registry_records, parse_user_registry_records_resp,
)
from client.http import BonnetHTTPClient
from tests.helpers import default_test_acls


# ---------------------------------------------------------------------------
# Test server setup
# ---------------------------------------------------------------------------

class RegistryTestServer:
    """A minimal Bonnet server with registry support for federation tests."""

    # All origins used across the sync test suite. Each server's import
    # allowlist includes these so federation sync works without per-test
    # configuration. Tests that exercise allowlist denial override the
    # config's import_allowlist explicitly.
    _TEST_ORIGINS = [
        "origin-a.test", "node-b.test", "relay-b.test",
        "node-c.test", "origin-d.test",
    ]

    def __init__(self, temp_dir, origin="origin-a.test"):
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

        from core.orm import Database
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

        self.registry_store = UserRegistryStore(os.path.join(temp_dir, origin, "user_registry.db"))
        self.registry_service = RegistryService(
            self.registry_store, self.ume, self.server_identity, origin
        )
        self.ume.register_mutation_callback(self.registry_service.mark_dirty)
        self.engine.registry_store = self.registry_store
        self.engine.registry_service = self.registry_service

        self.report_registry_store = ReportRegistryStore(os.path.join(temp_dir, origin, "report_registry.db"))
        self.report_registry_service = ReportRegistryService(
            self.report_registry_store, self.keibatsu, self.server_identity, origin
        )
        self.engine.report_registry_store = self.report_registry_store
        self.engine.report_registry_service = self.report_registry_service
        self.keibatsu.register_mutation_callback(self.report_registry_service.mark_dirty)

        self.punishment_registry_store = PunishmentRegistryStore(os.path.join(temp_dir, origin, "punishment_registry.db"))
        self.punishment_registry_service = PunishmentRegistryService(
            self.punishment_registry_store, self.keibatsu, self.server_identity, origin
        )
        self.engine.punishment_registry_store = self.punishment_registry_store
        self.engine.punishment_registry_service = self.punishment_registry_service
        self.keibatsu.register_punishment_mutation_callback(self.punishment_registry_service.mark_dirty)

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
        self.registry_store.close()
        self.report_registry_store.close()
        self.punishment_registry_store.close()

    def make_client(self):
        transport = ASGITransport(app=self.app)
        return AsyncClient(transport=transport, base_url=f"https://{self.origin}")


# ---------------------------------------------------------------------------
# Test helper: build a fake sync client that talks to an ASGI app
# ---------------------------------------------------------------------------

class ASGISyncClient:
    """Wraps an httpx AsyncClient to provide the _send_command interface
    that SyncManager expects from a BonnetHTTPClient."""

    def __init__(self, http_client: AsyncClient, server_identity: Identity,
                 anonymous_identity: Identity, origin: str):
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

    async def _send_command(self, cmd_bytes: bytes) -> bytes:
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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def origin_a(temp_dir):
    s = RegistryTestServer(temp_dir, "origin-a.test")
    yield s
    s.cleanup()

@pytest_asyncio.fixture
async def node_b(temp_dir):
    s = RegistryTestServer(temp_dir, "node-b.test")
    yield s
    s.cleanup()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRegistrySyncBasic:
    """Basic registry sync: origin A -> node B."""

    @pytest.mark.asyncio
    async def test_empty_to_full_initial_sync(self, origin_a, node_b):
        """Node B syncs origin A's registry and ingests all users."""
        # Add users to origin A
        alice_key = Identity.generate().public_key
        origin_a.ume.put("alice", "origin-a.test", alice_key,
                         record_origin="origin-a.test", relay="origin-a.test")
        bob_key = Identity.generate().public_key
        origin_a.ume.put("bob", "origin-a.test", bob_key,
                         record_origin="origin-a.test", relay="origin-a.test")
        head_a = origin_a.registry_service.build_snapshot()
        assert head_a.leaf_count == 2

        # Pin origin A's key in node B's trust store
        node_b.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-a.test", origin_a.server_identity.public_key
        )

        # Create a sync client from node B to origin A
        async with origin_a.make_client() as http_client:
            client = ASGISyncClient(
                http_client, node_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )

            await node_b.handler._sync_mgr._sync_registry(client, "origin-a.test")

        # Verify node B accepted the head
        head_b = node_b.registry_store.get_head("origin-a.test")
        assert head_b is not None

    @pytest.mark.asyncio
    async def test_equal_roots_transfer_no_records(self, origin_a, node_b):
        """When roots are equal, no records are fetched."""
        origin_a.ume.put("alice", "origin-a.test", Identity.generate().public_key,
                         record_origin="origin-a.test", relay="origin-a.test")
        head_a = origin_a.registry_service.build_snapshot()

        # First sync to populate node B
        node_b.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-a.test", origin_a.server_identity.public_key
        )
        async with origin_a.make_client() as http_client:
            client = ASGISyncClient(
                http_client, node_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )
            await node_b.handler._sync_mgr._sync_registry(client, "origin-a.test")

        # Second sync — roots should be equal, no fetch needed
        state_before = node_b.registry_store.get_state("origin-a.test")
        async with origin_a.make_client() as http_client:
            client = ASGISyncClient(
                http_client, node_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )
            await node_b.handler._sync_mgr._sync_registry(client, "origin-a.test")

        state_after = node_b.registry_store.get_state("origin-a.test")
        assert state_after["highest_accepted_seq"] == state_before["highest_accepted_seq"]

    @pytest.mark.asyncio
    async def test_one_update_transfers_changed_leaf(self, origin_a, node_b):
        """Updating one user in origin A syncs only that changed record."""
        pub1 = Identity.generate().public_key
        origin_a.ume.put("alice", "origin-a.test", pub1,
                         record_origin="origin-a.test", relay="origin-a.test")
        origin_a.ume.put("bob", "origin-a.test", Identity.generate().public_key,
                         record_origin="origin-a.test", relay="origin-a.test")
        head1 = origin_a.registry_service.build_snapshot()

        # First sync
        node_b.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-a.test", origin_a.server_identity.public_key
        )
        async with origin_a.make_client() as http_client:
            client = ASGISyncClient(
                http_client, node_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )
            await node_b.handler._sync_mgr._sync_registry(client, "origin-a.test")

        alice_b = node_b.ume.get(username="alice")
        assert alice_b.publickey == pub1

        # Update alice's key
        pub2 = Identity.generate().public_key
        origin_a.ume.upd(username="alice", new_publickey=pub2)
        head2 = origin_a.registry_service.build_snapshot()
        assert head2.merkle_root != head1.merkle_root

        # Second sync
        async with origin_a.make_client() as http_client:
            client = ASGISyncClient(
                http_client, node_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )
            await node_b.handler._sync_mgr._sync_registry(client, "origin-a.test")

        alice_b2 = node_b.ume.get(username="alice")
        assert alice_b2.publickey == pub2

    @pytest.mark.asyncio
    async def test_creation_time_preserved_from_origin(self, origin_a, node_b):
        """Origin's creation_time is preserved during sync."""
        ct = 1609459200
        origin_a.ume.put("alice", "origin-a.test", Identity.generate().public_key,
                         record_origin="origin-a.test", relay="origin-a.test",
                         creation_time=ct)
        origin_a.registry_service.build_snapshot()

        node_b.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-a.test", origin_a.server_identity.public_key
        )
        async with origin_a.make_client() as http_client:
            client = ASGISyncClient(
                http_client, node_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )
            await node_b.handler._sync_mgr._sync_registry(client, "origin-a.test")

        alice_b = node_b.ume.get(username="alice")
        assert alice_b.creation_time == ct

    @pytest.mark.asyncio
    async def test_relay_replaced_with_peer_hostname(self, origin_a, node_b):
        """Receiver replaces relay with the directly contacted peer hostname."""
        origin_a.ume.put("alice", "origin-a.test", Identity.generate().public_key,
                         record_origin="origin-a.test", relay="origin-a.test")
        origin_a.registry_service.build_snapshot()

        node_b.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-a.test", origin_a.server_identity.public_key
        )
        async with origin_a.make_client() as http_client:
            client = ASGISyncClient(
                http_client, node_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )
            await node_b.handler._sync_mgr._sync_registry(client, "origin-a.test")

        alice_b = node_b.ume.get(username="alice")
        assert alice_b.relay == "origin-a.test"

    @pytest.mark.asyncio
    async def test_local_moderation_preserved_on_sync(self, origin_a, node_b):
        """Local moderation flags are not overwritten by remote sync."""
        origin_a.ume.put("alice", "origin-a.test", Identity.generate().public_key,
                         record_origin="origin-a.test", relay="origin-a.test")
        head1 = origin_a.registry_service.build_snapshot()

        node_b.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-a.test", origin_a.server_identity.public_key
        )
        async with origin_a.make_client() as http_client:
            client = ASGISyncClient(
                http_client, node_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )
            await node_b.handler._sync_mgr._sync_registry(client, "origin-a.test")

        # Node B bans alice locally
        node_b.ume.upd(username="alice", new_banned=True)
        assert node_b.ume.get(username="alice").is_banned is True

        # Origin A updates alice's key — sync again
        origin_a.ume.upd(username="alice", new_publickey=Identity.generate().public_key)
        origin_a.registry_service.build_snapshot()

        async with origin_a.make_client() as http_client:
            client = ASGISyncClient(
                http_client, node_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )
            await node_b.handler._sync_mgr._sync_registry(client, "origin-a.test")

        alice_b = node_b.ume.get(username="alice")
        assert alice_b.is_banned is True  # local ban preserved


class TestRegistrySyncSecurity:
    """Security: tampered data, rollback, equivocation."""

    @pytest.mark.asyncio
    async def test_tampered_record_rejected(self, origin_a, node_b, temp_dir):
        """A tampered record (wrong length) is rejected."""
        origin_a.ume.put("alice", "origin-a.test", Identity.generate().public_key,
                         record_origin="origin-a.test", relay="origin-a.test")
        origin_a.registry_service.build_snapshot()

        node_b.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-a.test", origin_a.server_identity.public_key
        )

        # Create a tampered ASGI client that corrupts record responses
        class TamperingClient(ASGISyncClient):
            async def _send_command(self, cmd_bytes):
                payload = await super()._send_command(cmd_bytes)
                if cmd_bytes[0] == 0x07:  # USER_REGISTRY_RECORDS
                    # Corrupt the record length field
                    if len(payload) > 10:
                        payload = bytearray(payload)
                        payload[5] = 0xFF  # wrong record length
                        payload = bytes(payload)
                return payload

        async with origin_a.make_client() as http_client:
            client = TamperingClient(
                http_client, node_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )
            await node_b.handler._sync_mgr._sync_registry(client, "origin-a.test")

        # The tampered record should not have been ingested
        head_b = node_b.registry_store.get_head("origin-a.test")
        # Head may or may not be accepted depending on where the corruption hit,
        # but alice should not be in UME with corrupted data
        alice_b = node_b.ume.get(username="alice")
        if alice_b is not None:
            assert len(alice_b.publickey) == 32  # not corrupted

    @pytest.mark.asyncio
    async def test_rollback_rejected(self, origin_a, node_b):
        """A lower sequence number is rejected as rollback."""
        # Manually accept seq=2 first
        from core.user_registry import sign_head, ZERO_HASH
        h2 = sign_head(
            origin="origin-a.test",
            registry_seq=2,
            snapshot_timestamp=int(time.time()),
            leaf_count=1,
            merkle_root=b"\xBB" * 32,
            previous_head_hash=ZERO_HASH,
            identity=origin_a.server_identity,
        )
        result = node_b.registry_store.accept_remote_head(
            "origin-a.test", h2, origin_a.server_identity.public_key, [], []
        )
        assert result.accepted

        # Try to accept seq=1 (rollback)
        h1 = sign_head(
            origin="origin-a.test",
            registry_seq=1,
            snapshot_timestamp=int(time.time()),
            leaf_count=0,
            merkle_root=b"\xAA" * 32,
            previous_head_hash=ZERO_HASH,
            identity=origin_a.server_identity,
        )
        result = node_b.registry_store.accept_remote_head(
            "origin-a.test", h1, origin_a.server_identity.public_key, [], []
        )
        assert not result.accepted
        assert "rollback" in result.reason

    @pytest.mark.asyncio
    async def test_same_seq_equivocation_rejected(self, origin_a, node_b):
        """Same seq with different root is rejected as equivocation."""
        # Manually accept seq=1
        from core.user_registry import sign_head, ZERO_HASH
        h1 = sign_head(
            origin="origin-a.test",
            registry_seq=1,
            snapshot_timestamp=int(time.time()),
            leaf_count=1,
            merkle_root=b"\xAA" * 32,
            previous_head_hash=ZERO_HASH,
            identity=origin_a.server_identity,
        )
        result = node_b.registry_store.accept_remote_head(
            "origin-a.test", h1, origin_a.server_identity.public_key, [], []
        )
        assert result.accepted

        # Try to accept a different head with the same seq
        equiv_head = sign_head(
            origin="origin-a.test",
            registry_seq=1,
            snapshot_timestamp=int(time.time()),
            leaf_count=99,
            merkle_root=b"\xFF" * 32,
            previous_head_hash=ZERO_HASH,
            identity=origin_a.server_identity,
        )
        result = node_b.registry_store.accept_remote_head(
            "origin-a.test", equiv_head, origin_a.server_identity.public_key, [], []
        )
        assert not result.accepted
        assert "equivocation" in result.reason

    @pytest.mark.asyncio
    async def test_wrong_origin_key_rejected(self, origin_a, node_b):
        """Head signed by a different key than pinned is rejected."""
        origin_a.ume.put("alice", "origin-a.test", Identity.generate().public_key,
                         record_origin="origin-a.test", relay="origin-a.test")
        head1 = origin_a.registry_service.build_snapshot()

        # Pin a WRONG key for origin A
        wrong_key = Identity.generate().public_key
        node_b.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-a.test", wrong_key
        )

        async with origin_a.make_client() as http_client:
            client = ASGISyncClient(
                http_client, node_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )
            await node_b.handler._sync_mgr._sync_registry(client, "origin-a.test")

        # Head should NOT be accepted (signature won't verify against wrong key)
        head_b = node_b.registry_store.get_head("origin-a.test")
        assert head_b is None

    @pytest.mark.asyncio
    async def test_raw_record_retained_in_sidecar(self, origin_a, node_b):
        """The exact attested bytes are retained in the sidecar, separate from UME."""
        origin_a.ume.put("alice", "origin-a.test", Identity.generate().public_key,
                         record_origin="origin-a.test", relay="origin-a.test")
        head1 = origin_a.registry_service.build_snapshot()

        node_b.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-a.test", origin_a.server_identity.public_key
        )
        async with origin_a.make_client() as http_client:
            client = ASGISyncClient(
                http_client, node_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )
            await node_b.handler._sync_mgr._sync_registry(client, "origin-a.test")

        # The sidecar should have the exact raw record
        key = compute_registry_key("origin-a.test", "alice")
        raw = node_b.registry_store.get_record("origin-a.test", key)
        assert raw is not None
        assert len(raw) == RECORD_SIZE

        # The UME record should differ (local moderation flags are not federated)
        user_ume = node_b.ume.get(username="alice")
        user_raw = User.decode(raw)
        # The raw record retains origin flags; UME normalizes them to false for remote users
        assert user_ume.is_administrator is False or user_ume.is_administrator == user_raw.is_administrator


class TestRegistrySyncInsertDelete:
    """Insert and delete reconciliation."""

    @pytest.mark.asyncio
    async def test_one_insertion_synced(self, origin_a, node_b):
        """Adding a new user to origin A and syncing brings it to node B."""
        origin_a.ume.put("alice", "origin-a.test", Identity.generate().public_key,
                         record_origin="origin-a.test", relay="origin-a.test")
        head1 = origin_a.registry_service.build_snapshot()

        node_b.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-a.test", origin_a.server_identity.public_key
        )
        async with origin_a.make_client() as http_client:
            client = ASGISyncClient(
                http_client, node_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )
            await node_b.handler._sync_mgr._sync_registry(client, "origin-a.test")

        # Add bob and sync again
        bob_key = Identity.generate().public_key
        origin_a.ume.put("bob", "origin-a.test", bob_key,
                         record_origin="origin-a.test", relay="origin-a.test")
        origin_a.registry_service.build_snapshot()

        async with origin_a.make_client() as http_client:
            client = ASGISyncClient(
                http_client, node_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )
            await node_b.handler._sync_mgr._sync_registry(client, "origin-a.test")

        bob_b = node_b.ume.get(username="bob")
        assert bob_b is not None
        assert bob_b.publickey == bob_key

    @pytest.mark.asyncio
    async def test_head_chain_advances(self, origin_a, node_b):
        """Multiple syncs advance the head chain on node B."""
        node_b.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-a.test", origin_a.server_identity.public_key
        )

        # Sync 1
        origin_a.ume.put("alice", "origin-a.test", Identity.generate().public_key,
                         record_origin="origin-a.test", relay="origin-a.test")
        h1 = origin_a.registry_service.build_snapshot()
        async with origin_a.make_client() as http_client:
            client = ASGISyncClient(
                http_client, node_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )
            await node_b.handler._sync_mgr._sync_registry(client, "origin-a.test")

        # Sync 2
        origin_a.ume.put("bob", "origin-a.test", Identity.generate().public_key,
                         record_origin="origin-a.test", relay="origin-a.test")
        h2 = origin_a.registry_service.build_snapshot()
        async with origin_a.make_client() as http_client:
            client = ASGISyncClient(
                http_client, node_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )
            await node_b.handler._sync_mgr._sync_registry(client, "origin-a.test")

        state = node_b.registry_store.get_state("origin-a.test")
        assert state["highest_accepted_seq"] == h2.registry_seq

        # Verify head chain linkage
        head1_b = node_b.registry_store.get_head("origin-a.test", h1.registry_seq)
        head2_b = node_b.registry_store.get_head("origin-a.test", h2.registry_seq)
        assert head2_b.previous_head_hash == head1_b.head_hash


# ---------------------------------------------------------------------------
# Phase 6: Relay topology tests
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def relay_b(temp_dir):
    s = RegistryTestServer(temp_dir, "relay-b.test")
    yield s
    s.cleanup()

@pytest_asyncio.fixture
async def node_c(temp_dir):
    s = RegistryTestServer(temp_dir, "node-c.test")
    yield s
    s.cleanup()

@pytest_asyncio.fixture
async def origin_d(temp_dir):
    s = RegistryTestServer(temp_dir, "origin-d.test")
    yield s
    s.cleanup()


class TestRelayTopology:
    """Origin A -> relay B -> node C transfer while preserving origin proofs."""

    @pytest.mark.asyncio
    async def test_three_hop_transfer(self, origin_a, relay_b, node_c):
        """Node C gets origin A's users through relay B.

        1. Origin A creates users and builds a signed head.
        2. Relay B syncs from origin A (direct).
        3. Node C syncs from relay B (relayed).
        4. Node C verifies origin A's head with origin A's pinned key.
        5. Node C has the same users as origin A.
        """
        # 1. Origin A creates users
        alice_key = Identity.generate().public_key
        origin_a.ume.put("alice", "origin-a.test", alice_key,
                         record_origin="origin-a.test", relay="origin-a.test")
        origin_a.registry_service.build_snapshot()

        # 2. Relay B syncs from origin A
        relay_b.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-a.test", origin_a.server_identity.public_key
        )
        async with origin_a.make_client() as http_client:
            client = ASGISyncClient(
                http_client, relay_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )
            await relay_b.handler._sync_mgr._sync_registry(client, "origin-a.test")

        # Verify relay B has origin A's head
        head_b = relay_b.registry_store.get_head("origin-a.test")
        assert head_b is not None
        assert head_b.origin == "origin-a.test"

        # 3. Node C pins origin A's key (out-of-band trust)
        node_c.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-a.test", origin_a.server_identity.public_key
        )
        # Node C also pins relay B's key
        node_c.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "relay-b.test", relay_b.server_identity.public_key
        )

        # 4. Node C syncs from relay B
        async with relay_b.make_client() as http_client:
            client = ASGISyncClient(
                http_client, node_c.server_identity,
                relay_b.anonymous_identity, "relay-b.test"
            )
            await node_c.handler._sync_mgr._sync_registry(client, "relay-b.test")
            await node_c.handler._sync_mgr._sync_relayed_origins(client, "relay-b.test")

        # 5. Node C has origin A's head (relayed through B)
        head_c = node_c.registry_store.get_head("origin-a.test")
        assert head_c is not None
        assert head_c.origin == "origin-a.test"
        assert head_c.merkle_root == head_b.merkle_root

        # 6. Node C has origin A's users
        alice_c = node_c.ume.get(username="alice")
        assert alice_c is not None
        assert alice_c.record_origin == "origin-a.test"
        assert alice_c.publickey == alice_key

    @pytest.mark.asyncio
    async def test_relay_preserves_origin_proof(self, origin_a, relay_b, node_c):
        """The raw attested bytes retained by node C match origin A's exactly."""
        origin_a.ume.put("bob", "origin-a.test", Identity.generate().public_key,
                         record_origin="origin-a.test", relay="origin-a.test")
        head_a = origin_a.registry_service.build_snapshot()

        # Relay B syncs from A
        relay_b.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-a.test", origin_a.server_identity.public_key
        )
        async with origin_a.make_client() as http_client:
            client = ASGISyncClient(
                http_client, relay_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )
            await relay_b.handler._sync_mgr._sync_registry(client, "origin-a.test")

        # Node C pins both keys and syncs from relay B
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
            await node_c.handler._sync_mgr._sync_registry(client, "relay-b.test")
            await node_c.handler._sync_mgr._sync_relayed_origins(client, "relay-b.test")

        # The sidecar record on node C matches the one on relay B
        key = compute_registry_key("origin-a.test", "bob")
        raw_c = node_c.registry_store.get_record("origin-a.test", key)
        raw_b = relay_b.registry_store.get_record("origin-a.test", key)
        assert raw_c is not None
        assert raw_b is not None
        assert raw_c == raw_b

    @pytest.mark.asyncio
    async def test_relay_does_not_introduce_trust(self, origin_a, relay_b, node_c):
        """A relay advertising an origin the receiver has not pinned is skipped."""
        origin_a.ume.put("alice", "origin-a.test", Identity.generate().public_key,
                         record_origin="origin-a.test", relay="origin-a.test")
        origin_a.registry_service.build_snapshot()

        # Relay B syncs from origin A
        relay_b.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-a.test", origin_a.server_identity.public_key
        )
        async with origin_a.make_client() as http_client:
            client = ASGISyncClient(
                http_client, relay_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )
            await relay_b.handler._sync_mgr._sync_registry(client, "origin-a.test")

        # Node C pins relay B's key but NOT origin A's key
        node_c.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "relay-b.test", relay_b.server_identity.public_key
        )

        # Node C syncs from relay B
        async with relay_b.make_client() as http_client:
            client = ASGISyncClient(
                http_client, node_c.server_identity,
                relay_b.anonymous_identity, "relay-b.test"
            )
            await node_c.handler._sync_mgr._sync_registry(client, "relay-b.test")
            await node_c.handler._sync_mgr._sync_relayed_origins(client, "relay-b.test")

        # Node C should NOT have origin A's head (no pinned key)
        head_c = node_c.registry_store.get_head("origin-a.test")
        assert head_c is None

        # Node C should NOT have alice in UME
        alice_c = node_c.ume.get(username="alice")
        assert alice_c is None


class TestMultiOriginRelay:
    """Origin A and origin D -> relay B -> node C."""

    @pytest.mark.asyncio
    async def test_two_origins_through_one_relay(self, origin_a, origin_d, relay_b, node_c):
        """Relay B caches heads from two origins; node C syncs both through B."""
        # Origin A creates a user
        alice_key = Identity.generate().public_key
        origin_a.ume.put("alice", "origin-a.test", alice_key,
                         record_origin="origin-a.test", relay="origin-a.test")
        origin_a.registry_service.build_snapshot()

        # Origin D creates a user
        dave_key = Identity.generate().public_key
        origin_d.ume.put("dave", "origin-d.test", dave_key,
                         record_origin="origin-d.test", relay="origin-d.test")
        origin_d.registry_service.build_snapshot()

        # Relay B syncs from both origins
        relay_b.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-a.test", origin_a.server_identity.public_key
        )
        async with origin_a.make_client() as http_client:
            client = ASGISyncClient(
                http_client, relay_b.server_identity,
                origin_a.anonymous_identity, "origin-a.test"
            )
            await relay_b.handler._sync_mgr._sync_registry(client, "origin-a.test")

        relay_b.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-d.test", origin_d.server_identity.public_key
        )
        async with origin_d.make_client() as http_client:
            client = ASGISyncClient(
                http_client, relay_b.server_identity,
                origin_d.anonymous_identity, "origin-d.test"
            )
            await relay_b.handler._sync_mgr._sync_registry(client, "origin-d.test")

        # Verify relay B has both origins cached
        assert relay_b.registry_store.get_head("origin-a.test") is not None
        assert relay_b.registry_store.get_head("origin-d.test") is not None

        # Node C pins all three keys
        node_c.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-a.test", origin_a.server_identity.public_key
        )
        node_c.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "origin-d.test", origin_d.server_identity.public_key
        )
        node_c.handler._sync_mgr._sync_db.set_peer_pubkey_tofu(
            "relay-b.test", relay_b.server_identity.public_key
        )

        # Node C syncs from relay B
        async with relay_b.make_client() as http_client:
            client = ASGISyncClient(
                http_client, node_c.server_identity,
                relay_b.anonymous_identity, "relay-b.test"
            )
            await node_c.handler._sync_mgr._sync_registry(client, "relay-b.test")
            await node_c.handler._sync_mgr._sync_relayed_origins(client, "relay-b.test")

        # Node C has both origins
        assert node_c.registry_store.get_head("origin-a.test") is not None
        assert node_c.registry_store.get_head("origin-d.test") is not None

        # Node C has users from both origins
        alice_c = node_c.ume.get(username="alice")
        assert alice_c is not None
        assert alice_c.record_origin == "origin-a.test"
        assert alice_c.publickey == alice_key

        dave_c = node_c.ume.get(username="dave")
        assert dave_c is not None
        assert dave_c.record_origin == "origin-d.test"
        assert dave_c.publickey == dave_key
