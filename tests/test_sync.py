# -*- coding: utf-8 -*-
"""Tests for federation trust hardening: board-signature verification (#1),
relay/origin hostname validation / SSRF guard (#2), and user/report sync
parser defects (Phase 0 failing tests)."""

import asyncio
import os
import socket
import struct
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from net.sync import (
    SyncManager,
    SyncDB,
    _is_dialable_host,
    _resolves_to_global_only,
    _build_board_signature_payload,
)
from engine.ame import Ame, NavDB
from engine.ume import Ume
from core.crypto import Identity


# ---------------------------------------------------------------------------
# #2 -- _is_dialable_host
# ---------------------------------------------------------------------------


class TestIsDialableHost:
    def test_rejects_empty(self):
        assert _is_dialable_host("") is False
        assert _is_dialable_host("   ") is False
        assert _is_dialable_host(None) is False

    def test_rejects_private_loopback_linklocal(self):
        assert _is_dialable_host("127.0.0.1") is False
        assert _is_dialable_host("10.0.0.1") is False
        assert _is_dialable_host("192.168.1.1") is False
        assert _is_dialable_host("172.16.0.1") is False
        assert _is_dialable_host("169.254.169.254") is False  # cloud metadata
        assert _is_dialable_host("::1") is False
        assert _is_dialable_host("fc00::1") is False  # ULA/private v6

    def test_rejects_invalid_hostname_strings(self):
        assert _is_dialable_host("not a host") is False
        assert _is_dialable_host("exa mple.com") is False
        assert _is_dialable_host("-leading.com") is False
        assert _is_dialable_host("trailing-.com") is False

    def test_accepts_public_hostname_and_ip(self):
        assert _is_dialable_host("peer.example.com") is True
        assert _is_dialable_host("peer") is True
        assert _is_dialable_host("8.8.8.8") is True
        assert _is_dialable_host("1.1.1.1") is True

    def test_bracketed_ipv6_stripped(self):
        # A globally routable IPv6 inside brackets should still be evaluated.
        assert _is_dialable_host("[2606:4700:4700::1111]") is True

    def test_rejects_localhost_special_use(self):
        # R2: 'localhost' and the .localhost TLD are syntactically valid
        # hostnames but must never be dialed.
        assert _is_dialable_host("localhost") is False
        assert _is_dialable_host("foo.localhost") is False
        assert _is_dialable_host("sub.foo.localhost") is False
        # A real public hostname that merely starts with 'localhost' is fine.
        assert _is_dialable_host("localhost.example.com") is True


# ---------------------------------------------------------------------------
# helpers to build a SyncManager against a temp data dir
# ---------------------------------------------------------------------------


def _build_engine(temp_dir):
    ident = Identity.generate()
    ame_path = os.path.join(temp_dir, "ame")
    nav_db_path = os.path.join(temp_dir, "nav.db")
    ame = Ame(ame_path, origin="local.test", signing_key=ident.signing_key, nav_db_path=nav_db_path)

    config = MagicMock()
    config.origin = "local.test"
    config.data_dir = temp_dir

    engine = MagicMock()
    engine.ume = MagicMock()
    engine.ame = ame
    engine.keibatsu = MagicMock()
    engine.config = config
    engine.server_identity = ident
    return engine, ident, ame


def _encode_board_list(entries):
    """Encode a BOARD_LIST response payload (after status byte, as returned by _send_command).

    entries: list of dicts with keys name, origin, signature (bytes), closed (int).
    """
    payload = struct.pack(">H", len(entries))
    for e in entries:
        name_b = e["name"].encode("utf-8")
        origin_b = e["origin"].encode("utf-8")
        sig = e["signature"]
        payload += struct.pack("B", len(name_b)) + name_b
        payload += struct.pack("B", len(origin_b)) + origin_b
        payload += struct.pack("B", len(sig)) + sig
        payload += struct.pack("B", 1 if e.get("closed") else 0)
    return payload


@pytest_asyncio.fixture
async def sync_setup(temp_dir):
    engine, ident, ame = _build_engine(temp_dir)
    mgr = SyncManager(engine)
    yield mgr, ident, ame, engine
    # tear down the background worker task created in __init__
    task = mgr._worker_task
    if task is not None and not task.done():
        task.cancel()
        try:
            await task
        except BaseException:
            pass


# ---------------------------------------------------------------------------
# #2 -- _do_sync_from_peer refuses to dial non-dialable hosts
# ---------------------------------------------------------------------------


def _gai(family, ip):
    """Build a single getaddrinfo result tuple for `ip` under `family`."""
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 0))


class TestDoSyncFromPeerSSRFGuard:
    @pytest.mark.asyncio
    async def test_refuses_private_loopback(self, sync_setup):
        mgr, ident, ame, engine = sync_setup
        for bad in ["127.0.0.1", "169.254.169.254", "10.0.0.1", "not a host"]:
            client_mock = MagicMock()
            with pytest.MonkeyPatch().context() as mp:
                mp.setattr("client.http.BonnetHTTPClient", MagicMock(return_value=client_mock))
                await mgr._do_sync_from_peer(bad)
            # No outbound connection should have been opened.
            client_mock.connect.assert_not_called()

    @pytest.mark.asyncio
    async def test_refuses_localhost(self, sync_setup):
        mgr, ident, ame, engine = sync_setup
        client_mock = MagicMock()
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("client.http.BonnetHTTPClient", MagicMock(return_value=client_mock))
            await mgr._do_sync_from_peer("localhost")
        client_mock.connect.assert_not_called()

    @pytest.mark.asyncio
    async def test_dials_public_host(self, sync_setup):
        mgr, ident, ame, engine = sync_setup
        client_mock = MagicMock()
        client_mock.server_public_key = ident.public_key
        client_mock.connect = AsyncMock()
        client_mock.close = AsyncMock()
        client_mock._send_command = AsyncMock(return_value=struct.pack(">H", 0))

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("socket.getaddrinfo", lambda h, p, proto=0: [_gai(socket.AF_INET, "8.8.8.8")])
            mp.setattr("client.http.BonnetHTTPClient", MagicMock(return_value=client_mock))
            await mgr._do_sync_from_peer("peer.example.com")

        client_mock.connect.assert_awaited()

    @pytest.mark.asyncio
    async def test_refuses_hostname_resolving_to_private_ip(self, sync_setup):
        """R2: a public-looking hostname whose DNS resolves to a private/
        loopback/link-local IP must be refused before dialing."""
        mgr, ident, ame, engine = sync_setup
        for bad_ip in ["127.0.0.1", "10.0.0.1", "169.254.169.254"]:
            client_mock = MagicMock()
            with pytest.MonkeyPatch().context() as mp:
                mp.setattr("socket.getaddrinfo", lambda h, p, proto=0: [_gai(socket.AF_INET, bad_ip)])
                mp.setattr("client.http.BonnetHTTPClient", MagicMock(return_value=client_mock))
                await mgr._do_sync_from_peer("peer.example.com")
            client_mock.connect.assert_not_called()

    @pytest.mark.asyncio
    async def test_refuses_hostname_with_any_private_resolution(self, sync_setup):
        """If ANY resolved address is non-global, the dial is refused even when
        some addresses are public."""
        mgr, ident, ame, engine = sync_setup
        client_mock = MagicMock()
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("socket.getaddrinfo", lambda h, p, proto=0: [
                _gai(socket.AF_INET, "8.8.8.8"),
                _gai(socket.AF_INET, "127.0.0.1"),
            ])
            mp.setattr("client.http.BonnetHTTPClient", MagicMock(return_value=client_mock))
            await mgr._do_sync_from_peer("peer.example.com")
        client_mock.connect.assert_not_called()

    @pytest.mark.asyncio
    async def test_refuses_hostname_that_fails_resolution(self, sync_setup):
        mgr, ident, ame, engine = sync_setup
        client_mock = MagicMock()

        def raise_gaierror(h, p, proto=0):
            raise socket.gaierror("no such host")

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("socket.getaddrinfo", raise_gaierror)
            mp.setattr("client.http.BonnetHTTPClient", MagicMock(return_value=client_mock))
            await mgr._do_sync_from_peer("peer.example.com")
        client_mock.connect.assert_not_called()


# ---------------------------------------------------------------------------
# #2 / R2 -- _resolves_to_global_only
# ---------------------------------------------------------------------------


class TestResolvesToGlobalOnly:
    def test_public_ip_resolution_passes(self):
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("socket.getaddrinfo", lambda h, p, proto=0: [_gai(socket.AF_INET, "8.8.8.8")])
            assert _resolves_to_global_only("peer.example.com") is True

    def test_private_ip_resolution_fails(self):
        for bad_ip in ["127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.1.1"]:
            with pytest.MonkeyPatch().context() as mp:
                mp.setattr("socket.getaddrinfo", lambda h, p, proto=0, bip=bad_ip: [_gai(socket.AF_INET, bip)])
                assert _resolves_to_global_only("peer.example.com") is False, bad_ip

    def test_mixed_resolution_fails(self):
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("socket.getaddrinfo", lambda h, p, proto=0: [
                _gai(socket.AF_INET, "8.8.8.8"),
                _gai(socket.AF_INET, "10.0.0.1"),
            ])
            assert _resolves_to_global_only("peer.example.com") is False

    def test_resolution_failure_returns_false(self):
        def raise_gaierror(h, p, proto=0):
            raise socket.gaierror("no such host")

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("socket.getaddrinfo", raise_gaierror)
            assert _resolves_to_global_only("peer.example.com") is False

    def test_empty_resolution_returns_false(self):
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("socket.getaddrinfo", lambda h, p, proto=0: [])
            assert _resolves_to_global_only("peer.example.com") is False

    def test_public_ipv6_resolution_passes(self):
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("socket.getaddrinfo", lambda h, p, proto=0: [
                _gai(socket.AF_INET6, "2606:4700:4700::1111"),
            ])
            assert _resolves_to_global_only("peer.example.com") is True

    def test_rejects_empty_and_non_str(self):
        assert _resolves_to_global_only("") is False
        assert _resolves_to_global_only("   ") is False
        assert _resolves_to_global_only(None) is False


# ---------------------------------------------------------------------------
# #1 -- _sync_boards verifies board signatures
# ---------------------------------------------------------------------------


class TestSyncBoardsSignatureVerification:
    def _make_sync_client(self, board_payload):
        """Create a mock BonnetHTTPClient for _sync_boards tests."""
        class FakeClient:
            def __init__(self):
                self._payload = board_payload
                self.server_public_key = b"\x00" * 32
            async def _send_command(self, cmd):
                return self._payload
            async def connect(self, ident):
                pass
            async def close(self):
                pass
        return FakeClient()

    @pytest.mark.asyncio
    async def test_accepts_correctly_signed_board(self, sync_setup):
        mgr, ident, ame, engine = sync_setup
        peer_origin = "peer.example.com"
        # TOFU the peer origin with a known key we sign the board with.
        peer_ident = Identity.generate()
        mgr._sync_db.set_peer_pubkey_tofu(peer_origin, peer_ident.public_key)

        name = "goodboard"
        sig = peer_ident.sign(_build_board_signature_payload(name, peer_origin))

        payload = _encode_board_list([
            {"name": name, "origin": peer_origin, "signature": sig, "closed": 0}
        ])
        client = self._make_sync_client(payload)

        await mgr._sync_boards(client, peer_origin)

        nav = ame.get_nav()
        entry = nav.get(name)
        assert entry is not None
        assert entry["origin"] == peer_origin
        assert entry["signature"] == sig

    @pytest.mark.asyncio
    async def test_rejects_tampered_signature(self, sync_setup):
        mgr, ident, ame, engine = sync_setup
        peer_origin = "peer.example.com"
        peer_ident = Identity.generate()
        mgr._sync_db.set_peer_pubkey_tofu(peer_origin, peer_ident.public_key)

        name = "badboard"
        # Sign with a *different* key than the one TOFU'd for this origin.
        other_ident = Identity.generate()
        bad_sig = other_ident.sign(_build_board_signature_payload(name, peer_origin))

        payload = _encode_board_list([
            {"name": name, "origin": peer_origin, "signature": bad_sig, "closed": 0}
        ])
        client = self._make_sync_client(payload)

        await mgr._sync_boards(client, peer_origin)

        assert ame.get_nav().get(name) is None

    @pytest.mark.asyncio
    async def test_rejects_origin_without_tofu_key(self, sync_setup):
        mgr, ident, ame, engine = sync_setup
        peer_origin = "peer.example.com"
        # No TOFU for this origin.
        peer_ident = Identity.generate()
        name = "untrusted"
        sig = peer_ident.sign(_build_board_signature_payload(name, peer_origin))

        payload = _encode_board_list([
            {"name": name, "origin": peer_origin, "signature": sig, "closed": 0}
        ])
        client = self._make_sync_client(payload)

        await mgr._sync_boards(client, peer_origin)
        assert ame.get_nav().get(name) is None

    @pytest.mark.asyncio
    async def test_rejects_private_relay_ingest(self, sync_setup):
        """Even with a valid signature, a board whose relay is a private IP
        must not be ingested (#2 ingest guard)."""
        mgr, ident, ame, engine = sync_setup
        peer_origin = "peer.example.com"
        peer_ident = Identity.generate()
        mgr._sync_db.set_peer_pubkey_tofu(peer_origin, peer_ident.public_key)

        name = "ssrfboard"
        sig = peer_ident.sign(_build_board_signature_payload(name, peer_origin))

        # peer_hostname here is the relay that gets stored; use a private IP.
        payload = _encode_board_list([
            {"name": name, "origin": peer_origin, "signature": sig, "closed": 0}
        ])
        client = self._make_sync_client(payload)

        await mgr._sync_boards(client, "127.0.0.1")
        assert ame.get_nav().get(name) is None

    @pytest.mark.asyncio
    async def test_mixed_batch_only_verified_upserted(self, sync_setup):
        mgr, ident, ame, engine = sync_setup
        peer_origin = "peer.example.com"
        peer_ident = Identity.generate()
        mgr._sync_db.set_peer_pubkey_tofu(peer_origin, peer_ident.public_key)

        good = "goodboard"
        good_sig = peer_ident.sign(_build_board_signature_payload(good, peer_origin))
        tampered = "tamperedboard"
        tampered_sig = Identity.generate().sign(_build_board_signature_payload(tampered, peer_origin))

        payload = _encode_board_list([
            {"name": good, "origin": peer_origin, "signature": good_sig, "closed": 0},
            {"name": tampered, "origin": peer_origin, "signature": tampered_sig, "closed": 0},
        ])
        client = self._make_sync_client(payload)

        await mgr._sync_boards(client, peer_origin)
        nav = ame.get_nav()
        assert nav.get(good) is not None
        assert nav.get(tampered) is None


# ---------------------------------------------------------------------------
# Phase 0: _sync_users / _sync_reports parser defects (failing tests)
# ---------------------------------------------------------------------------


def _build_engine_with_real_ume(temp_dir):
    """Like _build_engine but with a real Ume for testing user ingestion."""
    ident = Identity.generate()
    ame_path = os.path.join(temp_dir, "ame")
    nav_db_path = os.path.join(temp_dir, "nav.db")
    ame = Ame(ame_path, origin="local.test", signing_key=ident.signing_key, nav_db_path=nav_db_path)

    ume = Ume(os.path.join(temp_dir, "userfile"))

    config = MagicMock()
    config.origin = "local.test"
    config.data_dir = temp_dir

    engine = MagicMock()
    engine.ume = ume
    engine.ame = ame
    engine.keibatsu = MagicMock()
    engine.config = config
    engine.server_identity = ident
    return engine, ident, ame, ume


def _encode_user_list(users):
    """Encode a LIST_USERS response payload (after status byte, as returned
    by _send_command). Mirrors _cmd_list output format."""
    payload = struct.pack(">H", len(users))
    for u in users:
        name_b = u["username"].encode("utf-8")
        reg_b = u["registrar"].encode("utf-8")
        origin_b = u["record_origin"].encode("utf-8")
        relay_b = u["relay"].encode("utf-8")
        pubkey = u["publickey"]
        payload += struct.pack("B", len(name_b)) + name_b
        payload += struct.pack("B", len(reg_b)) + reg_b
        payload += struct.pack("B", len(origin_b)) + origin_b
        payload += struct.pack("B", len(relay_b)) + relay_b
        payload += struct.pack("B", len(pubkey)) + pubkey
    return payload


def _encode_report_list(reports):
    """Encode a REPORT_LIST_SINCE response payload (after status byte, as
    returned by _send_command). Mirrors _cmd_report_list_since output format."""
    payload = struct.pack(">H", len(reports))
    for r in reports:
        payload += struct.pack(">Q", r["report_num"])
        payload += struct.pack(">Q", r["rule_num"])
        culprit = r["culprit_pubkey"]
        payload += struct.pack("B", len(culprit)) + culprit
        board_b = (r.get("board") or "").encode("utf-8")
        payload += struct.pack("B", len(board_b)) + board_b
        payload += struct.pack(">Q", r.get("post_num", 0))
        reporter = r["reporter_pubkey"]
        payload += struct.pack("B", len(reporter)) + reporter
        payload += struct.pack(">q", r["report_time"])
        origin_b = r["origin"].encode("utf-8")
        payload += struct.pack("B", len(origin_b)) + origin_b
        relay_b = r["relay"].encode("utf-8")
        payload += struct.pack("B", len(relay_b)) + relay_b
        desc_b = r["description"].encode("utf-8")
        payload += struct.pack("B", len(desc_b)) + desc_b
        origin_sig_b = (r.get("origin_sig") or "").encode("utf-8")
        payload += struct.pack("B", len(origin_sig_b)) + origin_sig_b
        reporter_sig_b = (r.get("reporter_sig") or "").encode("utf-8")
        payload += struct.pack("B", len(reporter_sig_b)) + reporter_sig_b
    return payload


class FakeSyncClient:
    """Fake HTTP client for sync tests. Returns payloads in order, then
    returns an empty list (count=0) to terminate pagination loops."""

    def __init__(self, payloads):
        self._payloads = list(payloads)
        self._call_count = 0
        self.server_public_key = b"\x00" * 32

    async def _send_command(self, cmd):
        self._call_count += 1
        if self._call_count <= len(self._payloads):
            return self._payloads[self._call_count - 1]
        return struct.pack(">H", 0)

    async def connect(self, ident):
        pass

    async def close(self):
        pass


@pytest_asyncio.fixture
async def sync_setup_real_ume(temp_dir):
    engine, ident, ame, ume = _build_engine_with_real_ume(temp_dir)
    mgr = SyncManager(engine)
    yield mgr, ident, ame, engine, ume
    task = mgr._worker_task
    if task is not None and not task.done():
        task.cancel()
        try:
            await task
        except BaseException:
            pass


class TestSyncUsersParsing:
    """Phase 0: Demonstrate that _sync_users raises NameError on non-empty
    responses because it reads an undefined variable `response` instead of
    `payload` (src/net/sync.py:337-360)."""

    @pytest.mark.asyncio
    async def test_nonempty_user_list_ingests_without_nameerror(self, sync_setup_real_ume):
        mgr, ident, ame, engine, ume = sync_setup_real_ume
        peer_hostname = "peer.example.com"

        pubkey = Identity.generate().public_key
        payload = _encode_user_list([{
            "username": "remote_alice",
            "registrar": "peer.example.com",
            "record_origin": "peer.example.com",
            "relay": "peer.example.com",
            "publickey": pubkey,
        }])
        client = FakeSyncClient([payload])

        await mgr._sync_users(client, peer_hostname)

        user = ume.get(username="remote_alice")
        assert user is not None
        assert user.record_origin == "peer.example.com"
        assert user.publickey == pubkey


class TestSyncReportsParsing:
    """Phase 0: Demonstrate that _sync_reports raises NameError on non-empty
    responses because it reads an undefined variable `response` instead of
    `payload` (src/net/sync.py:391-441)."""

    @pytest.mark.asyncio
    async def test_nonempty_report_list_ingests_without_nameerror(self, sync_setup):
        mgr, ident, ame, engine = sync_setup
        peer_hostname = "peer.example.com"

        pubkey = Identity.generate().public_key
        payload = _encode_report_list([{
            "report_num": 1,
            "rule_num": 1,
            "culprit_pubkey": pubkey,
            "board": "general",
            "post_num": 42,
            "reporter_pubkey": pubkey,
            "report_time": 1700000000,
            "origin": "peer.example.com",
            "relay": "peer.example.com",
            "description": "spam",
            "origin_sig": "",
            "reporter_sig": "",
        }])
        client = FakeSyncClient([payload])

        engine.keibatsu.upsert_remote_report = MagicMock(
            return_value=MagicMock(result=MagicMock(return_value=True))
        )

        await mgr._sync_reports(client, peer_hostname)

        engine.keibatsu.upsert_remote_report.assert_called_once()
