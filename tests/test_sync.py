# -*- coding: utf-8 -*-
"""Tests for federation trust hardening: board-signature verification (#1),
relay/origin hostname validation / SSRF guard (#2)."""

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
    """Encode a BOARD_LIST (0x11) response payload matching _sync_boards parser.

    entries: list of dicts with keys name, origin, signature (bytes), closed (int).
    """
    payload = struct.pack(">B", 0x00) + struct.pack(">H", len(entries))
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
            conn_mock = MagicMock()
            conn_mock.connect = AsyncMock()
            with pytest.MonkeyPatch().context() as mp:
                mp.setattr("net.sync.Connection", MagicMock(client=MagicMock(return_value=conn_mock)))
                await mgr._do_sync_from_peer(bad)
            # No outbound connection should have been opened.
            conn_mock.connect.assert_not_called()

    @pytest.mark.asyncio
    async def test_refuses_localhost(self, sync_setup):
        mgr, ident, ame, engine = sync_setup
        conn_mock = MagicMock()
        conn_mock.connect = AsyncMock()
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("net.sync.Connection", MagicMock(client=MagicMock(return_value=conn_mock)))
            await mgr._do_sync_from_peer("localhost")
        conn_mock.connect.assert_not_called()

    @pytest.mark.asyncio
    async def test_dials_public_host(self, sync_setup):
        mgr, ident, ame, engine = sync_setup
        conn_mock = MagicMock()
        conn_mock.peer_public_key = ident.public_key
        conn_mock.connect = AsyncMock()
        conn_mock.close = AsyncMock()
        conn_mock.send_request = AsyncMock()
        # Build empty board/user/report responses so the sync completes quickly.
        empty_boards = struct.pack(">B", 0x00) + struct.pack(">H", 0)
        conn_mock.recv_response = AsyncMock(side_effect=[empty_boards])

        with pytest.MonkeyPatch().context() as mp:
            # Mock DNS so the dial-site gate sees a globally routable address.
            mp.setattr("socket.getaddrinfo", lambda h, p, proto=0: [_gai(socket.AF_INET, "8.8.8.8")])
            mp.setattr("net.sync.Connection", MagicMock(client=MagicMock(return_value=conn_mock)))
            await mgr._do_sync_from_peer("peer.example.com")

        conn_mock.connect.assert_awaited()

    @pytest.mark.asyncio
    async def test_refuses_hostname_resolving_to_private_ip(self, sync_setup):
        """R2: a public-looking hostname whose DNS resolves to a private/
        loopback/link-local IP must be refused before dialing."""
        mgr, ident, ame, engine = sync_setup
        for bad_ip in ["127.0.0.1", "10.0.0.1", "169.254.169.254"]:
            conn_mock = MagicMock()
            conn_mock.connect = AsyncMock()
            with pytest.MonkeyPatch().context() as mp:
                mp.setattr("socket.getaddrinfo", lambda h, p, proto=0: [_gai(socket.AF_INET, bad_ip)])
                mp.setattr("net.sync.Connection", MagicMock(client=MagicMock(return_value=conn_mock)))
                await mgr._do_sync_from_peer("peer.example.com")
            conn_mock.connect.assert_not_called()

    @pytest.mark.asyncio
    async def test_refuses_hostname_with_any_private_resolution(self, sync_setup):
        """If ANY resolved address is non-global, the dial is refused even when
        some addresses are public."""
        mgr, ident, ame, engine = sync_setup
        conn_mock = MagicMock()
        conn_mock.connect = AsyncMock()
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("socket.getaddrinfo", lambda h, p, proto=0: [
                _gai(socket.AF_INET, "8.8.8.8"),
                _gai(socket.AF_INET, "127.0.0.1"),
            ])
            mp.setattr("net.sync.Connection", MagicMock(client=MagicMock(return_value=conn_mock)))
            await mgr._do_sync_from_peer("peer.example.com")
        conn_mock.connect.assert_not_called()

    @pytest.mark.asyncio
    async def test_refuses_hostname_that_fails_resolution(self, sync_setup):
        mgr, ident, ame, engine = sync_setup
        conn_mock = MagicMock()
        conn_mock.connect = AsyncMock()

        def raise_gaierror(h, p, proto=0):
            raise socket.gaierror("no such host")

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("socket.getaddrinfo", raise_gaierror)
            mp.setattr("net.sync.Connection", MagicMock(client=MagicMock(return_value=conn_mock)))
            await mgr._do_sync_from_peer("peer.example.com")
        conn_mock.connect.assert_not_called()


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
    @pytest.mark.asyncio
    async def test_accepts_correctly_signed_board(self, sync_setup):
        mgr, ident, ame, engine = sync_setup
        peer_origin = "peer.example.com"
        # TOFU the peer origin with a known key we sign the board with.
        peer_ident = Identity.generate()
        mgr._sync_db.set_peer_pubkey_tofu(peer_origin, peer_ident.public_key)

        name = "goodboard"
        sig = peer_ident.sign(_build_board_signature_payload(name, peer_origin))

        conn = MagicMock()
        conn.send_request = AsyncMock()
        conn.recv_response = AsyncMock(
            return_value=_encode_board_list([
                {"name": name, "origin": peer_origin, "signature": sig, "closed": 0}
            ])
        )

        await mgr._sync_boards(conn, peer_origin)

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

        conn = MagicMock()
        conn.send_request = AsyncMock()
        conn.recv_response = AsyncMock(
            return_value=_encode_board_list([
                {"name": name, "origin": peer_origin, "signature": bad_sig, "closed": 0}
            ])
        )

        await mgr._sync_boards(conn, peer_origin)

        assert ame.get_nav().get(name) is None

    @pytest.mark.asyncio
    async def test_rejects_origin_without_tofu_key(self, sync_setup):
        mgr, ident, ame, engine = sync_setup
        peer_origin = "peer.example.com"
        # No TOFU for this origin.
        peer_ident = Identity.generate()
        name = "untrusted"
        sig = peer_ident.sign(_build_board_signature_payload(name, peer_origin))

        conn = MagicMock()
        conn.send_request = AsyncMock()
        conn.recv_response = AsyncMock(
            return_value=_encode_board_list([
                {"name": name, "origin": peer_origin, "signature": sig, "closed": 0}
            ])
        )

        await mgr._sync_boards(conn, peer_origin)
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
        conn = MagicMock()
        conn.send_request = AsyncMock()
        conn.recv_response = AsyncMock(
            return_value=_encode_board_list([
                {"name": name, "origin": peer_origin, "signature": sig, "closed": 0}
            ])
        )

        await mgr._sync_boards(conn, "127.0.0.1")
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

        conn = MagicMock()
        conn.send_request = AsyncMock()
        conn.recv_response = AsyncMock(
            return_value=_encode_board_list([
                {"name": good, "origin": peer_origin, "signature": good_sig, "closed": 0},
                {"name": tampered, "origin": peer_origin, "signature": tampered_sig, "closed": 0},
            ])
        )

        await mgr._sync_boards(conn, peer_origin)
        nav = ame.get_nav()
        assert nav.get(good) is not None
        assert nav.get(tampered) is None
