# -*- coding: utf-8 -*-
"""Tests for command-handler trust hardening:
- #7 report origin is bound to the local server (client-supplied origin ignored)
- #6 remote-board redirect is gated behind auth + permission (no sync trigger
  for anonymous/unauthorized callers)
"""

import asyncio
import os
import struct
from unittest.mock import MagicMock, AsyncMock

import pytest
import pytest_asyncio

from net.commands import CommandHandler
from net.connection import Connection
from engine.facade import BonnetEngine
from engine.ume import Ume, User
from engine.ame import Ame
from engine.keibatsu import Keibatsu
from core.crypto import Identity
from core.config import Config, Matcher, ACLEntry
from core.orm import Database


# ---------------------------------------------------------------------------
# engine / handler fixtures
# ---------------------------------------------------------------------------


def _make_config(temp_dir, origin="local.test"):
    return Config(
        origin=origin,
        ame_path=os.path.join(temp_dir, "boards"),
        data_dir=temp_dir,
        nav_db_path=os.path.join(temp_dir, "nav.db"),
        reports_db_path=os.path.join(temp_dir, "reports.db"),
        punishments_db_path=os.path.join(temp_dir, "punishments.db"),
        log_dir=os.path.join(temp_dir, "logs"),
        acls=[],  # tests set ACLs explicitly
        anonymous_read=True,
    )


def _init_rules(reports_path):
    with Database(reports_path).open() as ctx:
        ctx.execute("""
            CREATE TABLE IF NOT EXISTS rules (
                rule_num INTEGER PRIMARY KEY,
                rule_name TEXT UNIQUE NOT NULL,
                description TEXT NOT NULL
            )
        """)


@pytest_asyncio.fixture
async def engine_setup(temp_dir):
    ident = Identity.generate()
    config = _make_config(temp_dir, origin="local.test")

    userfile = os.path.join(temp_dir, "userfile")
    ume = Ume(userfile)
    ame = Ame(config.ame_path, origin=config.origin, signing_key=ident.signing_key,
              nav_db_path=config.nav_db_path)
    _init_rules(config.reports_db_path)
    keibatsu = Keibatsu(config.reports_db_path, config.punishments_db_path,
                        ume=ume, signing_key=ident.signing_key, origin=config.origin)

    engine = BonnetEngine(ume, ame, keibatsu, config, ident)
    handler = CommandHandler(engine)

    # cancel the sync worker task created by SyncManager so it doesn't linger
    task = handler._sync_mgr._worker_task
    if task is not None and not task.done():
        task.cancel()
        try:
            await task
        except BaseException:
            pass

    yield handler, engine, ident, config, ume, ame, keibatsu

    ame.shutdown()
    keibatsu.shutdown()


def _auth_conn(ident, user=None, peer_pubkey=None, origin_header="evil.example"):
    """A Connection.server with a spoofable Host header (origin_header).

    By default no user => anonymous. Pass a User to make it authenticated.
    """
    ws = MagicMock()
    ws.remote_address = ("203.0.113.9", 12345)
    req = MagicMock()
    req.headers = {"Host": origin_header}
    ws.request = req
    engine = MagicMock()
    engine.ume = MagicMock()
    engine.config = MagicMock(max_request_size=0)
    conn = Connection.server(ident, ws, engine)
    if user is not None:
        conn.user = user
    if peer_pubkey is not None:
        conn.peer_public_key = peer_pubkey
    return conn


def _anonymous_conn(ident, origin_header="localhost"):
    return _auth_conn(ident, user=None, peer_pubkey=b"\x11" * 32, origin_header=origin_header)


def _decode_error(response):
    """Return (code, message) if response is an error frame, else None."""
    if len(response) > 0 and response[0] == 0x01:
        code = struct.unpack(">H", response[1:3])[0]
        msg_len = response[3]
        return code, response[4:4 + msg_len].decode("utf-8", errors="replace")
    return None


def _decode_report(response):
    """Parse a _encode_report payload into a dict (origin, origin_sig, ...)."""
    assert response[0] == 0x00, f"expected success frame, got error {_decode_error(response)}"
    idx = 1
    report_num = struct.unpack(">Q", response[idx:idx + 8])[0]; idx += 8
    rule_num = struct.unpack(">Q", response[idx:idx + 8])[0]; idx += 8
    cl = response[idx]; idx += 1; culprit = response[idx:idx + cl]; idx += cl
    bl = response[idx]; idx += 1; board = response[idx:idx + bl].decode(); idx += bl
    post_num = struct.unpack(">Q", response[idx:idx + 8])[0]; idx += 8
    rl = response[idx]; idx += 1; reporter = response[idx:idx + rl]; idx += rl
    report_time = struct.unpack(">q", response[idx:idx + 8])[0]; idx += 8
    ol = response[idx]; idx += 1; origin = response[idx:idx + ol].decode(); idx += ol
    rel = response[idx]; idx += 1; relay = response[idx:idx + rel].decode(); idx += rel
    dl = response[idx]; idx += 1; desc = response[idx:idx + dl].decode(); idx += dl
    osl = response[idx]; idx += 1; origin_sig = response[idx:idx + osl].decode() if osl else None; idx += osl
    rsl = response[idx]; idx += 1; reporter_sig = response[idx:idx + rsl].decode() if rsl else None
    return {
        "report_num": report_num, "rule_num": rule_num, "origin": origin, "relay": relay,
        "origin_sig": origin_sig, "reporter_sig": reporter_sig, "board": board, "description": desc,
    }


def _build_report_create(rule_num, culprit_pubkey, reporter_pubkey, description,
                         board=None, culprit_post_num=0, origin=None, relay=None):
    out = struct.pack(">Q", rule_num)
    out += struct.pack("B", len(culprit_pubkey)) + culprit_pubkey
    out += struct.pack("B", len(reporter_pubkey)) + reporter_pubkey
    desc_b = description.encode("utf-8")
    out += struct.pack("B", len(desc_b)) + desc_b
    if board:
        bb = board.encode("utf-8")
        out += struct.pack("B", len(bb)) + bb
    else:
        out += struct.pack("B", 0)
    out += struct.pack(">Q", culprit_post_num)
    if origin:
        ob = origin.encode("utf-8")
        out += struct.pack("B", len(ob)) + ob
    else:
        out += struct.pack("B", 0)
    if relay:
        rb = relay.encode("utf-8")
        out += struct.pack("B", len(rb)) + rb
    else:
        out += struct.pack("B", 0)
    return bytes([0x50]) + out


# ---------------------------------------------------------------------------
# #7 -- report origin is server-bound
# ---------------------------------------------------------------------------


class TestReportOriginServerBound:
    def test_client_origin_ignored(self, engine_setup):
        handler, engine, ident, config, ume, ame, keibatsu = engine_setup
        rule = keibatsu.create_rule("No Spam", "spam").result(timeout=5)

        culprit = Identity.generate().public_key
        reporter = Identity.generate().public_key

        user = ume.put("alice", config.origin, reporter, record_origin="local.test")
        conn = _auth_conn(ident, user=user, peer_pubkey=reporter)

        # Forge an origin/relay claiming the report came from elsewhere.
        req = _build_report_create(
            rule.rule_num, culprit, reporter, "Posted spam",
            board="board1", culprit_post_num=1,
            origin="other.example", relay="other.example",
        )
        resp = handler.handle(req, conn)
        err = _decode_error(resp)
        assert err is None, f"report create failed: {err}"

        report = _decode_report(resp)
        assert report["origin"] == config.origin
        assert report["relay"] == config.origin
        # origin_sig must verify against the LOCAL server key, not "other.example".
        assert report["origin_sig"]
        from core.crypto import Identity as _I
        # Reconstruct the canonical signed payload (mirrors
        # Keibatsu._build_signed_payload) and verify the origin signature
        # against the local server key.
        fetched = keibatsu.get_report(config.origin, report["report_num"]).result(timeout=5)
        assert fetched.origin == config.origin
        culprit_board_b = (fetched.culprit_board or "").encode("utf-8")
        origin_b = fetched.origin.encode("utf-8")
        desc_b = fetched.description.encode("utf-8")
        payload = (
            struct.pack(">Q", fetched.report_num)
            + struct.pack(">Q", fetched.rule_num)
            + struct.pack("B", len(fetched.culprit_pubkey)) + fetched.culprit_pubkey
            + struct.pack("B", len(culprit_board_b)) + culprit_board_b
            + struct.pack(">Q", fetched.culprit_post_num)
            + struct.pack("B", len(fetched.reporter_pubkey)) + fetched.reporter_pubkey
            + struct.pack(">q", fetched.report_time)
            + struct.pack("B", len(origin_b)) + origin_b
            + struct.pack("B", len(desc_b)) + desc_b
        )
        assert _I.verify(ident.public_key, payload, bytes.fromhex(report["origin_sig"])) is True

    def test_anonymous_report_rejected(self, engine_setup):
        handler, engine, ident, config, ume, ame, keibatsu = engine_setup
        rule = keibatsu.create_rule("No Spam", "spam").result(timeout=5)
        culprit = Identity.generate().public_key
        reporter = Identity.generate().public_key
        conn = _anonymous_conn(ident)
        req = _build_report_create(rule.rule_num, culprit, reporter, "x")
        resp = handler.handle(req, conn)
        code, _ = _decode_error(resp)
        assert code == 401


# ---------------------------------------------------------------------------
# #6 -- remote-board redirect gated behind auth + permission
# ---------------------------------------------------------------------------


def _build_post_create(board_name, root=0, subject="s", tags="", options="", content="c"):
    out = b""
    bb = board_name.encode("utf-8")
    out += struct.pack("B", len(bb)) + bb
    out += struct.pack(">Q", root)
    sb = subject.encode("utf-8")
    out += struct.pack("B", len(sb)) + sb
    tb = tags.encode("utf-8")
    out += struct.pack("B", len(tb)) + tb
    ob = options.encode("utf-8")
    out += struct.pack("B", len(ob)) + ob
    cb = content.encode("utf-8")
    out += struct.pack(">I", len(cb)) + cb
    return bytes([0x12]) + out


def _build_post_get(board_name, post_num=1):
    bb = board_name.encode("utf-8")
    return bytes([0x13]) + struct.pack("B", len(bb)) + bb + struct.pack(">Q", post_num)


def _build_post_list(board_name, offset=0, limit=10):
    bb = board_name.encode("utf-8")
    return bytes([0x14]) + struct.pack("B", len(bb)) + bb + struct.pack(">I", offset) + struct.pack(">I", limit)


def _seed_remote_board(ame, board_name, origin, relay, signature=b"\x00" * 64):
    """Insert a nav entry for a remote board so the redirect path is taken."""
    nav = ame.get_nav()
    nav.upsert_remote_batch([(board_name, board_name, origin, signature, relay, 0)])


def _install_fake_sync_mgr(handler):
    """Replace the handler's SyncManager with a lightweight fake whose
    queue_sync is an AsyncMock, so tests can assert on sync triggering without
    touching the cpdef method (which is read-only) or the real network."""
    fake = MagicMock()
    fake.queue_sync = AsyncMock()
    fake._worker_task = None
    handler._sync_mgr = fake
    return fake


class TestRemoteBoardRedirectAuthGated:
    @pytest.mark.asyncio
    async def test_anonymous_post_get_no_sync(self, engine_setup):
        handler, engine, ident, config, ume, ame, keibatsu = engine_setup
        # default config has no ACLs => nobody has read on remote board
        _seed_remote_board(ame, "remoteboard", "peer.example.com", "peer.example.com")
        conn = _anonymous_conn(ident, origin_header="localhost")
        fake = _install_fake_sync_mgr(handler)

        resp = handler.handle(_build_post_get("remoteboard"), conn)
        code, _ = _decode_error(resp)
        assert code == 403  # anonymous fails read ACL; no redirect/sync
        # let any scheduled tasks finish
        await asyncio.sleep(0)
        fake.queue_sync.assert_not_called()

    @pytest.mark.asyncio
    async def test_unauthorized_post_get_no_sync(self, engine_setup):
        handler, engine, ident, config, ume, ame, keibatsu = engine_setup
        _seed_remote_board(ame, "remoteboard", "peer.example.com", "peer.example.com")
        reporter = Identity.generate().public_key
        # registered user whose record_origin is NOT local.test => fails an
        # origin=localhost-style ACL.
        config.acls = [ACLEntry("local", Matcher(origin_pattern="localhost"), ["*"], True, False)]
        user = ume.put("bob", config.origin, reporter, record_origin="remote.test")
        conn = _auth_conn(ident, user=user, peer_pubkey=reporter, origin_header="localhost")
        fake = _install_fake_sync_mgr(handler)

        resp = handler.handle(_build_post_get("remoteboard"), conn)
        code, _ = _decode_error(resp)
        assert code == 403
        await asyncio.sleep(0)
        fake.queue_sync.assert_not_called()

    @pytest.mark.asyncio
    async def test_authorized_post_get_redirects_and_syncs(self, engine_setup):
        handler, engine, ident, config, ume, ame, keibatsu = engine_setup
        # Grant local.test origin read on all boards.
        config.acls = [ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, False)]
        _seed_remote_board(ame, "remoteboard", "peer.example.com", "peer.example.com")
        reporter = Identity.generate().public_key
        user = ume.put("alice", config.origin, reporter, record_origin="local.test")
        conn = _auth_conn(ident, user=user, peer_pubkey=reporter, origin_header="evil.example")
        fake = _install_fake_sync_mgr(handler)

        resp = handler.handle(_build_post_get("remoteboard"), conn)
        assert resp[0] == 0x02, f"expected redirect, got {_decode_error(resp)}"
        await asyncio.sleep(0)
        fake.queue_sync.assert_awaited_once_with("peer.example.com")

    @pytest.mark.asyncio
    async def test_anonymous_post_create_no_sync(self, engine_setup):
        handler, engine, ident, config, ume, ame, keibatsu = engine_setup
        _seed_remote_board(ame, "remoteboard", "peer.example.com", "peer.example.com")
        conn = _anonymous_conn(ident, origin_header="localhost")
        fake = _install_fake_sync_mgr(handler)

        resp = handler.handle(_build_post_create("remoteboard"), conn)
        # POST_CREATE is not a public command => 401 at the handle() gate.
        code, _ = _decode_error(resp)
        assert code == 401
        await asyncio.sleep(0)
        fake.queue_sync.assert_not_called()

    @pytest.mark.asyncio
    async def test_anonymous_post_list_no_sync(self, engine_setup):
        handler, engine, ident, config, ume, ame, keibatsu = engine_setup
        _seed_remote_board(ame, "remoteboard", "peer.example.com", "peer.example.com")
        conn = _anonymous_conn(ident, origin_header="localhost")
        fake = _install_fake_sync_mgr(handler)

        resp = handler.handle(_build_post_list("remoteboard"), conn)
        code, _ = _decode_error(resp)
        assert code == 403
        await asyncio.sleep(0)
        fake.queue_sync.assert_not_called()

    @pytest.mark.asyncio
    async def test_authorized_redirect_skips_sync_for_invalid_relay(self, engine_setup):
        """Even an authorized caller must not queue a sync to a non-dialable
        relay (defensive #2/#6 guard)."""
        handler, engine, ident, config, ume, ame, keibatsu = engine_setup
        config.acls = [ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, False)]
        # remote board with a poisoned (private-IP) relay
        _seed_remote_board(ame, "remoteboard", "peer.example.com", "127.0.0.1")
        reporter = Identity.generate().public_key
        user = ume.put("alice", config.origin, reporter, record_origin="local.test")
        conn = _auth_conn(ident, user=user, peer_pubkey=reporter, origin_header="evil.example")
        fake = _install_fake_sync_mgr(handler)

        resp = handler.handle(_build_post_get("remoteboard"), conn)
        # Still redirects (tells client the origin), but does NOT queue a sync.
        assert resp[0] == 0x02
        await asyncio.sleep(0)
        fake.queue_sync.assert_not_called()

    @pytest.mark.asyncio
    async def test_authorized_post_create_redirects_and_syncs(self, engine_setup):
        handler, engine, ident, config, ume, ame, keibatsu = engine_setup
        config.acls = [ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, True)]
        _seed_remote_board(ame, "remoteboard", "peer.example.com", "peer.example.com")
        reporter = Identity.generate().public_key
        user = ume.put("alice", config.origin, reporter, record_origin="local.test")
        conn = _auth_conn(ident, user=user, peer_pubkey=reporter, origin_header="evil.example")
        fake = _install_fake_sync_mgr(handler)

        resp = handler.handle(_build_post_create("remoteboard"), conn)
        assert resp[0] == 0x02, f"expected redirect, got {_decode_error(resp)}"
        await asyncio.sleep(0)
        fake.queue_sync.assert_awaited_once_with("peer.example.com")
