# -*- coding: utf-8 -*-
"""Tests for server-side article searching:

* LIKE widening on ``Board.query`` (subject/author).
* ``Board.content_search`` via ripgrep over flat-file post bodies.
* ``SearchLimiter`` per-identity concurrency + token-bucket rate limiting.
* protocol round-trip for ``POST_CONTENT_SEARCH`` (0x1A).
* command-handler integration (ACL gate, 404 for unknown/remote boards, 503
  when rg is missing, 429 when the limiter denies, anonymous-acceptance via
  ``public_commands``).
"""

import os
import struct
import threading
import time
from unittest.mock import MagicMock, AsyncMock

import pytest
import pytest_asyncio

from engine.ame import Ame, SearchUnavailable, SearchTimedOut
from engine.facade import BonnetEngine
from engine.ume import Ume
from engine.keibatsu import Keibatsu
from net.commands import CommandHandler
from net.connection import Connection, READ_ONLY_COMMANDS
from net.search_limiter import SearchLimiter
from core.crypto import Identity
from core.config import Config, Matcher, ACLEntry
from core.orm import Database
from core import binutil

from client.protocol import (
    COMMANDS,
    build_post_content_search,
    parse_post_content_search_resp,
    encode_string,
    encode_long_string,
)
from client.models import PostSummary

try:
    import shutil
    _HAS_RG = shutil.which("rg") is not None
except Exception:
    _HAS_RG = False

skip_if_no_rg = pytest.mark.skipif(not _HAS_RG, reason="ripgrep (rg) not installed")


# ===========================================================================
# Step 5a - resolve_rg (runtime binary resolution + bundling)
# ===========================================================================


class TestResolveRg:
    def test_frozen_meipass_lookup(self, tmp_path, monkeypatch):
        rg = tmp_path / "rg"
        rg.write_text("#!/bin/sh\nexit 0\n")
        rg.chmod(0o755)
        binutil.reset_resolve_cache()
        # simulate frozen runtime
        monkeypatch.setattr(binutil.sys, "frozen", True, raising=False)
        monkeypatch.setattr(binutil.sys, "_MEIPASS", str(tmp_path), raising=False)
        try:
            assert binutil.resolve_rg() == str(rg)
        finally:
            monkeypatch.setattr(binutil.sys, "frozen", False, raising=False)
            monkeypatch.delattr(binutil.sys, "_MEIPASS", raising=False)
            binutil.reset_resolve_cache()

    def test_returns_none_when_not_found(self, monkeypatch):
        binutil.reset_resolve_cache()
        monkeypatch.setattr(binutil.sys, "frozen", False, raising=False)
        monkeypatch.setattr(binutil.shutil, "which", lambda cmd: None)
        try:
            assert binutil.resolve_rg() is None
        finally:
            binutil.reset_resolve_cache()

    def test_result_is_cached(self, monkeypatch):
        binutil.reset_resolve_cache()
        monkeypatch.setattr(binutil.sys, "frozen", False, raising=False)
        calls = {"n": 0}

        def fake_which(cmd):
            calls["n"] += 1
            return "/fake/rg"

        monkeypatch.setattr(binutil.shutil, "which", fake_which)
        try:
            assert binutil.resolve_rg() == "/fake/rg"
            assert binutil.resolve_rg() == "/fake/rg"
            assert calls["n"] == 1  # looked up only once
        finally:
            binutil.reset_resolve_cache()


# ---------------------------------------------------------------------------
# engine fixtures
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
        acls=[],
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


@pytest.fixture
def ame_setup(temp_dir):
    ame_path = os.path.join(temp_dir, "ame")
    nav_db_path = os.path.join(temp_dir, "nav.db")
    ident = Identity.generate()
    ame = Ame(ame_path, origin="test_origin", signing_key=ident.signing_key, nav_db_path=nav_db_path)
    yield ame, ident
    ame.shutdown()


def _seed_remote_board(ame, board_name, origin, relay, signature=b"\x00" * 64):
    nav = ame.get_nav()
    nav.upsert_remote_batch([(board_name, board_name, origin, signature, relay, 0)])


def _anonymous_conn(ident, origin_header="localhost"):
    ws = MagicMock()
    ws.remote_address = ("203.0.113.9", 12345)
    req = MagicMock()
    req.headers = {"Host": origin_header}
    ws.request = req
    engine = MagicMock()
    engine.ume = MagicMock()
    engine.config = MagicMock(max_request_size=0)
    conn = Connection.server(ident, ws, engine)
    conn.peer_public_key = b"\x11" * 32
    return conn


def _decode_error(response):
    if len(response) > 0 and response[0] == 0x01:
        code = struct.unpack(">H", response[1:3])[0]
        msg_len = response[3]
        return code, response[4:4 + msg_len].decode("utf-8", errors="replace")
    return None


def _build_content_search(board_name, pattern, limit=100):
    bb = board_name.encode("utf-8")
    pb = pattern.encode("utf-8")
    out = struct.pack("B", len(bb)) + bb
    out += struct.pack(">I", len(pb)) + pb
    out += struct.pack(">I", limit)
    return bytes([0x1A]) + out


# ===========================================================================
# Step 1 - LIKE widening on Board.query
# ===========================================================================


class TestQueryLikeWidening:
    def test_subject_like_matches(self, ame_setup):
        ame, ident = ame_setup
        board = ame.create_board("b", owner_pubkey=Identity.generate().public_key)
        board.create_post(subject="Hello World", content="x", author="alice", author_registrar="o").result(timeout=5)
        board.create_post(subject="Goodbye", content="y", author="bob", author_registrar="o").result(timeout=5)
        board.create_post(subject="hello again", content="z", author="carol", author_registrar="o").result(timeout=5)

        res = board.query(where="subject LIKE ?", values=["%hello%"], orderby="post_num ASC", limit=10).result(timeout=5)
        nums = sorted(p.post_num for p in res)
        # SQLite LIKE is case-insensitive for ASCII -> matches both "Hello World" and "hello again"
        assert nums == [1, 3]

    def test_author_like_matches(self, ame_setup):
        ame, ident = ame_setup
        board = ame.create_board("b", owner_pubkey=Identity.generate().public_key)
        board.create_post(subject="a", content="x", author="alice", author_registrar="o").result(timeout=5)
        board.create_post(subject="b", content="y", author="bob", author_registrar="o").result(timeout=5)

        res = board.query(where="author LIKE ?", values=["%li%"], orderby="post_num ASC", limit=10).result(timeout=5)
        assert [p.post_num for p in res] == [1]

    def test_like_rejected_for_non_allowed_column(self, ame_setup):
        ame, ident = ame_setup
        board = ame.create_board("b", owner_pubkey=Identity.generate().public_key)
        board.create_post(subject="a", content="x", tags="news", author="alice", author_registrar="o").result(timeout=5)
        with pytest.raises(ValueError, match="LIKE not allowed"):
            board.query(where="tags LIKE ?", values=["%news%"]).result(timeout=5)

    def test_equality_still_works_for_all_columns(self, ame_setup):
        ame, ident = ame_setup
        board = ame.create_board("b", owner_pubkey=Identity.generate().public_key)
        board.create_post(subject="a", content="x", author="alice", author_registrar="o", sticky=1).result(timeout=5)
        board.create_post(subject="b", content="y", author="bob", author_registrar="o", sticky=0).result(timeout=5)
        res = board.query(where="sticky = ?", values=[1], limit=10).result(timeout=5)
        assert [p.post_num for p in res] == [1]

    def test_mixed_equals_and_like_with_and(self, ame_setup):
        ame, ident = ame_setup
        board = ame.create_board("b", owner_pubkey=Identity.generate().public_key)
        board.create_post(subject="Hello there", content="x", author="alice", author_registrar="o").result(timeout=5)
        board.create_post(subject="Hello", content="y", author="alice2", author_registrar="o").result(timeout=5)
        board.create_post(subject="Hello", content="z", author="alice", author_registrar="o").result(timeout=5)
        res = board.query(where="subject LIKE ? AND author = ?", values=["%Hello%", "alice"],
                          orderby="post_num ASC", limit=10).result(timeout=5)
        assert sorted(p.post_num for p in res) == [1, 3]

    def test_injection_attempt_rejected(self, ame_setup):
        ame, ident = ame_setup
        board = ame.create_board("b", owner_pubkey=Identity.generate().public_key)
        board.create_post(subject="a", content="x", author="alice", author_registrar="o").result(timeout=5)
        with pytest.raises(ValueError):
            board.query(where="subject = ?; DROP").result(timeout=5)
        with pytest.raises(ValueError):
            board.query(where="subject = ? OR 1=1").result(timeout=5)


# ===========================================================================
# Step 2 - Board.content_search
# ===========================================================================


class TestContentSearch:
    @skip_if_no_rg
    def test_content_search_returns_matching_posts(self, ame_setup):
        ame, ident = ame_setup
        board = ame.create_board("b", owner_pubkey=Identity.generate().public_key)
        board.create_post(subject="First", content="this has the needle word", author="alice", author_registrar="o").result(timeout=5)
        board.create_post(subject="Second", content="nothing here", author="bob", author_registrar="o").result(timeout=5)
        board.create_post(subject="Third", content="another needle here", author="carol", author_registrar="o").result(timeout=5)

        res = board.content_search("needle", result_limit=10).result(timeout=10)
        nums = sorted(p.post_num for p in res)
        assert nums == [1, 3]
        # hydration carries the metadata fields
        by_num = {p.post_num: p for p in res}
        assert by_num[1].subject == "First"
        assert by_num[1].author == "alice"
        assert by_num[3].root == 0

    @skip_if_no_rg
    def test_content_search_no_matches_returns_empty(self, ame_setup):
        ame, ident = ame_setup
        board = ame.create_board("b", owner_pubkey=Identity.generate().public_key)
        board.create_post(subject="x", content="hello world", author="a", author_registrar="o").result(timeout=5)
        res = board.content_search("nonexistentpatternxyz", result_limit=10).result(timeout=10)
        assert res == []

    @skip_if_no_rg
    def test_content_search_dedupes_multiple_matches_per_file(self, ame_setup):
        ame, ident = ame_setup
        board = ame.create_board("b", owner_pubkey=Identity.generate().public_key)
        # one file with the term on many lines -> single hydrated entry
        board.create_post(subject="s", content="needle\nneedle\nneedle\nneedle", author="a", author_registrar="o").result(timeout=5)
        res = board.content_search("needle", result_limit=10).result(timeout=10)
        assert len(res) == 1
        assert res[0].post_num == 1

    @skip_if_no_rg
    def test_content_search_result_limit_caps_unique_results(self, ame_setup):
        ame, ident = ame_setup
        board = ame.create_board("b", owner_pubkey=Identity.generate().public_key)
        for i in range(5):
            board.create_post(subject=f"s{i}", content="needle", author="a", author_registrar="o").result(timeout=5)
        res = board.content_search("needle", result_limit=2).result(timeout=10)
        assert len(res) == 2

    def test_content_search_empty_pattern_rejected(self, ame_setup):
        ame, ident = ame_setup
        board = ame.create_board("b", owner_pubkey=Identity.generate().public_key)
        with pytest.raises(ValueError):
            board.content_search("")

    def test_content_search_unavailable_when_no_rg(self, ame_setup, monkeypatch):
        ame, ident = ame_setup
        board = ame.create_board("b", owner_pubkey=Identity.generate().public_key)
        board.create_post(subject="s", content="needle", author="a", author_registrar="o").result(timeout=5)
        monkeypatch.setattr(binutil, "_rg_path", None)
        monkeypatch.setattr(binutil, "_rg_checked", True)
        with pytest.raises(SearchUnavailable):
            board.content_search("needle").result(timeout=10)

    @skip_if_no_rg
    def test_content_search_regex_pattern(self, ame_setup):
        ame, ident = ame_setup
        board = ame.create_board("b", owner_pubkey=Identity.generate().public_key)
        board.create_post(subject="s", content="error 404 not found", author="a", author_registrar="o").result(timeout=5)
        board.create_post(subject="s2", content="all good", author="a", author_registrar="o").result(timeout=5)
        res = board.content_search("error \\d+", result_limit=10).result(timeout=10)
        assert [p.post_num for p in res] == [1]


# ===========================================================================
# Step 3 - SearchLimiter
# ===========================================================================


class TestSearchLimiter:
    def test_concurrency_one_blocks_second_then_times_out(self):
        lim = SearchLimiter(per_identity_concurrency=1, rate_limit=100, rate_window_seconds=60)
        assert lim.acquire("id1", timeout=2.0) is True
        # second concurrent request for same identity must block, then fail fast
        start = time.monotonic()
        got = lim.acquire("id1", timeout=0.2)
        elapsed = time.monotonic() - start
        assert got is False
        assert elapsed >= 0.15
        lim.release("id1")

    def test_different_ids_proceed_independently(self):
        lim = SearchLimiter(per_identity_concurrency=1, rate_limit=100, rate_window_seconds=60)
        assert lim.acquire("id1", timeout=1.0) is True
        assert lim.acquire("id2", timeout=1.0) is True
        lim.release("id1")
        lim.release("id2")

    def test_release_unblocks_waiter(self):
        lim = SearchLimiter(per_identity_concurrency=1, rate_limit=100, rate_window_seconds=60)
        assert lim.acquire("id", timeout=1.0) is True
        result = {}

        def waiter():
            result["got"] = lim.acquire("id", timeout=2.0)

        t = threading.Thread(target=waiter)
        t.start()
        time.sleep(0.1)  # let waiter park on the condition
        lim.release("id")
        t.join(timeout=2.0)
        assert result["got"] is True
        lim.release("id")

    def test_rate_limit_exhausts_tokens(self):
        # capacity = 2 tokens, refill slow
        lim = SearchLimiter(per_identity_concurrency=10, rate_limit=2, rate_window_seconds=60)
        assert lim.acquire("id", timeout=0.1) is True
        lim.release("id")
        assert lim.acquire("id", timeout=0.1) is True
        lim.release("id")
        # third request within the window: no tokens left -> False (rate, not concurrency)
        assert lim.acquire("id", timeout=0.1) is False


# ===========================================================================
# Step 4 - protocol round-trip
# ===========================================================================


class TestProtocolRoundTrip:
    def test_command_opcode_registered(self):
        assert COMMANDS["POST_CONTENT_SEARCH"] == 0x1A

    def test_build_post_content_search_layout(self):
        msg = build_post_content_search("myboard", "needle", limit=25)
        assert msg[0] == 0x1A
        idx = 1
        b_len = msg[idx]
        idx += 1
        assert msg[idx:idx + b_len].decode() == "myboard"
        idx += b_len
        p_len = struct.unpack(">I", msg[idx:idx + 4])[0]
        idx += 4
        assert msg[idx:idx + p_len].decode() == "needle"
        idx += p_len
        assert struct.unpack(">I", msg[idx:idx + 4])[0] == 25

    def test_parse_post_content_search_resp(self):
        # Craft a 0x00 success payload with two PostSummary entries using the
        # full-Post encoding the server emits.
        def enc_summary(post_num, creation_date, subject, author, root):
            out = struct.pack(">Q", post_num)
            out += struct.pack(">q", 0)  # last_modified
            out += struct.pack(">q", creation_date)
            out += struct.pack(">q", 0)  # last_bumped
            out += struct.pack(">B", 0)  # closed
            out += struct.pack(">i", 0)  # sticky
            out += encode_string("")  # tags
            out += encode_string(subject)
            out += encode_string("")  # options
            out += struct.pack(">Q", root)
            out += encode_string(author)
            out += encode_string("")  # author_registrar
            out += encode_string("")  # signature
            return out

        payload = struct.pack(">B", 0x00) + enc_summary(1, 1000, "Sub A", "alice", 0) + enc_summary(2, 2000, "Sub B", "bob", 1)
        # parse_*_resp receives the payload AFTER the status byte is stripped
        # by parse_response(), so slice off the leading 0x00 here.
        results = parse_post_content_search_resp(payload[1:])
        assert len(results) == 2
        assert isinstance(results[0], PostSummary)
        assert results[0].post_num == 1
        assert results[0].subject == "Sub A"
        assert results[0].author == "alice"
        assert results[0].root == 0
        assert results[1].post_num == 2
        assert results[1].root == 1

    def test_read_only_command_set_includes_0x1a(self):
        assert 0x1A in READ_ONLY_COMMANDS


# ===========================================================================
# Step 4/6 - command-handler integration
# ===========================================================================


class TestPostContentSearchHandler:
    @skip_if_no_rg
    @pytest.mark.asyncio
    async def test_search_success(self, engine_setup):
        handler, engine, ident, config, ume, ame, keibatsu = engine_setup
        # grant anonymous read on all boards
        config.acls = [ACLEntry("anon", Matcher(anonymous=True), ["*"], True, False)]
        board = ame.create_board("localboard", owner_pubkey=ident.public_key)
        board.create_post(subject="S1", content="findme here", author="alice", author_registrar=config.origin).result(timeout=5)
        board.create_post(subject="S2", content="nothing", author="bob", author_registrar=config.origin).result(timeout=5)

        conn = _anonymous_conn(ident)
        resp = handler.handle(_build_content_search("localboard", "findme", 10), conn)
        assert resp[0] == 0x00, f"expected success, got {_decode_error(resp)}"
        summaries = parse_post_content_search_resp(resp[1:])
        assert [s.post_num for s in summaries] == [1]
        assert summaries[0].subject == "S1"
        assert summaries[0].author == "alice"

    @pytest.mark.asyncio
    async def test_search_403_when_permission_denied(self, engine_setup):
        handler, engine, ident, config, ume, ame, keibatsu = engine_setup
        # no ACLs => anonymous cannot read
        ame.create_board("localboard", owner_pubkey=ident.public_key)
        conn = _anonymous_conn(ident)
        resp = handler.handle(_build_content_search("localboard", "x", 10), conn)
        code, _ = _decode_error(resp)
        assert code == 403

    @pytest.mark.asyncio
    async def test_search_404_for_unknown_board(self, engine_setup):
        handler, engine, ident, config, ume, ame, keibatsu = engine_setup
        config.acls = [ACLEntry("anon", Matcher(anonymous=True), ["*"], True, False)]
        conn = _anonymous_conn(ident)
        resp = handler.handle(_build_content_search("nosuchboard", "x", 10), conn)
        code, _ = _decode_error(resp)
        assert code == 404

    @pytest.mark.asyncio
    async def test_search_404_for_remote_board(self, engine_setup):
        # remote boards have no local content files -> 404, not a redirect
        handler, engine, ident, config, ume, ame, keibatsu = engine_setup
        config.acls = [ACLEntry("anon", Matcher(anonymous=True), ["*"], True, False)]
        _seed_remote_board(ame, "remoteboard", "peer.example.com", "peer.example.com")
        conn = _anonymous_conn(ident)
        resp = handler.handle(_build_content_search("remoteboard", "x", 10), conn)
        code, _ = _decode_error(resp)
        assert code == 404

    @pytest.mark.asyncio
    async def test_search_503_when_rg_missing(self, engine_setup, monkeypatch):
        handler, engine, ident, config, ume, ame, keibatsu = engine_setup
        config.acls = [ACLEntry("anon", Matcher(anonymous=True), ["*"], True, False)]
        ame.create_board("localboard", owner_pubkey=ident.public_key)
        monkeypatch.setattr(binutil, "_rg_path", None)
        monkeypatch.setattr(binutil, "_rg_checked", True)
        conn = _anonymous_conn(ident)
        resp = handler.handle(_build_content_search("localboard", "x", 10), conn)
        code, _ = _decode_error(resp)
        assert code == 503

    @pytest.mark.asyncio
    async def test_search_429_when_limiter_denies(self, engine_setup, monkeypatch):
        handler, engine, ident, config, ume, ame, keibatsu = engine_setup
        config.acls = [ACLEntry("anon", Matcher(anonymous=True), ["*"], True, False)]
        board = ame.create_board("localboard", owner_pubkey=ident.public_key)
        board.create_post(subject="S1", content="findme", author="alice", author_registrar=config.origin).result(timeout=5)
        # replace the limiter with one that always denies (rate tokens exhausted)
        fake_lim = MagicMock()
        fake_lim.acquire.return_value = False
        handler._search_limiter = fake_lim
        conn = _anonymous_conn(ident)
        resp = handler.handle(_build_content_search("localboard", "findme", 10), conn)
        code, _ = _decode_error(resp)
        assert code == 429
        # release must not be called when acquire returned False
        fake_lim.release.assert_not_called()

    @pytest.mark.asyncio
    async def test_anonymous_accepted_when_public(self, engine_setup):
        handler, engine, ident, config, ume, ame, keibatsu = engine_setup
        config.acls = [ACLEntry("anon", Matcher(anonymous=True), ["*"], True, False)]
        # default public_commands includes 0x1A
        assert 0x1A in config.public_commands
        board = ame.create_board("localboard", owner_pubkey=ident.public_key)
        board.create_post(subject="S1", content="findme", author="alice", author_registrar=config.origin).result(timeout=5)
        conn = _anonymous_conn(ident)
        resp = handler.handle(_build_content_search("localboard", "findme", 10), conn)
        # should NOT be a 401 auth gate; either success or downstream error
        err = _decode_error(resp)
        assert err is None or err[0] != 401

    @pytest.mark.asyncio
    async def test_anonymous_rejected_401_when_not_public(self, engine_setup):
        handler, engine, ident, config, ume, ame, keibatsu = engine_setup
        config.acls = [ACLEntry("anon", Matcher(anonymous=True), ["*"], True, False)]
        config.public_commands = set()  # remove 0x1A from public set
        ame.create_board("localboard", owner_pubkey=ident.public_key)
        conn = _anonymous_conn(ident)
        resp = handler.handle(_build_content_search("localboard", "findme", 10), conn)
        code, _ = _decode_error(resp)
        assert code == 401

    @pytest.mark.asyncio
    async def test_search_releases_slot_on_success(self, engine_setup):
        handler, engine, ident, config, ume, ame, keibatsu = engine_setup
        config.acls = [ACLEntry("anon", Matcher(anonymous=True), ["*"], True, False)]
        board = ame.create_board("localboard", owner_pubkey=ident.public_key)
        board.create_post(subject="S1", content="findme", author="alice", author_registrar=config.origin).result(timeout=5)
        fake_lim = MagicMock()
        fake_lim.acquire.return_value = True
        handler._search_limiter = fake_lim
        conn = _anonymous_conn(ident)
        resp = handler.handle(_build_content_search("localboard", "findme", 10), conn)
        assert resp[0] == 0x00
        fake_lim.release.assert_called_once()
