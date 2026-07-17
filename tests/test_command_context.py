"""Tests for CommandContext and RateLimiter — the transport-neutral authorization
boundary extracted in Phase 2.

CommandContext replaces both net.connection.Connection and app.cli.LocalConnection
as the authorization principal.  These tests verify:
  - Permission methods match the old Connection/LocalConnection behavior
  - peer_public_key is always present (never None)
  - Connection.to_context() and LocalConnection.to_context() produce equivalent contexts
  - RateLimiter accumulates across calls (unlike the old per-connection deque)
  - RateLimiter keys by identity for authenticated, address for anonymous
"""

import os
import sys
import time
import pytest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from net.context import CommandContext
from net.rate_limiter import RateLimiter
from net.connection import Connection, ConnectionState
from app.cli import LocalConnection
from core.crypto import Identity
from engine.ume import User


def _mock_user(username="alice", is_admin=False, is_mod=False, is_banned=False, record_origin="localhost"):
    user = MagicMock(spec=User)
    user.username = username
    user.is_administrator = is_admin
    user.is_moderator = is_mod
    user.is_banned = is_banned
    user.record_origin = record_origin
    user.publickey = b"\x11" * 32
    user.registrar = "localhost"
    return user


class TestCommandContextPermissions:
    """Verify CommandContext permission methods match old Connection behavior."""

    def test_anonymous_context(self):
        ctx = CommandContext(
            peer_public_key=b"\x00" * 32,
            is_anonymous=True,
        )
        assert ctx.is_anonymous is True
        assert ctx.is_registered is False
        assert ctx.is_administrator() is False
        assert ctx.is_moderator() is False
        assert ctx.can_create_board() is False
        assert ctx.can_edit_post("alice") is False
        assert ctx.can_delete_post("alice") is False

    def test_registered_user(self):
        user = _mock_user("alice")
        ctx = CommandContext(
            peer_public_key=b"\x11" * 32,
            user=user,
            username="alice",
            is_anonymous=False,
        )
        assert ctx.is_anonymous is False
        assert ctx.is_registered is True
        assert ctx.is_administrator() is False
        assert ctx.can_edit_post("alice") is True
        assert ctx.can_edit_post("bob") is False
        assert ctx.can_delete_post("alice") is True
        assert ctx.can_delete_post("bob") is False

    def test_admin_user(self):
        user = _mock_user("admin", is_admin=True)
        ctx = CommandContext(
            peer_public_key=b"\x22" * 32,
            user=user,
            username="admin",
            is_anonymous=False,
        )
        assert ctx.is_administrator() is True
        assert ctx.can_create_board() is True
        assert ctx.can_promote_to_mod() is True
        assert ctx.can_demote_mod() is True
        assert ctx.can_delete_post("anyone") is True

    def test_moderator_user(self):
        user = _mock_user("mod", is_mod=True)
        ctx = CommandContext(
            peer_public_key=b"\x33" * 32,
            user=user,
            username="mod",
            is_anonymous=False,
        )
        assert ctx.is_moderator() is True
        assert ctx.can_create_board() is False
        assert ctx.can_delete_post("anyone") is True
        assert ctx.can_edit_post("mod") is True
        assert ctx.can_edit_post("alice") is False

    def test_peer_public_key_always_present(self):
        """CommandContext.peer_public_key must never be None — even for anonymous."""
        anon = CommandContext(peer_public_key=b"\x00" * 32, is_anonymous=True)
        assert anon.peer_public_key is not None
        assert len(anon.peer_public_key) == 32


class TestConnectionToContext:
    """Connection.to_context() produces a CommandContext with the right fields."""

    def test_anonymous_connection(self):
        ident = Identity.generate()
        ws = MagicMock()
        ws.remote_address = ("127.0.0.1", 12345)
        engine = MagicMock()
        engine.ume = MagicMock()
        engine.config = MagicMock()
        conn = Connection.server(ident, ws, engine)
        conn.peer_public_key = b"\x44" * 32

        ctx = conn.to_context()

        assert ctx.peer_public_key == b"\x44" * 32
        assert ctx.user is None
        assert ctx.is_anonymous is True
        assert ctx.is_registered is False
        assert ctx.remote_addr == "127.0.0.1"

    def test_authenticated_connection(self):
        ident = Identity.generate()
        ws = MagicMock()
        ws.remote_address = ("10.0.0.1", 9999)
        engine = MagicMock()
        engine.ume = MagicMock()
        engine.config = MagicMock()
        conn = Connection.server(ident, ws, engine)
        user = _mock_user("alice")
        conn.user = user
        conn.username = "alice"
        conn.peer_public_key = b"\x55" * 32

        ctx = conn.to_context()

        assert ctx.peer_public_key == b"\x55" * 32
        assert ctx.user is user
        assert ctx.username == "alice"
        assert ctx.is_anonymous is False
        assert ctx.is_registered is True
        assert ctx.is_administrator() is False


class TestLocalConnectionToContext:
    """LocalConnection.to_context() produces a CommandContext for the REPL."""

    def test_root_user_context(self):
        ident = Identity.generate()
        user = _mock_user("root", is_admin=True, record_origin="localhost")
        local = LocalConnection(user, ident.public_key)

        ctx = local.to_context()

        assert ctx.peer_public_key == ident.public_key
        assert ctx.user is user
        assert ctx.username == "root"
        assert ctx.is_anonymous is False
        assert ctx.is_administrator() is True
        assert ctx.remote_addr == "localhost"
        assert ctx.origin == "localhost"

    def test_context_with_engine(self):
        ident = Identity.generate()
        user = _mock_user("root", is_admin=True)
        engine = MagicMock()
        local = LocalConnection(user, ident.public_key, engine=engine, origin="bbs.example.com")

        ctx = local.to_context()

        assert ctx.origin == "bbs.example.com"


class TestRateLimiter:
    """Shared RateLimiter — accumulates across calls, keyed by identity/address."""

    def test_allows_under_limit(self):
        rl = RateLimiter(max_requests=5, window_seconds=60)
        key = rl.identity_key(b"\x01" * 32)
        for _ in range(5):
            assert rl.check(key) is True

    def test_blocks_over_limit(self):
        rl = RateLimiter(max_requests=3, window_seconds=60)
        key = rl.identity_key(b"\x01" * 32)
        assert rl.check(key) is True
        assert rl.check(key) is True
        assert rl.check(key) is True
        assert rl.check(key) is False

    def test_different_keys_independent(self):
        rl = RateLimiter(max_requests=2, window_seconds=60)
        key_a = rl.identity_key(b"\x01" * 32)
        key_b = rl.identity_key(b"\x02" * 32)

        assert rl.check(key_a) is True
        assert rl.check(key_a) is True
        assert rl.check(key_a) is False  # A is limited

        assert rl.check(key_b) is True   # B is unaffected
        assert rl.check(key_b) is True

    def test_address_key_for_anonymous(self):
        rl = RateLimiter(max_requests=2, window_seconds=60)
        key = rl.address_key("203.0.113.9")

        assert rl.check(key) is True
        assert rl.check(key) is True
        assert rl.check(key) is False

    def test_window_expiry(self):
        rl = RateLimiter(max_requests=2, window_seconds=0)  # 0-second window
        key = rl.identity_key(b"\x01" * 32)

        # With a 0-second window, timestamps expire immediately
        # So every request should be allowed (the bucket is always empty when checked)
        assert rl.check(key) is True
        assert rl.check(key) is True
        assert rl.check(key) is True

    def test_cleanup_removes_stale(self):
        rl = RateLimiter(max_requests=10, window_seconds=0)
        key = rl.identity_key(b"\x01" * 32)
        rl.check(key)

        # After cleanup, the stale bucket is removed
        rl.cleanup()
        assert key not in rl._buckets

    def test_identity_key_format(self):
        rl = RateLimiter()
        key = rl.identity_key(b"\xab\xcd" * 16)
        assert key == "identity:abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"

    def test_address_key_format(self):
        rl = RateLimiter()
        key = rl.address_key("203.0.113.9")
        assert key == "address:203.0.113.9"


class TestNoNetworkHeadersAsIdentity:
    """Exit gate: no command or ACL code reads HTTP/WebSocket headers as identity."""

    def test_command_handler_has_no_host_header_access(self):
        """CommandHandler.handle() and _cmd_* methods must not reference
        conn.origin, Host headers, or WebSocket request attributes."""
        import inspect
        from net.commands import CommandHandler

        source = inspect.getsource(CommandHandler)

        # Must use CommandContext, not Connection
        assert "CommandContext" in source
        assert "ctx: CommandContext" in source or "ctx)" in source

        # Must not reference network-level attributes
        assert "conn.origin" not in source
        assert "Host" not in source
        assert "websocket" not in source
        assert "_request_timestamps" not in source

    def test_facade_uses_context_not_connection(self):
        """BonnetEngine.check_permission must accept CommandContext, not Connection."""
        import inspect
        from engine.facade import BonnetEngine

        source = inspect.getsource(BonnetEngine.check_permission)
        assert "ctx: CommandContext" in source
        assert "conn" not in source

    def test_local_connection_is_context_factory(self):
        """LocalConnection should be a thin factory, not a full connection impl."""
        import inspect
        from app.cli import LocalConnection

        source = inspect.getsource(LocalConnection)

        # Must have to_context()
        assert "to_context" in source
        assert "CommandContext" in source

        # Must NOT have permission methods (those are on CommandContext now)
        assert "def is_administrator" not in source
        assert "def is_moderator" not in source
        assert "def can_create_board" not in source
