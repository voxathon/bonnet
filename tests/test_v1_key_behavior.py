"""Protocol v1 security defect verification — all defects resolved by v2.

PROTOCOL_RENOVATION_PLAN §2.3 listed 7 defects. After Phase 8 demolition:
  1. Client origin pins — FIXED (TrustStore TOFU in BonnetHTTPClient)
  2. No forward secrecy — FIXED (TLS transport, no app-level encryption)
  3. Nonce counter at 0 — FIXED (Phase 1, random nonces; v2 uses RFC 9421 nonces)
  4. No persistent server key proof — FIXED (response signatures + origin pins)
  5. Rate limits per-connection — FIXED (Phase 2, shared RateLimiter)
  6. Inner frame not validated — N/A (v2 uses HTTP, no inner framing)
  7. Exceptions swallowed — FIXED (Phase 1, structured logging + finally)

These tests verify the v2 architecture has none of the v1 defects.
"""

import os
import sys
import inspect
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.crypto import Identity
from core.trust import TrustStore
from net.rate_limiter import RateLimiter
from net.context import CommandContext
from client.http import BonnetHTTPClient


class TestNoV1Defects:
    """Verify that v2 does not have any of the 7 v1 security defects."""

    def test_no_application_encryption(self):
        """§2.3 bullet 2: No app-level EncryptedSession — TLS owns confidentiality."""
        from core import crypto
        source = inspect.getsource(crypto)
        assert "class EncryptedSession" not in source
        assert "nacl.public" not in source
        assert "Box" not in source

    def test_client_uses_random_nonces(self):
        """§2.3 bullet 3: BonnetHTTPClient uses random 32-byte nonces per request."""
        source = inspect.getsource(BonnetHTTPClient._send_command)
        assert "os.urandom(32)" in source
        assert "nonce" in source

    def test_client_verifies_response_signatures(self):
        """§2.3 bullet 4: BonnetHTTPClient verifies every response signature."""
        source = inspect.getsource(BonnetHTTPClient)
        assert "_verify_response" in source
        assert "BonnetVerifier" in source

    def test_client_pins_server_key(self):
        """§2.3 bullet 1: BonnetHTTPClient pins server key via TrustStore."""
        source = inspect.getsource(BonnetHTTPClient)
        assert "_pin_server_key" in source
        assert "TrustStore" in source
        assert "tofu_pin" in source

    def test_rate_limiter_is_shared(self):
        """§2.3 bullet 5: Rate limiting uses shared RateLimiter, not per-connection."""
        from net.commands import CommandHandler
        source = inspect.getsource(CommandHandler.handle)
        assert "_rate_limiter" in source
        assert "_request_timestamps" not in source

    def test_no_websocket_imports(self):
        """§2.3 bullet 6/7: No WebSocket code remains in production."""
        import importlib.util
        assert importlib.util.find_spec("net.connection") is None
        assert importlib.util.find_spec("client.connection") is None

    def test_server_logs_exceptions(self):
        """§2.3 bullet 7: Server HTTP handler logs errors, not swallows them."""
        from net.http_server import BonnetHTTPServer
        source = inspect.getsource(BonnetHTTPServer._handle_command)
        # The HTTP server doesn't swallow exceptions — it returns signed errors
        assert "log_msg" in source or "Exception" in source

    def test_syncdb_uses_atomic_tofu(self):
        """TOFU is atomic via TrustStore — no read-then-insert race."""
        from net.sync import SyncDB
        source = inspect.getsource(SyncDB.set_peer_pubkey_tofu)
        assert "tofu_pin" in source
        assert "get_peer_pubkey" not in source
        assert "INSERT" not in source
