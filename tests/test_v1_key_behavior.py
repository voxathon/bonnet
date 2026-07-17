"""Protocol v1 key/nonce/TOFU behavior tests — document security defects and fixes.

PROTOCOL_RENOVATION_PLAN §2.3 lists defects that v2 must not preserve:
  1. Client accepts server key without checking a persistent origin-to-key pin.     [UNFIXED — v2]
  2. Static identity keys derive command-encryption keys → no forward secrecy.       [UNFIXED — v2]
  3. Client-side encryption nonce counter starts at 0 for every connection.          [FIXED — Phase 1]
  4. No persistent proof that the responding key is the expected Bonnet origin key.  [UNFIXED — v2]
  5. Rate limits stored on a connection that handles only one request.               [UNFIXED — v2]
  6. Inner length prefix not checked strictly against WebSocket message length.      [FIXED — Phase 1]
  7. Unexpected server exceptions swallowed without useful diagnostics.              [FIXED — Phase 1]

Tests marked [FIXED] verify the Phase 1 containment fixes.
Tests marked [UNFIXED] document defects that remain until v2 replaces the transport.
"""

import os
import sys
import struct
import pytest
from unittest.mock import AsyncMock, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nacl.signing import SigningKey
from nacl.public import PrivateKey, PublicKey, Box

from core.crypto import Identity, EncryptedSession
from client.connection import BonnetClient
from net.connection import Connection, ConnectionState
from net.sync import SyncDB

from tests.fixtures.protocol_v1.wire_fixtures import TEST_SEED, TEST_PUBLIC_KEY


class TestClientNonceRandomAfterPhase1:
    """§2.3 bullet 3: [FIXED] Client now uses random nonces (Phase 1)."""

    def test_client_uses_random_nonces(self):
        """The client-side EncryptedSession is now the canonical core.crypto
        version, which uses random NaCl nonces — not a counter starting at 0."""
        from client.connection import EncryptedSession as ClientEncryptedSession

        # Verify it's the same class as core.crypto.EncryptedSession
        assert ClientEncryptedSession is EncryptedSession

        server_id = Identity.generate()
        client_id = Identity.generate()

        client_session = ClientEncryptedSession(client_id.private_key, server_id.public_key)

        # No _next_nonce method — random nonces are internal to NaCl Box.encrypt
        assert not hasattr(client_session, "_next_nonce")
        assert not hasattr(client_session, "nonce")

    def test_client_nonce_not_reused_across_connections(self):
        """Two connections with the same identity key now produce different
        ciphertexts because nonces are random, not counter-based."""
        from client.connection import EncryptedSession as ClientEncryptedSession

        server_id = Identity.generate()
        client_id = Identity.generate()

        sess1 = ClientEncryptedSession(client_id.private_key, server_id.public_key)
        sess2 = ClientEncryptedSession(client_id.private_key, server_id.public_key)

        ct1 = sess1.encrypt(b"same plaintext")
        ct2 = sess2.encrypt(b"same plaintext")

        # Random nonces → different ciphertexts even with same keys+plaintext
        assert ct1 != ct2, "Random nonces must produce different ciphertexts"


class TestNoForwardSecrecy:
    """§2.3 bullet 2: [UNFIXED] static identity keys derive command-encryption keys.

    The encryption key is still derived deterministically from the Ed25519 identity
    key via X25519 conversion. This means an attacker who compromises the private
    key can derive the same X25519 key. However, Phase 1 fixed the nonce reuse
    (bullet 3), so the same plaintext no longer produces the same ciphertext.
    Full forward secrecy requires ephemeral keys (v2 uses TLS for that).
    """

    def test_encryption_key_derived_from_identity(self):
        """Ed25519 → X25519 conversion means the encryption key is deterministic
        from the identity key. This is the fundamental no-forward-secrecy issue
        that remains until v2 replaces the transport with TLS."""
        identity = Identity.generate()

        signing_key = SigningKey(identity.private_key)
        x25519_priv = signing_key.to_curve25519_private_key()

        signing_key2 = SigningKey(identity.private_key)
        x25519_priv2 = signing_key2.to_curve25519_private_key()

        assert bytes(x25519_priv) == bytes(x25519_priv2)

    def test_same_keys_different_ciphertext_after_phase1(self):
        """With Phase 1's random nonces, the same identity keys and plaintext
        now produce different ciphertexts. The X25519 key is still static
        (no forward secrecy), but nonce randomness prevents the catastrophic
        nonce-reuse attack that existed before."""
        server_id = Identity.generate()
        client_id = Identity.generate()

        sess1 = EncryptedSession(client_id.private_key, server_id.public_key)
        sess2 = EncryptedSession(client_id.private_key, server_id.public_key)

        ct1 = sess1.encrypt(b"secret")
        ct2 = sess2.encrypt(b"secret")

        # Random nonces → different ciphertexts (Phase 1 fix)
        assert ct1 != ct2


class TestNoServerPin:
    """§2.3 bullet 1 & 4: client accepts server key without persistent pin."""

    def test_bonnet_client_has_no_pin_store(self):
        """BonnetClient stores server_pubkey per-connection but never persists it
        for comparison on the next connection."""
        import inspect
        from client.connection import BonnetClient

        source = inspect.getsource(BonnetClient)

        # The client stores server_pubkey during connect()
        assert "server_pubkey" in source

        # But there is no pin store, no origin_keys table, no TOFU check
        assert "pin" not in source.lower()
        assert "origin_keys" not in source
        assert "tofu" not in source.lower()

    def test_client_accepts_any_server_key(self):
        """On each connect(), the client accepts whatever pubkey the server sends
        without comparing it to a previously seen key."""
        store = MagicMock()
        client = BonnetClient(store, "ws://localhost:2272")

        # The client has no mechanism to reject a changed server key
        # server_pubkey is just stored, never compared to a pinned value
        assert not hasattr(client, "_pinned_server_key")
        assert not hasattr(client, "_origin_pin")
        assert not hasattr(client, "_trust_store")


class TestRateLimitSharedService:
    """§2.3 bullet 5: [FIXED — Phase 2] Rate limiting now uses a shared RateLimiter."""

    def test_rate_limit_uses_shared_limiter(self):
        """CommandHandler now uses a shared RateLimiter instance keyed by
        identity/address, not per-connection _request_timestamps."""
        import inspect
        from net.commands import CommandHandler

        source = inspect.getsource(CommandHandler.handle)

        # Uses the shared rate limiter
        assert "_rate_limiter" in source
        assert "rl_key" in source
        assert "identity_key" in source or "address_key" in source

        # No longer uses per-connection _request_timestamps
        assert "_request_timestamps" not in source
        assert "collections.deque" not in source

    def test_rate_limiter_is_shared_across_connections(self):
        """The RateLimiter is created once in __init__ and shared across all
        calls to handle(), so rate limits accumulate across connections."""
        from net.rate_limiter import RateLimiter

        rl = RateLimiter(max_requests=2, window_seconds=60)

        # First request from identity A
        assert rl.check(rl.identity_key(b"\x01" * 32)) is True
        # Second request from identity A
        assert rl.check(rl.identity_key(b"\x01" * 32)) is True
        # Third request from identity A — rate limited
        assert rl.check(rl.identity_key(b"\x01" * 32)) is False
        # First request from identity B — different key, not limited
        assert rl.check(rl.identity_key(b"\x02" * 32)) is True


class TestInnerFrameValidation:
    """§2.3 bullet 6: inner length prefix — now strictly validated (Phase 1 fix)."""

    def test_recv_frame_validates_length(self):
        """Connection._recv_frame now checks that 4+length == len(data),
        rejecting truncated frames and trailing bytes."""
        import inspect
        from net.connection import Connection

        source = inspect.getsource(Connection._recv_frame)

        # Validation is now present
        assert "4 + length > len(data)" in source or "4+length > len(data)" in source
        assert "Truncated" in source
        assert "Trailing" in source
        assert "ConnectionError(400" in source


class TestServerExceptionsLogged:
    """§2.3 bullet 7: server exceptions are now logged, not swallowed (Phase 1 fix)."""

    def test_handle_connection_logs_exceptions(self):
        """server.py handle_connection now logs error categories instead of
        bare `pass`, and uses `finally` to guarantee connection cleanup."""
        import inspect
        from app.server import Bonnet

        source = inspect.getsource(Bonnet.handle_connection)

        # All except blocks now log
        assert "log_msg" in source
        assert "timeout" in source.lower()
        assert "connection error" in source.lower()
        assert "crypto error" in source.lower()
        assert "unexpected error" in source.lower()

        # No bare `pass` in the main except blocks (before finally)
        # The finally block's inner `except Exception: pass` is intentional
        # (best-effort close), so we only check the try/except section.
        finally_idx = source.index("finally")
        try_except_section = source[:finally_idx]
        lines = try_except_section.split("\n")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("except") and ":" in stripped:
                for j in range(i + 1, min(i + 5, len(lines))):
                    next_stripped = lines[j].strip()
                    if next_stripped:
                        assert next_stripped != "pass", \
                            f"Except block at line {i} followed by bare 'pass'"
                        assert "log_msg" in next_stripped, \
                            f"Except block at line {i} should log, got {next_stripped!r}"
                        break

        # finally block guarantees cleanup
        assert "finally" in source
        assert "conn.close()" in source


class TestSyncDBAtomicTOFU:
    """SyncDB TOFU is now atomic via TrustStore (Phase 6 fix)."""

    def test_tofu_uses_atomic_trust_store(self):
        """SyncDB.set_peer_pubkey_tofu now delegates to TrustStore.tofu_pin,
        which uses INSERT OR IGNORE + SELECT — a single atomic operation."""
        import inspect
        from net.sync import SyncDB

        source = inspect.getsource(SyncDB.set_peer_pubkey_tofu)

        # Delegates to TrustStore
        assert "tofu_pin" in source
        assert "self._trust" in source

        # No read-then-insert pattern
        assert "get_peer_pubkey" not in source
        assert "INSERT" not in source
