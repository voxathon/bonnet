"""Phase 1 containment tests — verify the security fixes work.

Tests that the Phase 1 fixes prevent the documented v1 defects:
  1. No nonce reuse under a static key (random nonces, not counter)
  2. Strict frame validation rejects truncated/trailing frames
  3. Server connection cleanup is guaranteed via finally
  4. Server logs errors instead of swallowing them
"""

import os
import sys
import struct
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.crypto import Identity, EncryptedSession
from net.connection import Connection, ConnectionState, ConnectionError
from client.protocol import encode_frame

from tests.fixtures.protocol_v1.wire_fixtures import TEST_SEED


class TestNoNonceReuseUnderStaticKey:
    """Exit gate: reconnection tests prove no nonce reuse under a static key."""

    def test_two_sessions_same_keys_different_nonces(self):
        """Two EncryptedSession instances with the same identity keys must
        produce different ciphertexts for the same plaintext, because nonces
        are now random (not counter-based)."""
        server_id = Identity.generate()
        client_id = Identity.generate()

        sess1 = EncryptedSession(client_id.private_key, server_id.public_key)
        sess2 = EncryptedSession(client_id.private_key, server_id.public_key)

        ct1 = sess1.encrypt(b"same plaintext")
        ct2 = sess2.encrypt(b"same plaintext")

        assert ct1 != ct2, "Random nonces must produce different ciphertexts"

    def test_same_session_different_nonces(self):
        """Two encryptions from the same session must use different nonces."""
        server_id = Identity.generate()
        client_id = Identity.generate()

        session = EncryptedSession(client_id.private_key, server_id.public_key)

        ct1 = session.encrypt(b"msg1")
        ct2 = session.encrypt(b"msg1")

        # NaCl Box.encrypt prepends nonce to ciphertext: [nonce(24)][ciphertext]
        nonce1 = ct1[:24]
        nonce2 = ct2[:24]

        assert nonce1 != nonce2, "Two encrypt calls must use different random nonces"

    def test_reconnection_produces_different_ciphertext(self):
        """Simulate: client disconnects, reconnects with the same identity,
        sends the same command. The ciphertext must differ because the
        new session uses fresh random nonces."""
        server_id = Identity.from_private_key(TEST_SEED)
        client_id = Identity.generate()

        # First "connection"
        sess1 = EncryptedSession(client_id.private_key, server_id.public_key)
        cmd = b"\x11"  # BOARD_LIST
        ct1 = sess1.encrypt(cmd)

        # Second "connection" with same keys
        sess2 = EncryptedSession(client_id.private_key, server_id.public_key)
        ct2 = sess2.encrypt(cmd)

        assert ct1 != ct2

    def test_client_uses_canonical_encrypted_session(self):
        """Verify that src/client/connection.py now imports EncryptedSession
        from core.crypto, not defining its own."""
        import inspect
        from client import connection as client_conn_mod

        source = inspect.getsource(client_conn_mod)

        # Must import from core.crypto
        assert "from core.crypto import EncryptedSession" in source

        # Must NOT define its own EncryptedSession class
        assert "class EncryptedSession:" not in source
        assert "self.nonce = 0" not in source
        assert "_next_nonce" not in source


class TestStrictFrameValidation:
    """Exit gate: strict inner-frame length validation."""

    @pytest.mark.asyncio
    async def test_truncated_frame_rejected(self):
        """A frame where the length field claims more bytes than available
        must raise ConnectionError(400)."""
        identity = Identity.generate()
        websocket = AsyncMock()
        # Length field says 100 bytes, but only 5 follow
        websocket.recv.return_value = struct.pack(">I", 100) + b"short"

        ume = MagicMock()
        config = MagicMock()
        config.max_request_size = 0
        engine = MagicMock()
        engine.ume = ume
        engine.config = config

        conn = Connection.server(identity, websocket, engine)
        conn.state = ConnectionState.READY
        conn.websocket = websocket

        with pytest.raises(ConnectionError) as exc:
            await conn._recv_frame()
        assert exc.value.code == 400
        assert "Truncated" in exc.value.message

    @pytest.mark.asyncio
    async def test_trailing_bytes_rejected(self):
        """A frame with trailing bytes after the declared payload must raise
        ConnectionError(400)."""
        identity = Identity.generate()
        websocket = AsyncMock()
        # Length says 5, but 10 bytes follow
        websocket.recv.return_value = struct.pack(">I", 5) + b"helloextra"

        ume = MagicMock()
        config = MagicMock()
        config.max_request_size = 0
        engine = MagicMock()
        engine.ume = ume
        engine.config = config

        conn = Connection.server(identity, websocket, engine)
        conn.state = ConnectionState.READY
        conn.websocket = websocket

        with pytest.raises(ConnectionError) as exc:
            await conn._recv_frame()
        assert exc.value.code == 400
        assert "Trailing" in exc.value.message

    @pytest.mark.asyncio
    async def test_to_short_frame_rejected(self):
        """A frame with fewer than 4 bytes (no length prefix) must raise."""
        identity = Identity.generate()
        websocket = AsyncMock()
        websocket.recv.return_value = b"\x00\x00"

        engine = MagicMock()
        engine.ume = MagicMock()
        engine.config = MagicMock()
        conn = Connection.server(identity, websocket, engine)
        conn.state = ConnectionState.READY
        conn.websocket = websocket

        with pytest.raises(ConnectionError) as exc:
            await conn._recv_frame()
        assert exc.value.code == 400
        assert "short" in exc.value.message.lower()

    @pytest.mark.asyncio
    async def test_valid_frame_accepted(self):
        """A well-formed frame with exact length match must succeed."""
        identity = Identity.generate()
        websocket = AsyncMock()
        payload = b"hello bonnet"
        websocket.recv.return_value = encode_frame(payload)

        engine = MagicMock()
        engine.ume = MagicMock()
        engine.config = MagicMock()
        conn = Connection.server(identity, websocket, engine)
        conn.state = ConnectionState.READY
        conn.websocket = websocket

        result = await conn._recv_frame()
        assert result == payload

    @pytest.mark.asyncio
    async def test_non_binary_frame_rejected(self):
        """A non-bytes frame (e.g. str from WebSocket) must raise."""
        identity = Identity.generate()
        websocket = AsyncMock()
        websocket.recv.return_value = "text frame"

        engine = MagicMock()
        engine.ume = MagicMock()
        engine.config = MagicMock()
        conn = Connection.server(identity, websocket, engine)
        conn.state = ConnectionState.READY
        conn.websocket = websocket

        with pytest.raises(ConnectionError) as exc:
            await conn._recv_frame()
        assert exc.value.code == 400
        assert "binary" in exc.value.message.lower()


class TestServerConnectionCleanup:
    """Exit gate: server guarantees connection cleanup with finally."""

    @pytest.mark.asyncio
    async def test_cleanup_on_success(self):
        """After a successful command, the connection is closed in finally."""
        from app.server import Bonnet
        from unittest.mock import patch

        server_identity = Identity.from_private_key(TEST_SEED)
        client_identity = Identity.generate()

        sent_frames = []
        recv_count = [0]

        async def capture_send(data):
            sent_frames.append(data)

        async def mock_recv():
            recv_count[0] += 1
            if recv_count[0] == 1:
                frame = sent_frames[0]
                _, payload = encode_frame.__wrapped__ if hasattr(encode_frame, '__wrapped__') else (None, None)
                from client.protocol import decode_frame
                _, payload = decode_frame(frame)
                challenge = payload[32:]
                sig = client_identity.sign(challenge)
                return encode_frame(client_identity.public_key + sig)
            session = EncryptedSession(client_identity.private_key, server_identity.public_key)
            cmd = b"\x11"  # BOARD_LIST
            return encode_frame(session.encrypt(cmd))

        websocket = AsyncMock()
        websocket.send.side_effect = capture_send
        websocket.recv.side_effect = mock_recv
        websocket.remote_address = ("127.0.0.1", 12345)

        ume = MagicMock()
        ume.get_all_by_publickey.return_value = []
        config = MagicMock()
        config.max_request_size = 10 * 1024 * 1024
        config.rate_limit_window = 1
        config.rate_limit_requests = 100
        config.public_commands = {0x11}
        config.search_per_identity_concurrency = 1
        config.search_rate_limit = 10
        config.search_rate_window_seconds = 60
        config.data_dir = None
        config.origin = "localhost"
        config.timeout_seconds = 30

        ame = MagicMock()
        ame.list_boards.return_value = []
        ame.get_nav().list_all.return_value = []

        engine = MagicMock()
        engine.ume = ume
        engine.ame = ame
        engine.keibatsu = MagicMock()
        engine.config = config
        engine.check_permission.return_value = True
        engine.server_identity = server_identity

        from net.commands import CommandHandler
        handler = CommandHandler(engine)

        bonnet = MagicMock(spec=Bonnet)
        bonnet.server_identity = server_identity
        bonnet.engine = engine
        bonnet.command_handler = handler
        bonnet.config = config

        # Call handle_connection directly
        await Bonnet.handle_connection(bonnet, websocket)

        # The websocket should have been closed (via conn.close() in finally)
        websocket.close.assert_called()

    @pytest.mark.asyncio
    async def test_cleanup_on_handshake_failure(self):
        """Even when the handshake fails, the connection is cleaned up."""
        from app.server import Bonnet

        server_identity = Identity.from_private_key(TEST_SEED)
        wrong_identity = Identity.generate()

        sent_frames = []

        async def capture_send(data):
            sent_frames.append(data)

        async def mock_recv():
            if len(sent_frames) == 0:
                return b"\x00\x00\x00\x00"
            frame = sent_frames[0]
            from client.protocol import decode_frame
            _, payload = decode_frame(frame)
            challenge = payload[32:]
            # Sign with WRONG key
            sig = wrong_identity.sign(challenge)
            return encode_frame(wrong_identity.public_key + sig)

        websocket = AsyncMock()
        websocket.send.side_effect = capture_send
        websocket.recv.side_effect = mock_recv
        websocket.remote_address = ("127.0.0.1", 12345)

        ume = MagicMock()
        ume.get_all_by_publickey.return_value = []
        config = MagicMock()
        config.timeout_seconds = 30
        config.max_request_size = 0

        engine = MagicMock()
        engine.ume = ume
        engine.config = config

        bonnet = MagicMock(spec=Bonnet)
        bonnet.server_identity = server_identity
        bonnet.engine = engine
        bonnet.config = config

        # Mock CommandHandler so it doesn't try to create SyncManager
        handler = MagicMock()
        bonnet.command_handler = handler

        # handle_connection should not raise — it catches and logs
        await Bonnet.handle_connection(bonnet, websocket)

        # websocket.close should have been called (cleanup in finally)
        websocket.close.assert_called()

    @pytest.mark.asyncio
    async def test_cleanup_on_timeout(self):
        """Even on timeout, the connection is cleaned up."""
        from app.server import Bonnet
        import asyncio

        server_identity = Identity.from_private_key(TEST_SEED)

        async def slow_recv():
            await asyncio.sleep(100)  # will timeout

        websocket = AsyncMock()
        websocket.recv.side_effect = slow_recv
        websocket.remote_address = ("127.0.0.1", 12345)

        config = MagicMock()
        config.timeout_seconds = 0  # immediate timeout

        engine = MagicMock()
        engine.ume = MagicMock()
        engine.config = config

        bonnet = MagicMock(spec=Bonnet)
        bonnet.server_identity = server_identity
        bonnet.engine = engine
        bonnet.config = config
        bonnet.command_handler = MagicMock()

        # Should not raise
        await Bonnet.handle_connection(bonnet, websocket)

        # websocket.close should have been called
        websocket.close.assert_called()
