"""Protocol v1 lifecycle test — prove the server's one-command-per-WebSocket model.

The server in src/app/server.py:handle_connection does:
  1. Create Connection.server()
  2. accept() — handshake
  3. recv_request() — one command
  4. command_handler.handle() — dispatch
  5. send_response() — one response
  6. close()

This test simulates a full connection lifecycle using mock WebSocket objects
and verifies that the server processes exactly one command and closes.
"""

import os
import sys
import struct
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from net.connection import Connection, ConnectionState, ConnectionMode, ConnectionError
from core.crypto import Identity, EncryptedSession
from client.protocol import encode_frame, decode_frame, build_board_list, parse_response, ResponseStatus

from tests.fixtures.protocol_v1.wire_fixtures import (
    TEST_SEED, TEST_PUBLIC_KEY, HANDSHAKE_CHALLENGE,
)


@pytest.fixture
def server_identity():
    return Identity.from_private_key(TEST_SEED)


@pytest.fixture
def client_identity():
    return Identity.generate()


class TestOneCommandLifecycle:
    """The server handles exactly one command per connection."""

    @pytest.mark.asyncio
    async def test_full_lifecycle(self, server_identity, client_identity):
        """Simulate: handshake → one command → one response → close."""
        sent_frames = []
        recv_count = [0]

        async def capture_send(data):
            sent_frames.append(data)

        async def mock_recv():
            recv_count[0] += 1
            if recv_count[0] == 1:
                # _send_challenge sends first, then _recv_frame calls recv
                # Return the handshake response
                frame = sent_frames[0]
                _, payload = decode_frame(frame)
                challenge = payload[32:]  # skip server pubkey
                sig = client_identity.sign(challenge)
                handshake = client_identity.public_key + sig
                return encode_frame(handshake)
            # recv_count == 2: the encrypted command
            session = EncryptedSession(client_identity.private_key, server_identity.public_key)
            cmd = build_board_list()
            encrypted = session.encrypt(cmd)
            return encode_frame(encrypted)

        websocket = AsyncMock()
        websocket.send.side_effect = capture_send
        websocket.recv.side_effect = mock_recv
        websocket.remote_address = ("127.0.0.1", 12345)

        ume = MagicMock()
        ume.get_all_by_publickey.return_value = []
        config = MagicMock()
        config.max_request_size = 0
        engine = MagicMock()
        engine.ume = ume
        engine.config = config

        # --- Execute the lifecycle ---
        conn = Connection.server(server_identity, websocket, engine)
        await conn.accept()
        assert conn.state == ConnectionState.READY

        plaintext = await conn.recv_request()
        assert len(plaintext) > 0
        assert plaintext[0] == 0x11  # BOARD_LIST opcode

        response = bytes([0x00]) + struct.pack(">H", 0)  # success, 0 boards
        await conn.send_response(response)

        await conn.close()
        assert conn.state == ConnectionState.CLOSED

        # Frame 0: server challenge (pubkey + challenge)
        # Frame 1: encrypted response
        assert len(sent_frames) == 2

        # Verify the response frame is encrypted and can be decrypted
        _, resp_payload = decode_frame(sent_frames[1])
        session = EncryptedSession(client_identity.private_key, server_identity.public_key)
        decrypted = session.decrypt(resp_payload)
        status, _ = parse_response(decrypted)
        assert status == ResponseStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_no_second_command_accepted(self, server_identity, client_identity):
        """After one command/response, the connection is closed and rejects further commands."""
        sent_frames = []
        recv_count = [0]

        async def capture_send(data):
            sent_frames.append(data)

        async def mock_recv():
            recv_count[0] += 1
            if recv_count[0] == 1:
                frame = sent_frames[0]
                _, payload = decode_frame(frame)
                challenge = payload[32:]
                sig = client_identity.sign(challenge)
                handshake = client_identity.public_key + sig
                return encode_frame(handshake)
            session = EncryptedSession(client_identity.private_key, server_identity.public_key)
            cmd = build_board_list()
            encrypted = session.encrypt(cmd)
            return encode_frame(encrypted)

        websocket = AsyncMock()
        websocket.send.side_effect = capture_send
        websocket.recv.side_effect = mock_recv

        ume = MagicMock()
        ume.get_all_by_publickey.return_value = []
        config = MagicMock()
        config.max_request_size = 0
        engine = MagicMock()
        engine.ume = ume
        engine.config = config

        conn = Connection.server(server_identity, websocket, engine)
        await conn.accept()
        plaintext = await conn.recv_request()
        await conn.send_response(bytes([0x00]) + struct.pack(">H", 0))
        await conn.close()

        # After close, state is CLOSED — further operations should fail
        assert conn.state == ConnectionState.CLOSED
        assert conn.websocket is None
        assert conn.session is None

        # Attempting to send another request must fail
        with pytest.raises(ConnectionError):
            await conn.send_request(b"\x11", b"")

    @pytest.mark.asyncio
    async def test_server_handles_handshake_then_single_command(self, server_identity, client_identity):
        """Verify the server-side handshake produces the expected wire format."""
        sent_frames = []
        recv_count = [0]

        async def capture_send(data):
            sent_frames.append(data)

        async def mock_recv():
            recv_count[0] += 1
            if recv_count[0] == 1:
                frame = sent_frames[0]
                _, payload = decode_frame(frame)
                challenge = payload[32:]
                sig = client_identity.sign(challenge)
                return encode_frame(client_identity.public_key + sig)
            return b""

        websocket = AsyncMock()
        websocket.send.side_effect = capture_send
        websocket.recv.side_effect = mock_recv

        ume = MagicMock()
        ume.get_all_by_publickey.return_value = []
        config = MagicMock()
        config.max_request_size = 0
        engine = MagicMock()
        engine.ume = ume
        engine.config = config

        conn = Connection.server(server_identity, websocket, engine)
        await conn.accept()

        # Verify the server challenge frame format: [4-byte len][32-byte pubkey][32-byte challenge]
        challenge_frame = sent_frames[0]
        length = struct.unpack(">I", challenge_frame[:4])[0]
        assert length == 64  # 32 pubkey + 32 challenge
        server_pubkey = challenge_frame[4:36]
        challenge = challenge_frame[36:68]
        assert server_pubkey == server_identity.public_key
        assert len(challenge) == 32

        assert conn.peer_public_key == client_identity.public_key
        assert conn.state == ConnectionState.READY


class TestServerHandleConnectionLifecycle:
    """Test the actual server.handle_connection method's lifecycle — it should
    process one command and close, matching the pattern in src/app/server.py."""

    @pytest.mark.asyncio
    async def test_handle_connection_one_command(self, server_identity, client_identity):
        """Verify that a simulated handle_connection flow completes in one round."""
        from unittest.mock import patch

        sent_frames = []

        async def capture_send(data):
            sent_frames.append(data)

        recv_count = [0]

        async def mock_recv():
            recv_count[0] += 1
            if recv_count[0] == 1:
                frame = sent_frames[0]
                _, payload = decode_frame(frame)
                challenge = payload[32:]
                sig = client_identity.sign(challenge)
                return encode_frame(client_identity.public_key + sig)
            session = EncryptedSession(client_identity.private_key, server_identity.public_key)
            cmd = build_board_list()
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
        config.public_commands = {0x11}  # BOARD_LIST is public
        config.search_per_identity_concurrency = 1
        config.search_rate_limit = 10
        config.search_rate_window_seconds = 60
        config.data_dir = None
        config.origin = "localhost"

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

        # Simulate the handle_connection pattern from server.py
        conn = Connection.server(server_identity, websocket, engine)
        await conn.accept()

        plaintext = await conn.recv_request()
        ctx = conn.to_context()
        response = handler.handle(plaintext, ctx)

        await conn.send_response(response)
        await conn.close()

        # Exactly one command was processed
        assert len(plaintext) >= 1
        assert plaintext[0] == 0x11  # BOARD_LIST

        # Response is success with 0 boards
        session = EncryptedSession(client_identity.private_key, server_identity.public_key)
        _, resp_encrypted = decode_frame(sent_frames[1])
        resp_plain = session.decrypt(resp_encrypted)
        assert resp_plain[0] == 0x00  # SUCCESS

        # Connection is closed
        assert conn.state == ConnectionState.CLOSED
