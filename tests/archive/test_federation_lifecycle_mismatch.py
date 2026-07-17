"""Federation lifecycle mismatch — quarantined test demonstrating the protocol v1 defect.

PROTOCOL_RENOVATION_PLAN §2.1:
  "The federation client in src/net/sync.py assumes the opposite lifecycle: it
   tries to issue several commands over one connection. The protocol abstraction
   and server implementation therefore disagree about connection ownership."

The SyncManager._do_sync_from_peer method:
  1. Opens one Connection.client() to a peer
  2. Calls conn.connect() — one handshake
  3. Calls conn.send_request() / conn.recv_response() THREE times:
     a. _sync_boards: BOARD_LIST
     b. _sync_users: LIST_USERS (paged, potentially multiple round-trips)
     c. _sync_reports: REPORT_LIST_SINCE

But the server (src/app/server.py:handle_connection) closes the WebSocket after
processing ONE command.  The second send_request/recv_response pair will fail
because the server has already closed the connection.

This test is marked xfail to document the mismatch.  When protocol v2 replaces
v1 with HTTP (where multiple requests per connection is normal), this test
should be removed or inverted.
"""

import os
import sys
import struct
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from net.connection import Connection, ConnectionState, ConnectionError
from core.crypto import Identity, EncryptedSession
from client.protocol import encode_frame, decode_frame, build_board_list, parse_response

from tests.fixtures.protocol_v1.wire_fixtures import TEST_SEED


@pytest.fixture
def identities():
    server = Identity.from_private_key(TEST_SEED)
    client = Identity.generate()
    return server, client


class TestFederationLifecycleMismatch:
    """Document that SyncManager expects multiple commands per connection."""

    @pytest.mark.asyncio
    @pytest.mark.xfail(
        reason="Protocol v1 server closes after one command; federation expects multiple. "
               "This mismatch is the core motivation for protocol v2 (HTTP). "
               "See PROTOCOL_RENOVATION_PLAN §2.1.",
        strict=True,
    )
    async def test_multiple_commands_over_one_connection(self, identities):
        """Simulate the federation sync pattern: one connection, three command/response pairs.

        This SHOULD work from the federation client's perspective (SyncManager calls
        send_request/recv_response multiple times), but it FAILS because the server
        closes the WebSocket after the first command.
        """
        server_identity, client_identity = identities
        sent_frames = []
        recv_count = [0]

        async def capture_send(data):
            sent_frames.append(data)

        async def mock_recv():
            recv_count[0] += 1
            if recv_count[0] == 1:
                # Handshake response
                frame = sent_frames[0]
                _, payload = decode_frame(frame)
                challenge = payload[32:]
                sig = client_identity.sign(challenge)
                return encode_frame(client_identity.public_key + sig)
            # Subsequent recvs: encrypted responses
            session = EncryptedSession(client_identity.private_key, server_identity.public_key)
            # Return a minimal success response for each command
            resp = bytes([0x00]) + struct.pack(">H", 0)  # success, 0 items
            return encode_frame(session.encrypt(resp))

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
        assert conn.state == ConnectionState.READY

        # --- Command 1: BOARD_LIST ---
        session = EncryptedSession(client_identity.private_key, server_identity.public_key)
        cmd1 = build_board_list()
        await conn.send_request(bytes([cmd1[0]]), cmd1[1:])
        resp1 = await conn.recv_response()
        status1, _ = parse_response(session.decrypt(resp1))
        assert status1 == 0x00

        # --- Command 2: LIST_USERS ---
        cmd2 = bytes([0x03]) + struct.pack(">II", 0, 100)
        await conn.send_request(bytes([cmd2[0]]), cmd2[1:])
        resp2 = await conn.recv_response()
        status2, _ = parse_response(session.decrypt(resp2))
        assert status2 == 0x00

        # --- Command 3: REPORT_LIST_SINCE ---
        cmd3 = bytes([0x54]) + struct.pack(">q", 0)
        await conn.send_request(bytes([cmd3[0]]), cmd3[1:])
        resp3 = await conn.recv_response()
        status3, _ = parse_response(session.decrypt(resp3))
        assert status3 == 0x00

        # If we get here, three commands succeeded over one connection.
        # In v1 this should NOT happen because the server closes after one.
        # The xfail marker means we EXPECT this to fail.
        await conn.close()

    @pytest.mark.asyncio
    async def test_sync_manager_calls_multiple_commands(self, identities):
        """Document (without executing) that SyncManager._do_sync_from_peer
        issues three sync phases over one BonnetHTTPClient (not Connection).

        This is a static analysis test — it inspects the source code to verify
        the federation transport now uses HTTP (Phase 6), not WebSocket.
        """
        import inspect
        from net.sync import SyncManager

        source = inspect.getsource(SyncManager._do_sync_from_peer)

        # The sync method calls three sub-syncs, all using the same client
        assert "_sync_boards" in source
        assert "_sync_users" in source
        assert "_sync_reports" in source

        # Uses BonnetHTTPClient, not Connection.client
        assert "BonnetHTTPClient" in source
        assert "Connection.client" not in source

        # Verify each sub-sync uses _send_command (multiple commands over one client)
        boards_source = inspect.getsource(SyncManager._sync_boards)
        assert "_send_command" in boards_source

        users_source = inspect.getsource(SyncManager._sync_users)
        assert "_send_command" in users_source
        # Users sync is paged — sends multiple LIST_USERS commands in a loop
        assert "while True" in users_source

        reports_source = inspect.getsource(SyncManager._sync_reports)
        assert "_send_command" in reports_source

    def test_server_closes_after_one_command(self):
        """Document that the server's handle_connection processes exactly one command."""
        import inspect
        from app.server import Bonnet

        source = inspect.getsource(Bonnet.handle_connection)

        # One accept, one recv_request, one handle, one send_response, one close
        assert "conn.accept()" in source
        assert "conn.recv_request()" in source
        assert "command_handler.handle(" in source
        assert "conn.send_response(" in source
        assert "conn.close()" in source

        # No loop — just one command
        assert "while" not in source
        assert "for " not in source
