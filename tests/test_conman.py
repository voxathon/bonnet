# -*- coding: utf-8 -*-

import pytest
import struct
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from net.connection import Connection, ConnectionMode, ConnectionState, ConnectionError
from core.crypto import Identity, EncryptedSession
from engine.ume import User


class TestConnectionError:
    def test_connection_error_exception(self):
        exc = ConnectionError(401, "Unauthorized")
        assert exc.code == 401
        assert exc.message == "Unauthorized"
        assert str(exc) == "401: Unauthorized"

    def test_connection_error_different_codes(self):
        exc1 = ConnectionError(403, "Forbidden")
        exc2 = ConnectionError(500, "Internal Error")
        assert exc1.code != exc2.code
        assert exc1.message != exc2.message


class TestConnectionFactories:
    def test_client_factory(self):
        identity = Identity.generate()
        conn = Connection.client(identity, timeout_seconds=30)
        assert conn.mode == ConnectionMode.CLIENT
        assert conn.state == ConnectionState.DISCONNECTED
        assert conn.is_client is True
        assert conn.is_server is False
        assert conn.is_ready is False

    def test_server_factory(self):
        identity = Identity.generate()
        websocket = MagicMock()
        ume = MagicMock()
        config = MagicMock()
        engine = MagicMock()
        engine.ume = ume
        engine.config = config
        conn = Connection.server(identity, websocket, engine, timeout_seconds=30)
        assert conn.mode == ConnectionMode.SERVER
        assert conn.state == ConnectionState.AUTHENTICATING
        assert conn.is_client is False
        assert conn.is_server is True
        assert conn.is_ready is False


class TestConnectionProperties:
    def test_is_anonymous_no_user(self):
        identity = Identity.generate()
        conn = Connection.client(identity)
        assert conn.is_anonymous is True
        assert conn.user is None

    def test_is_anonymous_with_user(self):
        identity = Identity.generate()
        websocket = MagicMock()
        ume = MagicMock()
        config = MagicMock()
        engine = MagicMock()
        engine.ume = ume
        engine.config = config
        conn = Connection.server(identity, websocket, engine)
        user = MagicMock()
        user.username = "alice"
        conn.user = user
        assert conn.is_anonymous is False


class TestConnectionPermissions:
    def _create_user(self, username, is_admin=False, is_mod=False):
        user = MagicMock(spec=User)
        user.username = username
        user.is_administrator = is_admin
        user.is_moderator = is_mod
        return user

    def _create_connection_with_user(self, user=None):
        identity = Identity.generate()
        websocket = MagicMock()
        ume = MagicMock()
        config = MagicMock()
        engine = MagicMock()
        engine.ume = ume
        engine.config = config
        conn = Connection.server(identity, websocket, engine)
        conn.user = user
        return conn

    def test_is_registered_true(self):
        user = self._create_user("alice")
        conn = self._create_connection_with_user(user)
        assert conn.is_registered() is True

    def test_is_registered_false(self):
        conn = self._create_connection_with_user(None)
        assert conn.is_registered() is False

    def test_is_administrator_true(self):
        user = self._create_user("admin", is_admin=True)
        conn = self._create_connection_with_user(user)
        assert conn.is_administrator() is True

    def test_is_administrator_false_not_admin(self):
        user = self._create_user("user", is_admin=False)
        conn = self._create_connection_with_user(user)
        assert conn.is_administrator() is False

    def test_is_administrator_false_no_user(self):
        conn = self._create_connection_with_user(None)
        assert conn.is_administrator() is False

    def test_is_moderator_true(self):
        user = self._create_user("mod", is_mod=True)
        conn = self._create_connection_with_user(user)
        assert conn.is_moderator() is True

    def test_is_moderator_false(self):
        conn = self._create_connection_with_user(None)
        assert conn.is_moderator() is False

    def test_can_create_board_admin(self):
        user = self._create_user("admin", is_admin=True)
        conn = self._create_connection_with_user(user)
        assert conn.can_create_board() is True

    def test_can_create_board_non_admin(self):
        user = self._create_user("user", is_admin=False)
        conn = self._create_connection_with_user(user)
        assert conn.can_create_board() is False

    def test_can_promote_to_mod_admin(self):
        user = self._create_user("admin", is_admin=True)
        conn = self._create_connection_with_user(user)
        assert conn.can_promote_to_mod() is True

    def test_can_promote_to_mod_non_admin(self):
        user = self._create_user("user", is_admin=False)
        conn = self._create_connection_with_user(user)
        assert conn.can_promote_to_mod() is False

    def test_can_demote_mod_admin(self):
        user = self._create_user("admin", is_admin=True)
        conn = self._create_connection_with_user(user)
        assert conn.can_demote_mod() is True

    def test_can_demote_mod_non_admin(self):
        user = self._create_user("user", is_admin=False)
        conn = self._create_connection_with_user(user)
        assert conn.can_demote_mod() is False

    def test_can_edit_post_author(self):
        user = self._create_user("alice")
        conn = self._create_connection_with_user(user)
        assert conn.can_edit_post("alice") is True

    def test_can_edit_post_not_author(self):
        user = self._create_user("alice")
        conn = self._create_connection_with_user(user)
        assert conn.can_edit_post("bob") is False

    def test_can_edit_post_no_user(self):
        conn = self._create_connection_with_user(None)
        assert conn.can_edit_post("alice") is False

    def test_can_delete_post_author(self):
        user = self._create_user("alice")
        conn = self._create_connection_with_user(user)
        assert conn.can_delete_post("alice") is True

    def test_can_delete_post_not_author(self):
        user = self._create_user("alice")
        conn = self._create_connection_with_user(user)
        assert conn.can_delete_post("bob") is False


class TestConnectionAccept:
    @pytest.fixture
    def mock_ume(self):
        return MagicMock()

    @pytest.fixture
    def mock_config(self):
        return MagicMock()

    @pytest.fixture
    def server_identity(self):
        return Identity.generate()

    @pytest.fixture
    def client_identity(self):
        return Identity.generate()

    @pytest.mark.asyncio
    async def test_accept_anonymous(
        self, mock_ume, mock_config, server_identity, client_identity
    ):
        mock_ume.get_all_by_publickey.return_value = []
        websocket = AsyncMock()
        sent_frames = []

        async def capture_send(data):
            sent_frames.append(data)

        websocket.send.side_effect = capture_send

        async def mock_recv():
            if len(sent_frames) < 1:
                return b"\x00\x00\x00\x00"
            challenge_frame = sent_frames[0]
            challenge = challenge_frame[
                36:
            ]  # Frame is [4B len][32B pubkey][32B challenge]
            signature = client_identity.sign(challenge)
            handshake = client_identity.public_key + signature
            return struct.pack(">I", len(handshake)) + handshake

        websocket.recv.side_effect = mock_recv

        engine = MagicMock()
        engine.ume = mock_ume
        engine.config = mock_config
        conn = Connection.server(server_identity, websocket, engine)
        await conn.accept()

        assert conn.is_anonymous is True
        assert conn.user is None
        assert conn.peer_public_key == client_identity.public_key
        assert conn.state == ConnectionState.READY

    @pytest.mark.asyncio
    async def test_accept_single_user(
        self, mock_ume, mock_config, server_identity, client_identity
    ):
        user = MagicMock()
        user.username = "alice"
        mock_ume.get_all_by_publickey.return_value = [user]
        websocket = AsyncMock()
        sent_frames = []

        async def capture_send(data):
            sent_frames.append(data)

        websocket.send.side_effect = capture_send

        async def mock_recv():
            if len(sent_frames) < 1:
                return b"\x00\x00\x00\x00"
            challenge_frame = sent_frames[0]
            challenge = challenge_frame[36:]
            signature = client_identity.sign(challenge)
            handshake = client_identity.public_key + signature
            return struct.pack(">I", len(handshake)) + handshake

        websocket.recv.side_effect = mock_recv

        engine = MagicMock()
        engine.ume = mock_ume
        engine.config = mock_config
        conn = Connection.server(server_identity, websocket, engine)
        await conn.accept()

        assert conn.is_anonymous is False
        assert conn.user is user
        assert conn.username == "alice"
        assert conn.peer_public_key == client_identity.public_key

    @pytest.mark.asyncio
    async def test_accept_invalid_signature(
        self, mock_ume, mock_config, server_identity, client_identity
    ):
        mock_ume.get_all_by_publickey.return_value = []
        wrong_key = Identity.generate()
        websocket = AsyncMock()
        sent_frames = []

        async def capture_send(data):
            sent_frames.append(data)

        websocket.send.side_effect = capture_send

        async def mock_recv():
            if len(sent_frames) < 1:
                return b"\x00\x00\x00\x00"
            challenge_frame = sent_frames[0]
            challenge = challenge_frame[36:]
            signature = wrong_key.sign(challenge)
            handshake = client_identity.public_key + signature
            return struct.pack(">I", len(handshake)) + handshake

        websocket.recv.side_effect = mock_recv

        engine = MagicMock()
        engine.ume = mock_ume
        engine.config = mock_config
        conn = Connection.server(server_identity, websocket, engine)
        with pytest.raises(ConnectionError) as exc_info:
            await conn.accept()
        assert exc_info.value.code == 401
        assert "Invalid signature" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_accept_multi_user_selection(
        self, mock_ume, mock_config, server_identity, client_identity
    ):
        user1 = MagicMock()
        user1.username = "alice"
        user2 = MagicMock()
        user2.username = "bob"
        mock_ume.get_all_by_publickey.return_value = [user1, user2]
        websocket = AsyncMock()
        sent_frames = []

        async def capture_send(data):
            sent_frames.append(data)

        websocket.send.side_effect = capture_send

        async def mock_recv():
            if len(sent_frames) < 1:
                return b"\x00\x00\x00\x00"
            if len(sent_frames) == 1:
                challenge_frame = sent_frames[0]
                challenge = challenge_frame[36:]
                signature = client_identity.sign(challenge)
                handshake = client_identity.public_key + signature
                return struct.pack(">I", len(handshake)) + handshake
            client_session = EncryptedSession(
                client_identity.private_key, server_identity.public_key
            )
            encrypted = client_session.encrypt(b"alice")
            return struct.pack(">I", len(encrypted)) + encrypted

        websocket.recv.side_effect = mock_recv

        engine = MagicMock()
        engine.ume = mock_ume
        engine.config = mock_config
        conn = Connection.server(server_identity, websocket, engine)
        await conn.accept()

        assert conn.is_anonymous is False
        assert conn.user.username == "alice"

    @pytest.mark.asyncio
    async def test_accept_multi_user_invalid_selection(
        self, mock_ume, mock_config, server_identity, client_identity
    ):
        user1 = MagicMock()
        user1.username = "alice"
        user2 = MagicMock()
        user2.username = "bob"
        mock_ume.get_all_by_publickey.return_value = [user1, user2]
        websocket = AsyncMock()
        sent_frames = []

        async def capture_send(data):
            sent_frames.append(data)

        websocket.send.side_effect = capture_send

        async def mock_recv():
            if len(sent_frames) < 1:
                return b"\x00\x00\x00\x00"
            if len(sent_frames) == 1:
                challenge_frame = sent_frames[0]
                challenge = challenge_frame[36:]
                signature = client_identity.sign(challenge)
                handshake = client_identity.public_key + signature
                return struct.pack(">I", len(handshake)) + handshake
            client_session = EncryptedSession(
                client_identity.private_key, server_identity.public_key
            )
            encrypted = client_session.encrypt(b"charlie")
            return struct.pack(">I", len(encrypted)) + encrypted

        websocket.recv.side_effect = mock_recv

        engine = MagicMock()
        engine.ume = mock_ume
        engine.config = mock_config
        conn = Connection.server(server_identity, websocket, engine)
        with pytest.raises(ConnectionError) as exc_info:
            await conn.accept()
        assert exc_info.value.code == 400


class TestConnectionClientConnect:
    @pytest.fixture
    def server_identity(self):
        return Identity.generate()

    @pytest.fixture
    def client_identity(self):
        return Identity.generate()

    @pytest.mark.asyncio
    async def test_connect_invalid_state(self, client_identity):
        conn = Connection.client(client_identity)
        conn.state = ConnectionState.READY
        with pytest.raises(ConnectionError) as exc_info:
            await conn.connect("wss://example.com")
        assert exc_info.value.code == 500

    @pytest.mark.asyncio
    async def test_connect_server_mode_error(self, server_identity):
        websocket = MagicMock()
        ume = MagicMock()
        config = MagicMock()
        conn = Connection.server(server_identity, websocket, ume, config)
        with pytest.raises(ConnectionError) as exc_info:
            await conn.connect("wss://example.com")
        assert exc_info.value.code == 500
        assert "client mode" in exc_info.value.message


class TestConnectionSendRecvRequest:
    @pytest.fixture
    def client_identity(self):
        return Identity.generate()

    @pytest.fixture
    def ready_connection(self):
        identity = Identity.generate()
        websocket = AsyncMock()
        ume = MagicMock()
        config = MagicMock()
        config.max_request_size = 0
        engine = MagicMock()
        engine.ume = ume
        engine.config = config
        conn = Connection.server(identity, websocket, engine)
        conn.state = ConnectionState.READY
        session = MagicMock()
        session.encrypt.return_value = b"encrypted"
        session.decrypt.return_value = b"decrypted"
        conn.session = session
        conn.websocket = websocket
        return conn

    @pytest.mark.asyncio
    async def test_send_request_not_ready(self, client_identity):
        conn = Connection.client(client_identity)
        with pytest.raises(ConnectionError) as exc_info:
            await conn.send_request(b"\x01", b"data")
        assert exc_info.value.code == 500

    @pytest.mark.asyncio
    async def test_send_request_success(self, ready_connection):
        await ready_connection.send_request(b"\x01", b"payload")
        ready_connection.session.encrypt.assert_called_once_with(b"\x01payload")

    @pytest.mark.asyncio
    async def test_recv_request_not_ready(self, client_identity):
        conn = Connection.client(client_identity)
        with pytest.raises(ConnectionError) as exc_info:
            await conn.recv_request()
        assert exc_info.value.code == 500

    @pytest.mark.asyncio
    async def test_recv_request_success(self, ready_connection):
        ready_connection.websocket.recv.return_value = (
            struct.pack(">I", 10) + b"encrypted"
        )
        result = await ready_connection.recv_request()
        assert result == b"decrypted"


class TestConnectionClose:
    @pytest.mark.asyncio
    async def test_close_already_closed(self):
        identity = Identity.generate()
        conn = Connection.client(identity)
        conn.state = ConnectionState.CLOSED
        await conn.close()
        assert conn.state == ConnectionState.CLOSED

    @pytest.mark.asyncio
    async def test_close_with_websocket(self):
        identity = Identity.generate()
        websocket = AsyncMock()
        ume = MagicMock()
        config = MagicMock()
        engine = MagicMock()
        engine.ume = ume
        engine.config = config
        conn = Connection.server(identity, websocket, engine)
        conn.state = ConnectionState.READY
        conn.session = MagicMock()
        await conn.close()
        websocket.close.assert_called_once()
        assert conn.state == ConnectionState.CLOSED


class TestQueryPostsCommand:
    def test_query_posts_request_format(self):
        board = b"general"
        where = b"author=?"
        value_type = 0x02
        value = b"alice"
        orderby = b"last_bumped DESC"
        limit = 10

        payload = (
            bytes([len(board)])
            + board
            + struct.pack(">H", len(where))
            + where
            + bytes([1])
            + bytes([value_type, len(value)])
            + value
            + struct.pack(">H", len(orderby))
            + orderby
            + struct.pack(">I", limit)
        )

        cmd = 0x19
        request = bytes([cmd]) + payload

        idx = 0
        assert request[idx] == 0x19
        idx += 1

        b_len = request[idx]
        idx += 1
        assert request[idx : idx + b_len] == board
        idx += b_len

        where_len = struct.unpack(">H", request[idx : idx + 2])[0]
        idx += 2
        assert request[idx : idx + where_len] == where
        idx += where_len

        value_count = request[idx]
        idx += 1
        assert value_count == 1

        v_type = request[idx]
        idx += 1
        assert v_type == 0x02

        v_len = request[idx]
        idx += 1
        assert request[idx : idx + v_len] == value
        idx += v_len

        orderby_len = struct.unpack(">H", request[idx : idx + 2])[0]
        idx += 2
        assert request[idx : idx + orderby_len] == orderby
        idx += orderby_len

        parsed_limit = struct.unpack(">I", request[idx : idx + 4])[0]
        assert parsed_limit == limit

    def test_query_posts_request_no_where(self):
        board = b"test"
        payload = (
            bytes([len(board)])
            + board
            + struct.pack(">H", 0)
            + bytes([0])
            + struct.pack(">H", 0)
            + struct.pack(">I", 0)
        )

        cmd = 0x19
        request = bytes([cmd]) + payload

        idx = 0
        assert request[idx] == 0x19
        idx += 1

        b_len = request[idx]
        idx += 1
        assert request[idx : idx + b_len] == board
        idx += b_len

        where_len = struct.unpack(">H", request[idx : idx + 2])[0]
        assert where_len == 0
