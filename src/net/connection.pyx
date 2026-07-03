# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False

import struct
import os
import asyncio
import time
import re
from datetime import datetime
from enum import IntEnum
from typing import Optional, Callable, List, Any
from libc.stdint cimport uint64_t, int64_t

import nacl.exceptions
import websockets.client

from core.logging import log_msg, log_hex, log_dict

READ_ONLY_COMMANDS = {0x01, 0x02, 0x03, 0x11, 0x13, 0x14, 0x19, 0x1A, 0x30, 0x41, 0x42, 0x43, 0x51, 0x52, 0x61, 0x62, 0x63}

cdef int CHALLENGE_SIZE = 32


class ConnectionMode(IntEnum):
    CLIENT = 0
    SERVER = 1


class ConnectionState(IntEnum):
    DISCONNECTED = 0
    AUTHENTICATING = 1
    READY = 2
    CLOSED = 3


cdef str _state_name(int state):
    if state == ConnectionState.DISCONNECTED:
        return "DISCONNECTED"
    elif state == ConnectionState.AUTHENTICATING:
        return "AUTHENTICATING"
    elif state == ConnectionState.READY:
        return "READY"
    elif state == ConnectionState.CLOSED:
        return "CLOSED"
    return "UNKNOWN"


class ConnectionError(Exception):
    def __init__(self, int code, str message):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


cdef class Connection:
    cdef public int mode
    cdef public int state
    cdef object _identity
    cdef public object websocket
    cdef public object session
    cdef public bytes peer_public_key
    cdef public str username
    cdef public object user
    cdef object _user_callback
    cdef int _timeout_seconds
    cdef bytes _challenge
    cdef object _ume
    cdef object _ame
    cdef object _config
    cdef public object _engine
    cdef public str origin
    cdef public str remote_addr
    cdef public object _request_timestamps

    def __init__(self):
        self.state = ConnectionState.DISCONNECTED
        self.websocket = None
        self.session = None
        self.peer_public_key = None
        self.username = None
        self.user = None
        self._challenge = None
        self._ume = None
        self._ame = None
        self._config = None
        self.origin = None
        self.remote_addr = None

    @staticmethod
    def client(object identity, int timeout_seconds=30):
        cdef Connection conn = Connection()
        conn.mode = ConnectionMode.CLIENT
        conn._identity = identity
        conn._timeout_seconds = timeout_seconds
        return conn

    @staticmethod
    def server(object identity, object websocket, object engine,
               object user_callback=None, int timeout_seconds=30):
        cdef Connection conn = Connection()
        conn.mode = ConnectionMode.SERVER
        conn._identity = identity
        conn.websocket = websocket
        conn._engine = engine
        conn._ume = engine.ume
        conn._ame = getattr(engine, 'ame', None)
        conn._config = engine.config
        conn._user_callback = user_callback
        conn._timeout_seconds = timeout_seconds
        conn.state = ConnectionState.AUTHENTICATING
        
        if websocket and hasattr(websocket, 'remote_address') and websocket.remote_address:
            addr = websocket.remote_address
            if isinstance(addr, tuple) and len(addr) > 0:
                conn.remote_addr = str(addr[0])
            elif addr is not None:
                conn.remote_addr = str(addr)
        
        if websocket and hasattr(websocket, 'request') and websocket.request:
            req = websocket.request
            if hasattr(req, 'headers'):
                host = req.headers.get('Host', '') if callable(getattr(req.headers, 'get', None)) else ''
                if host and isinstance(host, str):
                    conn.origin = host.split(':')[0]
        
        return conn

    @property
    def is_ready(self) -> bool:
        return self.state == ConnectionState.READY

    @property
    def is_server(self) -> bool:
        return self.mode == ConnectionMode.SERVER

    @property
    def is_client(self) -> bool:
        return self.mode == ConnectionMode.CLIENT

    @property
    def is_anonymous(self) -> bool:
        return self.user is None

    cpdef bint is_registered(self):
        return self.user is not None

    cpdef bint is_administrator(self):
        return self.user is not None and self.user.is_administrator

    cpdef bint is_moderator(self):
        return self.user is not None and self.user.is_moderator

    cpdef bint can_create_board(self):
        return self.is_administrator()

    cpdef bint can_promote_to_mod(self):
        return self.is_administrator()

    cpdef bint can_demote_mod(self):
        return self.is_administrator()

    cpdef bint can_edit_post(self, str author):
        return self.user is not None and self.user.username == author

    cpdef bint can_delete_post(self, str author):
        return self.user is not None and (
            self.user.username == author or 
            self.is_moderator() or 
            self.is_administrator()
        )

    async def connect(self, str url, object ssl_context=None):
        if self.mode != ConnectionMode.CLIENT:
            raise ConnectionError(500, "connect() only valid for client mode")
        if self.state != ConnectionState.DISCONNECTED:
            raise ConnectionError(500, f"Invalid state: {_state_name(self.state)}")

        self.state = ConnectionState.AUTHENTICATING

        try:
            kwargs = {}
            if ssl_context is not None:
                kwargs['ssl'] = ssl_context

            self.websocket = await asyncio.wait_for(
                websockets.client.connect(url, **kwargs),
                timeout=self._timeout_seconds
            )

            frame = await self._recv_frame()
            if len(frame) != 32 + CHALLENGE_SIZE:
                raise ConnectionError(400, "Invalid challenge frame size")

            self.peer_public_key = frame[:32]
            challenge = frame[32:]

            await self._send_handshake(challenge)

            self.session = self._create_session(self._identity.private_key, self.peer_public_key)

            response = await self._recv_frame()
            if len(response) == 0:
                pass
            elif response[0] == 0x01:
                code = struct.unpack('>H', response[1:3])[0]
                msg_len = response[3]
                msg = response[4:4+msg_len].decode('utf-8', errors='replace')
                raise ConnectionError(code, msg)

            self.state = ConnectionState.READY

        except asyncio.TimeoutError:
            self.state = ConnectionState.DISCONNECTED
            raise ConnectionError(503, "Connection timeout")
        except ConnectionError:
            self.state = ConnectionState.DISCONNECTED
            raise
        except Exception as e:
            self.state = ConnectionState.DISCONNECTED
            raise ConnectionError(500, str(e))

    async def accept(self):
        if self.mode != ConnectionMode.SERVER:
            raise ConnectionError(500, "accept() only valid for server mode")
        if self.state != ConnectionState.AUTHENTICATING:
            raise ConnectionError(500, f"Invalid state: {_state_name(self.state)}")

        try:
            self._challenge = os.urandom(CHALLENGE_SIZE)
            await self._send_challenge()

            handshake = await asyncio.wait_for(
                self._recv_frame(),
                timeout=self._timeout_seconds
            )

            if not await self._verify_handshake(handshake):
                await self._send_error(401, "Invalid signature")
                raise ConnectionError(401, "Invalid signature")

            self.session = self._create_session(self._identity.private_key, self.peer_public_key)

            users = self._ume.get_all_by_publickey(self.peer_public_key)

            if len(users) > 0:
                if len(users) == 1:
                    self.user = users[0]
                    self.username = users[0].username
                else:
                    selected = await self._handle_user_selection(users)
                    if selected is None:
                        await self._send_error_encrypted(400, "Invalid username selection")
                        raise ConnectionError(400, "Invalid username selection")
                    self.user = selected
                    self.username = selected.username

            self.state = ConnectionState.READY

        except asyncio.TimeoutError:
            self.state = ConnectionState.CLOSED
            raise ConnectionError(503, "Authentication timeout")
        except ConnectionError:
            self.state = ConnectionState.CLOSED
            raise
        except Exception as e:
            self.state = ConnectionState.CLOSED
            raise ConnectionError(500, str(e))

    async def send_request(self, bytes cmd, bytes payload):
        if not self.is_ready:
            raise ConnectionError(500, f"Invalid state: {_state_name(self.state)}")
        if self.session is None:
            raise ConnectionError(500, "No active session")

        data = cmd + payload
        encrypted = self.session.encrypt(data)
        await self._send_frame(encrypted)

    async def recv_request(self) -> bytes:
        cdef int max_size = 0
        
        if not self.is_ready:
            raise ConnectionError(500, f"Invalid state: {_state_name(self.state)}")
        if self.session is None:
            raise ConnectionError(500, "No active session")

        encrypted = await asyncio.wait_for(
            self._recv_frame(),
            timeout=self._timeout_seconds
        )
        
        plaintext = self.session.decrypt(encrypted)
        
        if self._config is not None:
            try:
                max_size = self._config.max_request_size
            except AttributeError:
                max_size = 0
        
        if max_size > 0 and len(plaintext) > max_size:
            raise ConnectionError(413, f"Request too large (max {max_size} bytes)")
        
        return plaintext

    async def send_response(self, bytes data):
        if not self.is_ready:
            raise ConnectionError(500, f"Invalid state: {_state_name(self.state)}")
        if self.session is None:
            raise ConnectionError(500, "No active session")

        encrypted = self.session.encrypt(data)
        await self._send_frame(encrypted)

    async def recv_response(self) -> bytes:
        if not self.is_ready:
            raise ConnectionError(500, f"Invalid state: {_state_name(self.state)}")
        if self.session is None:
            raise ConnectionError(500, "No active session")

        encrypted = await asyncio.wait_for(
            self._recv_frame(),
            timeout=self._timeout_seconds
        )
        return self.session.decrypt(encrypted)

    async def close(self):
        if self.state == ConnectionState.CLOSED:
            return

        if self.websocket is not None:
            try:
                await self.websocket.close()
            except Exception:
                pass

        self.state = ConnectionState.CLOSED
        self.websocket = None
        self.session = None

    async def _send_frame(self, bytes data):
        if self.websocket is None:
            raise ConnectionError(500, "No websocket connection")
        await self.websocket.send(struct.pack('>I', len(data)) + data)

    async def _recv_frame(self) -> bytes:
        if self.websocket is None:
            raise ConnectionError(500, "No websocket connection")

        data = await self.websocket.recv()
        if isinstance(data, bytes):
            length = struct.unpack('>I', data[:4])[0]
            return data[4:4+length]
        raise ConnectionError(400, "Expected binary frame")

    async def _send_challenge(self):
        await self._send_frame(self._identity.public_key + self._challenge)

    async def _send_handshake(self, bytes challenge):
        signature = self._identity.sign(challenge)
        handshake = self._identity.public_key + signature
        await self._send_frame(handshake)

    async def _verify_handshake(self, bytes handshake) -> bool:
        if len(handshake) < 96:
            return False

        client_pubkey = handshake[:32]
        signature = handshake[32:96]

        from core.crypto import Identity

        if not Identity.verify(client_pubkey, self._challenge, signature):
            return False

        self.peer_public_key = client_pubkey
        return True

    async def _send_error(self, int code, str message):
        msg_bytes = message.encode('utf-8')
        payload = struct.pack('>BHB', 0x01, code, len(msg_bytes)) + msg_bytes
        await self._send_frame(payload)

    async def _send_error_encrypted(self, int code, str message):
        msg_bytes = message.encode('utf-8')
        payload = struct.pack('>BHB', 0x01, code, len(msg_bytes)) + msg_bytes
        encrypted = self.session.encrypt(payload)
        await self._send_frame(encrypted)

    def _create_session(self, bytes our_privkey, bytes their_pubkey):
        from core.crypto import EncryptedSession
        return EncryptedSession(our_privkey, their_pubkey)

    async def _handle_user_selection(self, list users) -> Optional[object]:
        username_list = ','.join(u.username for u in users)
        encrypted = self.session.encrypt(username_list.encode('utf-8'))
        await self._send_frame(encrypted)

        encrypted_response = await self._recv_frame()
        selected = self.session.decrypt(encrypted_response).decode('utf-8')

        for user in users:
            if user.username == selected:
                return user
        return None
