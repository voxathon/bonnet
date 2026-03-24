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

_log_file = None

cdef void _log_msg(str msg):
    global _log_file
    if _log_file is None:
        try:
            _log_file = open('bonnet.log', 'a')
        except:
            return
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    _log_file.write(f"[{ts}] {msg}\n")
    _log_file.flush()

cdef void _log_hex(str label, bytes data):
    global _log_file
    if _log_file is None:
        try:
            _log_file = open('bonnet.log', 'a')
        except:
            return
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    _log_file.write(f"[{ts}] {label} ({len(data)} bytes):\n")
    hex_str = data.hex()
    for i in range(0, len(hex_str), 64):
        _log_file.write(f"  {hex_str[i:i+64]}\n")
    _log_file.flush()

cdef void _log_dict(str label, dict d):
    global _log_file
    if _log_file is None:
        try:
            _log_file = open('bonnet.log', 'a')
        except:
            return
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    _log_file.write(f"[{ts}] {label}:\n")
    for k, v in d.items():
        if isinstance(v, str) and len(v) > 100:
            _log_file.write(f"  {k}: {v[:100]}... ({len(v)} chars)\n")
        else:
            _log_file.write(f"  {k}: {v}\n")
    _log_file.flush()

READ_ONLY_COMMANDS = {0x02, 0x03, 0x11, 0x13, 0x14, 0x19, 0x30, 0x41, 0x42, 0x43, 0x51, 0x52, 0x61, 0x62, 0x63}

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
    
    @staticmethod
    def client(object identity, int timeout_seconds=30):
        cdef Connection conn = Connection()
        conn.mode = ConnectionMode.CLIENT
        conn._identity = identity
        conn._timeout_seconds = timeout_seconds
        return conn
    
    @staticmethod
    def server(object identity, object websocket, object ume, object config, 
               object ame=None, object user_callback=None, int timeout_seconds=30):
        cdef Connection conn = Connection()
        conn.mode = ConnectionMode.SERVER
        conn._identity = identity
        conn.websocket = websocket
        conn._ume = ume
        conn._ame = ame
        conn._config = config
        conn._user_callback = user_callback
        conn._timeout_seconds = timeout_seconds
        conn.state = ConnectionState.AUTHENTICATING
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
        return self.user is not None and self.user.username == author
    
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
            
            challenge = await self._recv_frame()
            if len(challenge) != CHALLENGE_SIZE:
                raise ConnectionError(400, "Invalid challenge size")
            
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
        if not self.is_ready:
            raise ConnectionError(500, f"Invalid state: {_state_name(self.state)}")
        if self.session is None:
            raise ConnectionError(500, "No active session")
        
        encrypted = await asyncio.wait_for(
            self._recv_frame(),
            timeout=self._timeout_seconds
        )
        return self.session.decrypt(encrypted)
    
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
        await self._send_frame(self._challenge)
    
    async def _send_handshake(self, bytes challenge):
        signature = self._identity.sign(challenge)
        self.peer_public_key = self._identity.public_key
        handshake = self._identity.public_key + signature
        await self._send_frame(handshake)
    
    async def _verify_handshake(self, bytes handshake) -> bool:
        if len(handshake) < 96:
            return False
        
        client_pubkey = handshake[:32]
        signature = handshake[32:96]
        
        from crypto import Identity
        
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
        from crypto import EncryptedSession
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


cdef class CommandHandler:
    cdef object _ume
    cdef object _ame
    cdef object _keibatsu
    cdef object _config
    cdef object _server_identity
    cdef object _sync_mgr
    
    def __init__(self, object ume, object ame, object keibatsu, object config, object server_identity):
        self._ume = ume
        self._ame = ame
        self._keibatsu = keibatsu
        self._config = config
        self._server_identity = server_identity
        self._sync_mgr = SyncManager(ume, ame, config, server_identity)
    
    def handle(self, bytes request, object conn) -> bytes:
        if len(request) == 0:
            return self._build_error(400, "Empty request")
        
        cmd = request[0]
        data = request[1:]
        
        cmd_names = {
            0x01: 'REGISTER', 0x02: 'GET_USER', 0x03: 'LIST_USERS',
            0x10: 'BOARD_CREATE', 0x11: 'BOARD_LIST', 0x12: 'POST_CREATE',
            0x13: 'POST_GET', 0x14: 'POST_LIST', 0x15: 'POST_UPDATE',
            0x16: 'POST_DELETE', 0x17: 'BOARD_CLOSE', 0x18: 'BOARD_DELETE',
            0x19: 'QUERY_POSTS', 0x20: 'USER_PROMOTE', 0x21: 'USER_DEMOTE',
            0x22: 'POST_SIGN', 0x30: 'GET_PUBKEY',
            0x40: 'RULE_CREATE', 0x41: 'RULE_GET', 0x42: 'RULE_GET_BY_NAME',
            0x43: 'RULE_LIST', 0x44: 'RULE_UPDATE',
            0x50: 'REPORT_CREATE', 0x51: 'REPORT_GET', 0x52: 'REPORT_LIST_BY_CULPRIT',
            0x53: 'REPORT_SIGN',
            0x60: 'PUNISHMENT_CREATE', 0x61: 'PUNISHMENT_GET',
            0x62: 'PUNISHMENT_LIST_ACTIVE', 0x63: 'IS_BANNED'
        }
        cmd_name = cmd_names.get(cmd, f'UNKNOWN_{cmd:02x}')
        
        username = conn.user.username if hasattr(conn, 'user') and conn.user else 'anonymous'
        _log_msg(f"HANDLE: cmd=0x{cmd:02x} ({cmd_name}), user={username}")
        _log_hex(f"HANDLE: request", request)
        
        if conn.is_anonymous and cmd != 0x01:
            if not (self._config.anonymous_read and cmd in READ_ONLY_COMMANDS):
                _log_msg(f"HANDLE: rejected - anonymous user cannot run cmd=0x{cmd:02x}")
                return self._build_error(401, "Anonymous users must register first")
        
        if cmd == 0x01:
            return self._cmd_register(data, conn)
        elif cmd == 0x02:
            return self._cmd_get(data, conn)
        elif cmd == 0x03:
            return self._cmd_list(data, conn)
        elif cmd == 0x10:
            return self._cmd_board_create(data, conn)
        elif cmd == 0x11:
            return self._cmd_board_list(data, conn)
        elif cmd == 0x12:
            return self._cmd_post_create(data, conn)
        elif cmd == 0x13:
            return self._cmd_post_get(data, conn)
        elif cmd == 0x14:
            return self._cmd_post_list(data, conn)
        elif cmd == 0x15:
            return self._cmd_post_update(data, conn)
        elif cmd == 0x16:
            return self._cmd_post_delete(data, conn)
        elif cmd == 0x17:
            return self._cmd_board_close(data, conn)
        elif cmd == 0x18:
            return self._cmd_board_delete(data, conn)
        elif cmd == 0x19:
            return self._cmd_post_query(data, conn)
        elif cmd == 0x20:
            return self._cmd_user_promote(data, conn)
        elif cmd == 0x21:
            return self._cmd_user_demote(data, conn)
        elif cmd == 0x22:
            return self._cmd_post_sign(data, conn)
        elif cmd == 0x30:
            return self._cmd_get_pubkey(data, conn)
        elif cmd == 0x40:
            return self._cmd_rule_create(data, conn)
        elif cmd == 0x41:
            return self._cmd_rule_get(data, conn)
        elif cmd == 0x42:
            return self._cmd_rule_get_by_name(data, conn)
        elif cmd == 0x43:
            return self._cmd_rule_list(data, conn)
        elif cmd == 0x44:
            return self._cmd_rule_update(data, conn)
        elif cmd == 0x50:
            return self._cmd_report_create(data, conn)
        elif cmd == 0x51:
            return self._cmd_report_get(data, conn)
        elif cmd == 0x52:
            return self._cmd_report_list_by_culprit(data, conn)
        elif cmd == 0x53:
            return self._cmd_report_sign(data, conn)
        elif cmd == 0x60:
            return self._cmd_punishment_create(data, conn)
        elif cmd == 0x61:
            return self._cmd_punishment_get(data, conn)
        elif cmd == 0x62:
            return self._cmd_punishment_list_active(data, conn)
        elif cmd == 0x63:
            return self._cmd_is_banned(data, conn)
        else:
            return self._build_error(400, f"Unknown command {cmd}")
    
    cdef bytes _build_error(self, int code, str message):
        msg_bytes = message.encode('utf-8')
        return struct.pack('>BHB', 0x01, code, len(msg_bytes)) + msg_bytes
    
    cdef bytes _cmd_register(self, bytes data, object conn):
        cdef int idx = 0
        cdef int u_len, r_len
        cdef str username, registrar

        try:
            u_len = data[idx]
            idx += 1
            username = data[idx:idx+u_len].decode('utf-8')
            idx += u_len
            
            if u_len > 255:
                return self._build_error(400, "Username too long (max 255 chars)")
            
            if u_len == 0:
                return self._build_error(400, "Username cannot be empty")

            r_len = data[idx]
            idx += 1
            registrar = data[idx:idx+r_len].decode('utf-8')
            idx += r_len
            
            if r_len == 0:
                return self._build_error(400, "Registrar cannot be empty")

            invalid_chars = re.compile(r'[@<>:"/\\|?*]')
            if invalid_chars.search(username):
                return self._build_error(400, "Username contains invalid characters")

            if not self._config.registrar_valid(registrar):
                return self._build_error(403, f"Unknown registrar: {registrar}")
            
            existing_user = self._ume.get(username=username)
            if existing_user is not None:
                return self._build_error(409, f"Username '{username}' already exists")

            new_user = self._ume.put(username, registrar, conn.peer_public_key, record_origin=self._config.origin, relay=self._config.origin, password=None)

            u_bytes = new_user.username.encode('utf-8')
            return struct.pack('>B', 0x00) + u_bytes

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_get(self, bytes data, object conn):
        cdef int u_len
        cdef str username
        cdef object user

        try:
            u_len = data[0]
            username = data[1:1+u_len].decode('utf-8')

            user = self._ume.get(username=username)
            if user is None:
                return self._build_error(404, f"User {username} not found")

            r_bytes = user.registrar.encode('utf-8')
            return struct.pack('>B', 0x00) + user.publickey + struct.pack('>B', len(r_bytes)) + r_bytes

        except Exception as e:
            return self._build_error(400, str(e))
    
    cdef bytes _cmd_list(self, bytes data, object conn):
        cdef int offset, limit
        cdef list users
        cdef object user
        cdef bytes payload

        try:
            if len(data) >= 8:
                offset, limit = struct.unpack('>II', data[:8])
            else:
                offset = 0
                limit = 100

            users = self._ume.list_all()
            page = users[offset:offset+limit]

            payload = struct.pack('>B', 0x00) + struct.pack('>H', len(page))
            for user in page:
                username_bytes = user.username.encode('utf-8')
                registrar_bytes = user.registrar.encode('utf-8')
                origin_bytes = user.record_origin.encode('utf-8')
                relay_bytes = user.relay.encode('utf-8')
                payload += struct.pack('>B', len(username_bytes)) + username_bytes
                payload += struct.pack('>B', len(registrar_bytes)) + registrar_bytes
                payload += struct.pack('>B', len(origin_bytes)) + origin_bytes
                payload += struct.pack('>B', len(relay_bytes)) + relay_bytes
                payload += struct.pack('>B', 32) + user.publickey

            return payload

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_board_create(self, bytes data, object conn):
        cdef int b_len
        cdef str board_name
        cdef object board

        if not conn.can_create_board():
            return self._build_error(403, "Administrator permission required")

        try:
            b_len = data[0]
            board_name = data[1:1+b_len].decode('utf-8')

            if b_len == 0:
                return self._build_error(400, "Board name cannot be empty")

            if self._ame.get_board(board_name) is not None:
                return self._build_error(409, f"Board '{board_name}' already exists")

            board = self._ame.create_board(board_name)
            b_bytes = board_name.encode('utf-8')
            return struct.pack('>B', 0x00) + b_bytes

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_board_list(self, bytes data, object conn):
        cdef list boards, nav_entries
        cdef str name, origin
        cdef bint closed
        cdef bytes signature
        cdef dict nav_entry
        cdef bytes payload

        if not conn.is_registered():
            return self._build_error(401, "Authentication required")

        try:
            boards = self._ame.list_boards()
            nav_entries = self._ame.get_nav().list_all()
            
            nav_map = {e['board_name']: e for e in nav_entries}
            
            payload = struct.pack('>B', 0x00) + struct.pack('>H', len(boards))
            
            for name, closed in boards:
                nav_entry = nav_map.get(name)
                if nav_entry:
                    origin = nav_entry['origin']
                    signature = nav_entry['signature']
                else:
                    origin = self._config.origin
                    signature = b'\x00' * 64
                
                name_bytes = name.encode('utf-8')
                origin_bytes = origin.encode('utf-8')
                
                payload += struct.pack('>B', len(name_bytes)) + name_bytes
                payload += struct.pack('>B', len(origin_bytes)) + origin_bytes
                payload += struct.pack('>B', len(signature)) + signature
                payload += struct.pack('>B', 1 if closed else 0)
            
            return payload
        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_post_create(self, bytes data, object conn):
        cdef int b_len, s_len, t_len, o_len, c_len
        cdef uint64_t root
        cdef str board_name, subject, tags, options, content
        cdef object board, post, result
        cdef list tags_list

        if not conn.is_registered():
            return self._build_error(401, "Authentication required")

        try:
            idx = 0
            b_len = data[idx]
            idx += 1
            board_name = data[idx:idx+b_len].decode('utf-8')
            idx += b_len

            root = struct.unpack('>Q', data[idx:idx+8])[0]
            idx += 8

            s_len = data[idx]
            idx += 1
            subject = data[idx:idx+s_len].decode('utf-8')
            idx += s_len

            t_len = data[idx]
            idx += 1
            tags = data[idx:idx+t_len].decode('utf-8') if t_len > 0 else ""
            idx += t_len

            o_len = data[idx]
            idx += 1
            options = data[idx:idx+o_len].decode('utf-8') if o_len > 0 else ""
            idx += o_len

            c_len = struct.unpack('>I', data[idx:idx+4])[0]
            idx += 4
            content = data[idx:idx+c_len].decode('utf-8')

            if t_len > 0:
                tags_list = [t.strip() for t in tags.split(',') if t.strip()]
                if len(tags_list) > 255:
                    return self._build_error(400, "Too many tags (max 255)")
                for tag in tags_list:
                    if len(tag) > 255:
                        return self._build_error(400, f"Tag too long: {tag[:50]}...")
                tags = ','.join(tags_list)

            board = self._ame.get_board(board_name)
            if board is None:
                return self._build_error(404, f"Board '{board_name}' not found")

            result = board.create_post(
                subject=subject,
                tags=tags,
                options=options,
                content=content,
                root=root,
                author=conn.user.username,
                author_registrar=conn.user.registrar
            )
            post = result.result()

            author_bytes = post.author.encode('utf-8')
            author_registrar_bytes = (post.author_registrar or "").encode('utf-8')
            tags_bytes = (post.tags or "").encode('utf-8')
            subject_bytes = (post.subject or "").encode('utf-8')
            options_bytes = (post.options or "").encode('utf-8')

            return struct.pack('>B', 0x00) + \
                   struct.pack('>Q', post.post_num) + \
                   struct.pack('>q', post.creation_date) + \
                   struct.pack('>q', post.last_modified) + \
                   struct.pack('>B', len(author_bytes)) + author_bytes + \
                   struct.pack('>B', len(author_registrar_bytes)) + author_registrar_bytes + \
                   struct.pack('>B', len(tags_bytes)) + tags_bytes + \
                   struct.pack('>B', len(subject_bytes)) + subject_bytes + \
                   struct.pack('>B', len(options_bytes)) + options_bytes

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_post_get(self, bytes data, object conn):
        cdef int b_len
        cdef str board_name
        cdef uint64_t post_num
        cdef object board, result, post, nav_entry

        if not conn.is_registered():
            return self._build_error(401, "Authentication required")

        try:
            idx = 0
            b_len = data[idx]
            idx += 1
            board_name = data[idx:idx+b_len].decode('utf-8')
            idx += b_len

            post_num = struct.unpack('>Q', data[idx:idx+8])[0]

            nav_entry = self._ame.get_nav().get(board_name)
            if nav_entry is not None and nav_entry['origin'] != self._config.origin:
                asyncio.create_task(self._sync_mgr.sync_from_peer(nav_entry['relay']))
                origin_bytes = nav_entry['origin'].encode('utf-8')
                return struct.pack('>B', 0x02) + struct.pack('>B', len(origin_bytes)) + origin_bytes

            board = self._ame.get_board(board_name)
            if board is None:
                return self._build_error(404, f"Board '{board_name}' not found")

            result = board.get_post(post_num)
            post = result.result()

            if post is None:
                return self._build_error(404, f"Post {post_num} not found")

            closed_byte = 1 if post.closed else 0
            sticky_val = post.sticky if post.sticky else 0
            tags_bytes = (post.tags or "").encode('utf-8')
            subject_bytes = (post.subject or "").encode('utf-8')
            options_bytes = (post.options or "").encode('utf-8')
            author_bytes = (post.author or "").encode('utf-8')
            author_registrar_bytes = (post.author_registrar or "").encode('utf-8')
            signature_bytes = (post.signature or "").encode('utf-8')
            content_bytes = (post.content or "").encode('utf-8')

            return struct.pack('>B', 0x00) + \
                   struct.pack('>Q', post.post_num) + \
                   struct.pack('>q', post.last_modified) + \
                   struct.pack('>q', post.creation_date) + \
                   struct.pack('>q', post.last_bumped) + \
                   struct.pack('>B', closed_byte) + \
                   struct.pack('>i', sticky_val) + \
                   struct.pack('>B', len(tags_bytes)) + tags_bytes + \
                   struct.pack('>B', len(subject_bytes)) + subject_bytes + \
                   struct.pack('>B', len(options_bytes)) + options_bytes + \
                   struct.pack('>Q', post.root) + \
                   struct.pack('>B', len(author_bytes)) + author_bytes + \
                   struct.pack('>B', len(author_registrar_bytes)) + author_registrar_bytes + \
                   struct.pack('>B', len(signature_bytes)) + signature_bytes + \
                   struct.pack('>I', len(content_bytes)) + content_bytes

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_post_list(self, bytes data, object conn):
        cdef int b_len, offset, limit
        cdef str board_name
        cdef object board, result, nav_entry
        cdef list posts
        cdef object post
        cdef bytes payload

        if not conn.is_registered():
            return self._build_error(401, "Authentication required")

        try:
            idx = 0
            b_len = data[idx]
            idx += 1
            board_name = data[idx:idx+b_len].decode('utf-8')
            idx += b_len

            offset = struct.unpack('>I', data[idx:idx+4])[0]
            idx += 4
            limit = struct.unpack('>I', data[idx:idx+4])[0]

            nav_entry = self._ame.get_nav().get(board_name)
            if nav_entry is None:
                board = self._ame.get_board(board_name)
                if board is None:
                    return self._build_error(404, f"Board '{board_name}' not found")
            elif nav_entry['origin'] != self._config.origin:
                asyncio.create_task(self._sync_mgr.sync_from_peer(nav_entry['relay']))
                origin_bytes = nav_entry['origin'].encode('utf-8')
                return struct.pack('>B', 0x02) + struct.pack('>B', len(origin_bytes)) + origin_bytes

            board = self._ame.get_board(board_name)
            if board is None:
                return self._build_error(404, f"Board '{board_name}' not found")

            result = board.query(orderby="last_bumped DESC", limit=limit, offset=offset, include_content=False)
            posts = result.result()

            payload = struct.pack('>B', 0x00)
            for post in posts:
                subject_bytes = post.subject.encode('utf-8')
                author_bytes = post.author.encode('utf-8')
                payload += struct.pack('>Q', post.post_num)
                payload += struct.pack('>q', post.creation_date)
                payload += struct.pack('>B', len(subject_bytes)) + subject_bytes
                payload += struct.pack('>B', len(author_bytes)) + author_bytes
                payload += struct.pack('>Q', post.root)

            return payload

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_post_update(self, bytes data, object conn):
        cdef int b_len, field_count, field_type, field_len, i
        cdef str board_name
        cdef uint64_t post_num
        cdef object board, result, post
        cdef dict fields = {}
        cdef list mod_fields = []
        cdef bint is_mod
        cdef str tags_str
        cdef list tags_list
        cdef int sticky_val
        cdef int closed_val

        if not conn.is_registered():
            return self._build_error(401, "Authentication required")

        try:
            idx = 0
            b_len = data[idx]
            idx += 1
            board_name = data[idx:idx+b_len].decode('utf-8')
            idx += b_len

            post_num = struct.unpack('>Q', data[idx:idx+8])[0]
            idx += 8

            field_count = data[idx]
            idx += 1

            for i in range(field_count):
                field_type = data[idx]
                idx += 1

                if field_type == 0x01:
                    field_len = struct.unpack('>I', data[idx:idx+4])[0]
                    idx += 4
                    fields['content'] = data[idx:idx+field_len].decode('utf-8')
                    idx += field_len
                elif field_type == 0x02:
                    field_len = data[idx]
                    idx += 1
                    fields['subject'] = data[idx:idx+field_len].decode('utf-8')
                    idx += field_len
                elif field_type == 0x03:
                    field_len = data[idx]
                    idx += 1
                    fields['options'] = data[idx:idx+field_len].decode('utf-8')
                    idx += field_len
                elif field_type == 0x04:
                    field_len = data[idx]
                    idx += 1
                    tags_str = data[idx:idx+field_len].decode('utf-8')
                    idx += field_len
                    tags_list = [t.strip() for t in tags_str.split(',') if t.strip()]
                    if len(tags_list) > 255:
                        return self._build_error(400, "Too many tags (max 255)")
                    for tag in tags_list:
                        if len(tag) > 255:
                            return self._build_error(400, f"Tag too long: {tag[:50]}...")
                    fields['tags'] = ','.join(tags_list)
                elif field_type == 0x05:
                    sticky_val = struct.unpack('>i', data[idx:idx+4])[0]
                    idx += 4
                    fields['sticky'] = sticky_val
                    mod_fields.append('sticky')
                elif field_type == 0x06:
                    closed_val = data[idx]
                    idx += 1
                    fields['closed'] = bool(closed_val)
                    mod_fields.append('closed')
                else:
                    return self._build_error(400, f"Unknown field type: 0x{field_type:02x}")

            board = self._ame.get_board(board_name)
            if board is None:
                return self._build_error(404, f"Board '{board_name}' not found")

            result = board.get_post(post_num)
            post = result.result()

            if post is None:
                return self._build_error(404, f"Post {post_num} not found")

            is_mod = conn.is_moderator() or conn.is_administrator()

            for mf in mod_fields:
                if not is_mod:
                    return self._build_error(403, f"Field '{mf}' requires moderator permission")

            if not is_mod and not conn.can_edit_post(post.author):
                return self._build_error(403, "Can only edit your own posts")

            fields['last_modified'] = int(time.time())

            result = board.update_post(post_num, fields)
            result.result()

            return struct.pack('>B', 0x00)

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_post_delete(self, bytes data, object conn):
        cdef int b_len
        cdef str board_name
        cdef uint64_t post_num
        cdef object board, result, post

        if not conn.is_registered():
            return self._build_error(401, "Authentication required")

        try:
            idx = 0
            b_len = data[idx]
            idx += 1
            board_name = data[idx:idx+b_len].decode('utf-8')
            idx += b_len

            post_num = struct.unpack('>Q', data[idx:idx+8])[0]

            board = self._ame.get_board(board_name)
            if board is None:
                return self._build_error(404, f"Board '{board_name}' not found")

            result = board.get_post(post_num)
            post = result.result()

            if post is None:
                return self._build_error(404, f"Post {post_num} not found")

            if not conn.can_delete_post(post.author):
                return self._build_error(403, "Can only delete your own posts")

            result = board.delete_post(post_num)
            result.result()

            return struct.pack('>B', 0x00)

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_post_query(self, bytes data, object conn):
        cdef int b_len, where_len, orderby_len, value_count, value_type, value_len, i
        cdef int limit
        cdef str board_name, where_clause, orderby_clause
        cdef object board, result
        cdef list posts, values
        cdef object post
        cdef bytes payload

        if not conn.is_registered():
            return self._build_error(401, "Authentication required")

        try:
            idx = 0
            b_len = data[idx]
            idx += 1
            board_name = data[idx:idx+b_len].decode('utf-8')
            idx += b_len

            where_len = struct.unpack('>H', data[idx:idx+2])[0]
            idx += 2
            if where_len > 0:
                where_clause = data[idx:idx+where_len].decode('utf-8')
                idx += where_len
            else:
                where_clause = None

            value_count = data[idx]
            idx += 1

            values = []
            for i in range(value_count):
                value_type = data[idx]
                idx += 1

                if value_type == 0x01:
                    val = struct.unpack('>q', data[idx:idx+8])[0]
                    idx += 8
                    values.append(val)
                elif value_type == 0x02:
                    value_len = data[idx]
                    idx += 1
                    val = data[idx:idx+value_len].decode('utf-8')
                    idx += value_len
                    values.append(val)
                else:
                    return self._build_error(400, f"Unknown value type: 0x{value_type:02x}")

            orderby_len = struct.unpack('>H', data[idx:idx+2])[0]
            idx += 2
            if orderby_len > 0:
                orderby_clause = data[idx:idx+orderby_len].decode('utf-8')
                idx += orderby_len
            else:
                orderby_clause = "last_bumped DESC"

            limit = struct.unpack('>I', data[idx:idx+4])[0]

            board = self._ame.get_board(board_name)
            if board is None:
                return self._build_error(404, f"Board '{board_name}' not found")

            result = board.query(
                where=where_clause,
                values=values if values else None,
                orderby=orderby_clause,
                limit=limit if limit > 0 else None,
                include_content=False
            )
            posts = result.result()

            payload = struct.pack('>B', 0x00)
            for post in posts:
                tags_bytes = (post.tags or "").encode('utf-8')
                subject_bytes = (post.subject or "").encode('utf-8')
                options_bytes = (post.options or "").encode('utf-8')
                author_bytes = (post.author or "").encode('utf-8')
                author_registrar_bytes = (post.author_registrar or "").encode('utf-8')
                signature_bytes = (post.signature or "").encode('utf-8')

                payload += struct.pack('>Q', post.post_num)
                payload += struct.pack('>q', post.last_modified)
                payload += struct.pack('>q', post.creation_date)
                payload += struct.pack('>q', post.last_bumped)
                payload += struct.pack('>B', 1 if post.closed else 0)
                payload += struct.pack('>i', post.sticky if post.sticky else 0)
                payload += struct.pack('>B', len(tags_bytes)) + tags_bytes
                payload += struct.pack('>B', len(subject_bytes)) + subject_bytes
                payload += struct.pack('>B', len(options_bytes)) + options_bytes
                payload += struct.pack('>Q', post.root)
                payload += struct.pack('>B', len(author_bytes)) + author_bytes
                payload += struct.pack('>B', len(author_registrar_bytes)) + author_registrar_bytes
                payload += struct.pack('>B', len(signature_bytes)) + signature_bytes

            return payload

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_board_close(self, bytes data, object conn):
        cdef int b_len
        cdef str board_name
        cdef object board

        if not conn.can_create_board():
            return self._build_error(403, "Administrator permission required")

        try:
            b_len = data[0]
            board_name = data[1:1+b_len].decode('utf-8')

            if b_len == 0:
                return self._build_error(400, "Board name cannot be empty")

            board = self._ame.get_board(board_name)
            if board is None:
                return self._build_error(404, f"Board '{board_name}' not found")

            if board.is_closed():
                return struct.pack('>B', 0x00)

            self._ame.close_board(board_name)

            return struct.pack('>B', 0x00)

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_board_delete(self, bytes data, object conn):
        cdef int b_len
        cdef str board_name
        cdef object board

        if not conn.can_create_board():
            return self._build_error(403, "Administrator permission required")

        try:
            b_len = data[0]
            board_name = data[1:1+b_len].decode('utf-8')

            if b_len == 0:
                return self._build_error(400, "Board name cannot be empty")

            board = self._ame.get_board(board_name)
            if board is None:
                return self._build_error(404, f"Board '{board_name}' not found")

            self._ame.delete_board(board_name)

            return struct.pack('>B', 0x00)

        except RuntimeError as e:
            return self._build_error(409, str(e))
        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_user_promote(self, bytes data, object conn):
        cdef int u_len
        cdef str target_username
        cdef object target_user

        if not conn.can_promote_to_mod():
            return self._build_error(403, "Administrator permission required")

        try:
            u_len = data[0]
            target_username = data[1:1+u_len].decode('utf-8')

            target_user = self._ume.get(username=target_username)
            if target_user is None:
                return self._build_error(404, f"User '{target_username}' not found")

            if target_user.is_moderator:
                return struct.pack('>B', 0x00)

            self._ume.upd(username=target_username, new_moderator=True)

            return struct.pack('>B', 0x00)

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_user_demote(self, bytes data, object conn):
        cdef int u_len
        cdef str target_username
        cdef object target_user

        if not conn.can_demote_mod():
            return self._build_error(403, "Administrator permission required")

        try:
            u_len = data[0]
            target_username = data[1:1+u_len].decode('utf-8')

            target_user = self._ume.get(username=target_username)
            if target_user is None:
                return self._build_error(404, f"User '{target_username}' not found")

            if not target_user.is_moderator:
                return struct.pack('>B', 0x00)

            self._ume.upd(username=target_username, new_moderator=False)

            return struct.pack('>B', 0x00)

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_post_sign(self, bytes data, object conn):
        cdef int b_len, sig_len
        cdef str board_name, signature_hex
        cdef uint64_t post_num
        cdef object board, result, post, author_user
        cdef bytes signed_payload, signature_bytes

        _log_msg("POST_SIGN: starting")
        _log_hex("POST_SIGN: request data", data)

        if not conn.is_registered():
            _log_msg("POST_SIGN: rejected - not registered")
            return self._build_error(401, "Authentication required")

        try:
            idx = 0
            b_len = data[idx]
            idx += 1
            board_name = data[idx:idx+b_len].decode('utf-8')
            idx += b_len

            post_num = struct.unpack('>Q', data[idx:idx+8])[0]
            idx += 8

            sig_len = data[idx]
            idx += 1
            signature_hex = data[idx:idx+sig_len].decode('utf-8')
            
            _log_dict("POST_SIGN: parsed request", {
                'board': board_name,
                'post_num': post_num,
                'signature_hex': signature_hex[:32] + '...' if len(signature_hex) > 32 else signature_hex
            })
            _log_msg(f"POST_SIGN: conn.user={conn.user.username if conn.user else 'None'}")

            board = self._ame.get_board(board_name)
            if board is None:
                _log_msg(f"POST_SIGN: board '{board_name}' not found")
                return self._build_error(404, f"Board '{board_name}' not found")

            if board.is_closed():
                _log_msg(f"POST_SIGN: board '{board_name}' is closed")
                return self._build_error(409, "Board is closed")

            result = board.get_post(post_num)
            post = result.result()

            if post is None:
                _log_msg(f"POST_SIGN: post {post_num} not found")
                return self._build_error(404, f"Post {post_num} not found")

            _log_dict("POST_SIGN: post data", {
                'post_num': post.post_num,
                'author': post.author,
                'author_registrar': post.author_registrar,
                'creation_date': post.creation_date,
                'last_modified': post.last_modified,
                'subject': post.subject[:50] + '...' if len(post.subject) > 50 else post.subject,
                'tags': post.tags,
                'options': post.options,
                'content_len': len(post.content)
            })

            _log_msg(f"POST_SIGN: checking can_edit_post(conn.user.username='{conn.user.username}', post.author='{post.author}')")
            if not conn.can_edit_post(post.author):
                _log_msg(f"POST_SIGN: permission denied - conn.user='{conn.user.username}' != post.author='{post.author}'")
                return self._build_error(403, "Only the author can sign this post")
            
            _log_msg(f"POST_SIGN: permission check passed")

            author_user = self._ume.get(username=post.author)
            if author_user is None:
                _log_msg(f"POST_SIGN: author user '{post.author}' not found in ume")
                return self._build_error(404, f"Author user not found")
            
            _log_msg(f"POST_SIGN: author_user found, pubkey={author_user.publickey.hex()}")

            author_bytes = post.author.encode('utf-8')
            author_registrar_bytes = (post.author_registrar or "").encode('utf-8')
            tags_bytes = (post.tags or "").encode('utf-8')
            subject_bytes = (post.subject or "").encode('utf-8')
            options_bytes = (post.options or "").encode('utf-8')
            content_bytes = (post.content or "").encode('utf-8')

            _log_dict("POST_SIGN: payload field lengths", {
                'post_num': post.post_num,
                'creation_date': post.creation_date,
                'last_modified': post.last_modified,
                'author': len(author_bytes),
                'author_registrar': len(author_registrar_bytes),
                'tags': len(tags_bytes),
                'subject': len(subject_bytes),
                'options': len(options_bytes),
                'content': len(content_bytes)
            })

            signed_payload = \
                struct.pack('>Q', post.post_num) + \
                struct.pack('>q', post.creation_date) + \
                struct.pack('>q', post.last_modified) + \
                struct.pack('>B', len(author_bytes)) + author_bytes + \
                struct.pack('>B', len(author_registrar_bytes)) + author_registrar_bytes + \
                struct.pack('>B', len(tags_bytes)) + tags_bytes + \
                struct.pack('>B', len(subject_bytes)) + subject_bytes + \
                struct.pack('>B', len(options_bytes)) + options_bytes + \
                struct.pack('>I', len(content_bytes)) + content_bytes

            _log_hex("POST_SIGN: signed_payload (server)", signed_payload)

            try:
                signature_bytes = bytes.fromhex(signature_hex)
            except ValueError:
                _log_msg("POST_SIGN: invalid signature format (not hex)")
                return self._build_error(400, "Invalid signature format (expected hex)")

            if len(signature_bytes) != 64:
                _log_msg(f"POST_SIGN: invalid signature length={len(signature_bytes)} (expected 64)")
                return self._build_error(400, f"Invalid signature length: {len(signature_bytes)} (expected 64)")

            from crypto import Identity
            _log_msg(f"POST_SIGN: verifying signature with author_user.publickey={author_user.publickey.hex()}")
            verify_result = Identity.verify(author_user.publickey, signed_payload, signature_bytes)
            _log_msg(f"POST_SIGN: verification result={verify_result}")
            
            if not verify_result:
                _log_msg("POST_SIGN: signature verification FAILED")
                return self._build_error(400, "Signature verification failed")

            result = board.update_post(post_num, {'signature': signature_hex})
            result.result()

            _log_msg("POST_SIGN: success")
            return struct.pack('>B', 0x00)

        except Exception as e:
            _log_msg(f"POST_SIGN: exception: {e}")
            return self._build_error(400, str(e))

    cdef bytes _cmd_get_pubkey(self, bytes data, object conn):
        return struct.pack('>B', 0x00) + self._server_identity.public_key

    cdef bytes _cmd_rule_create(self, bytes data, object conn):
        cdef int name_len, desc_len
        cdef str rule_name, description
        cdef object result, rule

        if not conn.is_administrator():
            return self._build_error(403, "Administrator permission required")

        try:
            idx = 0
            name_len = data[idx]
            idx += 1
            rule_name = data[idx:idx+name_len].decode('utf-8')
            idx += name_len

            desc_len = data[idx]
            idx += 1
            description = data[idx:idx+desc_len].decode('utf-8')

            result = self._keibatsu.create_rule(rule_name, description)
            rule = result.result()

            name_bytes = rule.rule_name.encode('utf-8')
            desc_bytes = rule.description.encode('utf-8')

            return struct.pack('>B', 0x00) + \
                   struct.pack('>Q', rule.rule_num) + \
                   struct.pack('>B', len(name_bytes)) + name_bytes + \
                   struct.pack('>B', len(desc_bytes)) + desc_bytes

        except ValueError as e:
            return self._build_error(409, str(e))
        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_rule_get(self, bytes data, object conn):
        cdef uint64_t rule_num
        cdef object result, rule

        try:
            rule_num = struct.unpack('>Q', data[:8])[0]

            result = self._keibatsu.get_rule(rule_num)
            rule = result.result()

            if rule is None:
                return self._build_error(404, f"Rule {rule_num} not found")

            name_bytes = rule.rule_name.encode('utf-8')
            desc_bytes = rule.description.encode('utf-8')

            return struct.pack('>B', 0x00) + \
                   struct.pack('>Q', rule.rule_num) + \
                   struct.pack('>B', len(name_bytes)) + name_bytes + \
                   struct.pack('>B', len(desc_bytes)) + desc_bytes

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_rule_get_by_name(self, bytes data, object conn):
        cdef int name_len
        cdef str rule_name
        cdef object result, rule

        try:
            name_len = data[0]
            rule_name = data[1:1+name_len].decode('utf-8')

            result = self._keibatsu.get_rule_by_name(rule_name)
            rule = result.result()

            if rule is None:
                return self._build_error(404, f"Rule '{rule_name}' not found")

            name_bytes = rule.rule_name.encode('utf-8')
            desc_bytes = rule.description.encode('utf-8')

            return struct.pack('>B', 0x00) + \
                   struct.pack('>Q', rule.rule_num) + \
                   struct.pack('>B', len(name_bytes)) + name_bytes + \
                   struct.pack('>B', len(desc_bytes)) + desc_bytes

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_rule_list(self, bytes data, object conn):
        cdef object result
        cdef list rules
        cdef object rule
        cdef bytes payload

        try:
            result = self._keibatsu.list_rules()
            rules = result.result()

            payload = struct.pack('>B', 0x00) + struct.pack('>H', len(rules))
            for rule in rules:
                name_bytes = rule.rule_name.encode('utf-8')
                desc_bytes = rule.description.encode('utf-8')
                payload += struct.pack('>Q', rule.rule_num)
                payload += struct.pack('>B', len(name_bytes)) + name_bytes
                payload += struct.pack('>B', len(desc_bytes)) + desc_bytes

            return payload

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_rule_update(self, bytes data, object conn):
        cdef uint64_t rule_num
        cdef int field_count, field_type, field_len, i
        cdef str rule_name, description
        cdef object result, rule

        if not conn.is_administrator():
            return self._build_error(403, "Administrator permission required")

        try:
            idx = 0
            rule_num = struct.unpack('>Q', data[idx:idx+8])[0]
            idx += 8

            field_count = data[idx]
            idx += 1

            rule_name = None
            description = None

            for i in range(field_count):
                field_type = data[idx]
                idx += 1

                if field_type == 0x01:
                    field_len = data[idx]
                    idx += 1
                    rule_name = data[idx:idx+field_len].decode('utf-8')
                    idx += field_len
                elif field_type == 0x02:
                    field_len = data[idx]
                    idx += 1
                    description = data[idx:idx+field_len].decode('utf-8')
                    idx += field_len
                else:
                    return self._build_error(400, f"Unknown field type: 0x{field_type:02x}")

            result = self._keibatsu.update_rule(rule_num, rule_name, description)
            rule = result.result()

            name_bytes = rule.rule_name.encode('utf-8')
            desc_bytes = rule.description.encode('utf-8')

            return struct.pack('>B', 0x00) + \
                   struct.pack('>Q', rule.rule_num) + \
                   struct.pack('>B', len(name_bytes)) + name_bytes + \
                   struct.pack('>B', len(desc_bytes)) + desc_bytes

        except ValueError as e:
            return self._build_error(409, str(e))
        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_report_create(self, bytes data, object conn):
        cdef uint64_t rule_num, culprit_post_num
        cdef int culprit_len, reporter_len, desc_len, board_len, origin_len, relay_len
        cdef bytes culprit_pubkey, reporter_pubkey
        cdef str description, board, origin, relay
        cdef object result, report

        if not conn.is_registered():
            return self._build_error(401, "Authentication required")

        try:
            idx = 0
            rule_num = struct.unpack('>Q', data[idx:idx+8])[0]
            idx += 8

            culprit_len = data[idx]
            idx += 1
            culprit_pubkey = data[idx:idx+culprit_len]
            idx += culprit_len

            reporter_len = data[idx]
            idx += 1
            reporter_pubkey = data[idx:idx+reporter_len]
            idx += reporter_len

            desc_len = data[idx]
            idx += 1
            description = data[idx:idx+desc_len].decode('utf-8')
            idx += desc_len

            board_len = data[idx]
            idx += 1
            board = data[idx:idx+board_len].decode('utf-8') if board_len > 0 else None
            idx += board_len if board_len > 0 else 0

            culprit_post_num = struct.unpack('>Q', data[idx:idx+8])[0]
            idx += 8

            origin_len = data[idx]
            idx += 1
            origin = data[idx:idx+origin_len].decode('utf-8') if origin_len > 0 else None
            idx += origin_len if origin_len > 0 else 0

            relay_len = data[idx]
            idx += 1
            relay = data[idx:idx+relay_len].decode('utf-8') if relay_len > 0 else None

            result = self._keibatsu.create_report(
                rule_num, culprit_pubkey, reporter_pubkey, description,
                board, culprit_post_num, origin, relay
            )
            report = result.result()

            return self._encode_report(report)

        except ValueError as e:
            return self._build_error(404, str(e))
        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _encode_report(self, object report):
        cdef bytes culprit_bytes = report.culprit_pubkey
        cdef bytes board_bytes = (report.culprit_board or "").encode('utf-8')
        cdef bytes reporter_bytes = report.reporter_pubkey
        cdef bytes origin_bytes = report.origin.encode('utf-8')
        cdef bytes relay_bytes = report.relay.encode('utf-8')
        cdef bytes desc_bytes = report.description.encode('utf-8')
        cdef bytes origin_sig_bytes = (report.origin_sig or "").encode('utf-8')
        cdef bytes reporter_sig_bytes = (report.reporter_sig or "").encode('utf-8')

        return struct.pack('>B', 0x00) + \
               struct.pack('>Q', report.report_num) + \
               struct.pack('>Q', report.rule_num) + \
               struct.pack('>B', len(culprit_bytes)) + culprit_bytes + \
               struct.pack('>B', len(board_bytes)) + board_bytes + \
               struct.pack('>Q', report.culprit_post_num) + \
               struct.pack('>B', len(reporter_bytes)) + reporter_bytes + \
               struct.pack('>q', report.report_time) + \
               struct.pack('>B', len(origin_bytes)) + origin_bytes + \
               struct.pack('>B', len(relay_bytes)) + relay_bytes + \
               struct.pack('>B', len(desc_bytes)) + desc_bytes + \
               struct.pack('>B', len(origin_sig_bytes)) + origin_sig_bytes + \
               struct.pack('>B', len(reporter_sig_bytes)) + reporter_sig_bytes

    cdef bytes _cmd_report_get(self, bytes data, object conn):
        cdef uint64_t report_num
        cdef object result, report

        try:
            report_num = struct.unpack('>Q', data[:8])[0]

            result = self._keibatsu.get_report(report_num)
            report = result.result()

            if report is None:
                return self._build_error(404, f"Report {report_num} not found")

            return self._encode_report(report)

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_report_list_by_culprit(self, bytes data, object conn):
        cdef int pubkey_len
        cdef bytes pubkey
        cdef object result
        cdef list reports
        cdef bytes payload

        try:
            pubkey_len = data[0]
            pubkey = data[1:1+pubkey_len]

            result = self._keibatsu.list_reports_by_culprit(pubkey)
            reports = result.result()

            payload = struct.pack('>B', 0x00) + struct.pack('>H', len(reports))
            for report in reports:
                payload += self._encode_report_entry(report)

            return payload

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _encode_report_entry(self, object report):
        cdef bytes culprit_bytes = report.culprit_pubkey
        cdef bytes board_bytes = (report.culprit_board or "").encode('utf-8')
        cdef bytes reporter_bytes = report.reporter_pubkey
        cdef bytes origin_bytes = report.origin.encode('utf-8')
        cdef bytes relay_bytes = report.relay.encode('utf-8')
        cdef bytes desc_bytes = report.description.encode('utf-8')
        cdef bytes origin_sig_bytes = (report.origin_sig or "").encode('utf-8')
        cdef bytes reporter_sig_bytes = (report.reporter_sig or "").encode('utf-8')

        return struct.pack('>Q', report.report_num) + \
               struct.pack('>Q', report.rule_num) + \
               struct.pack('>B', len(culprit_bytes)) + culprit_bytes + \
               struct.pack('>B', len(board_bytes)) + board_bytes + \
               struct.pack('>Q', report.culprit_post_num) + \
               struct.pack('>B', len(reporter_bytes)) + reporter_bytes + \
               struct.pack('>q', report.report_time) + \
               struct.pack('>B', len(origin_bytes)) + origin_bytes + \
               struct.pack('>B', len(relay_bytes)) + relay_bytes + \
               struct.pack('>B', len(desc_bytes)) + desc_bytes + \
               struct.pack('>B', len(origin_sig_bytes)) + origin_sig_bytes + \
               struct.pack('>B', len(reporter_sig_bytes)) + reporter_sig_bytes

    cdef bytes _cmd_report_sign(self, bytes data, object conn):
        cdef uint64_t report_num
        cdef int sig_len
        cdef str signature_hex
        cdef bytes signature_bytes
        cdef object result, report

        if not conn.is_registered():
            return self._build_error(401, "Authentication required")

        try:
            idx = 0
            report_num = struct.unpack('>Q', data[idx:idx+8])[0]
            idx += 8

            sig_len = data[idx]
            idx += 1
            signature_hex = data[idx:idx+sig_len].decode('utf-8')

            result = self._keibatsu.get_report(report_num)
            report = result.result()

            if report is None:
                return self._build_error(404, f"Report {report_num} not found")

            if report.reporter_pubkey != conn.peer_public_key:
                return self._build_error(403, "Only the reporter can sign this report")

            try:
                signature_bytes = bytes.fromhex(signature_hex)
            except ValueError:
                return self._build_error(400, "Invalid signature format (expected hex)")

            if len(signature_bytes) != 64:
                return self._build_error(400, f"Invalid signature length: {len(signature_bytes)} (expected 64)")

            result = self._keibatsu.sign_report(report_num, signature_bytes)
            result.result()

            return struct.pack('>B', 0x00)

        except ValueError as e:
            return self._build_error(404, str(e))
        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_punishment_create(self, bytes data, object conn):
        cdef int pubkey_len, id_count, notes_len, i
        cdef bytes pubkey
        cdef list report_ids
        cdef uint64_t report_id
        cdef int64_t expires_at
        cdef str notes
        cdef object result, punishment

        if not conn.is_moderator() and not conn.is_administrator():
            return self._build_error(403, "Moderator permission required")

        try:
            idx = 0
            pubkey_len = data[idx]
            idx += 1
            pubkey = data[idx:idx+pubkey_len]
            idx += pubkey_len

            id_count = data[idx]
            idx += 1

            report_ids = []
            for i in range(id_count):
                report_id = struct.unpack('>Q', data[idx:idx+8])[0]
                idx += 8
                report_ids.append(report_id)

            expires_at = struct.unpack('>q', data[idx:idx+8])[0]
            idx += 8

            notes_len = data[idx]
            idx += 1
            notes = data[idx:idx+notes_len].decode('utf-8') if notes_len > 0 else ""

            result = self._keibatsu.create_punishment(pubkey, report_ids, expires_at, notes)
            punishment = result.result()

            return self._encode_punishment(punishment)

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _encode_punishment(self, object punishment):
        cdef bytes pubkey_bytes = punishment.punished_pubkey
        cdef bytes notes_bytes = (punishment.ban_notes or "").encode('utf-8')
        cdef bytes payload

        payload = struct.pack('>B', 0x00) + \
                  struct.pack('>B', len(pubkey_bytes)) + pubkey_bytes + \
                  struct.pack('>B', len(punishment.report_ids))

        for report_id in punishment.report_ids:
            payload += struct.pack('>Q', report_id)

        payload += struct.pack('>q', punishment.expires_at)
        payload += struct.pack('>B', len(notes_bytes)) + notes_bytes

        return payload

    cdef bytes _cmd_punishment_get(self, bytes data, object conn):
        cdef int pubkey_len
        cdef bytes pubkey
        cdef object result, punishment

        try:
            pubkey_len = data[0]
            pubkey = data[1:1+pubkey_len]

            result = self._keibatsu.get_punishment(pubkey)
            punishment = result.result()

            if punishment is None:
                return self._build_error(404, "No punishment found for pubkey")

            return self._encode_punishment(punishment)

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_punishment_list_active(self, bytes data, object conn):
        cdef object result
        cdef list punishments
        cdef bytes payload

        try:
            result = self._keibatsu.list_active_punishments()
            punishments = result.result()

            payload = struct.pack('>B', 0x00) + struct.pack('>H', len(punishments))
            for punishment in punishments:
                payload += self._encode_punishment(punishment)

            return payload

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_is_banned(self, bytes data, object conn):
        cdef int pubkey_len
        cdef bytes pubkey
        cdef object result
        cdef tuple banned_result
        cdef bint banned
        cdef str reason
        cdef bytes reason_bytes

        try:
            pubkey_len = data[0]
            pubkey = data[1:1+pubkey_len]

            result = self._keibatsu.is_banned(pubkey)
            banned_result = result.result()

            banned = banned_result[0]
            reason = banned_result[1] or "No reason given"
            reason_bytes = reason.encode('utf-8')

            return struct.pack('>B', 0x00) + \
                   struct.pack('>B', 1 if banned else 0) + \
                   struct.pack('>B', len(reason_bytes)) + reason_bytes

        except Exception as e:
            return self._build_error(400, str(e))


cdef class SyncManager:
    cdef object _ume
    cdef object _ame
    cdef object _config
    cdef object _server_identity
    cdef set _inflight_syncs
    
    def __init__(self, object ume, object ame, object config, object server_identity):
        self._ume = ume
        self._ame = ame
        self._config = config
        self._server_identity = server_identity
        self._inflight_syncs = set()
    
    async def sync_from_peer(self, str peer_hostname):
        if peer_hostname in self._inflight_syncs:
            _log_msg(f"SYNC: already syncing with {peer_hostname}, skipping")
            return
        self._inflight_syncs.add(peer_hostname)
        
        cdef Connection conn
        cdef bint connected = False
        
        try:
            conn = Connection.client(self._server_identity)
            try:
                await conn.connect(f"wss://{peer_hostname}:2272")
                connected = True
            except Exception as e:
                _log_msg(f"SYNC: port 2272 failed for {peer_hostname}: {e}, trying 272")
                await conn.close()
                conn = Connection.client(self._server_identity)
                try:
                    await conn.connect(f"wss://{peer_hostname}:272")
                    connected = True
                except Exception as e2:
                    _log_msg(f"SYNC: port 272 also failed for {peer_hostname}: {e2}")
                    await conn.close()
                    return
            
            await self._sync_boards(conn, peer_hostname)
            await self._sync_users(conn, peer_hostname)
            
        except Exception as e:
            _log_msg(f"SYNC: failed to sync with {peer_hostname}: {e}")
        finally:
            self._inflight_syncs.discard(peer_hostname)
            if conn is not None:
                await conn.close()
    
    async def _sync_boards(self, conn, str peer_hostname):
        await conn.send_request(bytes([0x11]), b'')
        response = await conn.recv_response()
        
        if len(response) == 0 or response[0] != 0x00:
            _log_msg(f"SYNC: BOARD_LIST failed for {peer_hostname}")
            return
        
        cdef int idx = 1
        cdef int count = struct.unpack('>H', response[idx:idx+2])[0]
        idx += 2
        
        if count == 0:
            _log_msg(f"SYNC: no boards from {peer_hostname}")
            return
        
        cdef object nav = self._ame.get_nav()
        cdef int n_len, o_len, s_len
        cdef str name, origin
        cdef bytes signature
        cdef int closed
        cdef list batch = []
        
        for _ in range(count):
            n_len = response[idx]
            idx += 1
            name = response[idx:idx+n_len].decode('utf-8')
            idx += n_len
            
            o_len = response[idx]
            idx += 1
            origin = response[idx:idx+o_len].decode('utf-8')
            idx += o_len
            
            s_len = response[idx]
            idx += 1
            signature = response[idx:idx+s_len]
            idx += s_len
            
            closed = response[idx]
            idx += 1
            
            batch.append((name, name, origin, signature, peer_hostname))
        
        if batch:
            nav.upsert_remote_batch(batch)
            _log_msg(f"SYNC: synced {len(batch)} boards from {peer_hostname}")
    
    async def _sync_users(self, conn, str peer_hostname):
        cdef int offset = 0
        cdef int limit = 100
        cdef int total = 0
        cdef bytes response
        cdef int idx, count, u_len, r_len, o_len, rel_len, pk_len
        cdef str username, registrar, record_origin, relay
        cdef bytes publickey
        cdef int result
        
        while True:
            await conn.send_request(bytes([0x03]), struct.pack('>II', offset, limit))
            response = await conn.recv_response()
            
            if len(response) == 0 or response[0] != 0x00:
                break
            
            idx = 1
            count = struct.unpack('>H', response[idx:idx+2])[0]
            idx += 2
            
            if count == 0:
                break
            
            for _ in range(count):
                u_len = response[idx]
                idx += 1
                username = response[idx:idx+u_len].decode('utf-8')
                idx += u_len
                
                r_len = response[idx]
                idx += 1
                registrar = response[idx:idx+r_len].decode('utf-8')
                idx += r_len
                
                o_len = response[idx]
                idx += 1
                record_origin = response[idx:idx+o_len].decode('utf-8')
                idx += o_len
                
                rel_len = response[idx]
                idx += 1
                relay = response[idx:idx+rel_len].decode('utf-8')
                idx += rel_len
                
                pk_len = response[idx]
                idx += 1
                publickey = response[idx:idx+pk_len]
                idx += pk_len
                
                result = self._ume.upsert_remote_user(username, registrar, publickey,
                                                        record_origin, peer_hostname)
                if result > 0:
                    total += 1
            
            offset += limit
        
        _log_msg(f"SYNC: synced {total} users from {peer_hostname}")