# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False

import struct
import os
import asyncio
import time
import re
from enum import IntEnum
from typing import Optional, Callable, List, Any
from libc.stdint cimport uint64_t, int64_t

import nacl.exceptions
import websockets.client

READ_ONLY_COMMANDS = {0x02, 0x03, 0x11, 0x13, 0x14, 0x19, 0x30}

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
    cdef object _config
    cdef object _server_identity
    
    def __init__(self, object ume, object ame, object config, object server_identity):
        self._ume = ume
        self._ame = ame
        self._config = config
        self._server_identity = server_identity
    
    def handle(self, bytes request, object conn) -> bytes:
        if len(request) == 0:
            return self._build_error(400, "Empty request")
        
        cmd = request[0]
        data = request[1:]
        
        if conn.is_anonymous and cmd != 0x01:
            if not (self._config.anonymous_read and cmd in READ_ONLY_COMMANDS):
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
        cdef object board, result
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

            board = self._ame.get_board(board_name)
            if board is None:
                return self._build_error(404, f"Board '{board_name}' not found")

            result = board.query(orderby="last_bumped DESC", limit=limit, include_content=False)
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

            sig_len = data[idx]
            idx += 1
            signature_hex = data[idx:idx+sig_len].decode('utf-8')

            board = self._ame.get_board(board_name)
            if board is None:
                return self._build_error(404, f"Board '{board_name}' not found")

            if board.is_closed():
                return self._build_error(409, "Board is closed")

            result = board.get_post(post_num)
            post = result.result()

            if post is None:
                return self._build_error(404, f"Post {post_num} not found")

            if not conn.can_edit_post(post.author):
                return self._build_error(403, "Only the author can sign this post")

            author_user = self._ume.get(username=post.author)
            if author_user is None:
                return self._build_error(404, f"Author user not found")

            author_bytes = post.author.encode('utf-8')
            author_registrar_bytes = (post.author_registrar or "").encode('utf-8')
            tags_bytes = (post.tags or "").encode('utf-8')
            subject_bytes = (post.subject or "").encode('utf-8')
            options_bytes = (post.options or "").encode('utf-8')
            content_bytes = (post.content or "").encode('utf-8')

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

            try:
                signature_bytes = bytes.fromhex(signature_hex)
            except ValueError:
                return self._build_error(400, "Invalid signature format (expected hex)")

            if len(signature_bytes) != 64:
                return self._build_error(400, f"Invalid signature length: {len(signature_bytes)} (expected 64)")

            from crypto import Identity
            if not Identity.verify(author_user.publickey, signed_payload, signature_bytes):
                return self._build_error(400, "Signature verification failed")

            result = board.update_post(post_num, {'signature': signature_hex})
            result.result()

            return struct.pack('>B', 0x00)

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_get_pubkey(self, bytes data, object conn):
        return struct.pack('>B', 0x00) + self._server_identity.public_key