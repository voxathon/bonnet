# cython: language_level=3

import asyncio
import websockets
import os
import struct
import base64
import argparse
import time
from libc.stdint cimport uint64_t, int64_t

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) or '.')
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'build'))

from ume import Ume, User
from ame import Ame, Board, Post
from conman import Connection, ConnectionError
from crypto import Identity
from config import Config
from export import PublicUserServer
import nacl.exceptions

PORT_PRIVILEGED = 272
PORT_STANDARD = 2272

cdef class BonnetServer:
    cdef str userfile_path
    cdef object ume
    cdef object ame
    cdef object server_identity
    cdef object config
    cdef object http_server
    
    def __init__(self, str userfile_path, str identity_path, object config):
        self.userfile_path = userfile_path
        self.ume = Ume(userfile_path)
        self.ame = Ame(config.ame_path)
        self.config = config
        with open(identity_path, 'rb') as f:
            key_bytes = f.read()
        self.server_identity = Identity.from_private_key(key_bytes)
        self.http_server = None
    
    async def handle_connection(self, websocket):
        cdef object conn
        
        try:
            async with asyncio.timeout(self.config.timeout_seconds):
                conn = Connection.server(
                    self.server_identity, websocket,
                    self.ume, self.config
                )
                await conn.accept()
                await self._handle_request(conn)
                
        except asyncio.TimeoutError:
            pass
        except ConnectionError:
            pass
        except nacl.exceptions.CryptoError:
            pass
        except Exception:
            pass
    
    async def _handle_request(self, conn):
        plaintext = await conn.recv_request()
        
        cmd = plaintext[0] if len(plaintext) > 0 else -1
        
        if conn.is_anonymous and cmd != 0x01:
            await conn.send_response(self._build_error(401, "Anonymous users must register first"))
            await conn.close()
            return
        
        response = self._dispatch_command(plaintext, conn)
        await conn.send_response(response)
        
        await conn.close()

    cdef bytes _dispatch_command(self, bytes request, object conn):
        cdef int cmd
        if len(request) == 0:
            return self._build_error(400, "Empty request")

        cmd = request[0]
        data = request[1:]
        
        if cmd == 0x01:
            return self._cmd_register(data, conn)
        elif cmd == 0x02:
            return self._cmd_get(data)
        elif cmd == 0x03:
            return self._cmd_list(data)
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

            import re
            invalid_chars = re.compile(r'[@<>:"/\\|?*]')
            if invalid_chars.search(username):
                return self._build_error(400, "Username contains invalid characters")

            if not self.config.registrar_valid(registrar):
                return self._build_error(403, f"Unknown registrar: {registrar}")
            
            existing_user = self.ume.get(username=username)
            if existing_user is not None:
                return self._build_error(409, f"Username '{username}' already exists")

            new_user = self.ume.put(username, registrar, conn.peer_public_key, password=None)

            u_bytes = new_user.username.encode('utf-8')
            return struct.pack('>B', 0x00) + u_bytes

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_get(self, bytes data):
        cdef int u_len
        cdef str username
        cdef object user

        try:
            u_len = data[0]
            username = data[1:1+u_len].decode('utf-8')

            user = self.ume.get(username=username)
            if user is None:
                return self._build_error(404, f"User {username} not found")

            r_bytes = user.registrar.encode('utf-8')
            return struct.pack('>B', 0x00) + user.publickey + struct.pack('>B', len(r_bytes)) + r_bytes

        except Exception as e:
            return self._build_error(400, str(e))
    
    cdef bytes _cmd_list(self, bytes data):
        cdef int offset, limit
        cdef list users, lines
        cdef object user

        try:
            if len(data) >= 8:
                offset, limit = struct.unpack('>II', data[:8])
            else:
                offset = 0
                limit = 100

            users = self.ume.list_all()
            page = users[offset:offset+limit]

            u_list = ",".join(u.username for u in page).encode('utf-8')
            return struct.pack('>B', 0x00) + u_list

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

            if self.ame.get_board(board_name) is not None:
                return self._build_error(409, f"Board '{board_name}' already exists")

            board = self.ame.create_board(board_name)
            b_bytes = board_name.encode('utf-8')
            return struct.pack('>B', 0x00) + b_bytes

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_board_list(self, bytes data, object conn):
        cdef list boards
        cdef list parts
        cdef str name
        cdef bint closed

        if not conn.is_registered():
            return self._build_error(401, "Authentication required")

        try:
            boards = self.ame.list_boards()
            parts = []
            for name, closed in boards:
                if closed:
                    parts.append(f"closed:{name}")
                else:
                    parts.append(name)
            b_list = ",".join(parts).encode('utf-8')
            return struct.pack('>B', 0x00) + b_list
        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_post_create(self, bytes data, object conn):
        cdef int b_len, s_len, t_len, o_len, c_len, root
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

            board = self.ame.get_board(board_name)
            if board is None:
                return self._build_error(404, f"Board '{board_name}' not found")

            result = board.create_post(
                subject=subject,
                tags=tags,
                options=options,
                content=content,
                root=root,
                author=conn.user.username
            )
            post = result.result()

            post_num_bytes = struct.pack('>Q', post.post_num)
            creation_date_bytes = struct.pack('>q', post.creation_date)
            last_modified_bytes = struct.pack('>q', post.last_modified)
            author_bytes = post.author.encode('utf-8')
            tags_bytes = (post.tags or "").encode('utf-8')
            subject_bytes = (post.subject or "").encode('utf-8')
            options_bytes = (post.options or "").encode('utf-8')

            return struct.pack('>B', 0x00) + \
                   post_num_bytes + \
                   creation_date_bytes + \
                   last_modified_bytes + \
                   struct.pack('>B', len(author_bytes)) + author_bytes + \
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

            board = self.ame.get_board(board_name)
            if board is None:
                return self._build_error(404, f"Board '{board_name}' not found")

            result = board.get_post(post_num)
            post = result.result()

            if post is None:
                return self._build_error(404, f"Post {post_num} not found")

            last_modified_bytes = str(post.last_modified).encode('utf-8')
            creation_date_bytes = str(post.creation_date).encode('utf-8')
            last_bumped_bytes = str(post.last_bumped).encode('utf-8')
            closed_byte = 1 if post.closed else 0
            sticky_val = post.sticky if post.sticky else 0
            tags_bytes = (post.tags or "").encode('utf-8')
            subject_bytes = (post.subject or "").encode('utf-8')
            options_bytes = (post.options or "").encode('utf-8')
            author_bytes = (post.author or "").encode('utf-8')
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

            board = self.ame.get_board(board_name)
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

            board = self.ame.get_board(board_name)
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

            board = self.ame.get_board(board_name)
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

            board = self.ame.get_board(board_name)
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

            board = self.ame.get_board(board_name)
            if board is None:
                return self._build_error(404, f"Board '{board_name}' not found")

            if board.is_closed():
                return struct.pack('>B', 0x00)

            self.ame.close_board(board_name)

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

            board = self.ame.get_board(board_name)
            if board is None:
                return self._build_error(404, f"Board '{board_name}' not found")

            self.ame.delete_board(board_name)

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

            target_user = self.ume.get(username=target_username)
            if target_user is None:
                return self._build_error(404, f"User '{target_username}' not found")

            if target_user.is_moderator:
                return struct.pack('>B', 0x00)

            self.ume.upd(username=target_username, new_moderator=True)

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

            target_user = self.ume.get(username=target_username)
            if target_user is None:
                return self._build_error(404, f"User '{target_username}' not found")

            if not target_user.is_moderator:
                return struct.pack('>B', 0x00)

            self.ume.upd(username=target_username, new_moderator=False)

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

            board = self.ame.get_board(board_name)
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

            author_user = self.ume.get(username=post.author)
            if author_user is None:
                return self._build_error(404, f"Author user not found")

            author_bytes = post.author.encode('utf-8')
            tags_bytes = (post.tags or "").encode('utf-8')
            subject_bytes = (post.subject or "").encode('utf-8')
            options_bytes = (post.options or "").encode('utf-8')
            content_bytes = (post.content or "").encode('utf-8')

            signed_payload = \
                struct.pack('>Q', post.post_num) + \
                struct.pack('>q', post.creation_date) + \
                struct.pack('>q', post.last_modified) + \
                struct.pack('>B', len(author_bytes)) + author_bytes + \
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

def load_or_generate_identity(str path):
    if os.path.exists(path):
        return
    key = Identity.generate()
    with open(path, 'wb') as f:
        f.write(bytes(key.private_key))
    os.chmod(path, 0o600)

async def main_async():
    cdef str config_dir, default_userfile, default_identity
    cdef BonnetServer server
    
    config_dir = os.path.expanduser('~/.config/bonnet')
    default_userfile = os.path.join(config_dir, 'userfile')
    default_identity = os.path.join(config_dir, 'identity')
    default_config = os.path.join(config_dir, 'config.toml')
    
    parser = argparse.ArgumentParser(description='Bonnet Server')
    parser.add_argument('userfile', nargs='?', default=default_userfile)
    parser.add_argument('identity', nargs='?', default=default_identity)
    parser.add_argument('--config', default=default_config, help='Config file path')
    parser.add_argument('--port', type=int, default=PORT_STANDARD)
    parser.add_argument('--privileged', action='store_true')
    parser.add_argument('--cert', help='TLS certificate path')
    parser.add_argument('--key', help='TLS private key path')
    args = parser.parse_args()
    
    os.makedirs(config_dir, exist_ok=True)
    if not os.path.exists(args.userfile):
        open(args.userfile, 'a').close()
        os.chmod(args.userfile, 0o600)
    
    port = PORT_PRIVILEGED if args.privileged else args.port
    load_or_generate_identity(args.identity)
    
    config = Config.load(args.config)
    
    server = BonnetServer(args.userfile, args.identity, config)
    
    if config.http_enabled:
        server.http_server = PublicUserServer(config.http_port, server.ume, server.server_identity)
        server.http_server.start()
        print(f"HTTP export server listening on port {config.http_port}")
    
    ssl_context = None
    if args.cert and args.key:
        import ssl
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(args.cert, args.key)

    async with websockets.serve(
        server.handle_connection,
        '0.0.0.0',
        port,
        ssl=ssl_context
    ):
        print(f"Bonnet server listening on port {port}")
        print(f"Server public key: {server.server_identity.public_key.hex()}")
        await asyncio.Future()

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()