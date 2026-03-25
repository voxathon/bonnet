# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False

import struct
import asyncio
import time
from net.sync import SyncManager
from core.crypto import Identity
from engine.facade import BonnetEngine
from core.logging import log_msg, log_hex, log_dict

import re
from datetime import datetime
from libc.stdint cimport uint64_t, int64_t

READ_ONLY_COMMANDS = {0x02, 0x03, 0x11, 0x13, 0x14, 0x19, 0x30, 0x41, 0x42, 0x43, 0x51, 0x52, 0x54, 0x61, 0x62, 0x63}

_WHITELIST_PATTERN = re.compile(r'^[a-zA-Z0-9\-_]+$')
_BLACKLIST_PATTERN = re.compile(r'[@<>:"/\\|?*]')

cdef object _validate_name(str name, str field_name):
    cdef int length = len(name)
    if length == 0:
        return (False, f"{field_name} cannot be empty")
    if length > 255:
        return (False, f"{field_name} too long (max 255 bytes)")
    if not _WHITELIST_PATTERN.match(name):
        return (False, f"{field_name} contains invalid characters")
    if _BLACKLIST_PATTERN.search(name):
        return (False, f"{field_name} contains invalid characters")
    return (True, "")


cdef class CommandHandler:
    cdef object _ume
    cdef object _ame
    cdef object _keibatsu
    cdef object _config
    cdef object _server_identity
    cdef object _sync_mgr
    cdef dict _rate_limits
    cdef public object _engine
    
    def __init__(self, object engine):
        self._engine = engine
        self._ume = engine.ume
        self._ame = engine.ame
        self._keibatsu = engine.keibatsu
        self._config = engine.config
        self._server_identity = engine.server_identity
        self._sync_mgr = SyncManager(engine)
    
    def handle(self, bytes request, object conn) -> bytes:
        cdef double current_time = time.time()
        cdef double window = float(self._config.rate_limit_window)
        cdef int max_requests = self._config.rate_limit_requests
        cdef int max_size = self._config.max_request_size
        
        if max_size > 0 and len(request) > max_size:
            return self._build_error(413, f"Request too large (max {max_size} bytes)")
        
        if not hasattr(conn, '_request_timestamps'):
            conn._request_timestamps = []

        conn._request_timestamps = [ts for ts in conn._request_timestamps if current_time - ts < window]

        if len(conn._request_timestamps) >= max_requests:
            return self._build_error(429, "Too many requests. Please slow down.")

        conn._request_timestamps.append(current_time)

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
            0x53: 'REPORT_SIGN', 0x54: 'REPORT_LIST_SINCE',
            0x60: 'PUNISHMENT_CREATE', 0x61: 'PUNISHMENT_GET',
            0x62: 'PUNISHMENT_LIST_ACTIVE', 0x63: 'IS_BANNED'
        }
        cmd_name = cmd_names.get(cmd, f'UNKNOWN_{cmd:02x}')
        
        username = conn.user.username if hasattr(conn, 'user') and conn.user else 'anonymous'
        log_msg(f"HANDLE: cmd=0x{cmd:02x} ({cmd_name}), user={username}")
        log_hex(f"HANDLE: request", request)
        
        if conn.is_anonymous and cmd != 0x01:
            log_msg(f"HANDLE: rejected - anonymous user cannot run cmd=0x{cmd:02x}")
            return self._build_error(401, "Anonymous users must register first")
        
        if not conn.is_anonymous and conn.user.is_banned:
            if cmd not in READ_ONLY_COMMANDS:
                log_msg(f"HANDLE: rejected - banned user '{conn.user.username}' attempted cmd=0x{cmd:02x}")
                return self._build_error(403, "You are banned from performing this action")

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
        elif cmd == 0x54:
            return self._cmd_report_list_since(data, conn)
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
            
            r_len = data[idx]
            idx += 1
            registrar = data[idx:idx+r_len].decode('utf-8')
            idx += r_len
            
            if r_len == 0:
                return self._build_error(400, "Registrar cannot be empty")

            valid, err = _validate_name(username, "Username")
            if not valid:
                return self._build_error(400, err)

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

        if not conn.is_registered():
            return self._build_error(401, "Authentication required")

        if not conn.can_create_board() and not self._engine.check_permission("write", None, conn):
            return self._build_error(403, "Permission denied to create boards")

        try:
            b_len = data[0]
            board_name = data[1:1+b_len].decode('utf-8')

            valid, err = _validate_name(board_name, "Board name")
            if not valid:
                return self._build_error(400, err)

            if self._ame.get_board(board_name) is not None:
                return self._build_error(409, f"Board '{board_name}' already exists")

            board = self._ame.create_board(board_name, owner_pubkey=conn.peer_public_key)
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
        cdef list visible_boards

        if not conn.is_registered():
            return self._build_error(401, "Authentication required")

        try:
            boards = self._ame.list_boards()
            nav_entries = self._ame.get_nav().list_all()
            
            nav_map = {e['board_name']: e for e in nav_entries}
            
            visible_boards = []
            for name, closed in boards:
                if self._engine.check_permission("read", name, conn):
                    visible_boards.append((name, closed))
            
            payload = struct.pack('>B', 0x00) + struct.pack('>H', len(visible_boards))
            
            for name, closed in visible_boards:
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
        cdef object board, post, result, nav_entry
        cdef list tags_list
        cdef int idx

        if not conn.is_registered():
            return self._build_error(401, "Authentication required")

        try:
            idx = 0
            b_len = data[idx]
            idx += 1
            board_name = data[idx:idx+b_len].decode('utf-8')
            idx += b_len

            valid, err = _validate_name(board_name, "Board name")
            if not valid:
                return self._build_error(400, err)

            nav_entry = self._ame.get_nav().get(board_name)
            if nav_entry is not None and nav_entry['origin'] != self._config.origin:
                asyncio.create_task(self._sync_mgr.sync_from_peer(nav_entry['relay']))
                origin_bytes = nav_entry['origin'].encode('utf-8')
                return struct.pack('>B', 0x02) + struct.pack('>B', len(origin_bytes)) + origin_bytes

            if not self._engine.check_permission("write", board_name, conn):
                return self._build_error(403, "Permission denied for this board")

            board = self._ame.get_board(board_name)
            if board is None:
                return self._build_error(404, f"Board '{board_name}' not found")

            if board.is_closed():
                return self._build_error(409, "Board is closed")

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

            tags_list = [t.strip() for t in tags.split(',') if t.strip()]
            if len(tags_list) > 255:
                return self._build_error(400, "Too many tags (max 255)")
            for tag in tags_list:
                if len(tag) > 255:
                    return self._build_error(400, f"Tag too long: {tag[:50]}...")

            result = board.create_post(
                root=root,
                subject=subject,
                tags=','.join(tags_list),
                options=options,
                content=content,
                author=conn.user.username,
                author_registrar=conn.user.registrar
            )
            post = result.result()

            author_bytes = post.author.encode('utf-8')
            author_registrar_bytes = post.author_registrar.encode('utf-8')
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

            valid, err = _validate_name(board_name, "Board name")
            if not valid:
                return self._build_error(400, err)

            post_num = struct.unpack('>Q', data[idx:idx+8])[0]

            nav_entry = self._ame.get_nav().get(board_name)
            if nav_entry is not None and nav_entry['origin'] != self._config.origin:
                asyncio.create_task(self._sync_mgr.sync_from_peer(nav_entry['relay']))
                origin_bytes = nav_entry['origin'].encode('utf-8')
                return struct.pack('>B', 0x02) + struct.pack('>B', len(origin_bytes)) + origin_bytes

            if not self._engine.check_permission("read", board_name, conn):
                return self._build_error(403, "Permission denied for this board")

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
        cdef int b_len, offset, limit, idx
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

            valid, err = _validate_name(board_name, "Board name")
            if not valid:
                return self._build_error(400, err)

            nav_entry = self._ame.get_nav().get(board_name)
            if nav_entry is None:
                board = self._ame.get_board(board_name)
                if board is None:
                    return self._build_error(404, f"Board '{board_name}' not found")
            elif nav_entry['origin'] != self._config.origin:
                asyncio.create_task(self._sync_mgr.sync_from_peer(nav_entry['relay']))
                origin_bytes = nav_entry['origin'].encode('utf-8')
                return struct.pack('>B', 0x02) + struct.pack('>B', len(origin_bytes)) + origin_bytes

            if not self._engine.check_permission("read", board_name, conn):
                return self._build_error(403, "Permission denied for this board")

            board = self._ame.get_board(board_name)
            if board is None:
                return self._build_error(404, f"Board '{board_name}' not found")

            offset = struct.unpack('>I', data[idx:idx+4])[0]
            idx += 4
            limit = struct.unpack('>I', data[idx:idx+4])[0]

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
        cdef int b_len, field_count, field_type, field_len, i, idx
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

            valid, err = _validate_name(board_name, "Board name")
            if not valid:
                return self._build_error(400, err)

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
                    valid, err = _validate_name(fields['subject'], "Subject")
                    if not valid:
                        return self._build_error(400, err)
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

            if not self._engine.check_permission("write", board_name, conn):
                return self._build_error(403, "Permission denied for this board")

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
        cdef int b_len, idx
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

            valid, err = _validate_name(board_name, "Board name")
            if not valid:
                return self._build_error(400, err)

            post_num = struct.unpack('>Q', data[idx:idx+8])[0]

            if not self._engine.check_permission("write", board_name, conn):
                return self._build_error(403, "Permission denied for this board")

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
        cdef int b_len, where_len, orderby_len, value_count, value_type, value_len, i, limit, idx
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

            valid, err = _validate_name(board_name, "Board name")
            if not valid:
                return self._build_error(400, err)

            if not self._engine.check_permission("read", board_name, conn):
                return self._build_error(403, "Permission denied for this board")

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

            valid, err = _validate_name(board_name, "Board name")
            if not valid:
                return self._build_error(400, err)

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

            valid, err = _validate_name(board_name, "Board name")
            if not valid:
                return self._build_error(400, err)

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

        log_msg("POST_SIGN: starting")
        log_hex("POST_SIGN: request data", data)

        if not conn.is_registered():
            log_msg("POST_SIGN: rejected - not registered")
            return self._build_error(401, "Authentication required")

        try:
            idx = 0
            b_len = data[idx]
            idx += 1
            board_name = data[idx:idx+b_len].decode('utf-8')
            idx += b_len

            valid, err = _validate_name(board_name, "Board name")
            if not valid:
                return self._build_error(400, err)

            post_num = struct.unpack('>Q', data[idx:idx+8])[0]
            idx += 8

            sig_len = data[idx]
            idx += 1
            signature_hex = data[idx:idx+sig_len].decode('utf-8')
            
            log_dict("POST_SIGN: parsed request", {
                'board': board_name,
                'post_num': post_num,
                'signature_hex': signature_hex[:32] + '...' if len(signature_hex) > 32 else signature_hex
            })
            log_msg(f"POST_SIGN: conn.user={conn.user.username if conn.user else 'None'}")

            if not self._engine.check_permission("write", board_name, conn):
                log_msg(f"POST_SIGN: ACL permission denied for board '{board_name}'")
                return self._build_error(403, "Permission denied for this board")

            board = self._ame.get_board(board_name)
            if board is None:
                log_msg(f"POST_SIGN: board '{board_name}' not found")
                return self._build_error(404, f"Board '{board_name}' not found")

            if board.is_closed():
                log_msg(f"POST_SIGN: board '{board_name}' is closed")
                return self._build_error(409, "Board is closed")

            result = board.get_post(post_num)
            post = result.result()

            if post is None:
                log_msg(f"POST_SIGN: post {post_num} not found")
                return self._build_error(404, f"Post {post_num} not found")

            log_dict("POST_SIGN: post data", {
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

            log_msg(f"POST_SIGN: checking can_edit_post(conn.user.username='{conn.user.username}', post.author='{post.author}')")
            if not conn.can_edit_post(post.author):
                log_msg(f"POST_SIGN: permission denied - conn.user='{conn.user.username}' != post.author='{post.author}'")
                return self._build_error(403, "Only the author can sign this post")
            
            log_msg(f"POST_SIGN: permission check passed")

            author_user = self._ume.get(username=post.author)
            if author_user is None:
                log_msg(f"POST_SIGN: author user '{post.author}' not found in ume")
                return self._build_error(404, f"Author user not found")
            
            log_msg(f"POST_SIGN: author_user found, pubkey={author_user.publickey.hex()}")

            author_bytes = post.author.encode('utf-8')
            author_registrar_bytes = (post.author_registrar or "").encode('utf-8')
            tags_bytes = (post.tags or "").encode('utf-8')
            subject_bytes = (post.subject or "").encode('utf-8')
            options_bytes = (post.options or "").encode('utf-8')
            content_bytes = (post.content or "").encode('utf-8')

            log_dict("POST_SIGN: payload field lengths", {
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

            log_hex("POST_SIGN: signed_payload (server)", signed_payload)

            try:
                signature_bytes = bytes.fromhex(signature_hex)
            except ValueError:
                log_msg("POST_SIGN: invalid signature format (not hex)")
                return self._build_error(400, "Invalid signature format (expected hex)")

            if len(signature_bytes) != 64:
                log_msg(f"POST_SIGN: invalid signature length={len(signature_bytes)} (expected 64)")
                return self._build_error(400, f"Invalid signature length: {len(signature_bytes)} (expected 64)")

            from core.crypto import Identity
            log_msg(f"POST_SIGN: verifying signature with author_user.publickey={author_user.publickey.hex()}")
            verify_result = Identity.verify(author_user.publickey, signed_payload, signature_bytes)
            log_msg(f"POST_SIGN: verification result={verify_result}")
            
            if not verify_result:
                log_msg("POST_SIGN: signature verification FAILED")
                return self._build_error(400, "Signature verification failed")

            result = board.update_post(post_num, {'signature': signature_hex})
            result.result()

            log_msg("POST_SIGN: success")
            return struct.pack('>B', 0x00)

        except Exception as e:
            log_msg(f"POST_SIGN: exception: {e}")
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

        if not conn.is_registered():
            return self._build_error(401, "Authentication required")

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

        if not conn.is_registered():
            return self._build_error(401, "Authentication required")

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

        if not conn.is_registered():
            return self._build_error(401, "Authentication required")

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
        cdef int origin_len
        cdef str origin
        cdef object result, report

        try:
            idx = 0
            origin_len = data[idx]
            idx += 1
            origin = data[idx:idx+origin_len].decode('utf-8')
            idx += origin_len

            report_num = struct.unpack('>Q', data[idx:idx+8])[0]

            result = self._keibatsu.get_report(origin, report_num)
            report = result.result()

            if report is None:
                return self._build_error(404, f"Report {origin}:{report_num} not found")

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
        cdef int sig_len, origin_len
        cdef str signature_hex, origin
        cdef bytes signature_bytes
        cdef object result, report

        if not conn.is_registered():
            return self._build_error(401, "Authentication required")

        try:
            idx = 0
            origin_len = data[idx]
            idx += 1
            origin = data[idx:idx+origin_len].decode('utf-8')
            idx += origin_len

            report_num = struct.unpack('>Q', data[idx:idx+8])[0]
            idx += 8

            sig_len = data[idx]
            idx += 1
            signature_hex = data[idx:idx+sig_len].decode('utf-8')

            result = self._keibatsu.get_report(origin, report_num)
            report = result.result()

            if report is None:
                return self._build_error(404, f"Report {origin}:{report_num} not found")

            if report.reporter_pubkey != conn.peer_public_key:
                return self._build_error(403, "Only the reporter can sign this report")

            try:
                signature_bytes = bytes.fromhex(signature_hex)
            except ValueError:
                return self._build_error(400, "Invalid signature format (expected hex)")

            if len(signature_bytes) != 64:
                return self._build_error(400, f"Invalid signature length: {len(signature_bytes)} (expected 64)")

            result = self._keibatsu.sign_report(origin, report_num, signature_bytes)
            result.result()

            return struct.pack('>B', 0x00)

        except ValueError as e:
            return self._build_error(404, str(e))
        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_report_list_since(self, bytes data, object conn):
        cdef int64_t since_timestamp
        cdef object result
        cdef list reports
        cdef bytes payload

        if not conn.is_registered():
            return self._build_error(401, "Authentication required")

        try:
            since_timestamp = struct.unpack('>q', data[:8])[0]

            result = self._keibatsu.list_reports_since(since_timestamp)
            reports = result.result()

            payload = struct.pack('>B', 0x00) + struct.pack('>H', len(reports))
            for report in reports:
                payload += self._encode_report_entry(report)

            return payload

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
