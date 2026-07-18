import struct
import time
from net.sync import SyncManager, _is_dialable_host
from net.search_limiter import SearchLimiter
from net.context import CommandContext
from net.rate_limiter import RateLimiter
from core.crypto import Identity
from core.binutil import resolve_rg
from engine.facade import BonnetEngine
from engine.ame import SearchUnavailable, SearchTimedOut
from core.logging import log_msg, log_hex, log_dict

import re
import collections
from datetime import datetime

_WHITELIST_PATTERN = re.compile(r'^[a-zA-Z0-9\-_]+$')
_BLACKLIST_PATTERN = re.compile(r'[@<>:"/\\|?*]')

def _validate_name(name: str, field_name: str) -> object:
    length = len(name)
    if length == 0:
        return (False, f"{field_name} cannot be empty")
    if length > 255:
        return (False, f"{field_name} too long (max 255 bytes)")
    if not _WHITELIST_PATTERN.match(name):
        return (False, f"{field_name} contains invalid characters")
    if _BLACKLIST_PATTERN.search(name):
        return (False, f"{field_name} contains invalid characters")
    return (True, "")


class CommandHandler:

    def __init__(self, engine):
        self._engine = engine
        self._ume = engine.ume
        self._ame = engine.ame
        self._keibatsu = engine.keibatsu
        self._config = engine.config
        self._server_identity = engine.server_identity
        self._sync_mgr = SyncManager(engine)
        self._search_limiter = SearchLimiter(
            per_identity_concurrency=getattr(self._config, 'search_per_identity_concurrency', 1),
            rate_limit=getattr(self._config, 'search_rate_limit', 10),
            rate_window_seconds=getattr(self._config, 'search_rate_window_seconds', 60),
        )
        self._rate_limiter = RateLimiter(
            max_requests=getattr(self._config, 'rate_limit_requests', 100),
            window_seconds=getattr(self._config, 'rate_limit_window', 1),
        )

    def handle(self, request: bytes, ctx: CommandContext) -> bytes:
        max_size = self._config.max_request_size

        if max_size > 0 and len(request) > max_size:
            return self._build_error(413, f"Request too large (max {max_size} bytes)")

        rl_key = self._rate_limiter.identity_key(ctx.peer_public_key) if ctx.peer_public_key else self._rate_limiter.address_key(ctx.remote_addr)
        if not self._rate_limiter.check(rl_key):
            return self._build_error(429, "Too many requests. Please slow down.")

        if len(request) == 0:
            return self._build_error(400, "Empty request")

        cmd = request[0]
        data = request[1:]

        cmd_names = {
            0x01: 'REGISTER', 0x02: 'GET_USER', 0x03: 'LIST_USERS', 0x04: 'LIST_PEERS',
            0x05: 'USER_REGISTRY_HEAD', 0x06: 'USER_REGISTRY_NODES',
            0x07: 'USER_REGISTRY_RECORDS', 0x08: 'USER_REGISTRY_HEADS',
            0x09: 'USER_REGISTRY_HEAD_CHAIN',
            0x10: 'BOARD_CREATE', 0x11: 'BOARD_LIST', 0x12: 'POST_CREATE',
            0x13: 'POST_GET', 0x14: 'POST_LIST', 0x15: 'POST_UPDATE',
            0x16: 'POST_DELETE', 0x17: 'BOARD_CLOSE', 0x18: 'BOARD_DELETE',
            0x19: 'QUERY_POSTS', 0x1A: 'POST_CONTENT_SEARCH', 0x20: 'USER_PROMOTE', 0x21: 'USER_DEMOTE',
            0x22: 'POST_SIGN', 0x30: 'GET_PUBKEY',
            0x40: 'RULE_CREATE', 0x41: 'RULE_GET', 0x42: 'RULE_GET_BY_NAME',
            0x43: 'RULE_LIST', 0x44: 'RULE_UPDATE',
            0x50: 'REPORT_CREATE', 0x51: 'REPORT_GET', 0x52: 'REPORT_LIST_BY_CULPRIT',
            0x53: 'REPORT_SIGN', 0x54: 'REPORT_LIST_SINCE',
            0x60: 'PUNISHMENT_CREATE', 0x61: 'PUNISHMENT_GET',
            0x62: 'PUNISHMENT_LIST_ACTIVE', 0x63: 'IS_BANNED',
            0x64: 'PUNISHMENT_LIST_BY_PUBKEY',
            0x70: 'PEER_KEY_ROTATE', 0x71: 'PEER_KEY_LIST'
        }
        cmd_name = cmd_names.get(cmd, f'UNKNOWN_{cmd:02x}')

        username = ctx.user.username if ctx.user else 'anonymous'
        log_msg(f"HANDLE: cmd=0x{cmd:02x} ({cmd_name}), user={username}")
        log_hex(f"HANDLE: request", request)

        if ctx.is_anonymous and cmd not in self._config.public_commands:
            log_msg(f"HANDLE: rejected - anonymous user cannot run cmd=0x{cmd:02x}")
            return self._build_error(401, "Authentication required for this command")

        if not ctx.is_anonymous and ctx.user is not None and ctx.user.is_banned:
            if cmd not in self._config.public_commands:
                log_msg(f"HANDLE: rejected - banned user '{ctx.user.username}' attempted cmd=0x{cmd:02x}")
                return self._build_error(403, "You are banned from performing this action")

        if cmd == 0x01:
            return self._cmd_register(data, ctx)
        elif cmd == 0x02:
            return self._cmd_get(data, ctx)
        elif cmd == 0x03:
            return self._cmd_list(data, ctx)
        elif cmd == 0x04:
            return self._cmd_list_peers(data, ctx)
        elif cmd == 0x05:
            return self._cmd_user_registry_head(data, ctx)
        elif cmd == 0x06:
            return self._cmd_user_registry_nodes(data, ctx)
        elif cmd == 0x07:
            return self._cmd_user_registry_records(data, ctx)
        elif cmd == 0x08:
            return self._cmd_user_registry_heads(data, ctx)
        elif cmd == 0x09:
            return self._cmd_user_registry_head_chain(data, ctx)
        elif cmd == 0x10:
            return self._cmd_board_create(data, ctx)
        elif cmd == 0x11:
            return self._cmd_board_list(data, ctx)
        elif cmd == 0x12:
            return self._cmd_post_create(data, ctx)
        elif cmd == 0x13:
            return self._cmd_post_get(data, ctx)
        elif cmd == 0x14:
            return self._cmd_post_list(data, ctx)
        elif cmd == 0x15:
            return self._cmd_post_update(data, ctx)
        elif cmd == 0x16:
            return self._cmd_post_delete(data, ctx)
        elif cmd == 0x17:
            return self._cmd_board_close(data, ctx)
        elif cmd == 0x18:
            return self._cmd_board_delete(data, ctx)
        elif cmd == 0x19:
            return self._cmd_post_query(data, ctx)
        elif cmd == 0x1A:
            return self._cmd_post_content_search(data, ctx)
        elif cmd == 0x20:
            return self._cmd_user_promote(data, ctx)
        elif cmd == 0x21:
            return self._cmd_user_demote(data, ctx)
        elif cmd == 0x22:
            return self._cmd_post_sign(data, ctx)
        elif cmd == 0x30:
            return self._cmd_get_pubkey(data, ctx)
        elif cmd == 0x40:
            return self._cmd_rule_create(data, ctx)
        elif cmd == 0x41:
            return self._cmd_rule_get(data, ctx)
        elif cmd == 0x42:
            return self._cmd_rule_get_by_name(data, ctx)
        elif cmd == 0x43:
            return self._cmd_rule_list(data, ctx)
        elif cmd == 0x44:
            return self._cmd_rule_update(data, ctx)
        elif cmd == 0x50:
            return self._cmd_report_create(data, ctx)
        elif cmd == 0x51:
            return self._cmd_report_get(data, ctx)
        elif cmd == 0x52:
            return self._cmd_report_list_by_culprit(data, ctx)
        elif cmd == 0x53:
            return self._cmd_report_sign(data, ctx)
        elif cmd == 0x54:
            return self._cmd_report_list_since(data, ctx)
        elif cmd == 0x60:
            return self._cmd_punishment_create(data, ctx)
        elif cmd == 0x61:
            return self._cmd_punishment_get(data, ctx)
        elif cmd == 0x62:
            return self._cmd_punishment_list_active(data, ctx)
        elif cmd == 0x63:
            return self._cmd_is_banned(data, ctx)
        elif cmd == 0x64:
            return self._cmd_punishment_list_by_pubkey(data, ctx)
        elif cmd == 0x70:
            return self._cmd_peer_key_rotate(data, ctx)
        elif cmd == 0x71:
            return self._cmd_peer_key_list(data, ctx)
        else:
            return self._build_error(400, f"Unknown command {cmd}")

    def _build_error(self, code: int, message: str) -> bytes:
        msg_bytes = message.encode('utf-8')
        return struct.pack('>BHB', 0x01, code, len(msg_bytes)) + msg_bytes

    def _cmd_register(self, data: bytes, ctx: CommandContext) -> bytes:
        idx = 0

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

            new_user = self._ume.put(username, registrar, ctx.peer_public_key, record_origin=self._config.origin, relay=self._config.origin)

            u_bytes = new_user.username.encode('utf-8')
            return struct.pack('>B', 0x00) + struct.pack('>B', len(u_bytes)) + u_bytes

        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_peer_key_rotate(self, data: bytes, ctx: CommandContext) -> bytes:
        idx = 0

        if not ctx.is_registered:
            return self._build_error(401, "Authentication required")

        try:
            origin_len = data[idx]
            idx += 1
            origin = data[idx:idx+origin_len].decode('utf-8')
            idx += origin_len

            old_pubkey = data[idx:idx+32]
            idx += 32
            new_pubkey = data[idx:idx+32]
            idx += 32
            signature = data[idx:idx+64]

            if self._sync_mgr.rotate_peer_pubkey(origin, old_pubkey, new_pubkey, signature):
                return struct.pack('>B', 0x00)
            else:
                return self._build_error(403, "Peer key rotation failed (invalid signature or old key mismatch)")
        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_peer_key_list(self, data: bytes, ctx: CommandContext) -> bytes:
        try:
            keys = self._sync_mgr.list_peer_keys()
            payload = struct.pack('>B', 0x00) + struct.pack('>H', len(keys))
            for k in keys:
                origin = k['origin']
                origin_bytes = origin.encode('utf-8')
                payload += struct.pack('>B', len(origin_bytes)) + origin_bytes
                payload += struct.pack('>B', len(k['publickey'])) + k['publickey']
            return payload
        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_get(self, data: bytes, ctx: CommandContext) -> bytes:
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

    def _cmd_list(self, data: bytes, ctx: CommandContext) -> bytes:
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

    def _cmd_list_peers(self, data: bytes, ctx: CommandContext) -> bytes:
        try:
            peers = self._ame.list_peers()
            payload = struct.pack('>B', 0x00) + struct.pack('>H', len(peers))
            for peer in peers:
                peer_bytes = peer.encode('utf-8')
                payload += struct.pack('>B', len(peer_bytes)) + peer_bytes
            return payload
        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_board_create(self, data: bytes, ctx: CommandContext) -> bytes:
        if not ctx.is_registered:
            return self._build_error(401, "Authentication required")

        if not ctx.can_create_board() and not self._engine.check_permission("write", None, ctx):
            return self._build_error(403, "Permission denied to create boards")

        try:
            b_len = data[0]
            board_name = data[1:1+b_len].decode('utf-8')

            valid, err = _validate_name(board_name, "Board name")
            if not valid:
                return self._build_error(400, err)

            if self._ame.get_board(board_name) is not None:
                return self._build_error(409, f"Board '{board_name}' already exists")

            board = self._ame.create_board(board_name, owner_pubkey=ctx.peer_public_key)
            b_bytes = board_name.encode('utf-8')
            return struct.pack('>B', 0x00) + b_bytes

        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_board_list(self, data: bytes, ctx: CommandContext) -> bytes:
        try:
            boards = self._ame.list_boards()
            nav_entries = self._ame.get_nav().list_all()

            nav_map = {e['board_name']: e for e in nav_entries}

            visible_boards = []
            for name, closed in boards:
                if self._engine.check_permission("read", name, ctx):
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

    def _cmd_post_create(self, data: bytes, ctx: CommandContext) -> bytes:
        if not ctx.is_registered:
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

            # Auth + permission gate runs BEFORE the remote-board redirect so
            # that only authenticated, ACL-permitted callers can trigger an
            # outbound sync (#6). Previously the redirect/queue_sync fired
            # before check_permission, letting an unauthorized (but registered)
            # caller drive syncs.
            if not self._engine.check_permission("write", board_name, ctx):
                return self._build_error(403, "Permission denied for this board")

            nav_entry = self._ame.get_nav().get(board_name)
            if nav_entry is not None and nav_entry['origin'] != self._config.origin:
                if _is_dialable_host(nav_entry['relay']):
                    self._sync_mgr.queue_sync_threadsafe(nav_entry['relay'])
                else:
                    log_msg(f"POST_CREATE: not queuing sync for remote board '{board_name}': non-dialable relay '{nav_entry['relay']}'")
                origin_bytes = nav_entry['origin'].encode('utf-8')
                return struct.pack('>B', 0x02) + struct.pack('>B', len(origin_bytes)) + origin_bytes

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
                author=ctx.user.username,
                author_registrar=ctx.user.registrar
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

    def _cmd_post_get(self, data: bytes, ctx: CommandContext) -> bytes:
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

            # Permission gate runs BEFORE the remote-board redirect so anonymous
            # or unauthorized callers cannot trigger an outbound sync (#6).
            if not self._engine.check_permission("read", board_name, ctx):
                return self._build_error(403, "Permission denied for this board")

            nav_entry = self._ame.get_nav().get(board_name)
            if nav_entry is not None and nav_entry['origin'] != self._config.origin:
                if _is_dialable_host(nav_entry['relay']):
                    self._sync_mgr.queue_sync_threadsafe(nav_entry['relay'])
                else:
                    log_msg(f"POST_GET: not queuing sync for remote board '{board_name}': non-dialable relay '{nav_entry['relay']}'")
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

    def _cmd_post_list(self, data: bytes, ctx: CommandContext) -> bytes:
        try:
            idx = 0
            b_len = data[idx]
            idx += 1
            board_name = data[idx:idx+b_len].decode('utf-8')
            idx += b_len

            valid, err = _validate_name(board_name, "Board name")
            if not valid:
                return self._build_error(400, err)

            # Permission gate runs BEFORE the remote-board redirect so anonymous
            # or unauthorized callers cannot trigger an outbound sync (#6).
            if not self._engine.check_permission("read", board_name, ctx):
                return self._build_error(403, "Permission denied for this board")

            nav_entry = self._ame.get_nav().get(board_name)
            if nav_entry is None:
                board = self._ame.get_board(board_name)
                if board is None:
                    return self._build_error(404, f"Board '{board_name}' not found")
            elif nav_entry['origin'] != self._config.origin:
                if _is_dialable_host(nav_entry['relay']):
                    self._sync_mgr.queue_sync_threadsafe(nav_entry['relay'])
                else:
                    log_msg(f"POST_LIST: not queuing sync for remote board '{board_name}': non-dialable relay '{nav_entry['relay']}'")
                origin_bytes = nav_entry['origin'].encode('utf-8')
                return struct.pack('>B', 0x02) + struct.pack('>B', len(origin_bytes)) + origin_bytes

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

    def _cmd_post_update(self, data: bytes, ctx: CommandContext) -> bytes:
        if not ctx.is_registered:
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

            fields = {}
            mod_fields = []

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

            is_mod = ctx.is_moderator() or ctx.is_administrator()

            if not self._engine.check_permission("write", board_name, ctx):
                return self._build_error(403, "Permission denied for this board")

            for mf in mod_fields:
                if not is_mod:
                    return self._build_error(403, f"Field '{mf}' requires moderator permission")

            if not is_mod and not ctx.can_edit_post(post.author):
                return self._build_error(403, "Can only edit your own posts")

            fields['last_modified'] = int(time.time())

            result = board.update_post(post_num, fields)
            result.result()

            return struct.pack('>B', 0x00)

        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_post_delete(self, data: bytes, ctx: CommandContext) -> bytes:
        if not ctx.is_registered:
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

            if not self._engine.check_permission("write", board_name, ctx):
                return self._build_error(403, "Permission denied for this board")

            board = self._ame.get_board(board_name)
            if board is None:
                return self._build_error(404, f"Board '{board_name}' not found")

            result = board.get_post(post_num)
            post = result.result()

            if post is None:
                return self._build_error(404, f"Post {post_num} not found")

            if not ctx.can_delete_post(post.author):
                return self._build_error(403, "Can only delete your own posts")

            result = board.delete_post(post_num)
            result.result()

            return struct.pack('>B', 0x00)

        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_post_query(self, data: bytes, ctx: CommandContext) -> bytes:
        try:
            idx = 0
            b_len = data[idx]
            idx += 1
            board_name = data[idx:idx+b_len].decode('utf-8')
            idx += b_len

            valid, err = _validate_name(board_name, "Board name")
            if not valid:
                return self._build_error(400, err)

            if not self._engine.check_permission("read", board_name, ctx):
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

    def _cmd_post_content_search(self, data: bytes, ctx: CommandContext) -> bytes:
        try:
            idx = 0
            b_len = data[idx]
            idx += 1
            board_name = data[idx:idx+b_len].decode('utf-8')
            idx += b_len

            valid, err = _validate_name(board_name, "Board name")
            if not valid:
                return self._build_error(400, err)

            if not self._engine.check_permission("read", board_name, ctx):
                return self._build_error(403, "Permission denied for this board")

            # pattern: long_string (u32 length) -- regex per ripgrep
            pattern_len = struct.unpack('>I', data[idx:idx+4])[0]
            idx += 4
            pattern = data[idx:idx+pattern_len].decode('utf-8')
            idx += pattern_len
            if not pattern:
                return self._build_error(400, "search pattern cannot be empty")

            # limit: u32 (0 => use configured default)
            limit = struct.unpack('>I', data[idx:idx+4])[0]

            # rg must be available; 503 if not (covers non-frozen envs without rg)
            if resolve_rg() is None:
                return self._build_error(503, "content search unavailable (ripgrep not found)")

            board = self._ame.get_board(board_name)
            if board is None:
                # Local-only: remote/relay boards have no mirrored bodies -> 404.
                return self._build_error(404, f"Board '{board_name}' not found")

            identity_key = ctx.peer_public_key.hex() if ctx.peer_public_key else "anonymous"
            admitted = self._search_limiter.acquire(
                identity_key,
                timeout=float(getattr(self._config, 'search_timeout_seconds', 10)),
            )
            if not admitted:
                return self._build_error(429, "content search rate limit exceeded")
            try:
                result_limit = limit if limit > 0 else getattr(self._config, 'search_result_limit', 100)
                result = board.content_search(
                    pattern,
                    max_count=getattr(self._config, 'search_max_count', 1000),
                    timeout_seconds=getattr(self._config, 'search_timeout_seconds', 10),
                    result_limit=result_limit,
                )
                posts = result.result()
            finally:
                self._search_limiter.release(identity_key)

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

        except SearchTimedOut:
            return self._build_error(504, "content search timed out")
        except SearchUnavailable:
            return self._build_error(503, "content search unavailable (ripgrep not found)")
        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_board_close(self, data: bytes, ctx: CommandContext) -> bytes:
        if not ctx.can_create_board():
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

    def _cmd_board_delete(self, data: bytes, ctx: CommandContext) -> bytes:
        if not ctx.can_create_board():
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

    def _cmd_user_promote(self, data: bytes, ctx: CommandContext) -> bytes:
        if not ctx.can_promote_to_mod():
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

    def _cmd_user_demote(self, data: bytes, ctx: CommandContext) -> bytes:
        if not ctx.can_demote_mod():
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

    def _cmd_post_sign(self, data: bytes, ctx: CommandContext) -> bytes:
        log_msg("POST_SIGN: starting")
        log_hex("POST_SIGN: request data", data)

        if not ctx.is_registered:
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
            log_msg(f"POST_SIGN: ctx.user={ctx.user.username if ctx.user else 'None'}")

            if not self._engine.check_permission("write", board_name, ctx):
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

            log_msg(f"POST_SIGN: checking can_edit_post(ctx.user.username='{ctx.user.username}', post.author='{post.author}')")
            if not ctx.can_edit_post(post.author):
                log_msg(f"POST_SIGN: permission denied - ctx.user='{ctx.user.username}' != post.author='{post.author}'")
                return self._build_error(403, "Only the author can sign this post")

            log_msg("POST_SIGN: permission check passed")

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

    def _cmd_get_pubkey(self, data: bytes, ctx: CommandContext) -> bytes:
        return struct.pack('>B', 0x00) + self._server_identity.public_key

    def _cmd_rule_create(self, data: bytes, ctx: CommandContext) -> bytes:
        if not ctx.is_administrator():
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

    def _cmd_rule_get(self, data: bytes, ctx: CommandContext) -> bytes:
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

    def _cmd_rule_get_by_name(self, data: bytes, ctx: CommandContext) -> bytes:
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

    def _cmd_rule_list(self, data: bytes, ctx: CommandContext) -> bytes:
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

    def _cmd_rule_update(self, data: bytes, ctx: CommandContext) -> bytes:
        if not ctx.is_administrator():
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

    def _cmd_report_create(self, data: bytes, ctx: CommandContext) -> bytes:
        if not ctx.is_registered:
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
            # Parse and discard client-supplied origin/relay: the report's
            # origin attribution must always be bound to this server, never to
            # a client-supplied value, otherwise any registered user could mint
            # an origin_sig claiming a report originated elsewhere (#7).
            client_origin = data[idx:idx+origin_len].decode('utf-8') if origin_len > 0 else None
            idx += origin_len if origin_len > 0 else 0

            relay_len = data[idx]
            idx += 1
            client_relay = data[idx:idx+relay_len].decode('utf-8') if relay_len > 0 else None

            if client_origin or client_relay:
                log_msg(f"REPORT_CREATE: ignoring client-supplied origin='{client_origin}' relay='{client_relay}' (origin is server-bound)")

            result = self._keibatsu.create_report(
                rule_num, culprit_pubkey, reporter_pubkey, description,
                board, culprit_post_num, None, None
            )
            report = result.result()

            return self._encode_report(report)

        except ValueError as e:
            return self._build_error(404, str(e))
        except Exception as e:
            return self._build_error(400, str(e))

    def _encode_report(self, report) -> bytes:
        culprit_bytes = report.culprit_pubkey
        board_bytes = (report.culprit_board or "").encode('utf-8')
        reporter_bytes = report.reporter_pubkey
        origin_bytes = report.origin.encode('utf-8')
        relay_bytes = report.relay.encode('utf-8')
        desc_bytes = report.description.encode('utf-8')
        origin_sig_bytes = (report.origin_sig or "").encode('utf-8')
        reporter_sig_bytes = (report.reporter_sig or "").encode('utf-8')

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

    def _cmd_report_get(self, data: bytes, ctx: CommandContext) -> bytes:
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

    def _cmd_report_list_by_culprit(self, data: bytes, ctx: CommandContext) -> bytes:
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

    def _encode_report_entry(self, report) -> bytes:
        culprit_bytes = report.culprit_pubkey
        board_bytes = (report.culprit_board or "").encode('utf-8')
        reporter_bytes = report.reporter_pubkey
        origin_bytes = report.origin.encode('utf-8')
        relay_bytes = report.relay.encode('utf-8')
        desc_bytes = report.description.encode('utf-8')
        origin_sig_bytes = (report.origin_sig or "").encode('utf-8')
        reporter_sig_bytes = (report.reporter_sig or "").encode('utf-8')

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

    def _cmd_report_sign(self, data: bytes, ctx: CommandContext) -> bytes:
        if not ctx.is_registered:
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

            if report.reporter_pubkey != ctx.peer_public_key:
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

    def _cmd_report_list_since(self, data: bytes, ctx: CommandContext) -> bytes:
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

    def _cmd_punishment_create(self, data: bytes, ctx: CommandContext) -> bytes:
        if not ctx.is_moderator() and not ctx.is_administrator():
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

            issued_by = ctx.peer_public_key or b''
            result = self._keibatsu.create_punishment(pubkey, report_ids, expires_at, notes, issued_by)
            punishment = result.result()

            return struct.pack('>B', 0x00) + self._encode_punishment(punishment)

        except Exception as e:
            return self._build_error(400, str(e))

    def _encode_punishment(self, punishment) -> bytes:
        pubkey_bytes = punishment.punished_pubkey
        notes_bytes = (punishment.ban_notes or "").encode('utf-8')
        report_ids_list = punishment.get_report_ids()
        issued_by_bytes = punishment.issued_by or b''

        payload = struct.pack('>Q', punishment.punishment_id) + \
                  struct.pack('>B', len(pubkey_bytes)) + pubkey_bytes + \
                  struct.pack('>B', len(report_ids_list))

        for report_id in report_ids_list:
            payload += struct.pack('>Q', report_id)

        payload += struct.pack('>q', punishment.expires_at)
        payload += struct.pack('>B', len(notes_bytes)) + notes_bytes
        payload += struct.pack('>B', len(issued_by_bytes)) + issued_by_bytes
        payload += struct.pack('>q', punishment.created_at)

        return payload

    def _cmd_punishment_get(self, data: bytes, ctx: CommandContext) -> bytes:
        try:
            punishment_id = struct.unpack('>Q', data[0:8])[0]

            result = self._keibatsu.get_punishment(punishment_id)
            punishment = result.result()

            if punishment is None:
                return self._build_error(404, "No punishment found for id")

            return struct.pack('>B', 0x00) + self._encode_punishment(punishment)

        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_punishment_list_active(self, data: bytes, ctx: CommandContext) -> bytes:
        try:
            result = self._keibatsu.list_active_punishments()
            punishments = result.result()

            payload = struct.pack('>B', 0x00) + struct.pack('>H', len(punishments))
            for punishment in punishments:
                payload += self._encode_punishment(punishment)

            return payload

        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_punishment_list_by_pubkey(self, data: bytes, ctx: CommandContext) -> bytes:
        try:
            pubkey_len = data[0]
            pubkey = data[1:1+pubkey_len]

            result = self._keibatsu.list_punishments_by_pubkey(pubkey)
            punishments = result.result()

            payload = struct.pack('>B', 0x00) + struct.pack('>H', len(punishments))
            for punishment in punishments:
                payload += self._encode_punishment(punishment)

            return payload

        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_is_banned(self, data: bytes, ctx: CommandContext) -> bytes:
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

    # ------------------------------------------------------------------
    # Registry commands (opcodes 0x05–0x09)
    # ------------------------------------------------------------------

    def _get_registry_service(self):
        svc = getattr(self._engine, 'registry_service', None)
        if svc is None:
            return None
        return svc

    def _get_registry_store(self):
        store = getattr(self._engine, 'registry_store', None)
        if store is None:
            return None
        return store

    def _cmd_user_registry_head(self, data: bytes, ctx: CommandContext) -> bytes:
        try:
            offset = 0
            if len(data) < 2:
                return self._build_error(400, "Request too short")
            origin_len = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2
            if origin_len > 255 or offset + origin_len + 8 > len(data):
                return self._build_error(400, "Invalid origin or truncated request")
            origin = data[offset:offset + origin_len].decode("utf-8")
            offset += origin_len
            requested_seq = struct.unpack(">Q", data[offset:offset + 8])[0]
            offset += 8
            if offset != len(data):
                return self._build_error(400, "Trailing data in request")

            svc = self._get_registry_service()
            store = self._get_registry_store()

            if svc is not None and origin == self._config.origin:
                head = svc.build_snapshot()
            elif store is not None:
                head = store.get_head(origin, requested_seq)
            else:
                head = None

            if head is None:
                return self._build_error(404, f"No registry head for origin '{origin}'")

            from core.user_registry import encode_head
            encoded = encode_head(head)
            return struct.pack(">B", 0x00) + struct.pack(">H", len(encoded)) + encoded

        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_user_registry_nodes(self, data: bytes, ctx: CommandContext) -> bytes:
        try:
            offset = 0
            if len(data) < 2:
                return self._build_error(400, "Request too short")
            origin_len = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2
            if origin_len > 255 or offset + origin_len + 8 + 2 > len(data):
                return self._build_error(400, "Invalid origin or truncated request")
            origin = data[offset:offset + origin_len].decode("utf-8")
            offset += origin_len
            registry_seq = struct.unpack(">Q", data[offset:offset + 8])[0]
            offset += 8
            prefix_count = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2
            if prefix_count > 256:
                return self._build_error(400, "Too many prefixes")

            prefixes = []
            for _ in range(prefix_count):
                if offset + 3 > len(data):
                    return self._build_error(400, "Truncated prefix header")
                bit_len = struct.unpack(">H", data[offset:offset + 2])[0]
                offset += 2
                byte_len = data[offset]
                offset += 1
                if bit_len > 256 or offset + byte_len > len(data):
                    return self._build_error(400, "Invalid prefix or truncated data")
                prefix = data[offset:offset + byte_len]
                offset += byte_len
                prefixes.append((bit_len, prefix))
            if offset != len(data):
                return self._build_error(400, "Trailing data in request")

            store = self._get_registry_store()
            if store is None:
                return self._build_error(503, "Registry not available")

            from core.user_registry import DEFAULT_HASHES, TREE_DEPTH

            state = store.get_state(origin)
            if state is None or (registry_seq != 0 and registry_seq > state["highest_accepted_seq"]):
                return self._build_error(404, f"No head at seq {registry_seq} for origin '{origin}'")
            actual_seq = registry_seq if registry_seq != 0 else state["highest_accepted_seq"]

            response = struct.pack(">B", 0x00) + struct.pack(">H", len(prefixes))
            for bit_len, prefix in prefixes:
                level = bit_len
                prefix_int = int.from_bytes(prefix, "big") if prefix else 0
                norm_prefix = prefix_int.to_bytes((level + 7) // 8 or 1, "big")
                node_hash = store.get_node(origin, actual_seq, level, norm_prefix)

                if node_hash is None:
                    if level <= TREE_DEPTH:
                        node_hash = DEFAULT_HASHES[level]
                    else:
                        node_hash = b"\x00" * 32

                from core.user_registry import EMPTY_LEAF, _leaf_hash
                is_leaf = (level == TREE_DEPTH)
                is_default = (node_hash == DEFAULT_HASHES[level])

                if is_default:
                    node_kind = 0
                elif is_leaf:
                    node_kind = 2
                else:
                    node_kind = 1

                response += struct.pack(">H", bit_len)
                response += struct.pack(">B", len(prefix)) + prefix
                response += struct.pack(">B", node_kind)
                response += node_hash

                if node_kind == 1:
                    left_prefix = (prefix_int << 1)
                    right_prefix = (prefix_int << 1) | 1
                    child_byte_len = ((level + 1) + 7) // 8 or 1
                    left_hash = store.get_node(origin, actual_seq, level + 1,
                                               left_prefix.to_bytes(child_byte_len, "big"))
                    right_hash = store.get_node(origin, actual_seq, level + 1,
                                                right_prefix.to_bytes(child_byte_len, "big"))
                    if left_hash is None:
                        left_hash = DEFAULT_HASHES[level + 1]
                    if right_hash is None:
                        right_hash = DEFAULT_HASHES[level + 1]
                    response += left_hash + right_hash
                elif node_kind == 2:
                    record = store.get_record(origin, prefix_int.to_bytes(32, "big"))
                    if record is not None:
                        from core.user_registry import compute_value_hash, compute_registry_key
                        from engine.ume import User
                        user = User.decode(record)
                        key = compute_registry_key(origin, user.username)
                        vh = compute_value_hash(record)
                        response += key + vh
                    else:
                        response += b"\x00" * 64

            return response

        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_user_registry_records(self, data: bytes, ctx: CommandContext) -> bytes:
        try:
            offset = 0
            if len(data) < 2:
                return self._build_error(400, "Request too short")
            origin_len = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2
            if origin_len > 255 or offset + origin_len + 8 + 2 + 1 > len(data):
                return self._build_error(400, "Invalid origin or truncated request")
            origin = data[offset:offset + origin_len].decode("utf-8")
            offset += origin_len
            registry_seq = struct.unpack(">Q", data[offset:offset + 8])[0]
            offset += 8
            record_count = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2
            if record_count > 64:
                return self._build_error(400, "Too many records requested")
            include_proofs = data[offset]
            offset += 1

            store = self._get_registry_store()
            if store is None:
                return self._build_error(503, "Registry not available")

            state = store.get_state(origin)
            if state is None:
                return self._build_error(404, f"No registry for origin '{origin}'")
            actual_seq = registry_seq if registry_seq != 0 else state["highest_accepted_seq"]

            if record_count == 0:
                all_records = store.get_all_records(origin)
                record_entries = [(r[0], r[1]) for r in all_records]
            else:
                expected_len = offset + record_count * 32
                if len(data) != expected_len:
                    return self._build_error(400, "Truncated or trailing key data")
                keys = []
                for _ in range(record_count):
                    keys.append(data[offset:offset + 32])
                    offset += 32
                record_entries = []
                for key in keys:
                    raw = store.get_record(origin, key)
                    if raw is not None:
                        record_entries.append((key, raw))
                    else:
                        record_entries.append((key, None))

            response = struct.pack(">B", 0x00) + struct.pack(">H", len(record_entries))
            for key, raw in record_entries:
                if raw is None:
                    response += key + struct.pack(">B", 0)
                else:
                    response += key + struct.pack(">B", 1)
                    response += struct.pack(">H", len(raw)) + raw
                    response += struct.pack(">H", 0)
            return response

        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_user_registry_heads(self, data: bytes, ctx: CommandContext) -> bytes:
        try:
            if len(data) < 6:
                return self._build_error(400, "Request too short")
            offset_val = struct.unpack(">I", data[:4])[0]
            limit = struct.unpack(">H", data[4:6])[0]
            if limit > 100:
                limit = 100

            store = self._get_registry_store()
            if store is None:
                return self._build_error(503, "Registry not available")

            heads = store.list_heads(offset=offset_val, limit=limit)
            from core.user_registry import encode_head

            response = struct.pack(">B", 0x00) + struct.pack(">H", len(heads))
            for head in heads:
                encoded = encode_head(head)
                response += struct.pack(">H", len(encoded)) + encoded
            return response

        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_user_registry_head_chain(self, data: bytes, ctx: CommandContext) -> bytes:
        try:
            offset = 0
            if len(data) < 2:
                return self._build_error(400, "Request too short")
            origin_len = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2
            if origin_len > 255 or offset + origin_len + 8 + 2 > len(data):
                return self._build_error(400, "Invalid origin or truncated request")
            origin = data[offset:offset + origin_len].decode("utf-8")
            offset += origin_len
            start_seq = struct.unpack(">Q", data[offset:offset + 8])[0]
            offset += 8
            max_count = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2
            if max_count > 100:
                max_count = 100
            if offset != len(data):
                return self._build_error(400, "Trailing data in request")

            store = self._get_registry_store()
            if store is None:
                return self._build_error(503, "Registry not available")

            state = store.get_state(origin)
            if state is None:
                return self._build_error(404, f"No registry for origin '{origin}'")

            from core.user_registry import encode_head

            end_seq = max(1, start_seq - max_count + 1)
            heads = []
            for seq in range(start_seq, end_seq - 1, -1):
                head = store.get_head(origin, seq)
                if head is not None:
                    heads.append(head)

            response = struct.pack(">B", 0x00) + struct.pack(">H", len(heads))
            for head in heads:
                encoded = encode_head(head)
                response += struct.pack(">H", len(encoded)) + encoded
            return response

        except Exception as e:
            return self._build_error(400, str(e))
