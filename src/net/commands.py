import struct
import time
from net.sync import SyncManager, _is_dialable_host
from net.search_limiter import SearchLimiter
from net.context import CommandContext
from net.rate_limiter import RateLimiter
from core.crypto import Identity
from core.binutil import resolve_rg
from core.commands import COMMAND_SPECS, get_spec, V3_COMMAND_SPECS, get_v3_spec
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

        spec = get_spec(cmd)
        cmd_name = spec.name if spec else f'UNKNOWN_{cmd:02x}'

        username = ctx.user.username if ctx.user else 'anonymous'
        log_msg(f"HANDLE: cmd=0x{cmd:02x} ({cmd_name}), user={username}")
        log_hex(f"HANDLE: request", request)

        if spec is None:
            return self._build_error(400, f"Unknown command 0x{cmd:02x}")

        # Command ACL gate (§5.4): default-deny, no admin/owner/mod bypass.
        if not self._engine.check_command_permission(spec, ctx):
            log_msg(f"HANDLE: rejected - command ACL denied cmd=0x{cmd:02x} ({cmd_name}) for user={username}")
            return self._build_error(403, "Command not permitted")

        # Object ACL gate (§5.5): conjunctive with command ACL. Dormant in
        # Phase 1 — no existing command has object_name set.
        if spec.object_name is not None:
            if not self._engine.check_object_permission(spec.action, spec.object_name, ctx):
                log_msg(f"HANDLE: rejected - object ACL denied object={spec.object_name} for cmd=0x{cmd:02x}")
                return self._build_error(403, "Object not permitted")

        # Banned-write gate (§6.2): effectively banned known users may read
        # but must be denied every write command. Uses Keibatsu as the
        # authoritative evaluator (§6.1), not the UME is_banned flag.
        if ctx.user is not None and spec.action == "write":
            ban_result = self._keibatsu.is_banned(ctx.user.publickey).result()
            if ban_result[0]:
                log_msg(f"HANDLE: rejected - banned user '{ctx.user.username}' attempted write cmd=0x{cmd:02x}")
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
        elif cmd == 0x20:
            return self._cmd_user_promote(data, ctx)
        elif cmd == 0x21:
            return self._cmd_user_demote(data, ctx)
        elif cmd == 0x30:
            return self._cmd_get_pubkey(data, ctx)
        elif cmd == 0x70:
            return self._cmd_peer_key_rotate(data, ctx)
        elif cmd == 0x71:
            return self._cmd_peer_key_list(data, ctx)
        else:
            return self._build_error(400, f"Unknown command {cmd}")

    # ------------------------------------------------------------------
    # Protocol v3 dispatch
    # ------------------------------------------------------------------

    def handle_v3(self, request: bytes, ctx: CommandContext) -> bytes:
        """Dispatch a protocol v3 command."""
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

        spec = get_v3_spec(cmd)
        cmd_name = spec.name if spec else f'UNKNOWN_{cmd:02x}'

        username = ctx.user.username if ctx.user else 'anonymous'
        log_msg(f"HANDLE_V3: cmd=0x{cmd:02x} ({cmd_name}), user={username}")

        if spec is None:
            return self._build_error(400, f"Unknown v3 command 0x{cmd:02x}")

        # Command ACL gate
        if not self._engine.check_command_permission(spec, ctx):
            log_msg(f"HANDLE_V3: rejected - command ACL denied cmd=0x{cmd:02x} ({cmd_name}) for user={username}")
            return self._build_error(403, "Command not permitted")

        # Object ACL gate
        if spec.object_name is not None:
            if not self._engine.check_object_permission(spec.action, spec.object_name, ctx):
                log_msg(f"HANDLE_V3: rejected - object ACL denied object={spec.object_name} for cmd=0x{cmd:02x}")
                return self._build_error(403, "Object not permitted")

        # Banned-write gate
        if ctx.user is not None and spec.action == "write":
            ban_result = self._keibatsu.is_banned(ctx.user.publickey).result()
            if ban_result[0]:
                log_msg(f"HANDLE_V3: rejected - banned user '{ctx.user.username}' attempted write cmd=0x{cmd:02x}")
                return self._build_error(403, "You are banned from performing this action")

        # Dispatch v3 commands
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
            return self._cmd_v3_article_publish(data, ctx)
        elif cmd == 0x13:
            return self._cmd_v3_article_get(data, ctx)
        elif cmd == 0x14:
            return self._cmd_v3_article_list(data, ctx)
        elif cmd == 0x15:
            return self._cmd_v3_feed_head(data, ctx)
        elif cmd == 0x16:
            return self._cmd_v3_feed_events(data, ctx)
        elif cmd == 0x17:
            return self._cmd_v3_article_body(data, ctx)
        elif cmd == 0x18:
            return self._cmd_v3_feed_heads(data, ctx)
        elif cmd == 0x19:
            return self._cmd_v3_article_search(data, ctx)
        elif cmd == 0x1A:
            return self._cmd_v3_board_set_state(data, ctx)
        elif cmd == 0x1B:
            return self._cmd_v3_ban_status(data, ctx)
        elif cmd == 0x20:
            return self._cmd_user_promote(data, ctx)
        elif cmd == 0x21:
            return self._cmd_user_demote(data, ctx)
        elif cmd == 0x30:
            return self._cmd_get_pubkey(data, ctx)
        elif cmd == 0x70:
            return self._cmd_peer_key_rotate(data, ctx)
        elif cmd == 0x71:
            return self._cmd_peer_key_list(data, ctx)
        else:
            return self._build_error(400, f"Unknown v3 command {cmd}")

    # ------------------------------------------------------------------
    # v3 article/feed command handlers (§13.4)
    # ------------------------------------------------------------------

    def _cmd_v3_article_publish(self, data: bytes, ctx: CommandContext) -> bytes:
        """ARTICLE_PUBLISH — publish an article or control event to the local feed."""
        if not ctx.is_registered:
            return self._build_error(401, "Authentication required")
        try:
            from core.article_feed import (
                decode_submission, validate_submission, verify_author_signature,
                SCHEME_V3, encode_event, encode_head, Submission,
            )
            idx = 0
            sub_len = struct.unpack(">I", data[idx:idx + 4])[0]
            idx += 4
            encoded_sub = data[idx:idx + sub_len]
            idx += sub_len
            body_len = struct.unpack(">I", data[idx:idx + 4])[0]
            idx += 4
            body = data[idx:idx + body_len]
            idx += body_len
            author_scheme = data[idx]
            idx += 1
            sig_len = struct.unpack(">H", data[idx:idx + 2])[0]
            idx += 2
            author_sig = data[idx:idx + sig_len]

            submission = decode_submission(encoded_sub)
            validate_submission(submission)

            # Verify the submission origin matches local origin
            if submission.origin != self._config.origin:
                return self._build_error(403, "Submission origin does not match server origin")

            # Check board write permission
            if not self._engine.check_permission("write", submission.board, ctx):
                return self._build_error(403, "Permission denied for this board")

            # Verify author signature for scheme 1
            if author_scheme == SCHEME_V3:
                if not verify_author_signature(submission, author_sig, submission.actor_pubkey):
                    return self._build_error(403, "Author signature verification failed")
            else:
                return self._build_error(400, "Only scheme 1 is supported for normal publication")

            # Verify body hash
            from core.article_feed import compute_body_hash
            actual_hash = compute_body_hash(body)
            if actual_hash != submission.body_hash:
                return self._build_error(400, "body_hash does not match supplied body")
            if len(body) != submission.body_size:
                return self._build_error(400, "body_size does not match supplied body")

            # Check that the actor pubkey matches the authenticated user
            if ctx.peer_public_key != submission.actor_pubkey:
                return self._build_error(403, "Actor pubkey does not match authenticated key")

            from core.article_feed import (
                EVENT_ARTICLE, EVENT_CANCEL, EVENT_RESTORE, EVENT_PURGE,
                EVENT_RULE, EVENT_RULE_REVOKE, EVENT_REPORT,
                EVENT_PUNISHMENT, EVENT_PUNISHMENT_REVOKE,
                EVENT_BOARD_CLOSE, EVENT_BOARD_REOPEN,
                EVENT_ARTICLE_PIN, EVENT_ARTICLE_UNPIN,
                EVENT_THREAD_CLOSE, EVENT_THREAD_REOPEN,
            )
            et = submission.event_type

            # --- Role checks (§14.1) ---
            # PURGE, PUNISHMENT, PUNISHMENT_REVOKE require moderator/admin
            # RULE, RULE_REVOKE require administrator
            # ARTICLE_PIN, ARTICLE_UNPIN, THREAD_CLOSE, THREAD_REOPEN require moderator/admin
            mod_admin_events = {
                EVENT_PURGE, EVENT_PUNISHMENT, EVENT_PUNISHMENT_REVOKE,
                EVENT_ARTICLE_PIN, EVENT_ARTICLE_UNPIN,
                EVENT_THREAD_CLOSE, EVENT_THREAD_REOPEN,
            }
            admin_only_events = {
                EVENT_RULE, EVENT_RULE_REVOKE,
            }
            if et in mod_admin_events:
                if not (ctx.is_moderator() or ctx.is_administrator()):
                    return self._build_error(403, "Moderator or administrator authority required for this event type")
            if et in admin_only_events:
                if not ctx.is_administrator():
                    return self._build_error(403, "Administrator authority required for this event type")

            # --- Closed-board publication enforcement (§14.1 lines 1374-1383) ---
            # When a board is closed, reject ARTICLE, CANCEL, RESTORE, REPORT,
            # RULE, PUNISHMENT, ARTICLE_PIN, ARTICLE_UNPIN, THREAD_CLOSE/REOPEN.
            # Permit PURGE, RULE_REVOKE, PUNISHMENT_REVOKE (retracting dangerous policy).
            # BOARD_CLOSE/BOARD_REOPEN go through BOARD_SET_STATE, not here.
            nav_entry = self._ame.get_nav().get(submission.board)
            board_closed = nav_entry['closed'] if nav_entry else False
            if board_closed:
                permitted_when_closed = {
                    EVENT_PURGE, EVENT_RULE_REVOKE, EVENT_PUNISHMENT_REVOKE,
                }
                if et not in permitted_when_closed:
                    return self._build_error(409, "Board is closed")

            # Dispatch to ArticleService
            service = self._engine.article_service
            if service is None:
                return self._build_error(500, "Article service not configured")

            if et == EVENT_ARTICLE:
                event, head = service.publish_article(submission, body, author_sig)
            elif et == EVENT_CANCEL:
                event, head = service.cancel_article(submission, author_sig)
            elif et == EVENT_RESTORE:
                event, head = service.restore_article(submission, author_sig)
            elif et == EVENT_PURGE:
                event, head = service.purge_article(submission, author_sig)
            else:
                # For other event types (REPORT, PUNISHMENT, RULE, etc.), use raw publish
                event, head = service.publish_article_raw(
                    et, submission, body, author_sig)

            # Build response: event_len:u32 + encoded_event + head_len:u16 + encoded_head
            encoded_event = encode_event(event)
            encoded_head_bytes = encode_head(head)
            return (
                struct.pack(">B", 0x00)
                + struct.pack(">I", len(encoded_event)) + encoded_event
                + struct.pack(">H", len(encoded_head_bytes)) + encoded_head_bytes
            )
        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_v3_article_get(self, data: bytes, ctx: CommandContext) -> bytes:
        """ARTICLE_GET — get a single article with lifecycle state."""
        try:
            from core.article_feed import encode_event
            idx = 0
            # board (u16 string)
            b_len = struct.unpack(">H", data[idx:idx + 2])[0]
            idx += 2
            board = data[idx:idx + b_len].decode("utf-8")
            idx += b_len

            valid, err = _validate_name(board, "Board name")
            if not valid:
                return self._build_error(400, err)

            if not self._engine.check_permission("read", board, ctx):
                return self._build_error(403, "Permission denied for this board")

            selector_type = data[idx]
            idx += 1
            if selector_type == 0x01:
                selector = struct.unpack(">Q", data[idx:idx + 8])[0]
                idx += 8
            elif selector_type == 0x02:
                selector = data[idx:idx + 32]
                idx += 32
            else:
                return self._build_error(400, "Invalid selector type")

            include_body = data[idx] if idx < len(data) else 0
            idx += 1

            service = self._engine.article_service
            if service is None:
                return self._build_error(500, "Article service not configured")

            view = service.get_article(self._config.origin, board, selector_type,
                                       selector, include_body=bool(include_body))
            if view is None:
                return self._build_error(404, "Article not found")

            from core.article_feed import (
                STATE_ACTIVE, STATE_CANCELLED, STATE_SUPERSEDED, STATE_PURGED,
                BODY_NOT_REQUESTED, BODY_INCLUDED, BODY_AVAILABLE_NOT_INCLUDED,
                BODY_UNAVAILABLE,
            )
            state_map = {
                "active": STATE_ACTIVE, "cancelled": STATE_CANCELLED,
                "superseded": STATE_SUPERSEDED, "purged": STATE_PURGED,
            }
            projected_state = state_map.get(view.projected_state, STATE_ACTIVE)

            if include_body and view.body is not None:
                body_status = BODY_INCLUDED
                body_bytes = view.body
            elif view.body_available:
                body_status = BODY_AVAILABLE_NOT_INCLUDED
                body_bytes = b""
            else:
                body_status = BODY_UNAVAILABLE
                body_bytes = b""

            encoded_event = encode_event(view.event)
            control_ids = view.control_event_ids

            out = struct.pack(">B", 0x00)
            out += struct.pack(">I", len(encoded_event)) + encoded_event
            out += struct.pack(">B", projected_state)
            out += struct.pack(">H", len(control_ids))
            for cid in control_ids:
                out += cid
            out += struct.pack(">B", body_status)
            out += struct.pack(">I", len(body_bytes)) + body_bytes
            return out
        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_v3_article_list(self, data: bytes, ctx: CommandContext) -> bytes:
        """ARTICLE_LIST — list articles with projection filtering."""
        try:
            from core.article_feed import (
                encode_event, FLAG_INCLUDE_CANCELLED, FLAG_INCLUDE_SUPERSEDED,
                FLAG_INCLUDE_PURGED, FLAG_INCLUDE_CONTROLS, FLAG_INCLUDE_BODIES,
                STATE_ACTIVE, STATE_CANCELLED, STATE_SUPERSEDED, STATE_PURGED,
                BODY_AVAILABLE_NOT_INCLUDED, BODY_INCLUDED, BODY_NOT_REQUESTED,
            )
            idx = 0
            b_len = struct.unpack(">H", data[idx:idx + 2])[0]
            idx += 2
            board = data[idx:idx + b_len].decode("utf-8")
            idx += b_len

            valid, err = _validate_name(board, "Board name")
            if not valid:
                return self._build_error(400, err)

            if not self._engine.check_permission("read", board, ctx):
                return self._build_error(403, "Permission denied for this board")

            offset = struct.unpack(">I", data[idx:idx + 4])[0]
            idx += 4
            limit = struct.unpack(">H", data[idx:idx + 2])[0]
            idx += 2
            flags = struct.unpack(">H", data[idx:idx + 2])[0]
            idx += 2

            include_cancelled = bool(flags & FLAG_INCLUDE_CANCELLED)
            include_superseded = bool(flags & FLAG_INCLUDE_SUPERSEDED)
            include_purged = bool(flags & FLAG_INCLUDE_PURGED)
            include_body = bool(flags & FLAG_INCLUDE_BODIES)

            service = self._engine.article_service
            if service is None:
                return self._build_error(500, "Article service not configured")

            articles = service.list_articles(
                self._config.origin, board, offset=offset, limit=limit,
                include_cancelled=include_cancelled,
                include_superseded=include_superseded,
                include_purged=include_purged,
                include_body=include_body,
            )

            state_map = {
                "active": STATE_ACTIVE, "cancelled": STATE_CANCELLED,
                "superseded": STATE_SUPERSEDED, "purged": STATE_PURGED,
            }

            out = struct.pack(">B", 0x00)
            out += struct.pack(">H", len(articles))
            for view in articles:
                encoded_event = encode_event(view.event)
                projected_state = state_map.get(view.projected_state, STATE_ACTIVE)
                out += struct.pack(">I", len(encoded_event)) + encoded_event
                out += struct.pack(">B", projected_state)
                out += struct.pack(">H", len(view.control_event_ids))
                for cid in view.control_event_ids:
                    out += cid
                if include_body and view.body is not None:
                    out += struct.pack(">B", BODY_INCLUDED)
                    out += struct.pack(">I", len(view.body)) + view.body
                else:
                    out += struct.pack(">B", BODY_AVAILABLE_NOT_INCLUDED)
                    out += struct.pack(">I", 0)
            return out
        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_v3_feed_head(self, data: bytes, ctx: CommandContext) -> bytes:
        """FEED_HEAD — get the signed feed head for a board."""
        try:
            from core.article_feed import encode_head
            idx = 0
            # origin (u16 string, may be empty for local)
            o_len = struct.unpack(">H", data[idx:idx + 2])[0]
            idx += 2
            origin = data[idx:idx + o_len].decode("utf-8") if o_len > 0 else self._config.origin
            idx += o_len
            b_len = struct.unpack(">H", data[idx:idx + 2])[0]
            idx += 2
            board = data[idx:idx + b_len].decode("utf-8")
            idx += b_len

            valid, err = _validate_name(board, "Board name")
            if not valid:
                return self._build_error(400, err)

            if not self._engine.check_permission("read", board, ctx):
                return self._build_error(403, "Permission denied for this board")

            service = self._engine.article_service
            if service is None:
                return self._build_error(500, "Article service not configured")

            head = service.store.get_head(origin, board)
            if head is None:
                # Board exists but no stored head (e.g., pre-v3 board not yet
                # migrated). Create and store one now as a fallback.
                from core.article_feed import make_empty_head, sign_head
                head = service.store.create_empty_feed(
                    origin, board, self._server_identity)

            encoded = encode_head(head)
            return struct.pack(">B", 0x00) + struct.pack(">H", len(encoded)) + encoded
        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_v3_feed_events(self, data: bytes, ctx: CommandContext) -> bytes:
        """FEED_EVENTS — fetch a contiguous range of feed events."""
        try:
            from core.article_feed import encode_event
            idx = 0
            o_len = struct.unpack(">H", data[idx:idx + 2])[0]
            idx += 2
            origin = data[idx:idx + o_len].decode("utf-8") if o_len > 0 else self._config.origin
            idx += o_len
            b_len = struct.unpack(">H", data[idx:idx + 2])[0]
            idx += 2
            board = data[idx:idx + b_len].decode("utf-8")
            idx += b_len

            valid, err = _validate_name(board, "Board name")
            if not valid:
                return self._build_error(400, err)

            if not self._engine.check_permission("read", board, ctx):
                return self._build_error(403, "Permission denied for this board")

            start_seq = struct.unpack(">Q", data[idx:idx + 8])[0]
            idx += 8
            max_count = struct.unpack(">H", data[idx:idx + 2])[0]

            service = self._engine.article_service
            if service is None:
                return self._build_error(500, "Article service not configured")

            events = service.store.get_events_range(origin, board, start_seq, max_count)
            out = struct.pack(">B", 0x00)
            out += struct.pack(">H", len(events))
            for ev in events:
                encoded = encode_event(ev)
                out += struct.pack(">I", len(encoded)) + encoded
            return out
        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_v3_article_body(self, data: bytes, ctx: CommandContext) -> bytes:
        """ARTICLE_BODY — fetch a body blob by hash."""
        try:
            idx = 0
            o_len = struct.unpack(">H", data[idx:idx + 2])[0]
            idx += 2
            origin = data[idx:idx + o_len].decode("utf-8") if o_len > 0 else self._config.origin
            idx += o_len
            b_len = struct.unpack(">H", data[idx:idx + 2])[0]
            idx += 2
            board = data[idx:idx + b_len].decode("utf-8")
            idx += b_len

            valid, err = _validate_name(board, "Board name")
            if not valid:
                return self._build_error(400, err)

            if not self._engine.check_permission("read", board, ctx):
                return self._build_error(403, "Permission denied for this board")

            message_id = data[idx:idx + 32]
            idx += 32
            body_hash = data[idx:idx + 32]

            service = self._engine.article_service
            if service is None:
                return self._build_error(500, "Article service not configured")

            # Verify the message belongs to this feed
            event = service.store.get_event_by_message_id(message_id)
            if event is None or event.origin != origin or event.board != board:
                return self._build_error(404, "Article not found")

            # Verify the body hash matches
            if event.body_hash != body_hash:
                return self._build_error(404, "Body hash mismatch")

            body = service.store.get_body(body_hash)
            if body is None:
                return self._build_error(410, "Body unavailable")

            return struct.pack(">B", 0x00) + struct.pack(">I", len(body)) + body
        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_v3_feed_heads(self, data: bytes, ctx: CommandContext) -> bytes:
        """FEED_HEADS — list feed heads across all boards."""
        try:
            from core.article_feed import encode_head
            offset = struct.unpack(">I", data[0:4])[0]
            limit = struct.unpack(">H", data[4:6])[0]

            service = self._engine.article_service
            if service is None:
                return self._build_error(500, "Article service not configured")

            heads = service.store.list_heads(offset, limit)
            out = struct.pack(">B", 0x00)
            out += struct.pack(">H", len(heads))
            for origin, board, head in heads:
                origin_b = origin.encode("utf-8")
                board_b = board.encode("utf-8")
                encoded = encode_head(head)
                out += struct.pack(">H", len(origin_b)) + origin_b
                out += struct.pack(">H", len(board_b)) + board_b
                out += struct.pack(">H", len(encoded)) + encoded
            return out
        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_v3_article_search(self, data: bytes, ctx: CommandContext) -> bytes:
        """ARTICLE_SEARCH — search articles with structured filters."""
        try:
            from core.article_feed import (
                encode_event, FLAG_INCLUDE_CANCELLED, FLAG_INCLUDE_SUPERSEDED,
                FLAG_INCLUDE_PURGED, FLAG_INCLUDE_BODIES,
                STATE_ACTIVE, STATE_CANCELLED, STATE_SUPERSEDED, STATE_PURGED,
                BODY_AVAILABLE_NOT_INCLUDED, BODY_INCLUDED,
            )
            idx = 0
            # origin (u16 string)
            o_len = struct.unpack(">H", data[idx:idx + 2])[0]
            idx += 2
            origin = data[idx:idx + o_len].decode("utf-8") if o_len > 0 else self._config.origin
            idx += o_len
            b_len = struct.unpack(">H", data[idx:idx + 2])[0]
            idx += 2
            board = data[idx:idx + b_len].decode("utf-8")
            idx += b_len

            valid, err = _validate_name(board, "Board name")
            if not valid:
                return self._build_error(400, err)

            if not self._engine.check_permission("read", board, ctx):
                return self._build_error(403, "Permission denied for this board")

            # Parse structured filters (§13.4)
            event_type_mask = struct.unpack(">I", data[idx:idx + 4])[0]
            idx += 4
            actor_pubkey_filter = data[idx:idx + 32]
            idx += 32
            subject_pubkey_filter = data[idx:idx + 32]
            idx += 32
            target_message_id_filter = data[idx:idx + 32]
            idx += 32
            created_after = struct.unpack(">q", data[idx:idx + 8])[0]
            idx += 8
            created_before = struct.unpack(">q", data[idx:idx + 8])[0]
            idx += 8

            # text_query (u16 string)
            tq_len = struct.unpack(">H", data[idx:idx + 2])[0]
            idx += 2
            text_query = data[idx:idx + tq_len].decode("utf-8") if tq_len > 0 else ""
            idx += tq_len

            offset = struct.unpack(">I", data[idx:idx + 4])[0]
            idx += 4
            limit = struct.unpack(">H", data[idx:idx + 2])[0]
            idx += 2
            flags = struct.unpack(">H", data[idx:idx + 2])[0]

            include_cancelled = bool(flags & FLAG_INCLUDE_CANCELLED)
            include_superseded = bool(flags & FLAG_INCLUDE_SUPERSEDED)
            include_purged = bool(flags & FLAG_INCLUDE_PURGED)

            # Normalize zero-valued filters to None for the service
            actor_pubkey = actor_pubkey_filter if actor_pubkey_filter != b"\x00" * 32 else None
            subject_pubkey = subject_pubkey_filter if subject_pubkey_filter != b"\x00" * 32 else None
            target_msg_id = target_message_id_filter if target_message_id_filter != b"\x00" * 32 else None

            service = self._engine.article_service
            if service is None:
                return self._build_error(500, "Article service not configured")

            results = service.search_articles(
                origin, board, text_query=text_query,
                offset=offset, limit=limit,
                include_cancelled=include_cancelled,
                include_superseded=include_superseded,
                include_purged=include_purged,
                actor_pubkey=actor_pubkey,
                subject_pubkey=subject_pubkey,
                created_after=created_after if created_after != 0 else 0,
                created_before=created_before if created_before != 0 else 0,
            )

            state_map = {
                "active": STATE_ACTIVE, "cancelled": STATE_CANCELLED,
                "superseded": STATE_SUPERSEDED, "purged": STATE_PURGED,
            }

            out = struct.pack(">B", 0x00)
            out += struct.pack(">B", 1)  # body_search_complete = true
            out += struct.pack(">H", len(results))
            for view in results:
                encoded = encode_event(view.event)
                projected_state = state_map.get(view.projected_state, STATE_ACTIVE)
                out += struct.pack(">I", len(encoded)) + encoded
                out += struct.pack(">B", projected_state)
                out += struct.pack(">H", len(view.control_event_ids))
                for cid in view.control_event_ids:
                    out += cid
                out += struct.pack(">B", BODY_AVAILABLE_NOT_INCLUDED)
                out += struct.pack(">I", 0)
            return out
        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_v3_board_set_state(self, data: bytes, ctx: CommandContext) -> bytes:
        """BOARD_SET_STATE — publish BOARD_CLOSE or BOARD_REOPEN via the feed.

        Uses the same request and success framing as ARTICLE_PUBLISH (§13.4),
        but accepts only BOARD_CLOSE (0x0A) or BOARD_REOPEN (0x0B) submissions
        and applies the privileged board-state handler. The submitted event
        remains author-signed.

        Per §14.1:
        - Reject BOARD_CLOSE when already closed and BOARD_REOPEN when already
          open as idempotent conflict errors, unless the identical message ID
          was already accepted.
        - Requires administrator authority (not just ACL grant).
        """
        if not ctx.is_registered:
            return self._build_error(401, "Authentication required")

        if not ctx.is_administrator():
            return self._build_error(403, "Administrator authority required for board state changes")

        try:
            from core.article_feed import (
                decode_submission, validate_submission, verify_author_signature,
                SCHEME_V3, EVENT_BOARD_CLOSE, EVENT_BOARD_REOPEN,
                encode_event, encode_head, compute_body_hash,
            )

            idx = 0
            sub_len = struct.unpack(">I", data[idx:idx + 4])[0]
            idx += 4
            encoded_sub = data[idx:idx + sub_len]
            idx += sub_len
            body_len = struct.unpack(">I", data[idx:idx + 4])[0]
            idx += 4
            body = data[idx:idx + body_len]
            idx += body_len
            author_scheme = data[idx]
            idx += 1
            sig_len = struct.unpack(">H", data[idx:idx + 2])[0]
            idx += 2
            author_sig = data[idx:idx + sig_len]

            submission = decode_submission(encoded_sub)
            validate_submission(submission)

            # Only BOARD_CLOSE or BOARD_REOPEN are accepted
            if submission.event_type not in (EVENT_BOARD_CLOSE, EVENT_BOARD_REOPEN):
                return self._build_error(400, "BOARD_SET_STATE accepts only BOARD_CLOSE or BOARD_REOPEN")

            # Verify the submission origin matches local origin
            if submission.origin != self._config.origin:
                return self._build_error(403, "Submission origin does not match server origin")

            # Check board write permission
            if not self._engine.check_permission("write", submission.board, ctx):
                return self._build_error(403, "Permission denied for this board")

            # Verify author signature for scheme 1
            if author_scheme == SCHEME_V3:
                if not verify_author_signature(submission, author_sig, submission.actor_pubkey):
                    return self._build_error(403, "Author signature verification failed")
            else:
                return self._build_error(400, "Only scheme 1 is supported for board state changes")

            # Verify body hash
            actual_hash = compute_body_hash(body)
            if actual_hash != submission.body_hash:
                return self._build_error(400, "body_hash does not match supplied body")
            if len(body) != submission.body_size:
                return self._build_error(400, "body_size does not match supplied body")

            # Check that the actor pubkey matches the authenticated user
            if ctx.peer_public_key != submission.actor_pubkey:
                return self._build_error(403, "Actor pubkey does not match authenticated key")

            # Check current board closed state for idempotent conflict rules
            nav_entry = self._ame.get_nav().get(submission.board)
            currently_closed = nav_entry['closed'] if nav_entry else False

            if submission.event_type == EVENT_BOARD_CLOSE and currently_closed:
                # Idempotent: if same message_id already accepted, return success
                existing = self._engine.article_service.store.get_event_by_message_id(
                    submission.message_id)
                if existing is not None:
                    event = existing
                    head = self._engine.article_service.store.get_head(
                        submission.origin, submission.board)
                    encoded_event = encode_event(event)
                    encoded_head_bytes = encode_head(head) if head else b""
                    return (
                        struct.pack(">B", 0x00)
                        + struct.pack(">I", len(encoded_event)) + encoded_event
                        + struct.pack(">H", len(encoded_head_bytes)) + encoded_head_bytes
                    )
                return self._build_error(409, "Board is already closed")

            if submission.event_type == EVENT_BOARD_REOPEN and not currently_closed:
                existing = self._engine.article_service.store.get_event_by_message_id(
                    submission.message_id)
                if existing is not None:
                    event = existing
                    head = self._engine.article_service.store.get_head(
                        submission.origin, submission.board)
                    encoded_event = encode_event(event)
                    encoded_head_bytes = encode_head(head) if head else b""
                    return (
                        struct.pack(">B", 0x00)
                        + struct.pack(">I", len(encoded_event)) + encoded_event
                        + struct.pack(">H", len(encoded_head_bytes)) + encoded_head_bytes
                    )
                return self._build_error(409, "Board is already open")

            # Dispatch to ArticleService
            service = self._engine.article_service
            if service is None:
                return self._build_error(500, "Article service not configured")

            event, head = service.publish_article_raw(
                submission.event_type, submission, body, author_sig)

            # Update nav closed state (derived read optimization, §6.9)
            if submission.event_type == EVENT_BOARD_CLOSE:
                self._ame.get_nav()._set_board_closed(submission.board)
            elif submission.event_type == EVENT_BOARD_REOPEN:
                with self._ame.get_nav()._db.open() as nav_ctx:
                    nav_ctx.execute(
                        "UPDATE nav SET closed = 0 WHERE board_name = ?",
                        [submission.board])

            # Build response: same framing as ARTICLE_PUBLISH
            encoded_event = encode_event(event)
            encoded_head_bytes = encode_head(head)
            return (
                struct.pack(">B", 0x00)
                + struct.pack(">I", len(encoded_event)) + encoded_event
                + struct.pack(">H", len(encoded_head_bytes)) + encoded_head_bytes
            )
        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_v3_ban_status(self, data: bytes, ctx: CommandContext) -> bytes:
        """BAN_STATUS — check effective ban status for a public key.

        Checks both legacy Keibatsu bans and v3 event-derived bans.
        The v3 check uses ModerationService if configured; the legacy check
        uses Keibatsu. During the migration transition, the union of both
        applies (§17.3, §18.6).
        """
        try:
            pubkey = data[0:32]

            # Check v3 event-derived bans first
            mod_service = getattr(self._engine, 'moderation_service', None)
            v3_ban = None
            if mod_service is not None:
                v3_ban = mod_service.is_banned(pubkey)

            # Check legacy bans
            ban_result = self._keibatsu.is_banned(pubkey).result()
            legacy_banned = ban_result[0] if ban_result else False
            legacy_reason = ""
            if ban_result and len(ban_result) > 1 and ban_result[1]:
                legacy_reason = ban_result[1]

            # Union: banned if either says banned (§18.6 transition)
            banned = legacy_banned or (v3_ban.banned if v3_ban else False)

            # Prefer v3 reason if available, else legacy
            if v3_ban and v3_ban.banned:
                reason = v3_ban.reason
                punishment_id = v3_ban.punishment_message_id
                source_origin = v3_ban.source_origin
                source_board = v3_ban.source_board
                expires_at = v3_ban.expires_at
            else:
                reason = legacy_reason
                punishment_id = b"\x00" * 32
                source_origin = ""
                source_board = ""
                expires_at = 0

            reason_b = reason.encode("utf-8")
            origin_b = source_origin.encode("utf-8")
            board_b = source_board.encode("utf-8")

            out = struct.pack(">B", 0x00)
            out += struct.pack(">B", 1 if banned else 0)
            out += struct.pack(">H", len(reason_b)) + reason_b
            out += punishment_id
            out += struct.pack(">H", len(origin_b)) + origin_b
            out += struct.pack(">H", len(board_b)) + board_b
            out += struct.pack(">q", expires_at)
            return out
        except Exception as e:
            return self._build_error(400, str(e))

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

            # Create and store a signed empty feed head (§9: BOARD_CREATE
            # creates and stores the signed empty head before making the board
            # visible in nav.db or BOARD_LIST)
            article_service = getattr(self._engine, 'article_service', None)
            if article_service is not None:
                from core.article_feed import make_empty_head, sign_head, encode_head, compute_head_hash
                article_service.store.create_empty_feed(
                    self._config.origin, board_name, self._server_identity)

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
        origin_bytes = (punishment.origin or "").encode('utf-8')
        origin_sig_bytes = (punishment.origin_sig or "").encode('utf-8')

        payload = struct.pack('>Q', punishment.punishment_id) + \
                  struct.pack('>B', len(origin_bytes)) + origin_bytes + \
                  struct.pack('>Q', punishment.rollover) + \
                  struct.pack('>B', len(pubkey_bytes)) + pubkey_bytes + \
                  struct.pack('>B', len(report_ids_list))

        for report_id in report_ids_list:
            payload += struct.pack('>Q', report_id)

        payload += struct.pack('>q', punishment.expires_at)
        payload += struct.pack('>B', len(notes_bytes)) + notes_bytes
        payload += struct.pack('>B', len(issued_by_bytes)) + issued_by_bytes
        payload += struct.pack('>q', punishment.created_at)
        payload += struct.pack('>B', len(origin_sig_bytes)) + origin_sig_bytes

        return payload

    def _cmd_punishment_get(self, data: bytes, ctx: CommandContext) -> bytes:
        try:
            offset = 0
            # §12.4: PUNISHMENT_GET now takes (origin: u8-length UTF-8, punishment_id: u64be)
            origin_len = data[offset]
            offset += 1
            origin = data[offset:offset+origin_len].decode('utf-8')
            offset += origin_len
            punishment_id = struct.unpack('>Q', data[offset:offset+8])[0]

            result = self._keibatsu.get_punishment(punishment_id, origin=origin)
            punishment = result.result()

            if punishment is None:
                return self._build_error(404, f"No punishment found for {origin}:{punishment_id}")

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

    # ------------------------------------------------------------------
    # Report registry commands (opcodes 0x55–0x59) — mirror user registry
    # ------------------------------------------------------------------

    def _get_report_registry_service(self):
        svc = getattr(self._engine, 'report_registry_service', None)
        if svc is None:
            return None
        return svc

    def _get_report_registry_store(self):
        store = getattr(self._engine, 'report_registry_store', None)
        if store is None:
            return None
        return store

    def _cmd_report_registry_head(self, data: bytes, ctx: CommandContext) -> bytes:
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

            svc = self._get_report_registry_service()
            store = self._get_report_registry_store()

            if svc is not None and origin == self._config.origin:
                head = svc.build_snapshot()
            elif store is not None:
                head = store.get_head(origin, requested_seq)
            else:
                head = None

            if head is None:
                return self._build_error(404, f"No report registry head for origin '{origin}'")

            from core.merkle_registry import encode_head
            encoded = encode_head(head)
            return struct.pack(">B", 0x00) + struct.pack(">H", len(encoded)) + encoded

        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_report_registry_nodes(self, data: bytes, ctx: CommandContext) -> bytes:
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

            store = self._get_report_registry_store()
            if store is None:
                return self._build_error(503, "Report registry not available")

            from core.merkle_registry import TREE_DEPTH, get_default_hashes
            from core.report_registry import REGISTRY_TYPE_REPORTS

            defaults = get_default_hashes(REGISTRY_TYPE_REPORTS)

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
                        node_hash = defaults[level]
                    else:
                        node_hash = b"\x00" * 32

                is_leaf = (level == TREE_DEPTH)
                is_default = (node_hash == defaults[level])

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
                        left_hash = defaults[level + 1]
                    if right_hash is None:
                        right_hash = defaults[level + 1]
                    response += left_hash + right_hash
                elif node_kind == 2:
                    record = store.get_record(origin, prefix_int.to_bytes(32, "big"))
                    if record is not None:
                        from core.merkle_registry import compute_value_hash
                        vh = compute_value_hash(REGISTRY_TYPE_REPORTS, record)
                        response += prefix_int.to_bytes(32, "big") + vh
                    else:
                        response += b"\x00" * 64

            return response

        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_report_registry_records(self, data: bytes, ctx: CommandContext) -> bytes:
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

            store = self._get_report_registry_store()
            if store is None:
                return self._build_error(503, "Report registry not available")

            state = store.get_state(origin)
            if state is None:
                return self._build_error(404, f"No report registry for origin '{origin}'")
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

    def _cmd_report_registry_heads(self, data: bytes, ctx: CommandContext) -> bytes:
        try:
            if len(data) < 6:
                return self._build_error(400, "Request too short")
            offset_val = struct.unpack(">I", data[:4])[0]
            limit = struct.unpack(">H", data[4:6])[0]
            if limit > 100:
                limit = 100

            store = self._get_report_registry_store()
            if store is None:
                return self._build_error(503, "Report registry not available")

            heads = store.list_heads(offset=offset_val, limit=limit)
            from core.merkle_registry import encode_head

            response = struct.pack(">B", 0x00) + struct.pack(">H", len(heads))
            for head in heads:
                encoded = encode_head(head)
                response += struct.pack(">H", len(encoded)) + encoded
            return response

        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_report_registry_head_chain(self, data: bytes, ctx: CommandContext) -> bytes:
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

            store = self._get_report_registry_store()
            if store is None:
                return self._build_error(503, "Report registry not available")

            state = store.get_state(origin)
            if state is None:
                return self._build_error(404, f"No report registry for origin '{origin}'")

            from core.merkle_registry import encode_head

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

    # ------------------------------------------------------------------
    # Punishment registry commands (opcodes 0x65–0x69) — mirror report registry
    # ------------------------------------------------------------------

    def _get_punishment_registry_service(self):
        svc = getattr(self._engine, 'punishment_registry_service', None)
        if svc is None:
            return None
        return svc

    def _get_punishment_registry_store(self):
        store = getattr(self._engine, 'punishment_registry_store', None)
        if store is None:
            return None
        return store

    def _cmd_punishment_registry_head(self, data: bytes, ctx: CommandContext) -> bytes:
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

            svc = self._get_punishment_registry_service()
            store = self._get_punishment_registry_store()

            if svc is not None and origin == self._config.origin:
                head = svc.build_snapshot()
            elif store is not None:
                head = store.get_head(origin, requested_seq)
            else:
                head = None

            if head is None:
                return self._build_error(404, f"No punishment registry head for origin '{origin}'")

            from core.merkle_registry import encode_head
            encoded = encode_head(head)
            return struct.pack(">B", 0x00) + struct.pack(">H", len(encoded)) + encoded

        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_punishment_registry_nodes(self, data: bytes, ctx: CommandContext) -> bytes:
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

            store = self._get_punishment_registry_store()
            if store is None:
                return self._build_error(503, "Punishment registry not available")

            from core.merkle_registry import TREE_DEPTH, get_default_hashes, compute_value_hash
            from core.punishment_registry import REGISTRY_TYPE_PUNISHMENTS

            defaults = get_default_hashes(REGISTRY_TYPE_PUNISHMENTS)

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
                        node_hash = defaults[level]
                    else:
                        node_hash = b"\x00" * 32

                is_leaf = (level == TREE_DEPTH)
                is_default = (node_hash == defaults[level])

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
                        left_hash = defaults[level + 1]
                    if right_hash is None:
                        right_hash = defaults[level + 1]
                    response += left_hash + right_hash
                elif node_kind == 2:
                    record = store.get_record(origin, prefix_int.to_bytes(32, "big"))
                    if record is not None:
                        vh = compute_value_hash(REGISTRY_TYPE_PUNISHMENTS, record)
                        response += prefix_int.to_bytes(32, "big") + vh
                    else:
                        response += b"\x00" * 64

            return response

        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_punishment_registry_records(self, data: bytes, ctx: CommandContext) -> bytes:
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

            store = self._get_punishment_registry_store()
            if store is None:
                return self._build_error(503, "Punishment registry not available")

            state = store.get_state(origin)
            if state is None:
                return self._build_error(404, f"No punishment registry for origin '{origin}'")
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

    def _cmd_punishment_registry_heads(self, data: bytes, ctx: CommandContext) -> bytes:
        try:
            if len(data) < 6:
                return self._build_error(400, "Request too short")
            offset_val = struct.unpack(">I", data[:4])[0]
            limit = struct.unpack(">H", data[4:6])[0]
            if limit > 100:
                limit = 100

            store = self._get_punishment_registry_store()
            if store is None:
                return self._build_error(503, "Punishment registry not available")

            heads = store.list_heads(offset=offset_val, limit=limit)
            from core.merkle_registry import encode_head

            response = struct.pack(">B", 0x00) + struct.pack(">H", len(heads))
            for head in heads:
                encoded = encode_head(head)
                response += struct.pack(">H", len(encoded)) + encoded
            return response

        except Exception as e:
            return self._build_error(400, str(e))

    def _cmd_punishment_registry_head_chain(self, data: bytes, ctx: CommandContext) -> bytes:
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

            store = self._get_punishment_registry_store()
            if store is None:
                return self._build_error(503, "Punishment registry not available")

            state = store.get_state(origin)
            if state is None:
                return self._build_error(404, f"No punishment registry for origin '{origin}'")

            from core.merkle_registry import encode_head

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
