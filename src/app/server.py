"""Bonnet Firehose Server bootstrap (PROTOCOL.md).

Constructs all firehose protocol components, wires them into an ASGI
HTTP server, and provides a runnable entry point. Replaces the old v3
Bonnet server bootstrap entirely.
"""

from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) or '.')

from core.crypto import Identity
from core.config import FirehoseConfig
from core.binutil import set_rg_path
from core.logging import init_logging, log_msg
from core.firehose import FirehoseStore
from core.bodies import BodyStore
from core.board_projection import board_db_path
from core.global_projections import NavProjection, UserProjection, PolicyProjection
from core.dispatcher import Dispatcher
from core.acl import ACLEvaluator, ACLRule, PrincipalMatcher, default_rules_for_admin
from core.kind_validator import KindValidator
from core.search import SearchService
from core.record import (
    Intent, MetadataMap, ZERO_ID,
    encode_intent, sign_intent, compute_body_hash,
    metadata_text, metadata_text_list, metadata_bytes, metadata_u64,
)
from net.firehose_commands import FirehoseCommandHandler, FirehoseContext
from net.firehose_http_server import FirehoseHTTPServer
from net.firehose_sync import SyncManager as FirehoseSyncManager, HttpSyncClient
from net.replay import ReplayLedger
from net.rate_limiter import RateLimiter
from app.cli import FirehoseLocalConnection

import struct


class BonnetFirehoseServer:
    """Complete Bonnet firehose server: all components wired and runnable."""

    def __init__(self, config: FirehoseConfig):
        self.config = config

        os.makedirs(config.data_dir, exist_ok=True)
        os.makedirs(config.boards_dir, exist_ok=True)
        os.makedirs(config.events_bodies_dir, exist_ok=True)

        set_rg_path(config.rg_path)
        log_msg(f"INIT: rg_path={config.rg_path or '(auto-resolve)'}")

        identity_path = config.identity_path
        if os.path.exists(identity_path):
            with open(identity_path, "rb") as f:
                key_bytes = f.read()
            self.server_identity = Identity.from_private_key(key_bytes)
        else:
            self.server_identity = Identity.generate()
            with open(identity_path, "wb") as f:
                f.write(self.server_identity.private_key)
            log_msg(f"INIT: generated new server identity at {identity_path}")

        log_msg(f"INIT: server_identity pubkey={self.server_identity.public_key.hex()}")

        self.anonymous_identity = Identity.generate()
        log_msg(f"INIT: anonymous_key={self.anonymous_identity.public_key.hex()}")

        self.firehose = FirehoseStore(config.events_db_path)
        self.firehose.init_origin_key(config.origin, self.server_identity.public_key)
        log_msg(f"INIT: FirehoseStore at {config.events_db_path}")

        self.nav = NavProjection(config.nav_db_path)
        self.users = UserProjection(config.users_db_path)
        self.policy = PolicyProjection(config.policy_db_path)
        log_msg(f"INIT: projections initialized (nav, users, policy)")

        self.body_store = BodyStore(
            boards_dir=config.boards_dir,
            events_dir=config.events_bodies_dir,
        )
        log_msg(f"INIT: BodyStore at boards={config.boards_dir}, events={config.events_bodies_dir}")

        self.dispatcher = Dispatcher(
            firehose=self.firehose,
            nav=self.nav,
            users=self.users,
            policy=self.policy,
            boards_dir=config.boards_dir,
            body_store=self.body_store,
        )
        log_msg("INIT: Dispatcher initialized")

        acl = config.acl
        if not acl._rules and config.admin_pubkey_hex:
            acl = ACLEvaluator(default_rules_for_admin(config.admin_pubkey_hex))
        elif not acl._rules:
            acl = ACLEvaluator(default_rules_for_admin(self.server_identity.public_key.hex()))
            log_msg("INIT: no ACL rules configured, defaulting to server identity as admin")

        self.validator = KindValidator()
        self.search = SearchService(
            boards_dir=config.boards_dir,
            body_store=self.body_store,
            max_count=config.search_max_count,
            timeout_seconds=config.search_timeout_seconds,
            result_limit=config.search_result_limit,
        )

        self.sync_manager = FirehoseSyncManager(
            self.firehose, self.server_identity, config.hostname,
            dispatcher=self.dispatcher,
        )
        if config.peers:
            for peer in config.peers:
                log_msg(f"INIT: configured peer '{peer.origin}' at {peer.hostname}:{peer.port} (verify_tls={peer.verify_tls})")

        self.command_handler = FirehoseCommandHandler(
            firehose=self.firehose,
            server_identity=self.server_identity,
            config_origin=config.origin,
            nav=self.nav,
            users=self.users,
            policy=self.policy,
            body_store=self.body_store,
            boards_dir=config.boards_dir,
            acl=acl,
            validator=self.validator,
            search=self.search,
            hostname=config.hostname,
            dispatcher=self.dispatcher,
            sync_manager=self.sync_manager,
        )
        log_msg("INIT: FirehoseCommandHandler initialized")

        self.replay_ledger = ReplayLedger(
            config.replay_db_path,
            clock_skew_seconds=config.clock_skew_seconds,
        )
        self.rate_limiter = RateLimiter(
            max_requests=config.rate_limit_requests,
            window_seconds=config.rate_limit_window,
        )

        self.http_server = FirehoseHTTPServer(
            command_handler=self.command_handler,
            server_identity=self.server_identity,
            config=config,
            anonymous_identity=self.anonymous_identity,
            replay_ledger=self.replay_ledger,
            rate_limiter=self.rate_limiter,
            users_projection=self.users,
        )
        log_msg("INIT: FirehoseHTTPServer initialized")

        self.dispatcher.dispatch_origin(config.origin)
        log_msg(f"INIT: dispatched local origin '{config.origin}'")

        for row in self.firehose._conn.execute(
            "SELECT DISTINCT origin FROM origin_state WHERE origin != ?", (config.origin,)
        ).fetchall():
            remote = row[0]
            count = self.dispatcher.dispatch_origin(remote)
            if count:
                log_msg(f"INIT: dispatched remote origin '{remote}' ({count} records)")

        self.local_conn = FirehoseLocalConnection(
            self.server_identity.public_key, config.origin,
        )

        log_msg("INIT: complete")

    async def run(self, port: int = None, ssl_certfile: str = None, ssl_keyfile: str = None):
        import uvicorn

        listen_port = port or self.config.port
        if ssl_certfile is None and self.config.tls_enabled and self.config.tls_cert_path:
            ssl_certfile = self.config.tls_cert_path
        if ssl_keyfile is None and self.config.tls_enabled and self.config.tls_key_path:
            ssl_keyfile = self.config.tls_key_path

        print(f"Bonnet firehose server listening on port {listen_port}")
        print(f"Origin: {self.config.origin}")
        print(f"Hostname: {self.config.hostname}")
        print(f"Server public key: {self.server_identity.public_key.hex()}")
        print(f"Anonymous key: {self.anonymous_identity.public_key.hex()}")

        uv_config = uvicorn.Config(
            self.http_server,
            host=self.config.http_host,
            port=listen_port,
            ssl_certfile=ssl_certfile,
            ssl_keyfile=ssl_keyfile,
            log_level="info",
        )
        server = uvicorn.Server(uv_config)

        repl_task = asyncio.create_task(self.repl_loop())

        for peer in self.config.peers:
            base_url = f"https://{peer.hostname}:{peer.port}"
            client = HttpSyncClient(base_url, verify_tls=peer.verify_tls)
            self.sync_manager.start_origin(peer.origin, client, self.config.sync_interval_seconds)
            log_msg(f"SYNC: started background sync for peer '{peer.origin}' from {base_url}")

        try:
            await server.serve()
        finally:
            repl_task.cancel()
            try:
                await repl_task
            except asyncio.CancelledError:
                pass
            await self.sync_manager.stop_all()

    # ------------------------------------------------------------------
    # REPL
    # ------------------------------------------------------------------

    async def repl_loop(self):
        loop = asyncio.get_event_loop()

        while True:
            try:
                line = await loop.run_in_executor(None, lambda: input("bonnet> "))
            except EOFError:
                break

            line = line.strip()
            if not line:
                continue

            log_msg(f"REPL: input='{line}'")
            parts = line.split()
            cmd = parts[0].lower() if parts else ""

            if cmd == "publish-article":
                try:
                    result = await self._repl_publish_article(parts[1:])
                except Exception as e:
                    result = f"Error: {e}"
            elif cmd == "register-user":
                try:
                    result = await self._repl_register_user(parts[1:])
                except Exception as e:
                    result = f"Error: {e}"
            elif cmd == "create-board":
                try:
                    result = await self._repl_create_board(parts[1:])
                except Exception as e:
                    result = f"Error: {e}"
            else:
                try:
                    result = self.dispatch_local_command(line)
                except Exception as e:
                    result = f"Error: {e}"

            if result is None:
                break

            if result:
                print(result)

    def dispatch_local_command(self, line) -> str:
        parts = line.split()
        cmd = parts[0].lower()

        if cmd in ("quit", "exit"):
            return None

        if cmd == "help":
            return self._cmd_help()

        if cmd == "whoami":
            return self._cmd_whoami()

        if cmd == "list-boards":
            return self._cmd_list_boards()

        if cmd == "create-board":
            return self._cmd_create_board(parts)

        if cmd == "get-article":
            return self._cmd_get_article(parts)

        if cmd == "list-articles":
            return self._cmd_list_articles(parts)

        if cmd == "search-articles":
            return self._cmd_search_articles(parts)

        if cmd == "query-articles":
            return self._cmd_query_articles(parts)

        if cmd == "list-users":
            return self._cmd_list_users()

        if cmd == "ban-status":
            return self._cmd_ban_status(parts)

        if cmd == "event-head":
            return self._cmd_event_head(parts)

        if cmd == "event-range":
            return self._cmd_event_range(parts)

        if cmd == "get-event":
            return self._cmd_get_event(parts)

        if cmd == "debug-nav":
            return self._cmd_debug_nav(parts)

        return f"Unknown command: {cmd}. Type 'help' for commands."

    def _cmd_help(self) -> str:
        return """Commands:
  help                          Show this help
  whoami                        Show server identity
  create-board <name>           Create a board (interactive)
  publish-article <board> [reply-to-num] [supersede-num]
                                Publish an article (interactive)
  register-user <name>          Register a user identity
  list-boards [origin]          List boards
  get-article <board> <num>     Get article by number
  list-articles <board> [off] [n]
                                List articles
  search-articles <board> <query>
                                Search article metadata
  query-articles <board> [filters]
                                Query articles by structured fields
  list-users [origin]           List registered users
  ban-status <pubkey-hex>       Check ban status
  event-head <origin>           Show firehose head
  event-range <origin> <start> <count>
                                Show firehose events
  get-event <origin> <event-id-hex>
                                Show full event details
  debug-nav [origin]            Dump nav.db state
  quit                          Exit"""

    def _cmd_whoami(self) -> str:
        return (f"Server pubkey: {self.server_identity.public_key.hex()}\n"
                f"Origin: {self.config.origin}\n"
                f"Role: administrator")

    def _local_handle(self, body: bytes) -> bytes:
        return self.command_handler.handle(body, self.local_conn.to_context())

    def _parse_response_error(self, resp: bytes) -> str:
        if resp[0] == 0x01:
            code = struct.unpack(">H", resp[1:3])[0]
            msg_len = struct.unpack(">H", resp[3:5])[0]
            msg = resp[5:5 + msg_len].decode("utf-8", errors="replace")
            return f"Error 0x{code:04x}: {msg}"
        return "Unknown error"

    def _enc_text16(self, s: str) -> bytes:
        encoded = s.encode("utf-8")
        return struct.pack(">H", len(encoded)) + encoded

    def _read_text16(self, data: bytes, offset: int) -> tuple[str, int]:
        n = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2
        return data[offset:offset + n].decode("utf-8"), offset + n

    # ------------------------------------------------------------------
    # create-board (interactive)
    # ------------------------------------------------------------------

    async def _repl_create_board(self, parts) -> str:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self._do_create_board(parts))

    def _do_create_board(self, parts) -> str:
        if not parts:
            return "Usage: create-board <name>"

        board = parts[0]

        display_name = ""
        try:
            display_name = input("Display name (optional): ").strip()
        except EOFError:
            pass

        m = MetadataMap([
            metadata_bytes(1, self.server_identity.public_key),
        ])
        if display_name:
            m.fields.append(metadata_text(2, display_name))

        import os as _os
        event_id = _os.urandom(32)

        intent = Intent(
            event_id=event_id,
            kind="bonnet.board.create",
            origin=self.config.origin,
            actor_pubkey=self.server_identity.public_key,
            actor_username="root",
            actor_registrar=self.config.origin,
            board=board,
            metadata=m,
        )

        actor_sig = sign_intent(self.server_identity, encode_intent(intent))

        from net.firehose_commands import OP_PUBLISH_RECORD
        req = struct.pack(">B", OP_PUBLISH_RECORD)
        encoded_intent = encode_intent(intent)
        req += struct.pack(">I", len(encoded_intent)) + encoded_intent
        req += actor_sig
        req += struct.pack(">I", 0)

        resp = self._local_handle(req)
        if resp[0] == 0x00:
            return f"Board '{board}' created."

        return self._parse_response_error(resp)

    def _cmd_create_board(self, parts) -> str:
        return self._do_create_board(parts[1:] if parts and parts[0] == "create-board" else parts)

    # ------------------------------------------------------------------
    # publish-article (interactive)
    # ------------------------------------------------------------------

    async def _repl_publish_article(self, parts) -> str:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self._do_publish_article(parts))

    def _do_publish_article(self, parts) -> str:
        if not parts:
            return "Usage: publish-article <board> [reply-to-num] [supersede-num]"

        board = parts[0]

        reply_to_num = 0
        if len(parts) >= 2:
            try:
                reply_to_num = int(parts[1])
            except ValueError:
                return "Invalid reply-to article number"

        supersede_num = 0
        if len(parts) >= 3:
            try:
                supersede_num = int(parts[2])
            except ValueError:
                return "Invalid supersede article number"

        try:
            subject = input("Subject: ").strip()
        except EOFError:
            return "Cancelled."

        tags_input = ""
        try:
            tags_input = input("Tags (comma-separated): ").strip()
        except EOFError:
            pass

        print("Content (empty line to finish):")
        lines = []
        try:
            while True:
                line = input()
                if line == "":
                    break
                lines.append(line)
        except EOFError:
            pass

        content = "\n".join(lines)
        if not content:
            return "Error: Content cannot be empty"

        content_bytes = content.encode("utf-8")
        body_hash = compute_body_hash(content_bytes)

        tags_list = [t.strip() for t in tags_input.split(",") if t.strip()] if tags_input else []

        from core.record import ZERO_ID, metadata_bytes

        m = MetadataMap([
            metadata_text(1, subject),
        ])
        if tags_list:
            m.fields.append(metadata_text_list(2, tags_list))
        m.fields.append(metadata_text(4, "text/plain"))

        root_article_id = ZERO_ID
        reply_to_article_id = ZERO_ID

        if reply_to_num > 0:
            bp = self.dispatcher._get_board_projection(self.config.origin, board)
            target = bp.get_article_by_num(self.config.origin, board, reply_to_num)
            if target is None:
                return f"Error: Article #{reply_to_num} not found in /{board}"

            reply_to_article_id = target.article_id

            target_root = getattr(target, 'root_article_id', ZERO_ID) or ZERO_ID
            if target_root and target_root != ZERO_ID:
                root_article_id = target_root
            else:
                root_article_id = target.article_id

            m.fields.append(metadata_bytes(5, root_article_id))
            m.fields.append(metadata_bytes(6, reply_to_article_id))

        if supersede_num > 0:
            bp = self.dispatcher._get_board_projection(self.config.origin, board)
            supersede_target = bp.get_article_by_num(self.config.origin, board, supersede_num)
            if supersede_target is None:
                return f"Error: Article #{supersede_num} not found in /{board}"
            m.fields.append(metadata_bytes(7, supersede_target.article_id))

        import os as _os
        event_id = _os.urandom(32)
        article_id = _os.urandom(32)

        intent = Intent(
            event_id=event_id,
            kind="bonnet.article",
            origin=self.config.origin,
            actor_pubkey=self.server_identity.public_key,
            actor_username="root",
            actor_registrar=self.config.origin,
            board=board,
            article_id=article_id,
            metadata=m,
            body_hash=body_hash,
            body_size=len(content_bytes),
        )

        actor_sig = sign_intent(self.server_identity, encode_intent(intent))

        from net.firehose_commands import OP_PUBLISH_RECORD
        req = struct.pack(">B", OP_PUBLISH_RECORD)
        encoded_intent = encode_intent(intent)
        req += struct.pack(">I", len(encoded_intent)) + encoded_intent
        req += actor_sig
        req += struct.pack(">I", len(content_bytes)) + content_bytes

        resp = self._local_handle(req)
        if resp[0] == 0x00:
            rec_len = struct.unpack(">I", resp[1:5])[0]
            from core.record import decode_record
            rec = decode_record(resp[5:5 + rec_len])
            return f"Article #{rec.article_num} published.\nSubject: {subject}\nEvent ID: {rec.event_id.hex()}"

        return self._parse_response_error(resp)

    # ------------------------------------------------------------------
    # register-user
    # ------------------------------------------------------------------

    async def _repl_register_user(self, parts) -> str:
        if not parts:
            return "Usage: register-user <name>"

        username = parts[0]
        user_pubkey = self.server_identity.public_key

        m = MetadataMap([
            metadata_text(1, username),
            metadata_bytes(2, user_pubkey),
            metadata_u64(3, 0),
        ])

        import os as _os
        event_id = _os.urandom(32)

        intent = Intent(
            event_id=event_id,
            kind="bonnet.user.register",
            origin=self.config.origin,
            actor_pubkey=self.server_identity.public_key,
            actor_username="root",
            actor_registrar=self.config.origin,
            metadata=m,
        )

        actor_sig = sign_intent(self.server_identity, encode_intent(intent))

        from net.firehose_commands import OP_PUBLISH_RECORD
        req = struct.pack(">B", OP_PUBLISH_RECORD)
        encoded_intent = encode_intent(intent)
        req += struct.pack(">I", len(encoded_intent)) + encoded_intent
        req += actor_sig
        req += struct.pack(">I", 0)

        resp = self._local_handle(req)
        if resp[0] == 0x00:
            return f"User '{username}' registered."

        return self._parse_response_error(resp)

    # ------------------------------------------------------------------
    # list-boards
    # ------------------------------------------------------------------

    def _cmd_list_boards(self, parts=None) -> str:
        origin = parts[1] if parts and len(parts) > 1 else self.config.origin

        from net.firehose_commands import OP_BOARD_LIST
        req = struct.pack(">B", OP_BOARD_LIST) + self._enc_text16(origin)
        resp = self._local_handle(req)

        if resp[0] != 0x00:
            return self._parse_response_error(resp)

        count = struct.unpack(">H", resp[1:3])[0]
        offset = 3
        lines = []
        for _ in range(count):
            name, offset = self._read_text16(resp, offset)
            closed = resp[offset]
            offset += 1
            owner_len = resp[offset]
            offset += 1 + owner_len
            display, offset = self._read_text16(resp, offset)
            status = " [closed]" if closed else ""
            lines.append(f"  /{name}{status}  {display}")

        if not lines:
            return "No boards."
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # get-article
    # ------------------------------------------------------------------

    def _cmd_get_article(self, parts) -> str:
        if len(parts) < 3:
            return "Usage: get-article <board> <num>"

        board = parts[1]
        try:
            article_num = int(parts[2])
        except ValueError:
            return "Invalid article number"

        from net.firehose_commands import OP_ARTICLE_GET
        req = struct.pack(">B", OP_ARTICLE_GET)
        req += self._enc_text16(self.config.origin)
        req += self._enc_text16(board)
        req += struct.pack(">B", 0x01)  # by article_num
        req += struct.pack(">Q", article_num)
        req += struct.pack(">B", 1)  # include body

        resp = self._local_handle(req)
        if resp[0] != 0x00:
            return self._parse_response_error(resp)

        return self._format_article_view(resp[1:], board)

    def _format_article_view(self, data: bytes, board: str) -> str:
        from core.record import ZERO_ID

        offset = 0
        article_num = struct.unpack(">Q", data[offset:offset + 8])[0]
        offset += 8
        aid_len = data[offset]
        offset += 1
        article_id = data[offset:offset + aid_len].hex()
        offset += aid_len
        eid_len = data[offset]
        offset += 1
        event_id = data[offset:offset + eid_len].hex()
        offset += eid_len
        visibility = data[offset]
        offset += 1
        body_state = data[offset]
        offset += 1
        bh_len = data[offset]
        offset += 1 + bh_len
        body_size = struct.unpack(">Q", data[offset:offset + 8])[0]
        offset += 8
        created_at = struct.unpack(">q", data[offset:offset + 8])[0]
        offset += 8
        ap_len = data[offset]
        offset += 1
        author_pubkey = data[offset:offset + ap_len].hex()
        offset += ap_len
        author_username, offset = self._read_text16(data, offset)
        author_registrar, offset = self._read_text16(data, offset)
        subject, offset = self._read_text16(data, offset)
        tags, offset = self._read_text16(data, offset)
        content_type, offset = self._read_text16(data, offset)

        root_len = data[offset]
        offset += 1
        root_id = data[offset:offset + root_len] if root_len else b""
        offset += root_len

        reply_len = data[offset]
        offset += 1
        reply_id = data[offset:offset + reply_len] if reply_len else b""
        offset += reply_len

        has_replacement = data[offset]
        offset += 1
        replacement_id = data[offset:offset + 32] if has_replacement else b""
        offset += 32 if has_replacement else 0

        pin_state, offset = self._read_text16(data, offset)
        thread_state, offset = self._read_text16(data, offset)

        body_len = struct.unpack(">I", data[offset:offset + 4])[0]
        offset += 4
        body = data[offset:offset + body_len].decode("utf-8", errors="replace") if body_len else ""

        from datetime import datetime
        ts = datetime.fromtimestamp(created_at).strftime("%Y-%m-%d %H:%M")

        vis_names = {0: "active", 1: "cancelled", 2: "superseded"}
        body_names = {0: "available", 1: "unavailable", 2: "purged"}

        lines = [
            f"Article #{article_num} in /{board}",
            f"Subject: {subject}",
            f"Created: {ts}",
        ]
        if author_username and author_registrar:
            lines.append(f"Author: {author_username}@{author_registrar}")
        else:
            lines.append(f"Author: {author_pubkey}")
        lines.extend([
            f"Article ID: {article_id}",
            f"Event ID: {event_id}",
            f"Visibility: {vis_names.get(visibility, '?')}",
            f"Body: {body_names.get(body_state, '?')}",
        ])
        if tags:
            lines.append(f"Tags: {tags}")
        if content_type:
            lines.append(f"Content-Type: {content_type}")
        if root_id:
            lines.append(f"Root: {root_id}")
        if reply_id:
            lines.append(f"Reply to: {reply_id}")
        if replacement_id:
            lines.append(f"Supersedes: {replacement_id}")
        if pin_state and pin_state != "unpinned":
            lines.append(f"Pin: {pin_state}")
        if thread_state and thread_state != "open":
            lines.append(f"Thread: {thread_state}")
        lines.append("-" * 40)
        if body:
            lines.append(body)
        else:
            lines.append("(body unavailable)")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # list-articles
    # ------------------------------------------------------------------

    def _cmd_list_articles(self, parts) -> str:
        if len(parts) < 2:
            return "Usage: list-articles [origin] <board> [offset] [limit]"

        origin = self.config.origin
        board = parts[1]
        offset = 0
        limit = 50

        known_origins = set()
        try:
            for row in self.firehose._conn.execute(
                "SELECT DISTINCT origin FROM origin_state"
            ).fetchall():
                known_origins.add(row[0])
        except Exception:
            pass

        if parts[1] in known_origins and len(parts) >= 3:
            origin = parts[1]
            board = parts[2]
            offset = int(parts[3]) if len(parts) > 3 else 0
            limit = int(parts[4]) if len(parts) > 4 else 50
        else:
            offset = int(parts[2]) if len(parts) > 2 else 0
            limit = int(parts[3]) if len(parts) > 3 else 50

        from net.firehose_commands import OP_ARTICLE_LIST
        req = struct.pack(">B", OP_ARTICLE_LIST)
        req += self._enc_text16(origin)
        req += self._enc_text16(board)
        req += struct.pack(">I", offset)
        req += struct.pack(">H", limit)
        req += struct.pack(">B", 0)

        resp = self._local_handle(req)
        if resp[0] != 0x00:
            return self._parse_response_error(resp)

        count = struct.unpack(">H", resp[1:3])[0]
        offset = 3
        lines = []
        for _ in range(count):
            article_num = struct.unpack(">Q", resp[offset:offset + 8])[0]
            offset += 8
            aid_len = resp[offset]
            offset += 1 + aid_len
            eid_len = resp[offset]
            offset += 1 + eid_len
            visibility = resp[offset]
            offset += 1
            body_state = resp[offset]
            offset += 1
            bh_len = resp[offset]
            offset += 1 + bh_len
            body_size = struct.unpack(">Q", resp[offset:offset + 8])[0]
            offset += 8
            created_at = struct.unpack(">q", resp[offset:offset + 8])[0]
            offset += 8
            ap_len = resp[offset]
            offset += 1 + ap_len
            author_username, offset = self._read_text16(resp, offset)
            author_registrar, offset = self._read_text16(resp, offset)
            subject, offset = self._read_text16(resp, offset)
            tags, offset = self._read_text16(resp, offset)
            content_type, offset = self._read_text16(resp, offset)

            root_id_len = resp[offset]
            offset += 1 + root_id_len
            reply_id_len = resp[offset]
            offset += 1 + reply_id_len
            has_replacement = resp[offset]
            offset += 1
            if has_replacement:
                offset += 32
            pin_state, offset = self._read_text16(resp, offset)
            thread_state, offset = self._read_text16(resp, offset)
            body_len = struct.unpack(">I", resp[offset:offset + 4])[0]
            offset += 4 + body_len

            from datetime import datetime
            ts = datetime.fromtimestamp(created_at).strftime("%Y-%m-%d %H:%M")
            lines.append(f"#{article_num:4} | {subject} | {ts}")

        if not lines:
            return "No articles."
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # search-articles
    # ------------------------------------------------------------------

    def _cmd_search_articles(self, parts) -> str:
        if len(parts) < 3:
            return "Usage: search-articles <board> <query>"

        board = parts[1]
        query = " ".join(parts[2:])

        from net.firehose_commands import OP_ARTICLE_SEARCH
        req = struct.pack(">B", OP_ARTICLE_SEARCH)
        req += self._enc_text16(self.config.origin)
        req += self._enc_text16(board)
        req += self._enc_text16(query)
        req += self._enc_text16("")  # no body search
        req += struct.pack(">I", 0)
        req += struct.pack(">H", 50)
        req += struct.pack(">B", 0)

        resp = self._local_handle(req)
        if resp[0] != 0x00:
            return self._parse_response_error(resp)

        count = struct.unpack(">H", resp[1:3])[0]
        total = struct.unpack(">I", resp[3:7])[0]
        truncated = resp[7]
        offset = 8
        lines = []
        for _ in range(count):
            article_num = struct.unpack(">Q", resp[offset:offset + 8])[0]
            offset += 8
            aid_len = resp[offset]
            offset += 1 + aid_len
            subj_len = resp[offset]
            offset += 1
            subject = resp[offset:offset + subj_len].decode("utf-8")
            offset += subj_len
            ap_len = resp[offset]
            offset += 1 + ap_len
            created_at = struct.unpack(">q", resp[offset:offset + 8])[0]
            offset += 8
            body_avail = resp[offset]
            offset += 1
            excerpt, offset = self._read_text16(resp, offset)

            from datetime import datetime
            ts = datetime.fromtimestamp(created_at).strftime("%Y-%m-%d %H:%M")
            lines.append(f"#{article_num:4} | {subject} | {ts}")

        if not lines:
            return "No matches."
        result = "\n".join(lines)
        if truncated:
            result += "\n(results truncated)"
        return result

    # ------------------------------------------------------------------
    # query-articles
    # ------------------------------------------------------------------

    def _cmd_query_articles(self, parts) -> str:
        if len(parts) < 2:
            return ("Usage: query-articles <board> [--author=<hex>] [--user=<name>] "
                    "[--tag=<tag>] [--since=<ts>] [--before=<ts>] "
                    "[--state=active|cancelled|superseded] "
                    "[--root] [--reply-to=<num>] [--pinned] "
                    "[--offset=N] [--limit=N]")

        board = parts[1]

        from core.record import ZERO_ID
        from net.firehose_commands import OP_ARTICLE_QUERY

        filters = []
        list_offset = 0
        limit = 100

        for p in parts[2:]:
            if p.startswith("--author="):
                pk_hex = p.split("=", 1)[1]
                try:
                    pk = bytes.fromhex(pk_hex)
                except ValueError:
                    return "Invalid author pubkey hex"
                filters.append((0x01, 0x01, 0x01, pk))
            elif p.startswith("--user="):
                val = p.split("=", 1)[1].encode("utf-8")
                filters.append((0x02, 0x01, 0x02, val))
            elif p.startswith("--tag="):
                val = p.split("=", 1)[1].encode("utf-8")
                filters.append((0x04, 0x05, 0x02, val))
            elif p.startswith("--since="):
                try:
                    ts = int(p.split("=", 1)[1])
                except ValueError:
                    return "Invalid since timestamp"
                filters.append((0x05, 0x03, 0x03, struct.pack(">q", ts)))
            elif p.startswith("--before="):
                try:
                    ts = int(p.split("=", 1)[1])
                except ValueError:
                    return "Invalid before timestamp"
                filters.append((0x05, 0x04, 0x03, struct.pack(">q", ts)))
            elif p.startswith("--state="):
                val = p.split("=", 1)[1].encode("utf-8")
                filters.append((0x06, 0x01, 0x02, val))
            elif p == "--root":
                filters.append((0x07, 0x01, 0x04, b"\x01"))
            elif p.startswith("--reply-to="):
                try:
                    reply_num = int(p.split("=", 1)[1])
                except ValueError:
                    return "Invalid reply-to article number"
                bp = self.dispatcher._get_board_projection(self.config.origin, board)
                target = bp.get_article_by_num(self.config.origin, board, reply_num)
                if target is None:
                    return f"Error: Article #{reply_num} not found in /{board}"
                filters.append((0x08, 0x01, 0x01, target.article_id))
            elif p == "--pinned":
                filters.append((0x09, 0x01, 0x04, b"\x01"))
            elif p.startswith("--offset="):
                try:
                    list_offset = int(p.split("=", 1)[1])
                except ValueError:
                    return "Invalid offset"
            elif p.startswith("--limit="):
                try:
                    limit = int(p.split("=", 1)[1])
                except ValueError:
                    return "Invalid limit"
            else:
                return f"Unknown flag: {p}"

        req = struct.pack(">B", OP_ARTICLE_QUERY)
        req += self._enc_text16(self.config.origin)
        req += self._enc_text16(board)
        req += struct.pack(">B", len(filters))
        for field_id, operator, value_type, value in filters:
            if isinstance(value, str):
                value = value.encode("utf-8")
            req += struct.pack(">B", field_id)
            req += struct.pack(">B", operator)
            req += struct.pack(">B", value_type)
            req += struct.pack(">H", len(value)) + value
        req += struct.pack(">I", list_offset)
        req += struct.pack(">H", limit)

        resp = self._local_handle(req)
        if resp[0] != 0x00:
            return self._parse_response_error(resp)

        count = struct.unpack(">H", resp[1:3])[0]
        offset = 3
        lines = []
        for _ in range(count):
            article_num = struct.unpack(">Q", resp[offset:offset + 8])[0]
            offset += 8
            aid_len = resp[offset]
            offset += 1 + aid_len
            eid_len = resp[offset]
            offset += 1 + eid_len
            visibility = resp[offset]
            offset += 1
            body_state = resp[offset]
            offset += 1
            bh_len = resp[offset]
            offset += 1 + bh_len
            body_size = struct.unpack(">Q", resp[offset:offset + 8])[0]
            offset += 8
            created_at = struct.unpack(">q", resp[offset:offset + 8])[0]
            offset += 8
            ap_len = resp[offset]
            offset += 1
            author_pubkey = resp[offset:offset + ap_len]
            offset += ap_len
            author_username, offset = self._read_text16(resp, offset)
            author_registrar, offset = self._read_text16(resp, offset)
            subject, offset = self._read_text16(resp, offset)
            tags, offset = self._read_text16(resp, offset)
            content_type, offset = self._read_text16(resp, offset)
            root_len = resp[offset]
            offset += 1 + root_len
            reply_len = resp[offset]
            offset += 1 + reply_len
            has_replacement = resp[offset]
            offset += 1 + (32 if has_replacement else 0)
            pin_state, offset = self._read_text16(resp, offset)
            thread_state, offset = self._read_text16(resp, offset)

            from datetime import datetime
            ts = datetime.fromtimestamp(created_at).strftime("%Y-%m-%d %H:%M")

            author_display = f"{author_username}@{author_registrar}" if author_username else author_pubkey.hex()
            extras = []
            if visibility != 0:
                vis_names = {1: "cancelled", 2: "superseded"}
                extras.append(vis_names.get(visibility, "?"))
            if pin_state and pin_state != "unpinned":
                extras.append(f"pin:{pin_state}")
            if thread_state and thread_state != "open":
                extras.append(f"thread:{thread_state}")
            extra_str = f" [{', '.join(extras)}]" if extras else ""

            lines.append(f"#{article_num:4} | {subject} | {author_display} | {ts}{extra_str}")

        if not lines:
            return "No articles match."
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # list-users
    # ------------------------------------------------------------------

    def _cmd_list_users(self, parts=None) -> str:
        origin = parts[1] if parts and len(parts) > 1 else self.config.origin

        from net.firehose_commands import OP_USER_LIST
        req = struct.pack(">B", OP_USER_LIST) + self._enc_text16(origin) + struct.pack(">B", 0)

        resp = self._local_handle(req)
        if resp[0] != 0x00:
            return self._parse_response_error(resp)

        count = struct.unpack(">H", resp[1:3])[0]
        offset = 3
        lines = []
        for _ in range(count):
            pk_len = resp[offset]
            offset += 1
            pubkey = resp[offset:offset + pk_len].hex()
            offset += pk_len
            username, offset = self._read_text16(resp, offset)
            flags = struct.unpack(">Q", resp[offset:offset + 8])[0]
            offset += 8
            revoked = resp[offset]
            offset += 1
            role = ""
            if flags & 0x01:
                role = " [admin]"
            if flags & 0x02:
                role += " [mod]"
            if revoked:
                role += " [REVOKED]"
            lines.append(f"  {username}  {pubkey}{role}")

        if not lines:
            return "No users."
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # ban-status
    # ------------------------------------------------------------------

    def _cmd_ban_status(self, parts) -> str:
        if len(parts) < 2:
            return "Usage: ban-status <pubkey-hex>"

        try:
            pubkey = bytes.fromhex(parts[1])
        except ValueError:
            return "Invalid hex pubkey"

        from net.firehose_commands import OP_BAN_STATUS
        req = struct.pack(">B", OP_BAN_STATUS) + struct.pack(">B", len(pubkey)) + pubkey

        resp = self._local_handle(req)
        if resp[0] != 0x00:
            return self._parse_response_error(resp)

        banned = resp[1]
        if not banned:
            return "Not banned."

        offset = 2
        eid_len = resp[offset]
        offset += 1
        event_id = resp[offset:offset + eid_len].hex()
        offset += eid_len
        origin, offset = self._read_text16(resp, offset)
        expires_at = struct.unpack(">q", resp[offset:offset + 8])[0]

        if expires_at < 0:
            exp = "permanent"
        elif expires_at == 0:
            exp = "warning"
        else:
            from datetime import datetime
            exp = datetime.fromtimestamp(expires_at).strftime("%Y-%m-%d %H:%M")

        return f"BANNED\nOrigin: {origin}\nExpires: {exp}\nEvent: {event_id}"

    # ------------------------------------------------------------------
    # event-head
    # ------------------------------------------------------------------

    def _cmd_event_head(self, parts) -> str:
        if len(parts) < 2:
            return "Usage: event-head <origin>"

        origin = parts[1]

        from net.firehose_commands import OP_EVENT_HEAD
        req = struct.pack(">B", OP_EVENT_HEAD) + self._enc_text16(origin)

        resp = self._local_handle(req)
        if resp[0] != 0x00:
            return self._parse_response_error(resp)

        head_len = struct.unpack(">H", resp[1:3])[0]
        from core.record import decode_head
        head = decode_head(resp[3:3 + head_len])

        return (f"Origin: {head.origin}\n"
                f"Latest seq: {head.latest_origin_seq}\n"
                f"Event count: {head.event_count}\n"
                f"Latest hash: {head.latest_event_hash.hex()}\n"
                f"Pubkey: {head.origin_pubkey.hex()}")

    # ------------------------------------------------------------------
    # event-range
    # ------------------------------------------------------------------

    def _cmd_event_range(self, parts) -> str:
        if len(parts) < 4:
            return "Usage: event-range <origin> <start> <count>"

        origin = parts[1]
        try:
            start = int(parts[2])
            count = int(parts[3])
        except ValueError:
            return "Invalid start or count"

        from net.firehose_commands import OP_EVENT_RANGE
        req = struct.pack(">B", OP_EVENT_RANGE)
        req += self._enc_text16(origin)
        req += struct.pack(">Q", start)
        req += struct.pack(">H", count)
        req += struct.pack(">I", 0)

        resp = self._local_handle(req)
        if resp[0] != 0x00:
            return self._parse_response_error(resp)

        resp_count = struct.unpack(">H", resp[1:3])[0]
        offset = 3
        lines = []
        for _ in range(resp_count):
            rec_len = struct.unpack(">I", resp[offset:offset + 4])[0]
            offset += 4
            from core.record import decode_record
            rec = decode_record(resp[offset:offset + rec_len])
            offset += rec_len
            w_len = struct.unpack(">H", resp[offset:offset + 2])[0]
            offset += 2 + w_len

            lines.append(f"  seq={rec.origin_seq:4} | {rec.kind:30} | eid={rec.event_id.hex()}")

        if not lines:
            return "No events."
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # get-event
    # ------------------------------------------------------------------

    def _cmd_get_event(self, parts) -> str:
        if len(parts) < 3:
            return "Usage: get-event <origin> <event-id-hex>"

        origin = parts[1]
        try:
            event_id = bytes.fromhex(parts[2])
        except ValueError:
            return "Invalid event ID hex"

        if len(event_id) != 32:
            return "Event ID must be 32 bytes (64 hex chars)"

        from net.firehose_commands import OP_EVENT_GET
        req = struct.pack(">B", OP_EVENT_GET) + self._enc_text16(origin) + event_id

        resp = self._local_handle(req)
        if resp[0] != 0x00:
            return self._parse_response_error(resp)

        offset = 1
        rec_len = struct.unpack(">I", resp[offset:offset + 4])[0]
        offset += 4
        from core.record import decode_record
        rec = decode_record(resp[offset:offset + rec_len])
        offset += rec_len
        w_len = struct.unpack(">H", resp[offset:offset + 2])[0]
        offset += 2
        from core.record import decode_witness, is_origin_witness
        witness = decode_witness(resp[offset:offset + w_len])

        from datetime import datetime
        ts = datetime.fromtimestamp(rec.created_at).strftime("%Y-%m-%d %H:%M:%S")

        lines = [
            f"=== Event ===",
            f"Origin:       {rec.origin}",
            f"Sequence:     {rec.origin_seq}",
            f"Event ID:     {rec.event_id.hex()}",
            f"Kind:         {rec.kind}",
            f"Schema:       {rec.schema_version}",
            f"Created:      {ts}",
            f"",
            f"=== Actor ===",
            f"Pubkey:       {rec.actor_pubkey.hex()}",
        ]

        if rec.actor_username:
            lines.append(f"Username:     {rec.actor_username}")
        if rec.actor_registrar:
            lines.append(f"Registrar:    {rec.actor_registrar}")

        lines.extend([
            f"",
            f"=== Content ===",
            f"Board:        {rec.board or '(none)'}",
            f"Article ID:   {rec.article_id.hex() if rec.article_id != ZERO_ID else '(none)'}",
            f"Article Num:  {rec.article_num if rec.article_num else '(none)'}",
        ])

        if rec.target_origin:
            lines.extend([
                f"",
                f"=== Target ===",
                f"Origin:       {rec.target_origin}",
                f"Board:        {rec.target_board}",
                f"Article ID:   {rec.target_article_id.hex() if rec.target_article_id != ZERO_ID else '(none)'}",
                f"Event ID:     {rec.target_event_id.hex() if rec.target_event_id != ZERO_ID else '(none)'}",
            ])

        lines.extend([
            f"",
            f"=== Body ===",
            f"Hash:         {rec.body_hash.hex()}",
            f"Size:         {rec.body_size} bytes",
        ])

        lines.extend([
            f"",
            f"=== Signatures ===",
            f"Actor sig:    {rec.actor_signature.hex()}",
            f"Origin sig:   {rec.origin_signature.hex()}",
        ])

        if rec.metadata.fields:
            lines.extend([
                f"",
                f"=== Metadata ({len(rec.metadata.fields)} fields) ===",
            ])
            for f in rec.metadata.fields:
                type_names = {1: "BYTES", 2: "TEXT", 3: "U64", 4: "I64", 5: "BOOL", 6: "ID_LIST", 7: "TEXT_LIST"}
                type_name = type_names.get(f.value_type, f"0x{f.value_type:02x}")
                if f.value_type == 2:
                    val = f.value.decode("utf-8", errors="replace")
                elif f.value_type == 3:
                    import struct as _s
                    val = str(_s.unpack(">Q", f.value)[0])
                elif f.value_type == 4:
                    import struct as _s
                    val = str(_s.unpack(">q", f.value)[0])
                elif f.value_type == 5:
                    val = "true" if f.value == b"\x01" else "false"
                elif f.value_type == 1:
                    if len(f.value) == 32:
                        val = f.value.hex()
                    else:
                        val = f"(len={len(f.value)})"
                else:
                    val = f"(len={len(f.value)})"
                lines.append(f"  [{f.field_id}] {type_name}: {val}")

        zero_key = b"\x00" * 32
        from_pubkey = witness.received_from_pubkey.hex() if witness.received_from_pubkey != zero_key else "(origin)"
        lines.extend([
            f"",
            f"=== Witness ===",
            f"Relay pubkey: {witness.relay_pubkey.hex()}",
            f"Relay host:   {witness.relay_hostname}",
            f"From pubkey:  {from_pubkey}",
            f"From host:    {witness.received_from_hostname or '(origin)'}",
            f"Seen at:      {datetime.fromtimestamp(witness.seen_at).strftime('%Y-%m-%d %H:%M:%S')}",
            f"Origin term:  {'yes' if is_origin_witness(witness) else 'no'}",
            f"Event hash:   {witness.event_hash.hex()}",
        ])

        return "\n".join(lines)

    def _cmd_debug_nav(self, parts) -> str:
        import sqlite3 as _sqlite3
        lines = []
        lines.append(f"CWD: {os.getcwd()}")
        lines.append(f"nav_db_path: {self.config.nav_db_path}")
        lines.append(f"nav object id: {id(self.nav)}")
        lines.append(f"dispatcher._nav object id: {id(self.dispatcher._nav)}")
        lines.append(f"command_handler._nav object id: {id(self.command_handler._nav)}")
        lines.append(f"same nav object: {self.nav is self.command_handler._nav}")

        lines.append("")
        lines.append("=== NavProjection.list_boards() (all origins) ===")
        all_boards = self.nav.list_boards()
        lines.append(f"count: {len(all_boards)}")
        for b in all_boards:
            lines.append(f"  origin={b['origin']} board={b['board']} display={b['display_name']} closed={b['closed']}")

        if parts and len(parts) > 1:
            origin = parts[1]
            lines.append("")
            lines.append(f"=== NavProjection.list_boards('{origin}') ===")
            filtered = self.nav.list_boards(origin)
            lines.append(f"count: {len(filtered)}")
            for b in filtered:
                lines.append(f"  origin={b['origin']} board={b['board']} display={b['display_name']} closed={b['closed']}")

        lines.append("")
        lines.append("=== Raw SQLite boards table ===")
        try:
            conn = _sqlite3.connect(str(self.config.nav_db_path))
            rows = conn.execute("SELECT origin, board, display_name, closed FROM boards").fetchall()
            lines.append(f"count: {len(rows)}")
            for r in rows:
                lines.append(f"  origin={r[0]} board={r[1]} display={r[2]} closed={r[3]}")
            conn.close()
        except Exception as e:
            lines.append(f"ERROR: {e}")

        lines.append("")
        lines.append("=== Raw SQLite applied_events ===")
        try:
            conn = _sqlite3.connect(str(self.config.nav_db_path))
            rows = conn.execute("SELECT origin, origin_seq, kind FROM applied_events ORDER BY origin, origin_seq").fetchall()
            lines.append(f"count: {len(rows)}")
            for r in rows:
                lines.append(f"  origin={r[0]} seq={r[1]} kind={r[2]}")
            conn.close()
        except Exception as e:
            lines.append(f"ERROR: {e}")

        lines.append("")
        lines.append("=== Firehose origin_state ===")
        try:
            rows = self.firehose._conn.execute(
                "SELECT origin, highest_seq FROM origin_state ORDER BY origin"
            ).fetchall()
            for r in rows:
                lines.append(f"  origin={r[0]} highest_seq={r[1]}")
        except Exception as e:
            lines.append(f"ERROR: {e}")

        lines.append("")
        lines.append("=== Firehose projection_checkpoints ===")
        try:
            rows = self.firehose._conn.execute(
                "SELECT origin, last_applied_seq FROM projection_checkpoints ORDER BY origin"
            ).fetchall()
            for r in rows:
                lines.append(f"  origin={r[0]} last_applied_seq={r[1]}")
        except Exception as e:
            lines.append(f"ERROR: {e}")

        return "\n".join(lines)

    def close(self):
        self.command_handler.close()
        self.dispatcher.close()
        self.firehose.close()
        self.nav.close()
        self.users.close()
        self.policy.close()
        self.replay_ledger.close()
        log_msg("INIT: shutdown complete")
