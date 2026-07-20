import asyncio
import os
import sys
import struct
import argparse
from datetime import datetime

from core.logging import init_logging, log_msg, log_hex, log_dict, get_log_path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) or '.')
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'build'))

from engine.ume import Ume
from engine.ame import Ame
from net.commands import CommandHandler
from core.crypto import Identity
from core.config import Config
from core.binutil import set_rg_path
from engine.keibatsu import Keibatsu
from app.cli import LocalConnection
from engine.facade import BonnetEngine
from net.http_server import BonnetHTTPServer
from net.replay import ReplayLedger
from net.rate_limiter import RateLimiter
from core.article_feed import ArticleFeedStore
from core.migration import MigrationExecutor
from engine.article_service import ArticleService, UserFeedPublisher
from engine.moderation_service import ModerationService

class Bonnet:
    def __init__(self, userfile_path, identity_path, config):
        self.userfile_path = userfile_path
        log_msg(f"INIT: userfile_path={userfile_path}")
        self.ume = Ume(userfile_path)
        log_msg(f"INIT: Ume loaded, user count={len(list(self.ume.list_all()))}")
        with open(identity_path, 'rb') as f:
            key_bytes = f.read()
        self.server_identity = Identity.from_private_key(key_bytes)
        log_msg(f"INIT: server_identity pubkey={self.server_identity.public_key.hex()}")
        set_rg_path(config.rg_path)
        log_msg(f"INIT: rg_path={config.rg_path or '(auto-resolve)'}")
        self.ame = Ame(config.ame_path, origin=config.origin, signing_key=self.server_identity.signing_key, nav_db_path=config.nav_db_path)
        log_msg(f"INIT: Ame initialized, path={config.ame_path}, origin={config.origin}")
        self.keibatsu = Keibatsu(
            reports_path=config.reports_db_path,
            punishments_path=config.punishments_db_path,
            ume=self.ume,
            signing_key=self.server_identity.signing_key,
            origin=config.origin,
            record_in_window=config.record_in_window
        )
        log_msg(f"INIT: Keibatsu initialized, reports={config.reports_db_path}, punishments={config.punishments_db_path}")
        self.config = config
        log_dict("INIT: config", {
            'origin': config.origin,
            'ame_path': config.ame_path,
            'nav_db_path': config.nav_db_path,
            'timeout_seconds': config.timeout_seconds,
            'anonymous_read': config.anonymous_read,
            'reports_db_path': config.reports_db_path,
            'punishments_db_path': config.punishments_db_path
        })
        self.engine = BonnetEngine(self.ume, self.ame, self.keibatsu, config, self.server_identity)

        # Article feed store + service (protocol v3)
        article_feeds_db_path = os.path.join(config.data_dir, "article_feeds.db")
        article_bodies_dir = os.path.join(config.data_dir, "article_bodies")
        self.article_feed_store = ArticleFeedStore(
            article_feeds_db_path, article_bodies_dir,
            max_body_size=getattr(config, 'max_article_body_size', 1024 * 1024),
        )
        self.article_service = ArticleService(
            self.article_feed_store, config.origin, self.server_identity,
        )
        self.engine.article_service = self.article_service
        self.moderation_service = ModerationService(
            self.article_feed_store, config,
        )
        self.engine.moderation_service = self.moderation_service
        log_msg(f"INIT: ArticleFeedStore at {article_feeds_db_path}")

        # UserFeedPublisher: publishes user registration events to the
        # users.registry feed when UME mutations occur.
        users_board = config.moderation_boards.users
        self.user_feed_publisher = UserFeedPublisher(
            self.article_service, self.server_identity, config.origin, users_board,
        )
        self.ume.register_mutation_callback(self.user_feed_publisher.on_mutation)

        # Ensure the users.registry feed exists
        try:
            existing = self.article_feed_store.get_head(config.origin, users_board)
            if existing is None:
                self.article_feed_store.create_empty_feed(
                    config.origin, users_board, self.server_identity)
                log_msg(f"INIT: created empty feed for users registry '{users_board}'")
        except Exception as e:
            log_msg(f"INIT: users.registry feed creation error (non-fatal): {e}")

        # Reconcile board creation state (§9 lines 707-716):
        # For each local board in nav, ensure a signed empty feed head exists.
        # For each feed_state with no nav entry, log a warning (orphaned feed).
        try:
            nav_entries = self.ame.get_nav().list_all()
            for entry in nav_entries:
                if entry['origin'] == config.origin:
                    board_name = entry['board_name']
                    existing_head = self.article_feed_store.get_head(config.origin, board_name)
                    if existing_head is None:
                        self.article_feed_store.create_empty_feed(
                            config.origin, board_name, self.server_identity)
                        log_msg(f"INIT: created empty feed head for board '{board_name}'")
        except Exception as e:
            log_msg(f"INIT: board feed reconciliation error (non-fatal): {e}")

        # Run migration from legacy v2 data to v3 events (Phase 6)
        # Idempotent: skips already-completed migration units on restart
        try:
            migrator = MigrationExecutor(
                self.article_feed_store, self.server_identity, config,
                ame=self.ame, keibatsu=self.keibatsu,
            )
            mig_results = migrator.migrate_all()
            if any(v > 0 for v in mig_results.values() if isinstance(v, int)):
                log_msg(f"INIT: migration completed — {mig_results}")
        except Exception as e:
            log_msg(f"INIT: migration error (non-fatal): {e}")

        self.command_handler = CommandHandler(self.engine)
        self.root_user = self.ume.ensure_root_user(config.origin, self.server_identity.public_key)
        log_msg(f"INIT: root_user={self.root_user.username}, pubkey={self.root_user.publickey.hex()}")
        self.local_conn = LocalConnection(self.root_user, self.server_identity.public_key)
        self.anonymous_identity = Identity.generate()
        self.replay_ledger = ReplayLedger(
            config.replay_db_path,
            clock_skew_seconds=getattr(config, 'clock_skew_seconds', 30),
        )
        self.rate_limiter = RateLimiter(
            max_requests=getattr(config, 'rate_limit_requests', 100),
            window_seconds=getattr(config, 'rate_limit_window', 1),
        )
        self.http_server = BonnetHTTPServer(
            command_handler=self.command_handler,
            server_identity=self.server_identity,
            config=config,
            ume=self.ume,
            anonymous_identity=self.anonymous_identity,
            replay_ledger=self.replay_ledger,
            rate_limiter=self.rate_limiter,
        )
        log_msg("INIT: complete")

    async def run(self, port, ssl_certfile=None, ssl_keyfile=None):
        print(f"Bonnet server listening on port {port}")
        print(f"Server public key: {self.server_identity.public_key.hex()}")
        print(f"Root user: root@{self.config.origin}")
        print(f"Anonymous key: {self.anonymous_identity.public_key.hex()}")

        import uvicorn
        config = uvicorn.Config(
            self.http_server,
            host=self.config.http_host,
            port=port,
            ssl_certfile=ssl_certfile,
            ssl_keyfile=ssl_keyfile,
            log_level="info",
        )
        server = uvicorn.Server(config)

        # Run REPL and HTTP server concurrently
        repl_task = asyncio.create_task(self.repl_loop())
        try:
            await server.serve()
        finally:
            repl_task.cancel()
            try:
                await repl_task
            except asyncio.CancelledError:
                pass

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

            if cmd == "create-post":
                result = await self._interactive_create_post(parts[1:])
            elif cmd == "update-post":
                result = await self._interactive_update_post(parts[1:])
            else:
                result = self.dispatch_local_command(line)

            if result is None:
                break

            if result:
                print(result)
                log_msg(f"REPL: result='{result[:200]}{'...' if len(result) > 200 else ''}'")

    def dispatch_local_command(self, line) -> str:
        parts = line.split()
        cmd = parts[0].lower()

        log_msg(f"DISPATCH: cmd='{cmd}', parts={parts}")

        if cmd in ("quit", "/quit", "exit", "/exit"):
            log_msg("DISPATCH: quit requested")
            return None

        if cmd in ("help", "/help"):
            return self._cmd_help()

        if cmd == "whoami":
            return self._cmd_whoami()

        if cmd == "register":
            return self._cmd_register(parts)

        if cmd == "get":
            return self._cmd_get(parts)

        if cmd == "list-users":
            return self._cmd_list_users(parts)

        if cmd == "create-board":
            return self._cmd_create_board(parts)

        if cmd == "list-boards":
            return self._cmd_list_boards()

        if cmd == "list-peers":
            return self._cmd_list_peers()

        if cmd == "close-board":
            return self._cmd_close_board(parts)

        if cmd == "delete-board":
            return self._cmd_delete_board(parts)

        if cmd == "list-posts":
            return self._cmd_list_posts(parts)

        if cmd == "get-post":
            return self._cmd_get_post(parts)

        if cmd == "delete-post":
            return self._cmd_delete_post(parts)

        if cmd == "sign-post":
            return self._cmd_sign_post(parts)

        if cmd == "query-posts":
            return self._cmd_query_posts(parts)

        if cmd == "content-search":
            return self._cmd_content_search(parts)

        if cmd == "promote":
            return self._cmd_promote(parts)

        if cmd == "demote":
            return self._cmd_demote(parts)

        if cmd == "list-acls":
            return self._cmd_list_acls()

        if cmd == "check-perm":
            return self._cmd_check_perm(parts)

        return f"Unknown command: {cmd}. Type 'help' for commands."

    def _cmd_help(self) -> str:
        return """Commands:
  help                  Show this help
  whoami                Show current identity
  register <user@reg>   Register new user
  get <username>        Get user info
  list-users [off] [n]  List users
  create-board <name>   Create board (admin)
  close-board <name>    Close board (read-only, admin)
  delete-board <name>   Delete board permanently (admin)
  list-boards           List boards
  list-peers            List known peer servers
  create-post <board> [root]
                         Create post (interactive)
  get-post <board> <n>  Get post
  list-posts <board> [off] [n]
                         List posts
  query-posts <board> [--where=...] [--value=...] [--orderby=...] [--limit=N]
                         Query posts by metadata
  content-search <board> <pattern> [--limit=N]
                         Search post bodies (content) by regex
  update-post <board> <n>
                         Edit post (interactive)
  sign-post <board> <n>
                         Sign a post
  delete-post <board> <n>
                         Delete post
  promote <username>    Promote to moderator (admin)
  demote <username>     Remove moderator (admin)
  list-acls             List ACL entries
  check-perm <board> [username]
                         Check user permission for board
  quit                  Exit"""

    def _cmd_whoami(self) -> str:
        pubkey_hex = self.server_identity.public_key.hex()
        return f"Identity: {pubkey_hex}\nUsername: root\nRegistrar: {self.config.origin}\nRole: Administrator"

    def _cmd_register(self, parts) -> str:
        if len(parts) < 2:
            return "Usage: register <username@registrar>"

        user_reg = parts[1]
        if "@" not in user_reg:
            return "Format: username@registrar"

        username, registrar = user_reg.split("@", 1)
        request = bytes([0x01]) + self._encode_string(username) + self._encode_string(registrar)
        response = self.command_handler.handle(request, self.local_conn.to_context())

        if response[0] == 0x00:
            return f"Registered: {username}"

        return self._parse_error(response)

    def _cmd_get(self, parts) -> str:
        if len(parts) < 2:
            return "Usage: get <username>"

        username = parts[1]
        request = bytes([0x02]) + self._encode_string(username)
        response = self.command_handler.handle(request, self.local_conn.to_context())

        if response[0] == 0x00:
            pubkey = response[1:33].hex()
            registrar = self._decode_string(response, 33)
            return f"Username: {username}\nRegistrar: {registrar}\nPublic Key: {pubkey}"

        return self._parse_error(response)

    def _cmd_list_users(self, parts) -> str:
        offset = 0
        limit = 100

        if len(parts) >= 2:
            try:
                offset = int(parts[1])
            except ValueError:
                pass
        if len(parts) >= 3:
            try:
                limit = int(parts[2])
            except ValueError:
                pass

        request = bytes([0x03]) + struct.pack(">I", offset) + struct.pack(">I", limit)
        response = self.command_handler.handle(request, self.local_conn.to_context())

        if response[0] == 0x00:
            return self._format_user_list(response)

        return self._parse_error(response)

    def _cmd_create_board(self, parts) -> str:
        if len(parts) < 2:
            return "Usage: create-board <name>"

        name = parts[1]
        request = bytes([0x10]) + self._encode_string(name)
        response = self.command_handler.handle(request, self.local_conn.to_context())

        if response[0] == 0x00:
            return f"Board '{name}' created."

        return self._parse_error(response)

    def _cmd_list_boards(self) -> str:
        request = bytes([0x11])
        response = self.command_handler.handle(request, self.local_conn.to_context())

        if response[0] == 0x00:
            return self._format_board_list(response)

        return self._parse_error(response)

    def _cmd_list_peers(self) -> str:
        request = bytes([0x04])
        response = self.command_handler.handle(request, self.local_conn.to_context())

        if response[0] == 0x00:
            return self._format_peer_list(response)

        return self._parse_error(response)

    def _cmd_close_board(self, parts) -> str:
        if len(parts) < 2:
            return "Usage: close-board <name>"

        name = parts[1]
        request = bytes([0x17]) + self._encode_string(name)
        response = self.command_handler.handle(request, self.local_conn.to_context())

        if response[0] == 0x00:
            return f"Board '{name}' closed (read-only)."

        return self._parse_error(response)

    def _cmd_delete_board(self, parts) -> str:
        if len(parts) < 2:
            return "Usage: delete-board <name>"

        name = parts[1]
        request = bytes([0x18]) + self._encode_string(name)
        response = self.command_handler.handle(request, self.local_conn.to_context())

        if response[0] == 0x00:
            return f"Board '{name}' deleted."

        return self._parse_error(response)

    def _cmd_list_posts(self, parts) -> str:
        if len(parts) < 2:
            return "Usage: list-posts <board> [offset] [limit]"

        board = parts[1]
        offset = int(parts[2]) if len(parts) > 2 else 0
        limit = int(parts[3]) if len(parts) > 3 else 50

        request = bytes([0x14]) + self._encode_string(board) + struct.pack(">I", offset) + struct.pack(">I", limit)
        response = self.command_handler.handle(request, self.local_conn.to_context())

        if response[0] == 0x00:
            return self._format_post_list(response)

        return self._parse_error(response)

    def _cmd_get_post(self, parts) -> str:
        if len(parts) < 3:
            return "Usage: get-post <board> <post_num>"

        board = parts[1]
        try:
            post_num = int(parts[2])
        except ValueError:
            return "Invalid post number"

        request = bytes([0x13]) + self._encode_string(board) + struct.pack(">Q", post_num)
        response = self.command_handler.handle(request, self.local_conn.to_context())

        if response[0] == 0x00:
            return self._format_post(response, board)

        return self._parse_error(response)

    async def _interactive_create_post(self, parts):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self._do_create_post(parts))

    async def _interactive_update_post(self, parts):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self._do_update_post(parts))

    def _do_create_post(self, parts) -> str:
        root = 0

        if len(parts) < 1:
            return "Usage: create-post <board> [root]"

        board = parts[0]
        if len(parts) >= 2:
            try:
                root = int(parts[1])
            except ValueError:
                return "Invalid root post number"

        try:
            subject = input("Subject: ").strip()
        except EOFError:
            return "Cancelled."

        try:
            tags = input("Tags (comma-separated): ").strip()
        except EOFError:
            tags = ""

        try:
            options = input("Options: ").strip()
        except EOFError:
            options = ""

        if tags:
            tags_list = [t.strip() for t in tags.split(',') if t.strip()]
            if len(tags_list) > 255:
                return "Error: Too many tags (max 255)"
            for tag in tags_list:
                if len(tag) > 255:
                    return f"Error: Tag too long: {tag[:50]}..."
            tags = ','.join(tags_list)

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

        log_dict("CREATE_POST: input", {
            'board': board,
            'root': root,
            'subject': subject,
            'tags': tags,
            'options': options,
            'content_len': len(content_bytes)
        })

        request = bytes([0x12])
        request += self._encode_string(board)
        request += struct.pack(">Q", root)
        request += self._encode_string(subject)
        request += self._encode_string(tags)
        request += self._encode_string(options)
        request += struct.pack(">I", len(content_bytes)) + content_bytes

        log_hex("CREATE_POST: POST_CREATE request", request)
        log_msg(f"CREATE_POST: local_conn.user={self.local_conn.user.username}, pubkey={self.local_conn.user.publickey.hex()}")

        response = self.command_handler.handle(request, self.local_conn.to_context())
        log_hex("CREATE_POST: POST_CREATE response", response)

        if response[0] == 0x00:
            post_num = struct.unpack(">Q", response[1:9])[0]
            log_msg(f"CREATE_POST: post created, post_num={post_num}")

            get_request = bytes([0x13]) + self._encode_string(board) + struct.pack(">Q", post_num)
            log_hex("CREATE_POST: POST_GET request", get_request)

            get_response = self.command_handler.handle(get_request, self.local_conn.to_context())
            log_hex("CREATE_POST: POST_GET response", get_response)

            if get_response[0] == 0x00:
                post = self._parse_post_data(get_response)
                log_dict("CREATE_POST: parsed post", post)

                signed_payload = self._build_signed_payload(post)
                log_hex("CREATE_POST: signed_payload (client)", signed_payload)

                signature = self.server_identity.sign(signed_payload).hex()
                log_msg(f"CREATE_POST: signature={signature}")
                log_msg(f"CREATE_POST: signing with server_identity pubkey={self.server_identity.public_key.hex()}")

                sign_request = bytes([0x22]) + self._encode_string(board) + struct.pack(">Q", post_num) + self._encode_string(signature)
                log_hex("CREATE_POST: POST_SIGN request", sign_request)

                sign_response = self.command_handler.handle(sign_request, self.local_conn.to_context())
                log_hex("CREATE_POST: POST_SIGN response", sign_response)

                if sign_response[0] == 0x00:
                    log_msg("CREATE_POST: sign success")
                    return self._format_create_response(response) + f"\nSigned: {signature[:16]}..."
                else:
                    log_msg(f"CREATE_POST: sign failed, error={self._parse_error(sign_response)}")
            else:
                log_msg(f"CREATE_POST: get failed, error={self._parse_error(get_response)}")

            return self._format_create_response(response) + "\nWarning: Failed to sign post."
        else:
            log_msg(f"CREATE_POST: create failed, error={self._parse_error(response)}")

        return self._parse_error(response)

    def _do_update_post(self, parts) -> str:
        post_num = 0

        if len(parts) < 2:
            return "Usage: update-post <board> <post_num>"

        board = parts[0]
        try:
            post_num = int(parts[1])
        except ValueError:
            return "Invalid post number"

        get_request = bytes([0x13]) + self._encode_string(board) + struct.pack(">Q", post_num)
        response = self.command_handler.handle(get_request, self.local_conn.to_context())

        if response[0] != 0x00:
            return self._parse_error(response)

        post = self._parse_post_data(response)

        print(f"Editing post #{post_num} in /{board}")
        print(f"Current subject: {post['subject']}")
        print(f"Current tags: {post['tags']}")
        print(f"Current options: {post['options']}")
        content_preview = post['content'][:500] + ("..." if len(post['content']) > 500 else "")
        print(f"Current content ({len(post['content'])} chars):")
        print("-" * 40)
        print(content_preview)
        print("-" * 40)

        fields = []

        try:
            content_input = input("Content [enter to keep, or start new]: ").strip()
            if content_input:
                content_lines = [content_input]
                print("(continue, empty line to finish)")
                try:
                    while True:
                        new_content_line = input()
                        if new_content_line == "":
                            break
                        content_lines.append(new_content_line)
                except EOFError:
                    pass
                fields.append((0x01, "\n".join(content_lines)))
        except EOFError:
            pass

        try:
            new_subject = input(f"Subject [{post['subject']}]: ").strip()
            if new_subject:
                fields.append((0x02, new_subject))
        except EOFError:
            pass

        try:
            new_tags = input(f"Tags [{post['tags']}]: ").strip()
            if new_tags:
                tags_list = [t.strip() for t in new_tags.split(',') if t.strip()]
                if len(tags_list) > 255:
                    return "Error: Too many tags (max 255)"
                for tag in tags_list:
                    if len(tag) > 255:
                        return f"Error: Tag too long: {tag[:50]}..."
                fields.append((0x04, ','.join(tags_list)))
        except EOFError:
            pass

        try:
            new_options = input(f"Options [{post['options']}]: ").strip()
            if new_options:
                fields.append((0x03, new_options))
        except EOFError:
            pass

        is_mod = self.local_conn.is_moderator() or self.local_conn.is_administrator()

        if is_mod:
            try:
                new_sticky = input(f"Sticky [{post['sticky']}, 0=none]: ").strip()
                if new_sticky:
                    try:
                        fields.append((0x05, int(new_sticky)))
                    except ValueError:
                        return "Invalid sticky value"
            except EOFError:
                pass

            try:
                closed_input = input(f"Closed [{'yes' if post['closed'] else 'no'}] (y/n): ").strip().lower()
                if closed_input in ('y', 'n'):
                    fields.append((0x06, closed_input == 'y'))
            except EOFError:
                pass

        if not fields:
            return "No changes made."

        request = bytes([0x15])
        request += self._encode_string(board)
        request += struct.pack(">Q", post_num)
        request += bytes([len(fields)])

        for field_type, value in fields:
            if field_type == 0x01:
                v_bytes = value.encode("utf-8")
                request += bytes([field_type]) + struct.pack(">I", len(v_bytes)) + v_bytes
            elif field_type in (0x02, 0x03, 0x04):
                v_bytes = value.encode("utf-8")
                request += bytes([field_type, len(v_bytes)]) + v_bytes
            elif field_type == 0x05:
                request += bytes([field_type]) + struct.pack(">i", value)
            elif field_type == 0x06:
                request += bytes([field_type, 1 if value else 0])

        response = self.command_handler.handle(request, self.local_conn.to_context())

        if response[0] == 0x00:
            return f"Post #{post_num} updated."

        return self._parse_error(response)

    def _format_create_response(self, data) -> str:
        offset = 1
        from datetime import datetime

        post_num = struct.unpack(">Q", data[offset:offset + 8])[0]
        offset += 8
        creation_date = struct.unpack(">q", data[offset:offset + 8])[0]
        offset += 8
        last_modified = struct.unpack(">q", data[offset:offset + 8])[0]
        offset += 8
        author = self._decode_string(data, offset)
        offset += 1 + len(author.encode())
        author_registrar = self._decode_string(data, offset)
        offset += 1 + len(author_registrar.encode())
        tags = self._decode_string(data, offset)
        offset += 1 + len(tags.encode())
        subject = self._decode_string(data, offset)
        offset += 1 + len(subject.encode())
        options = self._decode_string(data, offset)

        ts = datetime.fromtimestamp(creation_date).strftime("%Y-%m-%d %H:%M")

        return f"Post #{post_num} created.\nSubject: {subject}\nAuthor: {author}@{author_registrar}\nDate: {ts}"

    def _cmd_delete_post(self, parts) -> str:
        if len(parts) < 3:
            return "Usage: delete-post <board> <post_num>"

        board = parts[1]
        try:
            post_num = int(parts[2])
        except ValueError:
            return "Invalid post number"

        request = bytes([0x16]) + self._encode_string(board) + struct.pack(">Q", post_num)
        response = self.command_handler.handle(request, self.local_conn.to_context())

        if response[0] == 0x00:
            return "Post deleted."

        return self._parse_error(response)

    def _cmd_sign_post(self, parts) -> str:
        if len(parts) < 3:
            return "Usage: sign-post <board> <post_num>"

        board = parts[1]
        try:
            post_num = int(parts[2])
        except ValueError:
            return "Invalid post number"

        request = bytes([0x13]) + self._encode_string(board) + struct.pack(">Q", post_num)
        response = self.command_handler.handle(request, self.local_conn.to_context())

        if response[0] != 0x00:
            return self._parse_error(response)

        post = self._parse_post_data(response)
        signed_payload = self._build_signed_payload(post)
        signature = self.server_identity.sign(signed_payload).hex()

        sign_request = bytes([0x22]) + self._encode_string(board) + struct.pack(">Q", post_num) + self._encode_string(signature)
        sign_response = self.command_handler.handle(sign_request, self.local_conn.to_context())

        if sign_response[0] == 0x00:
            return f"Post #{post_num} signed."

        return self._parse_error(sign_response)

    def _cmd_query_posts(self, parts) -> str:
        if len(parts) < 2:
            return "Usage: query-posts <board> [--where=...] [--value=...] [--orderby=...] [--limit=N]"

        board = parts[1]
        where = None
        values = []
        orderby = None
        limit = 0

        for p in parts[2:]:
            if p.startswith("--where="):
                where = p.split("=", 1)[1]
            elif p.startswith("--value="):
                v = p.split("=", 1)[1]
                try:
                    values.append(int(v))
                except ValueError:
                    values.append(v)
            elif p.startswith("--orderby="):
                orderby = p.split("=", 1)[1]
            elif p.startswith("--limit="):
                limit = int(p.split("=", 1)[1])

        request = self._build_query_request(board, where, values, orderby, limit)
        response = self.command_handler.handle(request, self.local_conn.to_context())

        if response[0] == 0x00:
            return self._format_query_results(response)

        return self._parse_error(response)

    def _cmd_content_search(self, parts) -> str:
        if len(parts) < 3:
            return "Usage: content-search <board> <pattern> [--limit=N]"

        board = parts[1]
        limit = 0
        pattern_parts = []
        for i in range(2, len(parts)):
            if parts[i].startswith("--limit="):
                try:
                    limit = int(parts[i].split("=", 1)[1])
                except ValueError:
                    return "Invalid limit"
            else:
                pattern_parts.append(parts[i])

        if not pattern_parts:
            return "Usage: content-search <board> <pattern> [--limit=N]"
        pattern = " ".join(pattern_parts)

        request = self._build_content_search_request(board, pattern, limit)
        response = self.command_handler.handle(request, self.local_conn.to_context())

        if response[0] == 0x00:
            return self._format_query_results(response)

        return self._parse_error(response)

    def _build_content_search_request(self, board, pattern, limit) -> bytes:
        request = self._encode_string(board)
        pattern_bytes = pattern.encode("utf-8")
        request += struct.pack(">I", len(pattern_bytes)) + pattern_bytes
        request += struct.pack(">I", limit)
        return bytes([0x1A]) + request

    def _cmd_promote(self, parts) -> str:
        if len(parts) < 2:
            return "Usage: promote <username>"

        username = parts[1]
        request = bytes([0x20]) + self._encode_string(username)
        response = self.command_handler.handle(request, self.local_conn.to_context())

        if response[0] == 0x00:
            return f"{username} promoted to moderator."

        return self._parse_error(response)

    def _cmd_demote(self, parts) -> str:
        if len(parts) < 2:
            return "Usage: demote <username>"

        username = parts[1]
        request = bytes([0x21]) + self._encode_string(username)
        response = self.command_handler.handle(request, self.local_conn.to_context())

        if response[0] == 0x00:
            return f"{username} demoted from moderator."

        return self._parse_error(response)

    def _cmd_list_acls(self) -> str:
        lines = []

        lines.append(f"Admin bypass ACL: {self.config.admin_bypass_acl}")
        lines.append(f"ACL entries: {len(self.config.acls)}")
        lines.append("")

        for acl in self.config.acls:
            if acl.matcher.anonymous:
                matcher_info = "anonymous=true"
            elif acl.matcher.pubkey:
                matcher_info = f"pubkey={acl.matcher.pubkey.hex()[:16]}..."
            elif acl.matcher.origin_pattern:
                matcher_info = f"origin={acl.matcher.origin_pattern}"
            else:
                matcher_info = "wildcard=*"

            boards_info = ",".join(acl.board_patterns[:3])
            if len(acl.board_patterns) > 3:
                boards_info += "..."

            lines.append(f"  [{acl.name}]")
            lines.append(f"    match: {matcher_info}")
            lines.append(f"    boards: {boards_info}")
            lines.append(f"    read={acl.read_perm}, write={acl.write_perm}")

        return "\n".join(lines)

    def _cmd_check_perm(self, parts) -> str:
        if len(parts) < 2:
            return "Usage: check-perm <board> [username]"

        board = parts[1]
        username = parts[2] if len(parts) > 2 else "root"

        user = self.ume.get(username=username)
        if user is None:
            return f"User '{username}' not found"

        conn = LocalConnection(user, user.publickey, self.engine, origin=user.record_origin)

        can_read = self.engine.check_permission("read", board, conn.to_context())
        can_write = self.engine.check_permission("write", board, conn.to_context())

        board_owner = self.ame.get_board_owner(board)
        owner_info = f"owner={board_owner.hex()[:16]}..." if board_owner else "owner=none"

        return f"User: {username}@{user.record_origin}\nBoard: {board} ({owner_info})\nRead: {can_read}\nWrite: {can_write}"

    def _encode_string(self, s) -> bytes:
        encoded = s.encode("utf-8")
        return struct.pack("B", len(encoded)) + encoded

    def _decode_string(self, data, offset) -> str:
        length = data[offset]
        return data[offset + 1:offset + 1 + length].decode("utf-8")

    def _parse_error(self, response) -> str:
        if response[0] == 0x01:
            code = struct.unpack(">H", response[1:3])[0]
            msg_len = response[3]
            msg = response[4:4 + msg_len].decode("utf-8")
            return f"Error 0x{code:04x}: {msg}"
        return "Unknown error"

    def _format_user_list(self, data) -> str:
        offset = 1
        count = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2

        lines = []
        for _ in range(count):
            username = self._decode_string(data, offset)
            offset += 1 + len(username.encode())
            registrar = self._decode_string(data, offset)
            offset += 1 + len(registrar.encode())
            origin = self._decode_string(data, offset)
            offset += 1 + len(origin.encode())
            relay = self._decode_string(data, offset)
            offset += 1 + len(relay.encode())
            key_len = data[offset]
            offset += 1
            pubkey = data[offset:offset + key_len].hex()
            offset += key_len
            lines.append(f"  {username}@{registrar} o={origin} r={relay} {pubkey[:16]}...")

        if not lines:
            return "No users."
        return "\n".join(lines)

    def _format_board_list(self, data) -> str:
        offset = 1
        count = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2

        lines = []
        for _ in range(count):
            name = self._decode_string(data, offset)
            offset += 1 + len(name.encode())
            origin = self._decode_string(data, offset)
            offset += 1 + len(origin.encode())
            sig_len = data[offset]
            offset += 1 + sig_len + 1
            lines.append(f"  /{name} @{origin}")

        if not lines:
            return "No boards."
        return "\n".join(lines)

    def _format_peer_list(self, data) -> str:
        offset = 1
        count = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2

        lines = []
        for _ in range(count):
            peer = self._decode_string(data, offset)
            offset += 1 + len(peer.encode())
            lines.append(f"  {peer}")

        if not lines:
            return "No peers."
        return "\n".join(lines)

    def _format_post_list(self, data) -> str:
        offset = 1
        lines = []

        while offset < len(data):
            post_num = struct.unpack(">Q", data[offset:offset + 8])[0]
            offset += 8
            creation_date = struct.unpack(">Q", data[offset:offset + 8])[0]
            offset += 8
            subject = self._decode_string(data, offset)
            offset += 1 + len(subject.encode())
            author = self._decode_string(data, offset)
            offset += 1 + len(author.encode())
            root = struct.unpack(">Q", data[offset:offset + 8])[0]
            offset += 8
            from datetime import datetime
            ts = datetime.fromtimestamp(creation_date).strftime("%Y-%m-%d %H:%M")
            lines.append(f"#{post_num:4} | {subject[:30]:30} | {author:20} | {ts}")

        if not lines:
            return "No posts."
        return "\n".join(lines)

    def _parse_post_data(self, data) -> dict:
        offset = 1
        post = {}
        post["post_num"] = struct.unpack(">Q", data[offset:offset + 8])[0]
        offset += 8
        post["last_modified"] = struct.unpack(">q", data[offset:offset + 8])[0]
        offset += 8
        post["creation_date"] = struct.unpack(">q", data[offset:offset + 8])[0]
        offset += 8
        post["last_bumped"] = struct.unpack(">q", data[offset:offset + 8])[0]
        offset += 8
        post["closed"] = data[offset] != 0
        offset += 1
        post["sticky"] = struct.unpack(">i", data[offset:offset + 4])[0]
        offset += 4
        post["tags"] = self._decode_string(data, offset)
        offset += 1 + len(post["tags"].encode())
        post["subject"] = self._decode_string(data, offset)
        offset += 1 + len(post["subject"].encode())
        post["options"] = self._decode_string(data, offset)
        offset += 1 + len(post["options"].encode())
        post["root"] = struct.unpack(">Q", data[offset:offset + 8])[0]
        offset += 8
        post["author"] = self._decode_string(data, offset)
        offset += 1 + len(post["author"].encode())
        post["author_registrar"] = self._decode_string(data, offset)
        offset += 1 + len(post["author_registrar"].encode())
        post["signature"] = self._decode_string(data, offset)
        offset += 1 + len(post["signature"].encode())
        content_len = struct.unpack(">I", data[offset:offset + 4])[0]
        offset += 4
        post["content"] = data[offset:offset + content_len].decode("utf-8")
        return post

    def _format_post(self, data, board) -> str:
        post = self._parse_post_data(data)
        from datetime import datetime
        lines = []
        lines.append(f"Post #{post['post_num']} in /{board}")
        lines.append(f"Subject: {post['subject']}")
        lines.append(f"Author: {post['author']}@{post['author_registrar']}")
        lines.append(f"Created: {datetime.fromtimestamp(post['creation_date']).strftime('%Y-%m-%d %H:%M')}")
        lines.append(f"Last Modified: {datetime.fromtimestamp(post['last_modified']).strftime('%Y-%m-%d %H:%M')}")
        lines.append(f"Last Bumped: {datetime.fromtimestamp(post['last_bumped']).strftime('%Y-%m-%d %H:%M')}")
        if post['root']:
            lines.append(f"Reply to: #{post['root']}")
        if post['closed']:
            lines.append("Status: CLOSED")
        if post['sticky']:
            lines.append(f"Sticky: #{post['sticky']}")
        if post['tags']:
            lines.append(f"Tags: {post['tags']}")
        if post['options']:
            lines.append(f"Options: {post['options']}")
        if post['signature']:
            lines.append(f"Signature: {post['signature']}")
        lines.append("-" * 40)
        lines.append(post['content'])
        return "\n".join(lines)

    def _build_signed_payload(self, post) -> bytes:
        author_bytes = post["author"].encode("utf-8")
        author_registrar_bytes = (post.get("author_registrar") or "").encode("utf-8")
        tags_bytes = (post.get("tags") or "").encode("utf-8")
        subject_bytes = (post.get("subject") or "").encode("utf-8")
        options_bytes = (post.get("options") or "").encode("utf-8")
        content_bytes = (post.get("content") or "").encode("utf-8")

        payload = (
            struct.pack(">Q", post["post_num"])
            + struct.pack(">q", post["creation_date"])
            + struct.pack(">q", post["last_modified"])
            + struct.pack("B", len(author_bytes)) + author_bytes
            + struct.pack("B", len(author_registrar_bytes)) + author_registrar_bytes
            + struct.pack("B", len(tags_bytes)) + tags_bytes
            + struct.pack("B", len(subject_bytes)) + subject_bytes
            + struct.pack("B", len(options_bytes)) + options_bytes
            + struct.pack(">I", len(content_bytes)) + content_bytes
        )

        log_dict("BUILD_PAYLOAD: field lengths", {
            'post_num': post["post_num"],
            'creation_date': post["creation_date"],
            'last_modified': post["last_modified"],
            'author': len(author_bytes),
            'author_registrar': len(author_registrar_bytes),
            'tags': len(tags_bytes),
            'subject': len(subject_bytes),
            'options': len(options_bytes),
            'content': len(content_bytes)
        })

        return payload

    def _build_query_request(self, board, where, values, orderby, limit) -> bytes:
        request = self._encode_string(board)

        if where:
            where_bytes = where.encode("utf-8")
            request += struct.pack(">H", len(where_bytes)) + where_bytes
        else:
            request += struct.pack(">H", 0)

        request += bytes([len(values)])
        for v in values:
            if isinstance(v, int):
                request += bytes([0x01]) + struct.pack(">q", v)
            else:
                v_bytes = str(v).encode("utf-8")
                request += bytes([0x02, len(v_bytes)]) + v_bytes

        if orderby:
            orderby_bytes = orderby.encode("utf-8")
            request += struct.pack(">H", len(orderby_bytes)) + orderby_bytes
        else:
            request += struct.pack(">H", 0)

        request += struct.pack(">I", limit)
        return bytes([0x19]) + request

    def _format_query_results(self, data) -> str:
        offset = 1
        lines = []

        while offset < len(data):
            post_num = struct.unpack(">Q", data[offset:offset + 8])[0]
            offset += 8
            last_modified = struct.unpack(">q", data[offset:offset + 8])[0]
            offset += 8
            creation_date = struct.unpack(">q", data[offset:offset + 8])[0]
            offset += 8
            last_bumped = struct.unpack(">q", data[offset:offset + 8])[0]
            offset += 8
            closed = data[offset]
            offset += 1
            sticky = struct.unpack(">i", data[offset:offset + 4])[0]
            offset += 4
            tags = self._decode_string(data, offset)
            offset += 1 + len(tags.encode())
            subject = self._decode_string(data, offset)
            offset += 1 + len(subject.encode())
            options = self._decode_string(data, offset)
            offset += 1 + len(options.encode())
            root = struct.unpack(">Q", data[offset:offset + 8])[0]
            offset += 8
            author = self._decode_string(data, offset)
            offset += 1 + len(author.encode())
            author_registrar = self._decode_string(data, offset)
            offset += 1 + len(author_registrar.encode())
            signature = self._decode_string(data, offset)
            offset += 1 + len(signature.encode())

            from datetime import datetime
            ts = datetime.fromtimestamp(creation_date).strftime("%Y-%m-%d %H:%M")
            status = ""
            if sticky:
                status += f" [sticky:{sticky}]"
            if closed:
                status += " [closed]"
            lines.append(f"#{post_num:4} | {subject[:30]:30} | {author:20} | {ts}{status}")

        if not lines:
            return "No posts found."
        return "\n".join(lines)


def load_or_generate_identity(path):
    if os.path.exists(path):
        return
    key = Identity.generate()
    with open(path, 'wb') as f:
        f.write(bytes(key.private_key))
    os.chmod(path, 0o600)


async def main_async():
    default_config = './config.toml'

    parser = argparse.ArgumentParser(description='Bonnet Server')
    parser.add_argument('--config', default=default_config, help='Config file path')
    parser.add_argument('--userfile', help='User database path (overrides config)')
    parser.add_argument('--identity', help='Server identity path (overrides config)')
    parser.add_argument('--port', type=int, help='Listening port (overrides config)')
    parser.add_argument('--privileged', action='store_true', help='Use privileged port')
    parser.add_argument('--cert', help='TLS certificate path (overrides config)')
    parser.add_argument('--key', help='TLS private key path (overrides config)')
    args = parser.parse_args()

    config = Config.load(args.config)

    userfile_path = args.userfile if args.userfile else config.userfile_path
    identity_path = args.identity if args.identity else config.identity_path

    if args.port is not None:
        port = args.port
    elif args.privileged:
        port = config.port_privileged
    else:
        port = config.port_standard

    tls_enabled = config.tls_enabled
    tls_cert = args.cert if args.cert else config.tls_cert_path
    tls_key = args.key if args.key else config.tls_key_path

    if args.cert or args.key:
        tls_enabled = True

    try:
        init_logging(config.log_dir)
        print(f"Logging to: {get_log_path()}")
    except OSError as e:
        print(f"FATAL: Failed to initialize logging: {e}", file=sys.stderr)
        sys.exit(1)

    log_msg("MAIN: starting")

    log_dict("MAIN: args", {
        'config': args.config,
        'userfile': userfile_path,
        'identity': identity_path,
        'port': port,
        'privileged': args.privileged,
        'cert': tls_cert,
        'key': tls_key,
        'tls_enabled': tls_enabled
    })

    log_dict("MAIN: config", {
        'data_dir': config.data_dir,
        'origin': config.origin,
        'port_standard': config.port_standard,
        'port_privileged': config.port_privileged,
        'max_connections': config.max_connections,
        'max_request_size': config.max_request_size,
        'rate_limit_requests': config.rate_limit_requests
    })

    data_dir = os.path.dirname(userfile_path) if userfile_path else config.data_dir
    if data_dir:
        os.makedirs(data_dir, exist_ok=True)

    if userfile_path and not os.path.exists(userfile_path):
        open(userfile_path, 'a').close()
        os.chmod(userfile_path, 0o600)
        log_msg(f"MAIN: created userfile={userfile_path}")

    if identity_path:
        load_or_generate_identity(identity_path)
    log_msg(f"MAIN: port={port}")

    server = Bonnet(userfile_path, identity_path, config)

    ssl_certfile = None
    ssl_keyfile = None
    if tls_enabled and tls_cert and tls_key:
        ssl_certfile = tls_cert
        ssl_keyfile = tls_key
        log_msg("MAIN: SSL enabled")

    log_msg("MAIN: starting server")
    await server.run(port, ssl_certfile, ssl_keyfile)


def main():
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
