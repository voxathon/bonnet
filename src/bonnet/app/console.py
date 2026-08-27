"""Operator console (REPL) for a running Bonnet firehose server.

Extracted from BonnetFirehoseServer so the bootstrap class stays focused on
component construction and lifecycle. Attribute access delegates to the
server instance, so command bodies operate on the live components unchanged.
"""

import asyncio
import os
import struct

from bonnet.core.logging import log_msg
from bonnet.core.record import (
    ZERO_ID,
    Intent,
    MetadataMap,
    compute_body_hash,
    encode_intent,
    metadata_bytes,
    metadata_i64,
    metadata_text,
    metadata_text_list,
    metadata_u64,
    sign_intent,
)

ROLE_FLAGS = {
    "admin": 0x01,
    "administrator": 0x01,
    "moderator": 0x02,
    "mod": 0x02,
    "none": 0x00,
    "member": 0x00,
}

DURATION_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


class OperatorConsole:
    """Interactive administration loop for a BonnetFirehoseServer."""

    def __init__(self, server):
        self.server = server

    def __getattr__(self, name):
        return getattr(self.server, name)

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
            if hasattr(self, "_uvicorn_server") and self._uvicorn_server:
                self._uvicorn_server.should_exit = True
            return None

        if cmd == "help":
            return self._cmd_help()

        if cmd == "whoami":
            return self._cmd_whoami()

        if cmd == "list-boards":
            return self._cmd_list_boards(parts)

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

        if cmd == "grant-role":
            return self._cmd_grant_role(parts)

        if cmd == "revoke-user":
            return self._cmd_revoke_user(parts)

        if cmd == "warn":
            return self._cmd_warn(parts)

        if cmd == "ban":
            return self._cmd_ban(parts)

        if cmd == "permaban":
            return self._cmd_permaban(parts)

        if cmd == "revoke-punishment":
            return self._cmd_revoke_punishment(parts)

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

        if cmd == "debug-acl":
            return self._cmd_debug_acl()

        if cmd == "rebuild":
            return self._cmd_rebuild(parts)

        if cmd == "depeer":
            return self._cmd_depeer(parts)

        if cmd == "purge-origin":
            return self._cmd_purge_origin(parts)

        if cmd == "reset-key":
            return self._cmd_reset_key(parts)

        return f"Unknown command: {cmd}. Type 'help' for commands."

    def _cmd_help(self) -> str:
        return """Commands:
  help                          Show this help
  whoami                        Show server identity
  create-board <name>           Create a board (interactive)
  publish-article <board> [reply-to-num] [supersede-num]
                                Publish an article (interactive)
  register-user <name>          Rebind the server key's registration to <name>
  list-boards [origin]          List boards
  get-article [origin] <board> <num>
                                Get article by number
  list-articles <board> [off] [n]
                                List articles
  search-articles <board> <query>
                                Search article metadata
  query-articles <board> [filters]
                                Query articles by structured fields
  list-users [origin]           List registered users
  grant-role <pubkey-hex> <admin|moderator|none> [username]
                                Set a user's role (registers them if new; username
                                required for a first-time registration)
  revoke-user <pubkey-hex>      Revoke a user's registration on this origin
  warn <pubkey-hex> <reason...> [--board=<name>]
                                Issue a warning (default board: moderation.actions)
  ban <pubkey-hex> <duration> <reason...> [--board=<name>]
                                Issue a temporary ban. Duration is a unix timestamp
                                or <N>[smhdw], e.g. 7d, 24h
  permaban <pubkey-hex> <reason...> [--board=<name>]
                                Issue a permanent ban
  revoke-punishment <event-id-hex> [reason...]
                                Revoke a warning/ban/permaban by its event ID
  ban-status <pubkey-hex>       Check ban status
  event-head <origin>           Show firehose head
  event-range <origin> <start> <count>
                                Show firehose events
  get-event <origin> <event-id-hex>
                                Show full event details
  debug-nav [origin]            Dump nav.db state
  debug-acl                     Dump ACL state
  rebuild [origin]              Rebuild projections from firehose (retries failed records)
  depeer <origin>               Stop syncing an origin and freeze its projections
  purge-origin <origin>         Remove all firehose and projection data for an origin
  reset-key <origin>            Clear key epoch pinning for an origin
  quit                          Exit"""

    def _cmd_whoami(self) -> str:
        return (
            f"Server pubkey: {self.server_identity.public_key.hex()}\n"
            f"Origin: {self.config.origin}\n"
            f"Role: administrator"
        )

    def _local_handle(self, body: bytes) -> bytes:
        return self.command_handler.handle(body, self.local_conn.to_context())

    def _parse_response_error(self, resp: bytes) -> str:
        if resp[0] == 0x01:
            code = struct.unpack(">H", resp[1:3])[0]
            msg_len = struct.unpack(">H", resp[3:5])[0]
            msg = resp[5 : 5 + msg_len].decode("utf-8", errors="replace")
            return f"Error 0x{code:04x}: {msg}"
        return "Unknown error"

    def _sign_and_publish(
        self,
        kind: str,
        *,
        board: str = "",
        metadata: MetadataMap = None,
        target_origin: str = "",
        target_board: str = "",
        target_article_id: bytes = ZERO_ID,
        target_event_id: bytes = ZERO_ID,
        body: bytes = b"",
    ) -> bytes:
        """Sign and publish a record as the server's own identity.

        Shared by every permission-management command (grant-role, revoke-user,
        warn/ban/permaban, revoke-punishment) so each one only builds its
        kind-specific metadata and target tuple.
        """
        event_id = os.urandom(32)
        intent = Intent(
            event_id=event_id,
            kind=kind,
            origin=self.config.origin,
            actor_pubkey=self.server_identity.public_key,
            actor_username="root",
            actor_registrar=self.config.origin,
            board=board,
            target_origin=target_origin,
            target_board=target_board,
            target_article_id=target_article_id,
            target_event_id=target_event_id,
            metadata=metadata if metadata is not None else MetadataMap([]),
            body_hash=compute_body_hash(body) if body else ZERO_ID,
            body_size=len(body),
        )

        actor_sig = sign_intent(self.server_identity, encode_intent(intent))

        from bonnet.net.firehose_commands import OP_PUBLISH_RECORD

        req = struct.pack(">B", OP_PUBLISH_RECORD)
        encoded_intent = encode_intent(intent)
        req += struct.pack(">I", len(encoded_intent)) + encoded_intent
        req += actor_sig
        req += struct.pack(">I", len(body)) + body

        return self._local_handle(req)

    def _published_event_id(self, resp: bytes) -> str:
        rec_len = struct.unpack(">I", resp[1:5])[0]
        from bonnet.core.record import decode_record

        return decode_record(resp[5 : 5 + rec_len]).event_id.hex()

    def _parse_pubkey_arg(self, hex_str: str) -> bytes | None:
        try:
            pk = bytes.fromhex(hex_str)
        except ValueError:
            return None
        if len(pk) != 32:
            return None
        return pk

    def _extract_board_flag(self, tokens: list, default: str) -> tuple:
        board = default
        remaining = []
        for t in tokens:
            if t.startswith("--board="):
                board = t.split("=", 1)[1]
            else:
                remaining.append(t)
        return remaining, board

    def _parse_ban_duration(self, s: str) -> int | None:
        """Accept an absolute unix timestamp, or <N><s|m|h|d|w> relative to now."""
        try:
            return int(s)
        except ValueError:
            pass

        import re
        import time

        m = re.fullmatch(r"(\d+)([smhdw])", s.strip().lower())
        if not m:
            return None
        n = int(m.group(1))
        return int(time.time()) + n * DURATION_UNIT_SECONDS[m.group(2)]

    # ------------------------------------------------------------------
    # grant-role
    # ------------------------------------------------------------------

    def _cmd_grant_role(self, parts) -> str:
        if len(parts) < 3:
            return "Usage: grant-role <pubkey-hex> <admin|moderator|none> [username]"

        pubkey = self._parse_pubkey_arg(parts[1])
        if pubkey is None:
            return "Invalid hex pubkey (must be 32 bytes)"

        role = parts[2].lower()
        if role not in ROLE_FLAGS:
            return f"Unknown role '{role}'. Use admin, moderator, or none."
        flags = ROLE_FLAGS[role]

        existing = self.users.get_user_by_pubkey(self.config.origin, pubkey)
        if len(parts) >= 4:
            username = parts[3]
        elif existing is not None:
            username = existing["username"]
        else:
            return "Pubkey is not yet registered on this origin — supply a username."

        m = MetadataMap(
            [
                metadata_text(1, username),
                metadata_bytes(2, pubkey),
                metadata_u64(3, flags),
            ]
        )

        resp = self._sign_and_publish("bonnet.user.register", metadata=m)
        if resp[0] == 0x00:
            action = "Re-registered" if existing is not None else "Registered"
            return f"{action} '{username}' ({pubkey.hex()}) with role: {role}"
        return self._parse_response_error(resp)

    # ------------------------------------------------------------------
    # revoke-user
    # ------------------------------------------------------------------

    def _cmd_revoke_user(self, parts) -> str:
        if len(parts) < 2:
            return "Usage: revoke-user <pubkey-hex>"

        pubkey = self._parse_pubkey_arg(parts[1])
        if pubkey is None:
            return "Invalid hex pubkey (must be 32 bytes)"

        existing = self.users.get_user_by_pubkey(self.config.origin, pubkey)
        if existing is None:
            return f"'{parts[1]}' is not a registered user on this origin."
        if existing.get("revoked"):
            return f"'{parts[1]}' is already revoked."

        records = self.firehose.get_events_range(self.config.origin, existing["reg_seq"], 1)
        if not records:
            return "Could not locate the registration event (data inconsistency)."
        reg_event_id = records[0].event_id

        m = MetadataMap([metadata_bytes(1, pubkey)])
        resp = self._sign_and_publish(
            "bonnet.user.revoke",
            metadata=m,
            target_origin=self.config.origin,
            target_event_id=reg_event_id,
        )
        if resp[0] == 0x00:
            return f"Revoked '{existing['username']}' ({pubkey.hex()})."
        return self._parse_response_error(resp)

    # ------------------------------------------------------------------
    # warn / ban / permaban
    # ------------------------------------------------------------------

    def _issue_punishment(self, kind: str, pubkey: bytes, board: str, reason: str, expires_at=None):
        m = MetadataMap([metadata_bytes(1, pubkey)])
        if expires_at is not None:
            m.fields.append(metadata_i64(2, expires_at))
        return self._sign_and_publish(
            kind, board=board, metadata=m, body=reason.encode("utf-8")
        )

    def _cmd_warn(self, parts) -> str:
        if len(parts) < 3:
            return "Usage: warn <pubkey-hex> <reason...> [--board=<name>]"

        pubkey = self._parse_pubkey_arg(parts[1])
        if pubkey is None:
            return "Invalid hex pubkey (must be 32 bytes)"

        reason_tokens, board = self._extract_board_flag(parts[2:], "moderation.actions")
        reason = " ".join(reason_tokens)
        if not reason:
            return "A reason is required."

        resp = self._issue_punishment("bonnet.punishment.warn", pubkey, board, reason)
        if resp[0] == 0x00:
            return f"Warned {pubkey.hex()} on /{board}. Event: {self._published_event_id(resp)}"
        return self._parse_response_error(resp)

    def _cmd_ban(self, parts) -> str:
        if len(parts) < 4:
            return (
                "Usage: ban <pubkey-hex> <duration> <reason...> [--board=<name>]\n"
                "Duration is a unix timestamp or <N>[smhdw], e.g. 7d, 24h"
            )

        pubkey = self._parse_pubkey_arg(parts[1])
        if pubkey is None:
            return "Invalid hex pubkey (must be 32 bytes)"

        expires_at = self._parse_ban_duration(parts[2])
        if expires_at is None or expires_at <= 0:
            return "Invalid duration. Use a unix timestamp or <N>[smhdw], e.g. 7d, 24h."

        reason_tokens, board = self._extract_board_flag(parts[3:], "moderation.actions")
        reason = " ".join(reason_tokens)
        if not reason:
            return "A reason is required."

        resp = self._issue_punishment(
            "bonnet.punishment.ban", pubkey, board, reason, expires_at=expires_at
        )
        if resp[0] == 0x00:
            from datetime import datetime

            until = datetime.fromtimestamp(expires_at).strftime("%Y-%m-%d %H:%M")
            return (
                f"Banned {pubkey.hex()} on /{board} until {until}. "
                f"Event: {self._published_event_id(resp)}"
            )
        return self._parse_response_error(resp)

    def _cmd_permaban(self, parts) -> str:
        if len(parts) < 3:
            return "Usage: permaban <pubkey-hex> <reason...> [--board=<name>]"

        pubkey = self._parse_pubkey_arg(parts[1])
        if pubkey is None:
            return "Invalid hex pubkey (must be 32 bytes)"

        reason_tokens, board = self._extract_board_flag(parts[2:], "moderation.actions")
        reason = " ".join(reason_tokens)
        if not reason:
            return "A reason is required."

        resp = self._issue_punishment("bonnet.punishment.permaban", pubkey, board, reason)
        if resp[0] == 0x00:
            return f"Permabanned {pubkey.hex()} on /{board}. Event: {self._published_event_id(resp)}"
        return self._parse_response_error(resp)

    # ------------------------------------------------------------------
    # revoke-punishment
    # ------------------------------------------------------------------

    def _cmd_revoke_punishment(self, parts) -> str:
        if len(parts) < 2:
            return "Usage: revoke-punishment <event-id-hex> [reason...]"

        try:
            event_id = bytes.fromhex(parts[1])
        except ValueError:
            return "Invalid event ID hex"
        if len(event_id) != 32:
            return "Event ID must be 32 bytes (64 hex chars)"

        reason = " ".join(parts[2:])

        resp = self._sign_and_publish(
            "bonnet.punishment.revoke",
            target_origin=self.config.origin,
            target_event_id=event_id,
            body=reason.encode("utf-8"),
        )
        if resp[0] == 0x00:
            return f"Revoked punishment {parts[1]}."
        return self._parse_response_error(resp)

    def _enc_text16(self, s: str) -> bytes:
        encoded = s.encode("utf-8")
        return struct.pack(">H", len(encoded)) + encoded

    def _read_text16(self, data: bytes, offset: int) -> tuple[str, int]:
        n = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2
        return data[offset : offset + n].decode("utf-8"), offset + n

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

        m = MetadataMap(
            [
                metadata_bytes(1, self.server_identity.public_key),
            ]
        )
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

        from bonnet.net.firehose_commands import OP_PUBLISH_RECORD

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

        from bonnet.core.record import ZERO_ID, metadata_bytes

        m = MetadataMap(
            [
                metadata_text(1, subject),
            ]
        )
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

            target_root = getattr(target, "root_article_id", ZERO_ID) or ZERO_ID
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

        from bonnet.net.firehose_commands import OP_PUBLISH_RECORD

        req = struct.pack(">B", OP_PUBLISH_RECORD)
        encoded_intent = encode_intent(intent)
        req += struct.pack(">I", len(encoded_intent)) + encoded_intent
        req += actor_sig
        req += struct.pack(">I", len(content_bytes)) + content_bytes

        resp = self._local_handle(req)
        if resp[0] == 0x00:
            rec_len = struct.unpack(">I", resp[1:5])[0]
            from bonnet.core.record import decode_record

            rec = decode_record(resp[5 : 5 + rec_len])
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

        m = MetadataMap(
            [
                metadata_text(1, username),
                metadata_bytes(2, user_pubkey),
                metadata_u64(3, 0),
            ]
        )

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

        from bonnet.net.firehose_commands import OP_PUBLISH_RECORD

        req = struct.pack(">B", OP_PUBLISH_RECORD)
        encoded_intent = encode_intent(intent)
        req += struct.pack(">I", len(encoded_intent)) + encoded_intent
        req += actor_sig
        req += struct.pack(">I", 0)

        resp = self._local_handle(req)
        if resp[0] == 0x00:
            return (
                f"Registered '{username}' under the server identity's public key. "
                "This replaces any previous registration for that key (including 'root')."
            )

        return self._parse_response_error(resp)

    # ------------------------------------------------------------------
    # list-boards
    # ------------------------------------------------------------------

    def _cmd_list_boards(self, parts=None) -> str:
        aggregate = not parts or len(parts) <= 1
        origin = parts[1] if parts and len(parts) > 1 else ""

        from bonnet.net.firehose_commands import OP_BOARD_LIST

        req = struct.pack(">B", OP_BOARD_LIST) + self._enc_text16(origin)
        resp = self._local_handle(req)

        if resp[0] != 0x00:
            return self._parse_response_error(resp)

        count = struct.unpack(">H", resp[1:3])[0]
        offset = 3
        lines = []
        for _ in range(count):
            if aggregate:
                board_origin, offset = self._read_text16(resp, offset)
            name, offset = self._read_text16(resp, offset)
            closed = resp[offset]
            offset += 1
            owner_len = resp[offset]
            offset += 1 + owner_len
            display, offset = self._read_text16(resp, offset)
            status = " [closed]" if closed else ""
            if aggregate:
                lines.append(f"  {board_origin}/{name}{status}  {display}")
            else:
                lines.append(f"  /{name}{status}  {display}")

        if not lines:
            return "No boards."
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # get-article
    # ------------------------------------------------------------------

    def _cmd_get_article(self, parts) -> str:
        if len(parts) < 3:
            return "Usage: get-article [origin] <board> <num>"

        origin = self.config.origin
        board = parts[1]
        article_num_str = parts[2]

        known_origins = set()
        try:
            for row in self.firehose._conn.execute(
                "SELECT DISTINCT origin FROM origin_state"
            ).fetchall():
                known_origins.add(row[0])
        except Exception:
            pass

        if parts[1] in known_origins and len(parts) >= 4:
            origin = parts[1]
            board = parts[2]
            article_num_str = parts[3]

        try:
            article_num = int(article_num_str)
        except ValueError:
            return "Invalid article number"

        from bonnet.net.firehose_commands import OP_ARTICLE_GET

        req = struct.pack(">B", OP_ARTICLE_GET)
        req += self._enc_text16(origin)
        req += self._enc_text16(board)
        req += struct.pack(">B", 0x01)  # by article_num
        req += struct.pack(">Q", article_num)
        req += struct.pack(">B", 1)  # include body

        resp = self._local_handle(req)
        if resp[0] != 0x00:
            return self._parse_response_error(resp)

        return self._format_article_view(resp[1:], board)

    def _format_article_view(self, data: bytes, board: str) -> str:

        offset = 0
        article_num = struct.unpack(">Q", data[offset : offset + 8])[0]
        offset += 8
        aid_len = data[offset]
        offset += 1
        article_id = data[offset : offset + aid_len].hex()
        offset += aid_len
        eid_len = data[offset]
        offset += 1
        event_id = data[offset : offset + eid_len].hex()
        offset += eid_len
        visibility = data[offset]
        offset += 1
        body_state = data[offset]
        offset += 1
        bh_len = data[offset]
        offset += 1 + bh_len
        body_size = struct.unpack(">Q", data[offset : offset + 8])[0]
        offset += 8
        created_at = struct.unpack(">q", data[offset : offset + 8])[0]
        offset += 8
        ap_len = data[offset]
        offset += 1
        author_pubkey = data[offset : offset + ap_len].hex()
        offset += ap_len
        author_username, offset = self._read_text16(data, offset)
        author_registrar, offset = self._read_text16(data, offset)
        subject, offset = self._read_text16(data, offset)
        tags, offset = self._read_text16(data, offset)
        content_type, offset = self._read_text16(data, offset)

        root_len = data[offset]
        offset += 1
        root_id = data[offset : offset + root_len] if root_len else b""
        offset += root_len

        reply_len = data[offset]
        offset += 1
        reply_id = data[offset : offset + reply_len] if reply_len else b""
        offset += reply_len

        has_replacement = data[offset]
        offset += 1
        replacement_id = data[offset : offset + 32] if has_replacement else b""
        offset += 32 if has_replacement else 0

        pin_state, offset = self._read_text16(data, offset)
        thread_state, offset = self._read_text16(data, offset)

        body_len = struct.unpack(">I", data[offset : offset + 4])[0]
        offset += 4
        body = (
            data[offset : offset + body_len].decode("utf-8", errors="replace") if body_len else ""
        )

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
        lines.extend(
            [
                f"Article ID: {article_id}",
                f"Event ID: {event_id}",
                f"Visibility: {vis_names.get(visibility, '?')}",
                f"Body: {body_names.get(body_state, '?')}",
            ]
        )
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

        origin = ""
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

        aggregate = origin == ""

        from bonnet.net.firehose_commands import OP_ARTICLE_LIST

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
            if aggregate:
                art_origin, offset = self._read_text16(resp, offset)
            article_num = struct.unpack(">Q", resp[offset : offset + 8])[0]
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
            body_size = struct.unpack(">Q", resp[offset : offset + 8])[0]
            offset += 8
            created_at = struct.unpack(">q", resp[offset : offset + 8])[0]
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
            body_len = struct.unpack(">I", resp[offset : offset + 4])[0]
            offset += 4 + body_len

            from datetime import datetime

            ts = datetime.fromtimestamp(created_at).strftime("%Y-%m-%d %H:%M")
            if aggregate:
                lines.append(f"{art_origin} #{article_num:4} | {subject} | {ts}")
            else:
                lines.append(f"#{article_num:4} | {subject} | {ts}")

        if not lines:
            return "No articles."
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # search-articles
    # ------------------------------------------------------------------

    def _cmd_search_articles(self, parts) -> str:
        if len(parts) < 3:
            return "Usage: search-articles [origin] <board> <query>"

        origin = ""
        board = parts[1]
        query = " ".join(parts[2:])

        known_origins = set()
        try:
            for row in self.firehose._conn.execute(
                "SELECT DISTINCT origin FROM origin_state"
            ).fetchall():
                known_origins.add(row[0])
        except Exception:
            pass

        if parts[1] in known_origins and len(parts) >= 4:
            origin = parts[1]
            board = parts[2]
            query = " ".join(parts[3:])

        aggregate = origin == ""

        from bonnet.net.firehose_commands import OP_ARTICLE_SEARCH

        req = struct.pack(">B", OP_ARTICLE_SEARCH)
        req += self._enc_text16(origin)
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
            if aggregate:
                result_origin, offset = self._read_text16(resp, offset)
            article_num = struct.unpack(">Q", resp[offset : offset + 8])[0]
            offset += 8
            aid_len = resp[offset]
            offset += 1 + aid_len
            subj_len = resp[offset]
            offset += 1
            subject = resp[offset : offset + subj_len].decode("utf-8")
            offset += subj_len
            ap_len = resp[offset]
            offset += 1 + ap_len
            created_at = struct.unpack(">q", resp[offset : offset + 8])[0]
            offset += 8
            body_avail = resp[offset]
            offset += 1
            excerpt, offset = self._read_text16(resp, offset)

            from datetime import datetime

            ts = datetime.fromtimestamp(created_at).strftime("%Y-%m-%d %H:%M")
            if aggregate:
                lines.append(f"{result_origin} #{article_num:4} | {subject} | {ts}")
            else:
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
            return (
                "Usage: query-articles <board> [--author=<hex>] [--user=<name>] "
                "[--tag=<tag>] [--since=<ts>] [--before=<ts>] "
                "[--state=active|cancelled|superseded] "
                "[--root] [--reply-to=<num>] [--pinned] "
                "[--offset=N] [--limit=N]"
            )

        board = parts[1]

        from bonnet.net.firehose_commands import OP_ARTICLE_QUERY

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
                if not (0 <= limit <= 0xFFFF):
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
            article_num = struct.unpack(">Q", resp[offset : offset + 8])[0]
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
            body_size = struct.unpack(">Q", resp[offset : offset + 8])[0]
            offset += 8
            created_at = struct.unpack(">q", resp[offset : offset + 8])[0]
            offset += 8
            ap_len = resp[offset]
            offset += 1
            author_pubkey = resp[offset : offset + ap_len]
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

            author_display = (
                f"{author_username}@{author_registrar}" if author_username else author_pubkey.hex()
            )
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

        from bonnet.net.firehose_commands import OP_USER_LIST

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
            pubkey = resp[offset : offset + pk_len].hex()
            offset += pk_len
            username, offset = self._read_text16(resp, offset)
            flags = struct.unpack(">Q", resp[offset : offset + 8])[0]
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

        from bonnet.net.firehose_commands import OP_BAN_STATUS, PUNISHMENT_TYPE_CODES

        req = struct.pack(">B", OP_BAN_STATUS) + struct.pack(">B", len(pubkey)) + pubkey

        resp = self._local_handle(req)
        if resp[0] != 0x00:
            return self._parse_response_error(resp)

        count = resp[1]
        if count == 0:
            return "No pending punishments."

        type_names = {code: name for name, code in PUNISHMENT_TYPE_CODES.items()}
        offset = 2
        lines = []
        from datetime import datetime

        for _ in range(count):
            type_code = resp[offset]
            offset += 1
            (expires_at,) = struct.unpack(">q", resp[offset : offset + 8])
            offset += 8
            (body_size,) = struct.unpack(">I", resp[offset : offset + 4])
            offset += 4
            body_hash = resp[offset : offset + 32].hex()
            offset += 32
            event_id = resp[offset : offset + 32].hex()
            offset += 32
            origin, offset = self._read_text16(resp, offset)

            ptype = type_names.get(type_code, f"unknown({type_code})")
            if expires_at > 0:
                exp = "expires " + datetime.fromtimestamp(expires_at).strftime("%Y-%m-%d %H:%M")
            else:
                exp = "no expiry"
            lines.append(
                f"  {ptype}\n    Origin: {origin}\n    {exp}\n"
                f"    Event: {event_id}\n"
                f"    Body: {body_size} bytes (hash {body_hash[:16]}...)"
            )

        return "Pending punishments:\n" + "\n".join(lines)

    # ------------------------------------------------------------------
    # event-head
    # ------------------------------------------------------------------

    def _cmd_event_head(self, parts) -> str:
        if len(parts) < 2:
            return "Usage: event-head <origin>"

        origin = parts[1]

        from bonnet.net.firehose_commands import OP_EVENT_HEAD

        req = struct.pack(">B", OP_EVENT_HEAD) + self._enc_text16(origin)

        resp = self._local_handle(req)
        if resp[0] != 0x00:
            return self._parse_response_error(resp)

        head_len = struct.unpack(">H", resp[1:3])[0]
        from bonnet.core.record import decode_head

        head = decode_head(resp[3 : 3 + head_len])

        return (
            f"Origin: {head.origin}\n"
            f"Latest seq: {head.latest_origin_seq}\n"
            f"Event count: {head.event_count}\n"
            f"Latest hash: {head.latest_event_hash.hex()}\n"
            f"Pubkey: {head.origin_pubkey.hex()}"
        )

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

        from bonnet.net.firehose_commands import OP_EVENT_RANGE

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
            rec_len = struct.unpack(">I", resp[offset : offset + 4])[0]
            offset += 4
            from bonnet.core.record import decode_record

            rec = decode_record(resp[offset : offset + rec_len])
            offset += rec_len
            w_len = struct.unpack(">H", resp[offset : offset + 2])[0]
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

        from bonnet.net.firehose_commands import OP_EVENT_GET

        req = struct.pack(">B", OP_EVENT_GET) + self._enc_text16(origin) + event_id

        resp = self._local_handle(req)
        if resp[0] != 0x00:
            return self._parse_response_error(resp)

        offset = 1
        rec_len = struct.unpack(">I", resp[offset : offset + 4])[0]
        offset += 4
        from bonnet.core.record import decode_record

        rec = decode_record(resp[offset : offset + rec_len])
        offset += rec_len
        w_len = struct.unpack(">H", resp[offset : offset + 2])[0]
        offset += 2
        from bonnet.core.record import decode_witness, is_origin_witness

        witness = decode_witness(resp[offset : offset + w_len])

        from datetime import datetime

        ts = datetime.fromtimestamp(rec.created_at).strftime("%Y-%m-%d %H:%M:%S")

        lines = [
            "=== Event ===",
            f"Origin:       {rec.origin}",
            f"Sequence:     {rec.origin_seq}",
            f"Event ID:     {rec.event_id.hex()}",
            f"Kind:         {rec.kind}",
            f"Schema:       {rec.schema_version}",
            f"Created:      {ts}",
            "",
            "=== Actor ===",
            f"Pubkey:       {rec.actor_pubkey.hex()}",
        ]

        if rec.actor_username:
            lines.append(f"Username:     {rec.actor_username}")
        if rec.actor_registrar:
            lines.append(f"Registrar:    {rec.actor_registrar}")

        lines.extend(
            [
                "",
                "=== Content ===",
                f"Board:        {rec.board or '(none)'}",
                f"Article ID:   {rec.article_id.hex() if rec.article_id != ZERO_ID else '(none)'}",
                f"Article Num:  {rec.article_num if rec.article_num else '(none)'}",
            ]
        )

        if rec.target_origin:
            lines.extend(
                [
                    "",
                    "=== Target ===",
                    f"Origin:       {rec.target_origin}",
                    f"Board:        {rec.target_board}",
                    f"Article ID:   {rec.target_article_id.hex() if rec.target_article_id != ZERO_ID else '(none)'}",
                    f"Event ID:     {rec.target_event_id.hex() if rec.target_event_id != ZERO_ID else '(none)'}",
                ]
            )

        lines.extend(
            [
                "",
                "=== Body ===",
                f"Hash:         {rec.body_hash.hex()}",
                f"Size:         {rec.body_size} bytes",
            ]
        )

        lines.extend(
            [
                "",
                "=== Signatures ===",
                f"Actor sig:    {rec.actor_signature.hex()}",
                f"Origin sig:   {rec.origin_signature.hex()}",
            ]
        )

        if rec.metadata.fields:
            lines.extend(
                [
                    "",
                    f"=== Metadata ({len(rec.metadata.fields)} fields) ===",
                ]
            )
            for f in rec.metadata.fields:
                type_names = {
                    1: "BYTES",
                    2: "TEXT",
                    3: "U64",
                    4: "I64",
                    5: "BOOL",
                    6: "ID_LIST",
                    7: "TEXT_LIST",
                }
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
        from_pubkey = (
            witness.received_from_pubkey.hex()
            if witness.received_from_pubkey != zero_key
            else "(origin)"
        )
        lines.extend(
            [
                "",
                "=== Witness ===",
                f"Relay pubkey: {witness.relay_pubkey.hex()}",
                f"Relay host:   {witness.relay_hostname}",
                f"From pubkey:  {from_pubkey}",
                f"From host:    {witness.received_from_hostname or '(origin)'}",
                f"Seen at:      {datetime.fromtimestamp(witness.seen_at).strftime('%Y-%m-%d %H:%M:%S')}",
                f"Origin term:  {'yes' if is_origin_witness(witness) else 'no'}",
                f"Event hash:   {witness.event_hash.hex()}",
            ]
        )

        return "\n".join(lines)

    def _cmd_rebuild(self, parts) -> str:
        origin = parts[1] if len(parts) > 1 else self.config.origin
        count = self.dispatcher.rebuild_all(origin)
        return f"Rebuilt projections for '{origin}': {count} records replayed."

    def _cmd_depeer(self, parts) -> str:
        if len(parts) < 2:
            return "Usage: depeer <origin>"
        origin = parts[1]
        if origin == self.config.origin:
            return "Cannot depeer the local origin."
        if origin not in self.sync_manager._clients and origin not in self.sync_manager._tasks:
            return f"Origin '{origin}' is not a configured peer."
        self.sync_manager.stop_origin(origin)
        return f"Depeered '{origin}': sync stopped, data frozen and readable."

    def _cmd_reset_key(self, parts) -> str:
        if len(parts) < 2:
            return "Usage: reset-key <origin>"
        origin = parts[1]
        if origin == self.config.origin:
            return "Cannot reset key for the local origin."
        summary = self.firehose.get_origin_summary(origin)
        if summary["event_count"] == 0 and summary["witness_count"] == 0:
            return f"Origin '{origin}' has no data."
        self.firehose.reset_origin_key(origin)
        return f"Reset key pinning for '{origin}'. Next sync will perform fresh TOFU."

    def _cmd_purge_origin(self, parts) -> str:
        if len(parts) < 2:
            return "Usage: purge-origin <origin>"
        origin = parts[1]
        if origin == self.config.origin:
            return "Cannot purge the local origin."
        if origin in self.sync_manager._clients or origin in self.sync_manager._tasks:
            return f"Origin '{origin}' has active sync. Run 'depeer {origin}' first."

        summary = self.firehose.get_origin_summary(origin)
        if summary["event_count"] == 0 and summary["witness_count"] == 0:
            return f"Origin '{origin}' has no data to purge."

        manifest_path = os.path.join(self.config.data_dir, f"purge_manifest_{origin}.json")
        import json

        manifest = {
            "origin": origin,
            "summary": summary,
            "steps": [],
        }

        body_count = self.body_store.delete_origin_bodies(origin)
        manifest["steps"].append({"action": "delete_bodies", "count": body_count})

        self.dispatcher._boards_lock.acquire()
        try:
            for key, bp in list(self.dispatcher._board_projections.items()):
                if key[0] == origin:
                    bp.close()
                    del self.dispatcher._board_projections[key]
                    manifest["steps"].append({"action": "close_board_projection", "board": key[1]})
        finally:
            self.dispatcher._boards_lock.release()

        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

        try:
            self.nav.clear_origin(origin)
            self.users.clear_origin(origin)
            self.policy.clear_origin(origin)
            manifest["steps"].append({"action": "clear_global_projections"})

            counts = self.firehose.delete_origin_data(origin)
            manifest["steps"].append({"action": "delete_firehose_data", "counts": counts})

            os.remove(manifest_path)
        except Exception as e:
            log_msg(f"PURGE: error during purge of '{origin}': {e}")
            log_msg(f"PURGE: manifest saved at {manifest_path} for manual completion or re-run")
            return f"Purge of '{origin}' incomplete: {e}. Manifest at {manifest_path}."

        lines = [f"Purged '{origin}':"]
        lines.append(f"  body files deleted: {body_count}")
        lines.append(f"  firehose rows deleted: {sum(counts.values())}")
        for table, count in counts.items():
            if count > 0:
                lines.append(f"    {table}: {count}")
        return "\n".join(lines)

    def _cmd_debug_acl(self) -> str:
        lines = []
        ctx = self.local_conn.to_context()
        auth_ctx = ctx.to_auth_context()

        lines.append("=== FirehoseContext ===")
        lines.append(f"  peer_pubkey: {ctx.peer_pubkey.hex()}")
        lines.append(f"  is_anonymous: {ctx.is_anonymous}")
        lines.append(f"  is_unknown: {ctx.is_unknown}")
        lines.append(f"  is_registered: {ctx.is_registered}")
        lines.append(f"  role: '{ctx.role}'")
        lines.append(f"  origin: '{ctx.origin}'")

        lines.append("")
        lines.append("=== ACL Rules ===")
        acl = self.command_handler._acl
        lines.append(f"  rule count: {len(acl._rules)}")
        for i, rule in enumerate(acl._rules):
            m = rule.matcher
            matcher_desc = []
            if m.wildcard:
                matcher_desc.append("wildcard")
            if m.anonymous:
                matcher_desc.append("anonymous")
            if m.unknown:
                matcher_desc.append("unknown")
            if m.pubkey is not None:
                matcher_desc.append(f"pubkey={m.pubkey.hex()[:16]}...")
            if m.role is not None:
                matcher_desc.append(f"role={m.role}")
            if m.origin is not None:
                matcher_desc.append(f"origin={m.origin}")
            lines.append(
                f"  [{i}] effect={rule.effect} match=[{', '.join(matcher_desc)}] actions={rule.actions} commands={rule.commands} kinds={rule.kinds} boards={rule.boards} objects={rule.objects}"
            )

        lines.append("")
        lines.append("=== ACL Checks ===")
        from bonnet.net.firehose_commands import CMD_NAMES

        for opcode, cmd_name in sorted(CMD_NAMES.items(), key=lambda x: x[1]):
            action = "write" if opcode == 0x01 else "read"
            result = acl.check(auth_ctx, action, command=cmd_name)
            if not result:
                lines.append(f"  DENIED: {cmd_name} ({action})")
            # only show denied ones to keep output concise

        all_allowed = True
        for opcode, cmd_name in sorted(CMD_NAMES.items(), key=lambda x: x[1]):
            action = "write" if opcode == 0x01 else "read"
            if not acl.check(auth_ctx, action, command=cmd_name):
                all_allowed = False
        if all_allowed:
            lines.append("  (all commands allowed)")

        lines.append("")
        lines.append("=== Server identity ===")
        lines.append(f"  pubkey: {self.server_identity.public_key.hex()}")
        lines.append(f"  config.origin: '{self.config.origin}'")

        has_server_admin = any(
            r.matcher.pubkey == self.server_identity.public_key and r.effect == "allow"
            for r in acl._rules
            if r.matcher.pubkey is not None
        )
        lines.append(f"  has admin ACL rule for server pubkey: {has_server_admin}")

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
            lines.append(
                f"  origin={b['origin']} board={b['board']} display={b['display_name']} closed={b['closed']}"
            )

        if parts and len(parts) > 1:
            origin = parts[1]
            lines.append("")
            lines.append(f"=== NavProjection.list_boards('{origin}') ===")
            filtered = self.nav.list_boards(origin)
            lines.append(f"count: {len(filtered)}")
            for b in filtered:
                lines.append(
                    f"  origin={b['origin']} board={b['board']} display={b['display_name']} closed={b['closed']}"
                )

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
            rows = conn.execute(
                "SELECT origin, origin_seq, kind FROM applied_events ORDER BY origin, origin_seq"
            ).fetchall()
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
