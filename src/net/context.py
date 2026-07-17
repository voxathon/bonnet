"""Transport-neutral authorization context for command dispatch.

CommandContext replaces both net.connection.Connection and app.cli.LocalConnection
as the authorization principal passed to CommandHandler.handle() and
BonnetEngine.check_permission().

Unlike Connection, CommandContext carries no network state — no WebSocket,
no session, no handshake, no frames. It holds only the identity and permission
information that command and ACL code needs.

In protocol v2, peer_public_key is always present (never None):
  - Authenticated users: their registered Ed25519 key
  - Anonymous users: the server's shared anonymous key
  - Local REPL: the server identity key
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CommandContext:
    peer_public_key: bytes
    user: Optional[object] = None
    username: Optional[str] = None
    remote_addr: str = "localhost"
    request_id: str = ""
    is_anonymous: bool = False
    origin: str = "unknown"

    @property
    def is_registered(self) -> bool:
        return self.user is not None

    def is_administrator(self) -> bool:
        return self.user is not None and self.user.is_administrator

    def is_moderator(self) -> bool:
        return self.user is not None and self.user.is_moderator

    def can_create_board(self) -> bool:
        return self.is_administrator()

    def can_promote_to_mod(self) -> bool:
        return self.is_administrator()

    def can_demote_mod(self) -> bool:
        return self.is_administrator()

    def can_edit_post(self, author: str) -> bool:
        return self.user is not None and self.user.username == author

    def can_delete_post(self, author: str) -> bool:
        return self.user is not None and (
            self.user.username == author or
            self.is_moderator() or
            self.is_administrator()
        )
