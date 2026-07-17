from core.crypto import Identity
from engine.ume import User
from net.context import CommandContext


class LocalConnection:
    """Local REPL principal — produces CommandContext for local command dispatch.

    In protocol v2, LocalConnection is a thin factory that builds a
    transport-neutral CommandContext. It is NOT a second connection implementation.
    """

    def __init__(self, user, peer_pubkey, engine=None, origin=None):
        self.user = user
        self.peer_public_key = peer_pubkey
        self._engine = engine
        self.origin = origin or "localhost"
        self.remote_addr = "localhost"

    def to_context(self) -> CommandContext:
        return CommandContext(
            peer_public_key=self.peer_public_key,
            user=self.user,
            username=self.user.username if self.user else None,
            remote_addr=self.remote_addr,
            is_anonymous=self.user is None,
            origin=self.origin,
        )

