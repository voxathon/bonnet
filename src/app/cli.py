import struct
from core.crypto import Identity
from engine.ume import User


class LocalConnection:
    def __init__(self, user, peer_pubkey, engine=None, origin=None):
        self.user = user
        self.peer_public_key = peer_pubkey
        self._engine = engine
        self.origin = origin or "localhost"
        self.remote_addr = "localhost"

    @property
    def is_anonymous(self) -> bool:
        return False

    def is_registered(self) -> bool:
        return True

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
