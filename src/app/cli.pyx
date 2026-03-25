# cython: language_level=3
import struct
from core.crypto import Identity
from engine.ume import User


cdef class LocalConnection:
    cdef public object user
    cdef public bytes peer_public_key
    cdef public str origin
    cdef public str remote_addr
    cdef public object _engine

    def __init__(self, user, peer_pubkey, engine=None, origin=None):
        self.user = user
        self.peer_public_key = peer_pubkey
        self._engine = engine
        self.origin = origin or "localhost"
        self.remote_addr = "localhost"

    @property
    def is_anonymous(self) -> bool:
        return False

    cpdef bint is_registered(self):
        return True

    cpdef bint is_administrator(self):
        return self.user is not None and self.user.is_administrator

    cpdef bint is_moderator(self):
        return self.user is not None and self.user.is_moderator

    cpdef bint can_create_board(self):
        return self.is_administrator()

    cpdef bint can_promote_to_mod(self):
        return self.is_administrator()

    cpdef bint can_demote_mod(self):
        return self.is_administrator()

    cpdef bint can_edit_post(self, str author):
        return self.user is not None and self.user.username == author

    cpdef bint can_delete_post(self, str author):
        return self.user is not None and self.user.username == author
