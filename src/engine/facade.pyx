# cython: language_level=3

cdef class BonnetEngine:
    cdef public object ume
    cdef public object ame
    cdef public object keibatsu
    cdef public object config
    cdef public object server_identity
    
    def __init__(self, ume, ame, keibatsu, config, server_identity):
        self.ume = ume
        self.ame = ame
        self.keibatsu = keibatsu
        self.config = config
        self.server_identity = server_identity
    
    cpdef bint check_permission(self, str action, str board, object conn):
        """
        Check if connection has permission for action on board.
        
        Args:
            action: "read" or "write"
            board: board name or None for global actions
            conn: Connection or LocalConnection object
        
        Returns:
            True if permission granted, False otherwise
        """
        cdef bytes peer_pubkey = conn.peer_public_key if hasattr(conn, 'peer_public_key') and conn.peer_public_key else None
        cdef bint is_admin = conn.is_administrator() if hasattr(conn, 'is_administrator') else False
        cdef bint is_mod = conn.is_moderator() if hasattr(conn, 'is_moderator') else False
        cdef bint is_anonymous = conn.is_anonymous if hasattr(conn, 'is_anonymous') else True
        cdef str origin = self._resolve_origin(conn)
        cdef bytes board_owner = None
        
        if board:
            board_owner = self.ame.get_board_owner(board)
        
        return self.config.check_permission(action, board, peer_pubkey, origin, is_admin, is_mod, board_owner, is_anonymous)
    
    cdef str _resolve_origin(self, object conn):
        """
        Resolve origin for ACL matching.

        Only a *locally-registered* user's record_origin is trusted for ACL
        decisions, and only when it equals this server's configured origin.
        The WebSocket `Host` header (conn.origin) is client-controllable and
        MUST NOT be used for ACL matching (#4); and a remote-synced user's
        record_origin is peer-supplied and forgeable, so it must not become an
        ACL principal (R1) -- otherwise a peer could sync a user with
        record_origin="localhost" to satisfy a `match.origin = "localhost"` ACL.
        Locally-registered users (created via REGISTER) and the root user always
        have record_origin == config.origin, so they still match origin-pattern
        ACLs. Anonymous/unresolved connections, and any user whose
        record_origin != config.origin, resolve to the literal "unknown", which
        matches no origin-pattern ACL unless an explicit `anonymous` matcher
        grants access. Cross-origin trust should use `match.pubkey`.
        conn.origin remains populated for logging/diagnostics only.
        """
        if hasattr(conn, 'user') and conn.user and hasattr(conn.user, 'record_origin') and conn.user.record_origin:
            if conn.user.record_origin == self.config.origin:
                return conn.user.record_origin
        return "unknown"