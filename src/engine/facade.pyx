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

        Only an authenticated user's record_origin is trusted for ACL
        decisions. The WebSocket `Host` header (conn.origin) is client-
        controllable and MUST NOT be used for ACL matching, otherwise any
        peer could spoof `Host: localhost` to satisfy a
        `match.origin = "localhost"` ACL (#4). conn.origin remains populated
        for logging/diagnostics only. Anonymous/unresolved connections resolve
        to the literal "unknown", which matches no origin-pattern ACL unless an
        explicit `anonymous` matcher grants access.
        """
        if hasattr(conn, 'user') and conn.user and hasattr(conn.user, 'record_origin') and conn.user.record_origin:
            return conn.user.record_origin
        return "unknown"