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
        cdef bytes peer_pubkey = conn.peer_public_key
        cdef bint is_admin = conn.is_administrator() if hasattr(conn, 'is_administrator') else False
        cdef bint is_mod = conn.is_moderator() if hasattr(conn, 'is_moderator') else False
        cdef str origin = self._resolve_origin(conn)
        cdef bytes board_owner = None
        
        if board:
            board_owner = self.ame.get_board_owner(board)
        
        return self.config.check_permission(action, board, peer_pubkey, origin, is_admin, is_mod, board_owner)
    
    cdef str _resolve_origin(self, object conn):
        """
        Resolve origin for ACL matching.
        Priority: user.record_origin -> connection origin -> IP
        """
        if hasattr(conn, 'user') and conn.user and hasattr(conn.user, 'record_origin') and conn.user.record_origin:
            return conn.user.record_origin
        if hasattr(conn, 'origin') and conn.origin:
            return conn.origin
        if hasattr(conn, 'websocket') and conn.websocket and hasattr(conn.websocket, 'remote_address'):
            addr = conn.websocket.remote_address
            if addr:
                return str(addr[0]) if isinstance(addr, tuple) else str(addr)
        return "unknown"