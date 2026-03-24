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
