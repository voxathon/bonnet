# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True

"""
User Management Engine - Fixed-record-width KV datastore
"""

import os
import struct
from libc.stdint cimport uint64_t, int64_t

cdef size_t USERNAME_SIZE = 255
cdef size_t REGISTRAR_SIZE = 255
cdef size_t PUBLICKEY_SIZE = 32
cdef size_t PASSWORD_SIZE = 28
cdef size_t SEQ_NUMBR_SIZE = 8
cdef size_t RECORD_SIZE = USERNAME_SIZE + REGISTRAR_SIZE + PUBLICKEY_SIZE + PASSWORD_SIZE + SEQ_NUMBR_SIZE

cdef class User:
    cdef public str username
    cdef public str registrar
    cdef public bytes publickey
    cdef public bytes password
    cdef public uint64_t seq_numbr

    def __init__(self, str username="", str registrar="", bytes publickey=b"", bytes password=b"", uint64_t seq_numbr=0):
        self.username = username
        self.registrar = registrar
        self.publickey = publickey
        self.password = password
        self.seq_numbr = seq_numbr

    cpdef bytes encode(self):
        cdef bytes username_bytes = self.username.encode('ascii')[:USERNAME_SIZE].ljust(USERNAME_SIZE, b'\x00')
        cdef bytes registrar_bytes = self.registrar.encode('ascii')[:REGISTRAR_SIZE].ljust(REGISTRAR_SIZE, b'\x00')
        cdef bytes publickey_bytes = self.publickey[:PUBLICKEY_SIZE].ljust(PUBLICKEY_SIZE, b'\x00')
        cdef bytes password_bytes = self.password[:PASSWORD_SIZE].ljust(PASSWORD_SIZE, b'\x00')
        cdef bytes seq_bytes = struct.pack('<Q', self.seq_numbr)
        return username_bytes + registrar_bytes + publickey_bytes + password_bytes + seq_bytes

    @staticmethod
    cdef User decode(bytes data):
        cdef User user = User()
        user.username = data[:USERNAME_SIZE].rstrip(b'\x00').decode('ascii')
        user.registrar = data[USERNAME_SIZE:USERNAME_SIZE + REGISTRAR_SIZE].rstrip(b'\x00').decode('ascii')
        user.publickey = data[USERNAME_SIZE + REGISTRAR_SIZE:USERNAME_SIZE + REGISTRAR_SIZE + PUBLICKEY_SIZE].rstrip(b'\x00')
        user.password = data[USERNAME_SIZE + REGISTRAR_SIZE + PUBLICKEY_SIZE:USERNAME_SIZE + REGISTRAR_SIZE + PUBLICKEY_SIZE + PASSWORD_SIZE].rstrip(b'\x00')
        user.seq_numbr = struct.unpack('<Q', data[USERNAME_SIZE + REGISTRAR_SIZE + PUBLICKEY_SIZE + PASSWORD_SIZE:])[0]
        return user


cdef class Ume:
    cdef str _filepath
    cdef object _lock
    cdef uint64_t _next_seq

    def __init__(self, str filepath="./userfile"):
        self._filepath = filepath
        self._lock = object()
        self._next_seq = 0
        if not os.path.exists(self._filepath):
            open(self._filepath, 'wb').close()
        self._next_seq = self._find_max_seq() + 1

    cdef uint64_t _find_max_seq(self):
        cdef uint64_t max_seq = 0
        cdef uint64_t seq
        with open(self._filepath, 'rb') as f:
            while True:
                data = f.read(RECORD_SIZE)
                if len(data) < RECORD_SIZE:
                    break
                seq = struct.unpack('<Q', data[USERNAME_SIZE + REGISTRAR_SIZE + PUBLICKEY_SIZE + PASSWORD_SIZE:])[0]
                if seq > max_seq:
                    max_seq = seq
        return max_seq

    cdef size_t _find_record_by_username(self, str username):
        cdef bytes target = username.encode('ascii')[:USERNAME_SIZE].ljust(USERNAME_SIZE, b'\x00')
        cdef size_t pos = 0
        cdef bytes data
        with open(self._filepath, 'rb') as f:
            while True:
                data = f.read(RECORD_SIZE)
                if len(data) < RECORD_SIZE:
                    break
                if data[:USERNAME_SIZE] == target:
                    return pos
                pos += 1
        return -1

    cdef size_t _find_record_by_seq(self, uint64_t seq_numbr):
        cdef size_t pos = 0
        cdef bytes data
        cdef uint64_t rec_seq
        with open(self._filepath, 'rb') as f:
            while True:
                data = f.read(RECORD_SIZE)
                if len(data) < RECORD_SIZE:
                    break
                rec_seq = struct.unpack('<Q', data[USERNAME_SIZE + REGISTRAR_SIZE + PUBLICKEY_SIZE + PASSWORD_SIZE:])[0]
                if rec_seq == seq_numbr:
                    return pos
                pos += 1
        return -1

    cdef User _get_at_pos(self, size_t pos):
        with open(self._filepath, 'rb') as f:
            f.seek(pos * RECORD_SIZE)
            data = f.read(RECORD_SIZE)
            if len(data) == RECORD_SIZE:
                return User.decode(data)
        return None

    cpdef User get(self, str username=None, uint64_t seq_numbr=0):
        cdef size_t pos
        if username is not None:
            pos = self._find_record_by_username(username)
            if pos != <size_t>-1:
                return self._get_at_pos(pos)
        elif seq_numbr > 0:
            pos = self._find_record_by_seq(seq_numbr)
            if pos != <size_t>-1:
                return self._get_at_pos(pos)
        return None

    cpdef User put(self, str username, str registrar, bytes publickey, bytes password):
        cdef size_t existing = self._find_record_by_username(username)
        if existing != <size_t>-1:
            raise ValueError(f"User '{username}' already exists")
        cdef User user = User(username, registrar, publickey, password, self._next_seq)
        self._next_seq += 1
        with open(self._filepath, 'ab') as f:
            f.write(user.encode())
        return user

    cpdef bint upd(self, str username=None, uint64_t seq_numbr=0, str new_registrar=None, bytes new_publickey=None, bytes new_password=None):
        cdef size_t pos
        cdef User user
        if username is not None:
            pos = self._find_record_by_username(username)
        elif seq_numbr > 0:
            pos = self._find_record_by_seq(seq_numbr)
        else:
            raise ValueError("Must provide username or seq_numbr")

        if pos == <size_t>-1:
            return False

        user = self._get_at_pos(pos)
        if user is None:
            return False

        if new_registrar is not None:
            user.registrar = new_registrar
        if new_publickey is not None:
            user.publickey = new_publickey
        if new_password is not None:
            user.password = new_password

        with open(self._filepath, 'r+b') as f:
            f.seek(pos * RECORD_SIZE)
            f.write(user.encode())
        return True

    cpdef bint delete(self, str username=None, uint64_t seq_numbr=0):
        cdef size_t pos
        if username is not None:
            pos = self._find_record_by_username(username)
        elif seq_numbr > 0:
            pos = self._find_record_by_seq(seq_numbr)
        else:
            raise ValueError("Must provide username or seq_numbr")

        if pos == <size_t>-1:
            return False

        cdef bytes empty_record = b'\x00' * RECORD_SIZE
        with open(self._filepath, 'r+b') as f:
            f.seek(pos * RECORD_SIZE)
            f.write(empty_record)
        return True

    cpdef void export(self, str export_path="./users"):
        cdef User user
        cdef bytes data
        cdef str line
        with open(self._filepath, 'rb') as fin:
            with open(export_path, 'w', encoding='utf-8') as fout:
                while True:
                    data = fin.read(RECORD_SIZE)
                    if len(data) < RECORD_SIZE:
                        break
                    if data == b'\x00' * RECORD_SIZE:
                        continue
                    user = User.decode(data)
                    line = f"<{user.username}@{user.registrar}>:{user.publickey.hex()}\n"
                    fout.write(line)

    cpdef list list_all(self):
        cdef list users = []
        cdef User user
        cdef bytes data
        with open(self._filepath, 'rb') as f:
            while True:
                data = f.read(RECORD_SIZE)
                if len(data) < RECORD_SIZE:
                    break
                if data == b'\x00' * RECORD_SIZE:
                    continue
                user = User.decode(data)
                users.append(user)
        return users