# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True

"""
User Management Engine - Fixed-record-width KV datastore
"""

import os
import struct
import threading
from libc.stdint cimport uint64_t, int64_t

cdef extern from "openssl/sha.h":
    unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md)

cdef extern from "openssl/evp.h":
    ctypedef struct EVP_MD:
        int dummy
    const EVP_MD *EVP_sha256()

cdef extern from "openssl/kdf.h":
    int PKCS5_PBKDF2_HMAC(const char *password, int passlen,
                          const unsigned char *salt, int saltlen,
                          int iter, const EVP_MD *digest,
                          int keylen, unsigned char *out)

cdef size_t USERNAME_SIZE = 255
cdef size_t REGISTRAR_SIZE = 255
cdef size_t RECORD_ORIGIN_SIZE = 255
cdef size_t RELAY_SIZE = 255
cdef size_t PUBLICKEY_SIZE = 32
cdef size_t HASH_SIZE = 32
cdef size_t SALT_SIZE = 16
cdef size_t SEQ_NUMBR_SIZE = 8
cdef size_t FLAGS_SIZE = 3
cdef size_t CREATION_TIME_SIZE = 8
cdef size_t RELAY_TIME_SIZE = 8
cdef size_t RECORD_SIZE = USERNAME_SIZE + REGISTRAR_SIZE + RECORD_ORIGIN_SIZE + RELAY_SIZE + PUBLICKEY_SIZE + HASH_SIZE + SALT_SIZE + SEQ_NUMBR_SIZE + FLAGS_SIZE + CREATION_TIME_SIZE + RELAY_TIME_SIZE
cdef int PBKDF2_ITERATIONS = 600000

cdef size_t OFFSET_USERNAME = 0
cdef size_t OFFSET_REGISTRAR = USERNAME_SIZE
cdef size_t OFFSET_RECORD_ORIGIN = USERNAME_SIZE + REGISTRAR_SIZE
cdef size_t OFFSET_RELAY = USERNAME_SIZE + REGISTRAR_SIZE + RECORD_ORIGIN_SIZE
cdef size_t OFFSET_PUBLICKEY = USERNAME_SIZE + REGISTRAR_SIZE + RECORD_ORIGIN_SIZE + RELAY_SIZE
cdef size_t OFFSET_HASH = USERNAME_SIZE + REGISTRAR_SIZE + RECORD_ORIGIN_SIZE + RELAY_SIZE + PUBLICKEY_SIZE
cdef size_t OFFSET_SALT = USERNAME_SIZE + REGISTRAR_SIZE + RECORD_ORIGIN_SIZE + RELAY_SIZE + PUBLICKEY_SIZE + HASH_SIZE
cdef size_t OFFSET_SEQ = USERNAME_SIZE + REGISTRAR_SIZE + RECORD_ORIGIN_SIZE + RELAY_SIZE + PUBLICKEY_SIZE + HASH_SIZE + SALT_SIZE
cdef size_t OFFSET_FLAGS = USERNAME_SIZE + REGISTRAR_SIZE + RECORD_ORIGIN_SIZE + RELAY_SIZE + PUBLICKEY_SIZE + HASH_SIZE + SALT_SIZE + SEQ_NUMBR_SIZE
cdef size_t OFFSET_CREATION_TIME = OFFSET_FLAGS + FLAGS_SIZE
cdef size_t OFFSET_RELAY_TIME = OFFSET_CREATION_TIME + CREATION_TIME_SIZE

cdef class User:
    cdef public str username
    cdef public str registrar
    cdef public str record_origin
    cdef public str relay
    cdef public bytes publickey
    cdef public bytes password_hash
    cdef public bytes salt
    cdef public uint64_t seq_numbr
    cdef public bint is_administrator
    cdef public bint is_moderator
    cdef public bint is_banned
    cdef public int64_t creation_time
    cdef public int64_t relay_time

    def __init__(self, str username="", str registrar="", str record_origin="", str relay="", bytes publickey=b"", bytes password_hash=b"", bytes salt=b"", uint64_t seq_numbr=0, bint is_administrator=False, bint is_moderator=False, bint is_banned=False, int64_t creation_time=0, int64_t relay_time=0):
        self.username = username
        self.registrar = registrar
        self.record_origin = record_origin
        self.relay = relay
        self.publickey = publickey
        self.password_hash = password_hash
        self.salt = salt
        self.seq_numbr = seq_numbr
        self.is_administrator = is_administrator
        self.is_moderator = is_moderator
        self.is_banned = is_banned
        self.creation_time = creation_time
        self.relay_time = relay_time

    cdef bytes _encode_and_truncate(self, str s, size_t max_size):
        cdef bytes b = s.encode('utf-8')
        if len(b) <= max_size:
            return b.ljust(max_size, b'\x00')
        return b[:max_size].decode('utf-8', 'ignore').encode('utf-8').ljust(max_size, b'\x00')

    cpdef bytes encode(self):
        cdef bytes username_bytes = self._encode_and_truncate(self.username, USERNAME_SIZE)
        cdef bytes registrar_bytes = self._encode_and_truncate(self.registrar, REGISTRAR_SIZE)
        cdef bytes record_origin_bytes = self._encode_and_truncate(self.record_origin, RECORD_ORIGIN_SIZE)
        cdef bytes relay_bytes = self._encode_and_truncate(self.relay, RELAY_SIZE)
        cdef bytes publickey_bytes = self.publickey
        cdef bytes hash_bytes = self.password_hash
        cdef bytes salt_bytes = self.salt
        cdef bytes seq_bytes = struct.pack('<Q', self.seq_numbr)
        cdef bytes flags_bytes = struct.pack('>BBB', 1 if self.is_administrator else 0, 1 if self.is_moderator else 0, 1 if self.is_banned else 0)
        cdef bytes creation_time_bytes = struct.pack('>q', self.creation_time)
        cdef bytes relay_time_bytes = struct.pack('>q', self.relay_time)
        return username_bytes + registrar_bytes + record_origin_bytes + relay_bytes + publickey_bytes + hash_bytes + salt_bytes + seq_bytes + flags_bytes + creation_time_bytes + relay_time_bytes

    @staticmethod
    cdef User decode(bytes data):
        cdef User user = User()
        user.username = data[OFFSET_USERNAME:OFFSET_REGISTRAR].rstrip(b'\x00').decode('utf-8', errors='replace')
        user.registrar = data[OFFSET_REGISTRAR:OFFSET_RECORD_ORIGIN].rstrip(b'\x00').decode('utf-8', errors='replace')
        user.record_origin = data[OFFSET_RECORD_ORIGIN:OFFSET_RELAY].rstrip(b'\x00').decode('utf-8', errors='replace')
        user.relay = data[OFFSET_RELAY:OFFSET_PUBLICKEY].rstrip(b'\x00').decode('utf-8', errors='replace')
        user.publickey = data[OFFSET_PUBLICKEY:OFFSET_HASH]
        user.password_hash = data[OFFSET_HASH:OFFSET_SALT]
        user.salt = data[OFFSET_SALT:OFFSET_SEQ]
        user.seq_numbr = struct.unpack('<Q', data[OFFSET_SEQ:OFFSET_FLAGS])[0]
        user.is_administrator = data[OFFSET_FLAGS] != 0
        user.is_moderator = data[OFFSET_FLAGS + 1] != 0
        user.is_banned = data[OFFSET_FLAGS + 2] != 0
        user.creation_time = struct.unpack('>q', data[OFFSET_CREATION_TIME:OFFSET_RELAY_TIME])[0]
        user.relay_time = struct.unpack('>q', data[OFFSET_RELAY_TIME:OFFSET_RELAY_TIME + RELAY_TIME_SIZE])[0]
        return user

    cpdef bint verify_password(self, bytes password):
        cdef unsigned char hash_out[32]
        PKCS5_PBKDF2_HMAC(password, len(password), self.salt, len(self.salt),
                           PBKDF2_ITERATIONS, EVP_sha256(), 32, hash_out)
        return bytes(hash_out[:32]) == self.password_hash


cdef bytes _generate_salt():
    return os.urandom(SALT_SIZE)


cdef bytes _hash_password(bytes password, bytes salt):
    cdef unsigned char hash_out[32]
    PKCS5_PBKDF2_HMAC(password, len(password), salt, len(salt),
                       PBKDF2_ITERATIONS, EVP_sha256(), 32, hash_out)
    return bytes(hash_out[:32])


cdef class Ume:
    cdef str _filepath
    cdef object _lock
    cdef uint64_t _next_seq

    def __init__(self, str filepath="./userfile"):
        self._filepath = filepath
        self._lock = threading.Lock()
        self._next_seq = 0
        with self._lock:
            if not os.path.exists(self._filepath):
                try:
                    open(self._filepath, 'wb').close()
                except OSError as e:
                    raise IOError(f"Failed to create user database: {e}")
            self._next_seq = self._find_max_seq() + 1

    cdef uint64_t _find_max_seq(self):
        cdef uint64_t max_seq = 0
        cdef uint64_t seq
        cdef bytes data
        try:
            with open(self._filepath, 'rb') as f:
                while True:
                    data = f.read(RECORD_SIZE)
                    if len(data) < RECORD_SIZE:
                        break
                    try:
                        seq = struct.unpack('<Q', data[OFFSET_SEQ:OFFSET_FLAGS])[0]
                    except struct.error:
                        continue
                    if seq > max_seq:
                        max_seq = seq
        except OSError:
            pass
        return max_seq

    cdef bytes _encode_and_truncate(self, str s, size_t max_size):
        cdef bytes b = s.encode('utf-8')
        if len(b) <= max_size:
            return b.ljust(max_size, b'\x00')
        return b[:max_size].decode('utf-8', 'ignore').encode('utf-8').ljust(max_size, b'\x00')

    cdef size_t _find_record_by_username(self, str username):
        cdef bytes target = self._encode_and_truncate(username, USERNAME_SIZE)
        cdef size_t pos = 0
        cdef bytes data
        try:
            with open(self._filepath, 'rb') as f:
                while True:
                    data = f.read(RECORD_SIZE)
                    if len(data) < RECORD_SIZE:
                        break
                    if data[:USERNAME_SIZE] == target:
                        return pos
                    pos += 1
        except OSError:
            pass
        return -1

    cdef size_t _find_record_by_seq(self, uint64_t seq_numbr):
        cdef size_t pos = 0
        cdef bytes data
        cdef uint64_t rec_seq
        try:
            with open(self._filepath, 'rb') as f:
                while True:
                    data = f.read(RECORD_SIZE)
                    if len(data) < RECORD_SIZE:
                        break
                    try:
                        rec_seq = struct.unpack('<Q', data[OFFSET_SEQ:OFFSET_FLAGS])[0]
                    except struct.error:
                        pos += 1
                        continue
                    if rec_seq == seq_numbr:
                        return pos
                    pos += 1
        except OSError:
            pass
        return -1

    cdef User _get_at_pos(self, size_t pos):
        try:
            with open(self._filepath, 'rb') as f:
                f.seek(pos * RECORD_SIZE)
                data = f.read(RECORD_SIZE)
                if len(data) == RECORD_SIZE:
                    try:
                        return User.decode(data)
                    except (struct.error, UnicodeDecodeError):
                        return None
        except OSError:
            pass
        return None

    cdef size_t _find_record_by_publickey(self, bytes publickey):
        cdef bytes target = publickey[:PUBLICKEY_SIZE]
        cdef size_t pos = 0
        cdef bytes data
        try:
            with open(self._filepath, 'rb') as f:
                while True:
                    data = f.read(RECORD_SIZE)
                    if len(data) < RECORD_SIZE:
                        break
                    if data[OFFSET_PUBLICKEY:OFFSET_HASH] == target:
                        return pos
                    pos += 1
        except OSError:
            pass
        return -1

    cpdef User get(self, str username=None, uint64_t seq_numbr=0, bytes publickey=None):
        cdef size_t pos
        with self._lock:
            if username is not None:
                pos = self._find_record_by_username(username)
                if pos != <size_t>-1:
                    return self._get_at_pos(pos)
            elif seq_numbr > 0:
                pos = self._find_record_by_seq(seq_numbr)
                if pos != <size_t>-1:
                    return self._get_at_pos(pos)
            elif publickey is not None:
                pos = self._find_record_by_publickey(publickey)
                if pos != <size_t>-1:
                    return self._get_at_pos(pos)
        return None

    cpdef list get_all_by_publickey(self, bytes publickey):
        cdef bytes target = publickey[:PUBLICKEY_SIZE]
        cdef list users = []
        cdef bytes data
        cdef User user
        with self._lock:
            try:
                with open(self._filepath, 'rb') as f:
                    while True:
                        data = f.read(RECORD_SIZE)
                        if len(data) < RECORD_SIZE:
                            break
                        if data == b'\x00' * RECORD_SIZE:
                            continue
                        if data[OFFSET_PUBLICKEY:OFFSET_HASH] == target:
                            try:
                                user = User.decode(data)
                                users.append(user)
                            except (struct.error, UnicodeDecodeError):
                                continue
            except OSError:
                pass
        return users

    cpdef User put(self, str username, str registrar, bytes publickey, str record_origin="", str relay="", bytes password=None, bint is_administrator=False, bint is_moderator=False, bint is_banned=False, int64_t creation_time=0, int64_t relay_time=0):
        cdef size_t existing
        cdef bytes salt, password_hash
        cdef User user
        import time as _time

        if len(publickey) != PUBLICKEY_SIZE:
            raise ValueError(f"Public key must be exactly {PUBLICKEY_SIZE} bytes")

        with self._lock:
            existing = self._find_record_by_username(username)
            if existing != <size_t>-1:
                raise ValueError(f"User '{username}' already exists")
            
            if password is not None:
                salt = _generate_salt()
                password_hash = _hash_password(password, salt)
            else:
                salt = b'\x00' * SALT_SIZE
                password_hash = b'\x00' * HASH_SIZE
            
            if creation_time == 0:
                creation_time = <int64_t>_time.time()
            if relay_time == 0:
                relay_time = creation_time
            
            user = User(username, registrar, record_origin, relay, publickey, password_hash, salt, self._next_seq, is_administrator, is_moderator, is_banned, creation_time, relay_time)
            self._next_seq += 1
            try:
                with open(self._filepath, 'ab') as f:
                    f.write(user.encode())
            except OSError as e:
                raise IOError(f"Failed to write user record: {e}")
        return user

    cpdef bint upd(self, str username=None, uint64_t seq_numbr=0, str new_registrar=None, str new_record_origin=None, str new_relay=None, bytes new_publickey=None, bytes new_password=None, object new_administrator=None, object new_moderator=None, object new_banned=None, object new_creation_time=None, object new_relay_time=None):
        cdef size_t pos
        cdef User user
        with self._lock:
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
            if new_record_origin is not None:
                user.record_origin = new_record_origin
            if new_relay is not None:
                user.relay = new_relay
            if new_publickey is not None:
                if len(new_publickey) != PUBLICKEY_SIZE:
                    raise ValueError(f"Public key must be exactly {PUBLICKEY_SIZE} bytes")
                user.publickey = new_publickey
            if new_password is not None:
                user.salt = _generate_salt()
                user.password_hash = _hash_password(new_password, user.salt)
            if new_administrator is not None:
                user.is_administrator = new_administrator
            if new_moderator is not None:
                user.is_moderator = new_moderator
            if new_banned is not None:
                user.is_banned = new_banned
            if new_creation_time is not None:
                user.creation_time = new_creation_time
            if new_relay_time is not None:
                user.relay_time = new_relay_time

            try:
                with open(self._filepath, 'r+b') as f:
                    f.seek(pos * RECORD_SIZE)
                    f.write(user.encode())
            except OSError as e:
                raise IOError(f"Failed to update user record: {e}")
        return True

    cpdef bint delete(self, str username=None, uint64_t seq_numbr=0):
        cdef size_t pos
        cdef bytes empty_record = b'\x00' * RECORD_SIZE
        with self._lock:
            if username is not None:
                pos = self._find_record_by_username(username)
            elif seq_numbr > 0:
                pos = self._find_record_by_seq(seq_numbr)
            else:
                raise ValueError("Must provide username or seq_numbr")

            if pos == <size_t>-1:
                return False

            try:
                with open(self._filepath, 'r+b') as f:
                    f.seek(pos * RECORD_SIZE)
                    f.write(empty_record)
            except OSError as e:
                raise IOError(f"Failed to delete user record: {e}")
        return True

    cpdef void export(self, str export_path="./users"):
        cdef User user
        cdef bytes data
        cdef str line
        cdef str ban_marker
        with self._lock:
            try:
                with open(self._filepath, 'rb') as fin:
                    with open(export_path, 'w', encoding='utf-8') as fout:
                        while True:
                            data = fin.read(RECORD_SIZE)
                            if len(data) < RECORD_SIZE:
                                break
                            if data == b'\x00' * RECORD_SIZE:
                                continue
                            try:
                                user = User.decode(data)
                                ban_marker = "!" if user.is_banned else ""
                                line = f"{ban_marker}<{user.username}@{user.registrar}>[{user.record_origin}|{user.relay}]:{user.publickey.hex()}\n"
                                fout.write(line)
                            except (struct.error, UnicodeDecodeError):
                                continue
            except OSError as e:
                raise IOError(f"Failed to export users: {e}")

    cpdef list list_all(self):
        cdef list users = []
        cdef User user
        cdef bytes data
        with self._lock:
            try:
                with open(self._filepath, 'rb') as f:
                    while True:
                        data = f.read(RECORD_SIZE)
                        if len(data) < RECORD_SIZE:
                            break
                        if data == b'\x00' * RECORD_SIZE:
                            continue
                        try:
                            user = User.decode(data)
                            users.append(user)
                        except (struct.error, UnicodeDecodeError):
                            continue
            except OSError:
                pass
        return users

    cpdef User ensure_root_user(self, str origin, bytes publickey):
        cdef User existing
        existing = self.get(username="root")
        if existing is not None:
            if existing.publickey != publickey:
                self.upd(username="root", new_publickey=publickey)
            return self.get(username="root")
        return self.put(
            "root", origin, publickey,
            record_origin=origin, relay=origin,
            is_administrator=True
        )

    cpdef int upsert_remote_user(self, str username, str registrar, bytes publickey,
                                  str record_origin, str relay):
        """
        Atomically insert or update user from remote sync.
        Returns:
            1 if inserted (new user)
            2 if updated (same origin)
            0 if skipped (conflicting origin)
        """
        cdef size_t pos
        cdef User user
        import time as _time

        if len(publickey) != PUBLICKEY_SIZE:
            raise ValueError(f"Public key must be exactly {PUBLICKEY_SIZE} bytes")

        with self._lock:
            pos = self._find_record_by_username(username)
            
            if pos == <size_t>-1:
                # INSERT - user doesn't exist
                user = User(
                    username, registrar, record_origin, relay, publickey,
                    b'\x00' * HASH_SIZE, b'\x00' * SALT_SIZE,
                    self._next_seq, False, False, False,
                    <int64_t>_time.time(), <int64_t>_time.time()
                )
                self._next_seq += 1
                try:
                    with open(self._filepath, 'ab') as f:
                        f.write(user.encode())
                except OSError as e:
                    raise IOError(f"Failed to write user record: {e}")
                return 1
            
            # User exists - check origin
            user = self._get_at_pos(pos)
            if user is None:
                return 0
            
            if user.record_origin == record_origin:
                # UPDATE - same origin, safe to overwrite
                user.registrar = registrar
                user.relay = relay
                user.publickey = publickey
                user.relay_time = <int64_t>_time.time()
                
                try:
                    with open(self._filepath, 'r+b') as f:
                        f.seek(pos * RECORD_SIZE)
                        f.write(user.encode())
                except OSError as e:
                    raise IOError(f"Failed to update user record: {e}")
                return 2
            
            # SKIP - different origin, conflict
            return 0