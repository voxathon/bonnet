"""
User Management Engine - Fixed-record-width KV datastore
"""

import os
import struct
import threading

try:
    import fcntl
    def _flock_lock(fd):
        fcntl.flock(fd, fcntl.LOCK_EX)
    def _flock_unlock(fd):
        fcntl.flock(fd, fcntl.LOCK_UN)
except ImportError:
    def _flock_lock(fd):
        pass
    def _flock_unlock(fd):
        pass

USERNAME_SIZE = 255
REGISTRAR_SIZE = 255
RECORD_ORIGIN_SIZE = 255
RELAY_SIZE = 255
PUBLICKEY_SIZE = 32
SEQ_NUMBR_SIZE = 8
FLAGS_SIZE = 3
CREATION_TIME_SIZE = 8
RELAY_TIME_SIZE = 8
RECORD_SIZE = USERNAME_SIZE + REGISTRAR_SIZE + RECORD_ORIGIN_SIZE + RELAY_SIZE + PUBLICKEY_SIZE + SEQ_NUMBR_SIZE + FLAGS_SIZE + CREATION_TIME_SIZE + RELAY_TIME_SIZE

OFFSET_USERNAME = 0
OFFSET_REGISTRAR = USERNAME_SIZE
OFFSET_RECORD_ORIGIN = USERNAME_SIZE + REGISTRAR_SIZE
OFFSET_RELAY = USERNAME_SIZE + REGISTRAR_SIZE + RECORD_ORIGIN_SIZE
OFFSET_PUBLICKEY = USERNAME_SIZE + REGISTRAR_SIZE + RECORD_ORIGIN_SIZE + RELAY_SIZE
OFFSET_SEQ = USERNAME_SIZE + REGISTRAR_SIZE + RECORD_ORIGIN_SIZE + RELAY_SIZE + PUBLICKEY_SIZE
OFFSET_FLAGS = USERNAME_SIZE + REGISTRAR_SIZE + RECORD_ORIGIN_SIZE + RELAY_SIZE + PUBLICKEY_SIZE + SEQ_NUMBR_SIZE
OFFSET_CREATION_TIME = OFFSET_FLAGS + FLAGS_SIZE
OFFSET_RELAY_TIME = OFFSET_CREATION_TIME + CREATION_TIME_SIZE


class User:
    def __init__(self, username: str = "", registrar: str = "", record_origin: str = "", relay: str = "", publickey: bytes = b"", seq_numbr: int = 0, is_administrator: bool = False, is_moderator: bool = False, is_banned: bool = False, creation_time: int = 0, relay_time: int = 0):
        self.username = username
        self.registrar = registrar
        self.record_origin = record_origin
        self.relay = relay
        self.publickey = publickey
        self.seq_numbr = seq_numbr
        self.is_administrator = is_administrator
        self.is_moderator = is_moderator
        self.is_banned = is_banned
        self.creation_time = creation_time
        self.relay_time = relay_time

    def _encode_and_truncate(self, s: str, max_size: int) -> bytes:
        b = s.encode('utf-8')
        if len(b) <= max_size:
            return b.ljust(max_size, b'\x00')
        return b[:max_size].decode('utf-8', 'ignore').encode('utf-8').ljust(max_size, b'\x00')

    def encode(self) -> bytes:
        username_bytes = self._encode_and_truncate(self.username, USERNAME_SIZE)
        registrar_bytes = self._encode_and_truncate(self.registrar, REGISTRAR_SIZE)
        record_origin_bytes = self._encode_and_truncate(self.record_origin, RECORD_ORIGIN_SIZE)
        relay_bytes = self._encode_and_truncate(self.relay, RELAY_SIZE)
        publickey_bytes = self.publickey
        seq_bytes = struct.pack('<Q', self.seq_numbr)
        flags_bytes = struct.pack('>BBB', 1 if self.is_administrator else 0, 1 if self.is_moderator else 0, 1 if self.is_banned else 0)
        creation_time_bytes = struct.pack('>q', self.creation_time)
        relay_time_bytes = struct.pack('>q', self.relay_time)
        return username_bytes + registrar_bytes + record_origin_bytes + relay_bytes + publickey_bytes + seq_bytes + flags_bytes + creation_time_bytes + relay_time_bytes

    @staticmethod
    def decode(data: bytes) -> 'User':
        user = User()
        user.username = data[OFFSET_USERNAME:OFFSET_REGISTRAR].rstrip(b'\x00').decode('utf-8', errors='replace')
        user.registrar = data[OFFSET_REGISTRAR:OFFSET_RECORD_ORIGIN].rstrip(b'\x00').decode('utf-8', errors='replace')
        user.record_origin = data[OFFSET_RECORD_ORIGIN:OFFSET_RELAY].rstrip(b'\x00').decode('utf-8', errors='replace')
        user.relay = data[OFFSET_RELAY:OFFSET_PUBLICKEY].rstrip(b'\x00').decode('utf-8', errors='replace')
        user.publickey = data[OFFSET_PUBLICKEY:OFFSET_SEQ]
        user.seq_numbr = struct.unpack('<Q', data[OFFSET_SEQ:OFFSET_FLAGS])[0]
        user.is_administrator = data[OFFSET_FLAGS] != 0
        user.is_moderator = data[OFFSET_FLAGS + 1] != 0
        user.is_banned = data[OFFSET_FLAGS + 2] != 0
        user.creation_time = struct.unpack('>q', data[OFFSET_CREATION_TIME:OFFSET_RELAY_TIME])[0]
        user.relay_time = struct.unpack('>q', data[OFFSET_RELAY_TIME:OFFSET_RELAY_TIME + RELAY_TIME_SIZE])[0]
        return user


class Ume:
    def __init__(self, filepath: str = "./userfile"):
        self._filepath = filepath
        self._lock = threading.Lock()
        self._next_seq = 0
        self._mutation_callbacks: list = []
        with self._lock:
            if not os.path.exists(self._filepath):
                try:
                    open(self._filepath, 'wb').close()
                except OSError as e:
                    raise IOError(f"Failed to create user database: {e}")
            self._next_seq = self._find_max_seq() + 1

    def register_mutation_callback(self, callback) -> None:
        self._mutation_callbacks.append(callback)

    def _notify_mutation(self) -> None:
        for cb in self._mutation_callbacks:
            try:
                cb()
            except Exception:
                pass

    def _find_max_seq(self) -> int:
        max_seq = 0
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

    def _encode_and_truncate(self, s: str, max_size: int) -> bytes:
        b = s.encode('utf-8')
        if len(b) <= max_size:
            return b.ljust(max_size, b'\x00')
        return b[:max_size].decode('utf-8', 'ignore').encode('utf-8').ljust(max_size, b'\x00')

    def _find_record_by_username(self, username: str) -> int:
        target = self._encode_and_truncate(username, USERNAME_SIZE)
        pos = 0
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

    def _find_record_by_seq(self, seq_numbr: int) -> int:
        pos = 0
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

    def _get_at_pos(self, pos: int) -> User:
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

    def _find_record_by_publickey(self, publickey: bytes) -> int:
        target = publickey[:PUBLICKEY_SIZE]
        pos = 0
        try:
            with open(self._filepath, 'rb') as f:
                while True:
                    data = f.read(RECORD_SIZE)
                    if len(data) < RECORD_SIZE:
                        break
                    if data[OFFSET_PUBLICKEY:OFFSET_SEQ] == target:
                        return pos
                    pos += 1
        except OSError:
            pass
        return -1

    def get(self, username: str = None, seq_numbr: int = 0, publickey: bytes = None) -> User:
        with self._lock:
            if username is not None:
                pos = self._find_record_by_username(username)
                if pos != -1:
                    return self._get_at_pos(pos)
            elif seq_numbr > 0:
                pos = self._find_record_by_seq(seq_numbr)
                if pos != -1:
                    return self._get_at_pos(pos)
            elif publickey is not None:
                pos = self._find_record_by_publickey(publickey)
                if pos != -1:
                    return self._get_at_pos(pos)
        return None

    def get_all_by_publickey(self, publickey: bytes) -> list:
        target = publickey[:PUBLICKEY_SIZE]
        users = []
        with self._lock:
            try:
                with open(self._filepath, 'rb') as f:
                    while True:
                        data = f.read(RECORD_SIZE)
                        if len(data) < RECORD_SIZE:
                            break
                        if data == b'\x00' * RECORD_SIZE:
                            continue
                        if data[OFFSET_PUBLICKEY:OFFSET_SEQ] == target:
                            try:
                                user = User.decode(data)
                                users.append(user)
                            except (struct.error, UnicodeDecodeError):
                                continue
            except OSError:
                pass
        return users

    def put(self, username: str, registrar: str, publickey: bytes, record_origin: str = "", relay: str = "", is_administrator: bool = False, is_moderator: bool = False, is_banned: bool = False, creation_time: int = 0, relay_time: int = 0) -> User:
        import time as _time

        if len(publickey) != PUBLICKEY_SIZE:
            raise ValueError(f"Public key must be exactly {PUBLICKEY_SIZE} bytes")

        with self._lock:
            with open(self._filepath, 'a+b') as lockfile:
                _flock_lock(lockfile.fileno())
                try:
                    existing = self._find_record_by_username(username)
                    if existing != -1:
                        raise ValueError(f"User '{username}' already exists")

                    if creation_time == 0:
                        creation_time = int(_time.time())
                    if relay_time == 0:
                        relay_time = creation_time

                    user = User(username, registrar, record_origin, relay, publickey, self._next_seq, is_administrator, is_moderator, is_banned, creation_time, relay_time)
                    try:
                        lockfile.write(user.encode())
                        lockfile.flush()
                        self._next_seq += 1
                    except OSError as e:
                        raise IOError(f"Failed to write user record: {e}")
                finally:
                    _flock_unlock(lockfile.fileno())
        self._notify_mutation()
        return user

    def upd(self, username: str = None, seq_numbr: int = 0, new_registrar: str = None, new_record_origin: str = None, new_relay: str = None, new_publickey: bytes = None, new_administrator=None, new_moderator=None, new_banned=None, new_creation_time=None, new_relay_time=None) -> bool:
        with self._lock:
            with open(self._filepath, 'r+b') as lockfile:
                _flock_lock(lockfile.fileno())
                try:
                    if username is not None:
                        pos = self._find_record_by_username(username)
                    elif seq_numbr > 0:
                        pos = self._find_record_by_seq(seq_numbr)
                    else:
                        raise ValueError("Must provide username or seq_numbr")

                    if pos == -1:
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
                        lockfile.seek(pos * RECORD_SIZE)
                        lockfile.write(user.encode())
                        lockfile.flush()
                    except OSError as e:
                        raise IOError(f"Failed to update user record: {e}")
                finally:
                    _flock_unlock(lockfile.fileno())
        self._notify_mutation()
        return True

    def delete(self, username: str = None, seq_numbr: int = 0) -> bool:
        empty_record = b'\x00' * RECORD_SIZE
        with self._lock:
            with open(self._filepath, 'r+b') as lockfile:
                _flock_lock(lockfile.fileno())
                try:
                    if username is not None:
                        pos = self._find_record_by_username(username)
                    elif seq_numbr > 0:
                        pos = self._find_record_by_seq(seq_numbr)
                    else:
                        raise ValueError("Must provide username or seq_numbr")

                    if pos == -1:
                        return False

                    try:
                        lockfile.seek(pos * RECORD_SIZE)
                        lockfile.write(empty_record)
                        lockfile.flush()
                    except OSError as e:
                        raise IOError(f"Failed to delete user record: {e}")
                finally:
                    _flock_unlock(lockfile.fileno())
        self._notify_mutation()
        return True

    def export(self, export_path: str = "./users") -> None:
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
                                line = f"{ban_marker}<{user.username}@{user.registrar}>[{user.record_origin}|{user.relay}]:{user.publickey.hex()}\tcreation_time={user.creation_time}\trelay_time={user.relay_time}\n"
                                fout.write(line)
                            except (struct.error, UnicodeDecodeError):
                                continue
            except OSError as e:
                raise IOError(f"Failed to export users: {e}")

    def list_all(self) -> list:
        users = []
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

    def snapshot_raw_records(self) -> list[bytes]:
        """Return exact raw RECORD_SIZE byte chunks for all non-deleted slots.

        Holds the UME lock for the entire read to provide a consistent view.
        Returns a list of immutable ``bytes`` values (not a generator).
        """
        records: list[bytes] = []
        with self._lock:
            try:
                with open(self._filepath, 'rb') as f:
                    while True:
                        data = f.read(RECORD_SIZE)
                        if len(data) < RECORD_SIZE:
                            break
                        if data == b'\x00' * RECORD_SIZE:
                            continue
                        records.append(bytes(data))
            except OSError:
                pass
        return records

    def ensure_root_user(self, origin: str, publickey: bytes) -> User:
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

    def upsert_remote_user(self, username: str, registrar: str, publickey: bytes,
                           record_origin: str, relay: str,
                           creation_time: int | None = None,
                           max_creation_time_correction: int | None = None) -> int:
        """
        Atomically insert or update user from remote sync.
        Returns:
            1 if inserted (new user)
            2 if updated (same origin)
            0 if skipped (conflicting origin)
        """
        import time as _time

        if len(publickey) != PUBLICKEY_SIZE:
            raise ValueError(f"Public key must be exactly {PUBLICKEY_SIZE} bytes")

        with self._lock:
            with open(self._filepath, 'r+b') as lockfile:
                _flock_lock(lockfile.fileno())
                try:
                    pos = self._find_record_by_username(username)

                    if pos == -1:
                        ct = creation_time if creation_time is not None else int(_time.time())
                        now = int(_time.time())
                        if ct > now + 300:
                            raise ValueError(f"creation_time {ct} is in the future")
                        user = User(
                            username, registrar, record_origin, relay, publickey,
                            self._next_seq, False, False, False,
                            ct, now
                        )
                        try:
                            lockfile.seek(0, 2)  # seek to end
                            lockfile.write(user.encode())
                            lockfile.flush()
                            self._next_seq += 1
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
                        user.relay_time = int(_time.time())
                        if creation_time is not None:
                            now = int(_time.time())
                            if creation_time > now + 300:
                                raise ValueError(f"creation_time {creation_time} is in the future")
                            if max_creation_time_correction is not None:
                                delta = abs(creation_time - user.creation_time)
                                if delta > max_creation_time_correction:
                                    raise ValueError(
                                        f"creation_time correction {delta}s exceeds "
                                        f"max {max_creation_time_correction}s"
                                    )
                            user.creation_time = creation_time

                        try:
                            lockfile.seek(pos * RECORD_SIZE)
                            lockfile.write(user.encode())
                            lockfile.flush()
                        except OSError as e:
                            raise IOError(f"Failed to update user record: {e}")
                        return 2

                    # SKIP - different origin, conflict
                    return 0
                finally:
                    _flock_unlock(lockfile.fileno())
