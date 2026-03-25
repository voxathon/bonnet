# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False

import struct
import asyncio
import os
import time
from libc.stdint cimport uint64_t, int64_t
from net.connection import Connection
from engine.facade import BonnetEngine
from core.logging import log_msg
from core.orm import Database

cdef class SyncDB:
    cdef str _db_path
    cdef object _db

    def __init__(self, str db_path):
        self._db_path = db_path
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        self._db = Database(self._db_path)
        with self._db.open() as ctx:
            ctx.execute("""
            CREATE TABLE IF NOT EXISTS peer_keys (
                origin TEXT PRIMARY KEY,
                publickey BLOB NOT NULL,
                first_seen INTEGER NOT NULL,
                last_rotated INTEGER NOT NULL
            )
            """)

    cpdef bytes get_peer_pubkey(self, str origin):
        cdef list rows
        with self._db.open() as ctx:
            rows = ctx.execute("SELECT publickey FROM peer_keys WHERE origin=?", [origin]).fetchall()
        if rows and rows[0][0]:
            return bytes(rows[0][0])
        return None

    cpdef bint set_peer_pubkey_tofu(self, str origin, bytes publickey):
        cdef bytes existing = self.get_peer_pubkey(origin)
        if existing:
            return existing == publickey

        cdef int64_t now = int(time.time())
        with self._db.open() as ctx:
            ctx.execute(
                "INSERT INTO peer_keys (origin, publickey, first_seen, last_rotated) VALUES (?, ?, ?, ?)",
                [origin, publickey, now, now]
            )
        return True

    cpdef bint rotate_peer_pubkey(self, str origin, bytes old_publickey, bytes new_publickey, bytes signature):
        cdef bytes existing = self.get_peer_pubkey(origin)
        if not existing:
            return False
        if existing != old_publickey:
            return False

        from core.crypto import Identity
        cdef bytes origin_bytes = origin.encode('utf-8')
        cdef bytes payload = struct.pack('B', len(origin_bytes)) + origin_bytes + old_publickey + new_publickey

        if not Identity.verify(old_publickey, payload, signature):
            return False

        cdef int64_t now = int(time.time())
        with self._db.open() as ctx:
            ctx.execute(
                "UPDATE peer_keys SET publickey=?, last_rotated=? WHERE origin=?",
                [new_publickey, now, origin]
            )
        return True

    cpdef list list_peer_keys(self):
        cdef list rows
        cdef list result = []
        with self._db.open() as ctx:
            rows = ctx.execute("SELECT origin, publickey, first_seen, last_rotated FROM peer_keys").fetchall()
        for row in rows:
            result.append({
                'origin': row[0],
                'publickey': bytes(row[1]),
                'first_seen': row[2],
                'last_rotated': row[3]
            })
        return result

cdef class SyncManager:
    cdef object _ume
    cdef object _ame
    cdef object _keibatsu
    cdef object _config
    cdef public object _engine
    cdef object _server_identity
    cdef set _inflight_syncs
    cdef object _sync_queue
    cdef object _worker_task
    cdef public object _sync_db

    def __init__(self, object engine):
        self._engine = engine
        self._ume = engine.ume
        self._ame = engine.ame
        self._keibatsu = engine.keibatsu
        self._config = engine.config
        self._server_identity = engine.server_identity
        self._inflight_syncs = set()
        self._sync_queue = asyncio.Queue()
        self._worker_task = asyncio.create_task(self._sync_worker())

        cdef str sync_db_path = "/var/lib/bonnet/sync.db"
        if hasattr(engine.config, "data_dir") and engine.config.data_dir:
            sync_db_path = os.path.join(engine.config.data_dir, "sync.db")
        self._sync_db = SyncDB(sync_db_path)

    cpdef bytes get_peer_pubkey(self, str origin):
        return self._sync_db.get_peer_pubkey(origin)

    cpdef bint rotate_peer_pubkey(self, str origin, bytes old_publickey, bytes new_publickey, bytes signature):
        return self._sync_db.rotate_peer_pubkey(origin, old_publickey, new_publickey, signature)

    cpdef list list_peer_keys(self):
        return self._sync_db.list_peer_keys()

    async def _sync_worker(self):
        while True:
            peer_hostname = await self._sync_queue.get()
            try:
                await self._do_sync_from_peer(peer_hostname)
            except Exception as e:
                log_msg(f"SYNC_WORKER: Error syncing from {peer_hostname}: {e}")
            finally:
                self._sync_queue.task_done()
                self._inflight_syncs.discard(peer_hostname)

    async def queue_sync(self, str peer_hostname):
        if peer_hostname in self._inflight_syncs:
            log_msg(f"SYNC: already syncing with {peer_hostname}, skipping")
            return
        self._inflight_syncs.add(peer_hostname)
        await self._sync_queue.put(peer_hostname)

    async def _do_sync_from_peer(self, str peer_hostname):

        cdef object conn
        cdef bint connected = False

        try:
            conn = Connection.client(self._server_identity)
            try:
                await conn.connect(f"wss://{peer_hostname}:2272")
                connected = True
            except Exception as e:
                log_msg(f"SYNC: port 2272 failed for {peer_hostname}: {e}, trying 272")
                await conn.close()
                conn = Connection.client(self._server_identity)
                try:
                    await conn.connect(f"wss://{peer_hostname}:272")
                    connected = True
                except Exception as e2:
                    log_msg(f"SYNC: port 272 also failed for {peer_hostname}: {e2}")
                    await conn.close()
                    return

            # TOFU the peer's public key upon connection
            if not self._sync_db.set_peer_pubkey_tofu(peer_hostname, conn.peer_public_key):
                log_msg(f"SYNC: aborting sync with {peer_hostname} - public key mismatch (TOFU failed)")
                await conn.close()
                return

            await self._sync_boards(conn, peer_hostname)
            await self._sync_users(conn, peer_hostname)
            await self._sync_reports(conn, peer_hostname)

        except Exception as e:
            log_msg(f"SYNC: failed to sync with {peer_hostname}: {e}")
        finally:
            if conn is not None:
                await conn.close()

    async def _sync_boards(self, conn, str peer_hostname):
        await conn.send_request(bytes([0x11]), b'')
        response = await conn.recv_response()

        if len(response) == 0 or response[0] != 0x00:
            log_msg(f"SYNC: BOARD_LIST failed for {peer_hostname}")
            return

        cdef int idx = 1
        cdef int count = struct.unpack('>H', response[idx:idx+2])[0]
        idx += 2

        cdef object nav = self._ame.get_nav()
        cdef int n_len, o_len, s_len
        cdef str name, origin
        cdef bytes signature
        cdef int closed
        cdef list batch = []
        cdef set peer_native_boards = set()

        for _ in range(count):
            n_len = response[idx]
            idx += 1
            name = response[idx:idx+n_len].decode('utf-8')
            idx += n_len

            o_len = response[idx]
            idx += 1
            origin = response[idx:idx+o_len].decode('utf-8')
            idx += o_len

            s_len = response[idx]
            idx += 1
            signature = response[idx:idx+s_len]
            idx += s_len

            closed = response[idx]
            idx += 1

            if origin == peer_hostname:
                peer_native_boards.add(name)

            batch.append((name, name, origin, signature, peer_hostname, closed))

        if batch:
            nav.upsert_remote_batch(batch)
            log_msg(f"SYNC: upserted {len(batch)} boards from {peer_hostname}")

        nav.delete_by_origin_batch(peer_hostname, list(peer_native_boards))
        log_msg(f"SYNC: delta sync complete for {peer_hostname}, native boards: {len(peer_native_boards)}")

    async def _sync_users(self, conn, str peer_hostname):
        cdef int offset = 0
        cdef int limit = 100
        cdef int total = 0
        cdef bytes response
        cdef int idx, count, u_len, r_len, o_len, rel_len, pk_len
        cdef str username, registrar, record_origin, relay
        cdef bytes publickey
        cdef int result

        while True:
            await conn.send_request(bytes([0x03]), struct.pack('>II', offset, limit))
            response = await conn.recv_response()

            if len(response) == 0 or response[0] != 0x00:
                break

            idx = 1
            count = struct.unpack('>H', response[idx:idx+2])[0]
            idx += 2

            if count == 0:
                break

            for _ in range(count):
                u_len = response[idx]
                idx += 1
                username = response[idx:idx+u_len].decode('utf-8')
                idx += u_len

                r_len = response[idx]
                idx += 1
                registrar = response[idx:idx+r_len].decode('utf-8')
                idx += r_len

                o_len = response[idx]
                idx += 1
                record_origin = response[idx:idx+o_len].decode('utf-8')
                idx += o_len

                rel_len = response[idx]
                idx += 1
                relay = response[idx:idx+rel_len].decode('utf-8')
                idx += rel_len

                pk_len = response[idx]
                idx += 1
                publickey = response[idx:idx+pk_len]
                idx += pk_len

                result = self._ume.upsert_remote_user(username, registrar, publickey,
                                                        record_origin, peer_hostname)
                if result > 0:
                    total += 1

            offset += limit

        log_msg(f"SYNC: synced {total} users from {peer_hostname}")

    async def _sync_reports(self, conn, str peer_hostname):
        cdef int64_t since_timestamp = 0
        cdef bytes response
        cdef int idx, count, origin_len, rule_num_len
        cdef str origin
        cdef uint64_t report_num, rule_num, culprit_post_num
        cdef int culprit_len, reporter_len, relay_len, desc_len, origin_sig_len, reporter_sig_len
        cdef bytes culprit_pubkey, reporter_pubkey
        cdef int64_t report_time
        cdef str relay, description, origin_sig, reporter_sig, culprit_board
        cdef int board_len
        cdef int total = 0

        await conn.send_request(bytes([0x54]), struct.pack('>q', since_timestamp))
        response = await conn.recv_response()

        if len(response) == 0 or response[0] != 0x00:
            log_msg(f"SYNC: REPORT_LIST_SINCE failed for {peer_hostname}")
            return

        idx = 1
        count = struct.unpack('>H', response[idx:idx+2])[0]
        idx += 2

        if count == 0:
            log_msg(f"SYNC: no reports from {peer_hostname}")
            return

        for _ in range(count):
            report_num = struct.unpack('>Q', response[idx:idx+8])[0]
            idx += 8

            rule_num = struct.unpack('>Q', response[idx:idx+8])[0]
            idx += 8

            culprit_len = response[idx]
            idx += 1
            culprit_pubkey = response[idx:idx+culprit_len]
            idx += culprit_len

            board_len = response[idx]
            idx += 1
            culprit_board = response[idx:idx+board_len].decode('utf-8') if board_len > 0 else None
            idx += board_len if board_len > 0 else 0

            culprit_post_num = struct.unpack('>Q', response[idx:idx+8])[0]
            idx += 8

            reporter_len = response[idx]
            idx += 1
            reporter_pubkey = response[idx:idx+reporter_len]
            idx += reporter_len

            report_time = struct.unpack('>q', response[idx:idx+8])[0]
            idx += 8

            origin_len = response[idx]
            idx += 1
            origin = response[idx:idx+origin_len].decode('utf-8')
            idx += origin_len

            relay_len = response[idx]
            idx += 1
            relay = response[idx:idx+relay_len].decode('utf-8')
            idx += relay_len

            desc_len = response[idx]
            idx += 1
            description = response[idx:idx+desc_len].decode('utf-8')
            idx += desc_len

            origin_sig_len = response[idx]
            idx += 1
            origin_sig = response[idx:idx+origin_sig_len].decode('utf-8') if origin_sig_len > 0 else None
            idx += origin_sig_len if origin_sig_len > 0 else 0

            reporter_sig_len = response[idx]
            idx += 1
            reporter_sig = response[idx:idx+reporter_sig_len].decode('utf-8') if reporter_sig_len > 0 else None
            idx += reporter_sig_len if reporter_sig_len > 0 else 0

            if origin == self._config.origin:
                continue

            result = self._keibatsu.upsert_remote_report(
                report_num, origin, rule_num, culprit_pubkey, culprit_board, culprit_post_num,
                reporter_pubkey, report_time, peer_hostname, description, origin_sig, reporter_sig,
                self._sync_db.get_peer_pubkey
            )
            if result.result():
                total += 1

        log_msg(f"SYNC: synced {total} reports from {peer_hostname}")
