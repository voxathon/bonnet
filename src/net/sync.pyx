# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False

import struct
import asyncio
from net.connection import Connection
from engine.facade import BonnetEngine
from core.logging import log_msg


cdef class SyncManager:
    cdef object _ume
    cdef object _ame
    cdef object _config
    cdef public object _engine
    cdef object _server_identity
    cdef set _inflight_syncs

    def __init__(self, object engine):
        self._engine = engine
        self._ume = engine.ume
        self._ame = engine.ame
        self._config = engine.config
        self._server_identity = engine.server_identity
        self._inflight_syncs = set()

    async def sync_from_peer(self, str peer_hostname):
        if peer_hostname in self._inflight_syncs:
            log_msg(f"SYNC: already syncing with {peer_hostname}, skipping")
            return
        self._inflight_syncs.add(peer_hostname)

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

            await self._sync_boards(conn, peer_hostname)
            await self._sync_users(conn, peer_hostname)

        except Exception as e:
            log_msg(f"SYNC: failed to sync with {peer_hostname}: {e}")
        finally:
            self._inflight_syncs.discard(peer_hostname)
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

        if count == 0:
            log_msg(f"SYNC: no boards from {peer_hostname}")
            return

        cdef object nav = self._ame.get_nav()
        cdef int n_len, o_len, s_len
        cdef str name, origin
        cdef bytes signature
        cdef int closed
        cdef list batch = []

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

            batch.append((name, name, origin, signature, peer_hostname))

        if batch:
            nav.upsert_remote_batch(batch)
            log_msg(f"SYNC: synced {len(batch)} boards from {peer_hostname}")

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
