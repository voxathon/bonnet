import struct
import asyncio
import os
import time
import re
import socket
import ipaddress
from net.connection import Connection
from engine.facade import BonnetEngine
from core.crypto import Identity
from core.logging import log_msg
from core.orm import Database

# Strict hostname regex: dot-separated labels of [a-zA-Z0-9-], each label 1-63
# chars, no leading/trailing dash, total length <= 253.
_HOSTNAME_RE = re.compile(
    r'^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)'
    r'(\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
)


def _is_dialable_host(hostname):
    """Return True if `hostname` is a safe outbound dial/relay target (string gate).

    Rejects empty strings, IP literals in private/loopback/link-local/reserved/
    multicast/unspecified ranges (SSRF defense), the special-use name `localhost`
    and the `.localhost` TLD, and strings that are not valid hostnames. Public IPs
    and well-formed public-style hostnames are accepted.

    This is the cheap string/ingest gate used in `_sync_boards` and the
    `queue_sync` call sites. It validates the *string form* only -- it does NOT
    perform DNS resolution, so a hostname that resolves to a private IP is not
    caught here. The authoritative SSRF gate at the outbound dial site is
    `_resolves_to_global_only`, which must also pass before dialing.
    """
    if not hostname or not isinstance(hostname, str):
        return False
    host = hostname.strip()
    if not host:
        return False
    # IPv6 literals may be wrapped in brackets when carried with a port; strip them.
    if host.startswith('[') and host.endswith(']') and len(host) >= 2:
        host = host[1:len(host)-1]
    # IP literal?
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        # Reject anything that is not a globally routable address.
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved \
                or ip.is_multicast or ip.is_unspecified:
            return False
        return True
    # Explicitly reject the special-use name 'localhost' and the .localhost TLD,
    # which are syntactically valid hostnames but must never be dialed.
    if host == "localhost" or host.endswith(".localhost"):
        return False
    # Otherwise require a syntactically valid hostname.
    return _HOSTNAME_RE.match(host) is not None


def _resolves_to_global_only(hostname):
    """Return True only if `hostname` resolves and EVERY resolved address is
    globally routable (SSRF dial-site gate).

    Resolves A/AAAA via `socket.getaddrinfo(hostname, None, proto=IPPROTO_TCP)`
    and returns True only if there is at least one result and all results are
    public (none of is_private/is_loopback/is_link_local/is_reserved/
    is_multicast/is_unspecified). On resolution failure (gaierror/OSError),
    empty results, or any non-global address, returns False. No caching; re-
    resolved per dial (IP pinning belongs with the #3 TOFU-overhaul follow-up).
    """
    if not hostname or not isinstance(hostname, str):
        return False
    host = hostname.strip()
    if not host:
        return False
    if host.startswith('[') and host.endswith(']') and len(host) >= 2:
        host = host[1:len(host)-1]
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError, ValueError, TypeError):
        return False
    if not infos:
        return False
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            return False
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except (ValueError, TypeError):
            return False
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved \
                or ip.is_multicast or ip.is_unspecified:
            return False
    return True


def _build_board_signature_payload(name, origin):
    """Reconstruct the canonical board signature payload (mirrors Ame._sign_board)."""
    name_bytes = name.encode('utf-8')
    origin_bytes = origin.encode('utf-8')
    return struct.pack('B', len(name_bytes)) + name_bytes + \
        struct.pack('B', len(origin_bytes)) + origin_bytes


class SyncDB:

    def __init__(self, db_path):
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

    def get_peer_pubkey(self, origin) -> bytes:
        with self._db.open() as ctx:
            rows = ctx.execute("SELECT publickey FROM peer_keys WHERE origin=?", [origin]).fetchall()
        if rows and rows[0][0]:
            return bytes(rows[0][0])
        return None

    def set_peer_pubkey_tofu(self, origin, publickey) -> bool:
        existing = self.get_peer_pubkey(origin)
        if existing:
            return existing == publickey

        now = int(time.time())
        with self._db.open() as ctx:
            ctx.execute(
                "INSERT INTO peer_keys (origin, publickey, first_seen, last_rotated) VALUES (?, ?, ?, ?)",
                [origin, publickey, now, now]
            )
        return True

    def rotate_peer_pubkey(self, origin, old_publickey, new_publickey, signature) -> bool:
        existing = self.get_peer_pubkey(origin)
        if not existing:
            return False
        if existing != old_publickey:
            return False

        from core.crypto import Identity
        origin_bytes = origin.encode('utf-8')
        payload = struct.pack('B', len(origin_bytes)) + origin_bytes + old_publickey + new_publickey

        if not Identity.verify(old_publickey, payload, signature):
            return False

        now = int(time.time())
        with self._db.open() as ctx:
            ctx.execute(
                "UPDATE peer_keys SET publickey=?, last_rotated=? WHERE origin=?",
                [new_publickey, now, origin]
            )
        return True

    def list_peer_keys(self) -> list:
        result = []
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

class SyncManager:

    def __init__(self, engine):
        self._engine = engine
        self._ume = engine.ume
        self._ame = engine.ame
        self._keibatsu = engine.keibatsu
        self._config = engine.config
        self._server_identity = engine.server_identity
        self._inflight_syncs = set()
        self._sync_queue = asyncio.Queue()
        self._worker_task = asyncio.create_task(self._sync_worker())

        sync_db_path = "./data/sync.db"
        if hasattr(engine.config, "data_dir") and engine.config.data_dir:
            sync_db_path = os.path.join(engine.config.data_dir, "sync.db")
        self._sync_db = SyncDB(sync_db_path)

    def get_peer_pubkey(self, origin) -> bytes:
        return self._sync_db.get_peer_pubkey(origin)

    def rotate_peer_pubkey(self, origin, old_publickey, new_publickey, signature) -> bool:
        return self._sync_db.rotate_peer_pubkey(origin, old_publickey, new_publickey, signature)

    def list_peer_keys(self) -> list:
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

    async def queue_sync(self, peer_hostname):
        if peer_hostname in self._inflight_syncs:
            log_msg(f"SYNC: already syncing with {peer_hostname}, skipping")
            return
        self._inflight_syncs.add(peer_hostname)
        await self._sync_queue.put(peer_hostname)

    async def _do_sync_from_peer(self, peer_hostname):

        conn = None
        connected = False

        # SSRF dial-site gate: require BOTH the cheap string check AND a DNS
        # resolution check that every resolved address is globally routable.
        # This blocks hostnames that pass the string check but resolve to
        # private/loopback/link-local IPs (e.g. a rebind or poisoned relay),
        # before any outbound Connection is opened (#2 / R2).
        if not _is_dialable_host(peer_hostname) or not _resolves_to_global_only(peer_hostname):
            log_msg(f"SYNC: refusing to dial non-dialable/non-global peer hostname '{peer_hostname}' (SSRF guard)")
            return

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

    async def _sync_boards(self, conn, peer_hostname):
        await conn.send_request(bytes([0x11]), b'')
        response = await conn.recv_response()

        if len(response) == 0 or response[0] != 0x00:
            log_msg(f"SYNC: BOARD_LIST failed for {peer_hostname}")
            return

        idx = 1
        count = struct.unpack('>H', response[idx:idx+2])[0]
        idx += 2

        nav = self._ame.get_nav()
        batch = []
        peer_native_boards = set()
        verified = 0
        skipped = 0

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

            # SSRF guard: reject entries whose origin or the relay we will store
            # (peer_hostname) is not a dialable host, so poisoned relays/origins
            # never reach nav (#2).
            if not _is_dialable_host(origin) or not _is_dialable_host(peer_hostname):
                log_msg(f"SYNC: skipping board '{name}' from {peer_hostname}: non-dialable origin='{origin}'/relay='{peer_hostname}'")
                skipped += 1
                continue

            # Trust guard: verify the board signature against the origin's
            # TOFU-pinned pubkey before storing, mirroring the report
            # verification path. Entries whose origin has no pinned key or
            # whose signature does not verify are dropped (#1).
            origin_pubkey = self._sync_db.get_peer_pubkey(origin)
            if origin_pubkey is None:
                log_msg(f"SYNC: skipping board '{name}' from {peer_hostname}: no TOFU'd pubkey for origin '{origin}'")
                skipped += 1
                continue

            payload = _build_board_signature_payload(name, origin)
            try:
                if not Identity.verify(origin_pubkey, payload, signature):
                    log_msg(f"SYNC: skipping board '{name}' from {peer_hostname}: signature verification failed for origin '{origin}'")
                    skipped += 1
                    continue
            except Exception as e:
                log_msg(f"SYNC: skipping board '{name}' from {peer_hostname}: signature verification error: {e}")
                skipped += 1
                continue

            if origin == peer_hostname:
                peer_native_boards.add(name)

            batch.append((name, name, origin, signature, peer_hostname, closed))
            verified += 1

        if batch:
            nav.upsert_remote_batch(batch)
            log_msg(f"SYNC: upserted {len(batch)} boards from {peer_hostname} (verified={verified}, skipped={skipped})")

        nav.delete_by_origin_batch(peer_hostname, list(peer_native_boards))
        log_msg(f"SYNC: delta sync complete for {peer_hostname}, native boards: {len(peer_native_boards)}")

    async def _sync_users(self, conn, peer_hostname):
        offset = 0
        limit = 100
        total = 0

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

    async def _sync_reports(self, conn, peer_hostname):
        since_timestamp = 0
        total = 0

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
