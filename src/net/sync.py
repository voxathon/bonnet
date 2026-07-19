import struct
import asyncio
import os
import time
import re
import socket
import ipaddress
from engine.facade import BonnetEngine
from core.crypto import Identity
from core.trust import TrustStore
from core.logging import log_msg

from client.protocol import (
    build_board_list,
    build_user_registry_head, build_user_registry_nodes,
    build_user_registry_records, build_user_registry_heads,
    parse_user_registry_head_resp, parse_user_registry_nodes_resp,
    parse_user_registry_records_resp, parse_user_registry_heads_resp,
    build_report_registry_head, build_report_registry_nodes,
    build_report_registry_records, build_report_registry_heads,
    parse_report_registry_head_resp, parse_report_registry_nodes_resp,
    parse_report_registry_records_resp, parse_report_registry_heads_resp,
    build_punishment_registry_head, build_punishment_registry_nodes,
    build_punishment_registry_records, build_punishment_registry_heads,
    parse_punishment_registry_head_resp, parse_punishment_registry_nodes_resp,
    parse_punishment_registry_records_resp, parse_punishment_registry_heads_resp,
    parse_response, ResponseStatus,
)

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
        self._trust = TrustStore(db_path)

    def get_peer_pubkey(self, origin) -> bytes:
        return self._trust.get_pin(origin)

    def set_peer_pubkey_tofu(self, origin, publickey) -> bool:
        return self._trust.tofu_pin(origin, publickey)

    def rotate_peer_pubkey(self, origin, old_publickey, new_publickey, signature) -> bool:
        return self._trust.verify_rotation(origin, old_publickey, new_publickey, signature)

    def list_peer_keys(self) -> list:
        return self._trust.list_pins()

    def close(self):
        self._trust.close()

class SyncManager:

    def __init__(self, engine):
        self._engine = engine
        self._ume = engine.ume
        self._ame = engine.ame
        self._keibatsu = engine.keibatsu
        self._config = engine.config
        self._server_identity = engine.server_identity
        self._registry_store = getattr(engine, 'registry_store', None)
        self._registry_service = getattr(engine, 'registry_service', None)
        self._inflight_syncs = set()
        self._sync_queue = asyncio.Queue()
        self._worker_task = asyncio.create_task(self._sync_worker())
        self._loop = asyncio.get_running_loop()

        sync_db_path = "./data/sync.db"
        if hasattr(engine.config, "data_dir") and engine.config.data_dir:
            sync_db_path = os.path.join(engine.config.data_dir, "sync.db")
        self._sync_db = SyncDB(sync_db_path)

        # Outbound federation TLS verification.  Defaults to real cert
        # verification (True) for remote peers; a CA-bundle path (str) may be
        # configured, or False for dev/test with self-signed certs.
        self._federation_verify = True
        if hasattr(engine.config, "federation_tls_ca_bundle"):
            self._federation_verify = engine.config.federation_tls_ca_bundle
        elif hasattr(engine.config, "tls_ca_bundle"):
            self._federation_verify = engine.config.tls_ca_bundle

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

    def queue_sync_threadsafe(self, peer_hostname):
        """Schedule a federation sync from any thread (sync or asyncio worker).

        Safe to call from CommandHandler running inside asyncio.to_thread,
        as well as from direct sync callers (CLI/tests). Delegates to the
        async queue_sync on the SyncManager's event loop, preserving the
        inflight dedup logic.
        """
        asyncio.run_coroutine_threadsafe(self.queue_sync(peer_hostname), self._loop)

    async def _do_sync_from_peer(self, peer_hostname):
        # SSRF dial-site gate: require BOTH the cheap string check AND a DNS
        # resolution check that every resolved address is globally routable.
        if not _is_dialable_host(peer_hostname) or not _resolves_to_global_only(peer_hostname):
            log_msg(f"SYNC: refusing to dial non-dialable/non-global peer hostname '{peer_hostname}' (SSRF guard)")
            return

        client = None
        try:
            from client.http import BonnetHTTPClient, BonnetHTTPError

            # Try standard port first, then privileged
            base_url = f"https://{peer_hostname}:2272"
            client = BonnetHTTPClient(base_url=base_url, timeout=30.0, verify=self._federation_verify)

            try:
                await client.connect(self._server_identity)
            except Exception as e:
                log_msg(f"SYNC: port 2272 failed for {peer_hostname}: {e}, trying 272")
                await client.close()
                base_url = f"https://{peer_hostname}:272"
                client = BonnetHTTPClient(base_url=base_url, timeout=30.0, verify=self._federation_verify)
                try:
                    await client.connect(self._server_identity)
                except Exception as e2:
                    log_msg(f"SYNC: port 272 also failed for {peer_hostname}: {e2}")
                    await client.close()
                    return

            # TOFU the peer's public key
            if not self._sync_db.set_peer_pubkey_tofu(peer_hostname, client.server_public_key):
                log_msg(f"SYNC: aborting sync with {peer_hostname} - public key mismatch (TOFU failed)")
                await client.close()
                return

            # Sync using multiple commands over one HTTP client (fixes v1 lifecycle mismatch)
            await self._sync_boards(client, peer_hostname)
            await self._sync_registry(client, peer_hostname)
            await self._sync_report_registry(client, peer_hostname)
            await self._sync_punishment_registry(client, peer_hostname)
            await self._sync_relayed_origins(client, peer_hostname)
            await self._sync_report_relayed_origins(client, peer_hostname)
            await self._sync_punishment_relayed_origins(client, peer_hostname)

        except Exception as e:
            log_msg(f"SYNC: failed to sync with {peer_hostname}: {e}")
        finally:
            if client is not None:
                await client.close()

    async def _sync_boards(self, client, peer_hostname):
        cmd = build_board_list()
        try:
            payload = await client._send_command(cmd)
        except Exception as e:
            log_msg(f"SYNC: BOARD_LIST failed for {peer_hostname}: {e}")
            return

        idx = 0
        count = struct.unpack('>H', payload[idx:idx+2])[0]
        idx += 2

        nav = self._ame.get_nav()
        batch = []
        peer_native_boards = set()
        verified = 0
        skipped = 0

        for _ in range(count):
            n_len = payload[idx]
            idx += 1
            name = payload[idx:idx+n_len].decode('utf-8')
            idx += n_len

            o_len = payload[idx]
            idx += 1
            origin = payload[idx:idx+o_len].decode('utf-8')
            idx += o_len

            s_len = payload[idx]
            idx += 1
            signature = payload[idx:idx+s_len]
            idx += s_len

            closed = payload[idx]
            idx += 1

            # SSRF guard: reject entries whose origin or the relay we will store
            # (peer_hostname) is not a dialable host, so poisoned relays/origins
            # never reach nav (#2).
            if not _is_dialable_host(origin) or not _is_dialable_host(peer_hostname):
                log_msg(f"SYNC: skipping board '{name}' from {peer_hostname}: non-dialable origin='{origin}'/relay='{peer_hostname}'")
                skipped += 1
                continue

            # Import allowlist (§13): skip origins not in the boards allowlist
            # before expensive pin/signature work. Default-deny.
            if not self._config.is_import_origin_allowed("boards", origin):
                log_msg(f"SYNC: skipping board '{name}' from {peer_hostname}: origin '{origin}' not in boards import allowlist")
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

            sig_payload = _build_board_signature_payload(name, origin)
            try:
                if not Identity.verify(origin_pubkey, sig_payload, signature):
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

    # ------------------------------------------------------------------
    # Registry sync (Phase 5)
    # ------------------------------------------------------------------

    async def _sync_registry(self, client, peer_hostname):
        """Fetch and verify the peer's origin registry head, compare subtrees,
        fetch changed records, accept atomically, and normalize into UME."""
        await self._sync_registry_inner(client, peer_hostname)

    async def _sync_registry_inner(self, client, peer_hostname):

        if self._registry_store is None:
            log_msg("SYNC: registry store not available, skipping registry sync")
            return

        peer_origin = getattr(client, '_server_origin', None)
        if not peer_origin:
            log_msg("SYNC: cannot determine peer origin for registry sync")
            return

        if peer_origin == self._config.origin:
            log_msg("SYNC: skipping registry sync for own origin")
            return

        # Import allowlist (§13): skip origins not in the users allowlist
        # before expensive head/record fetches. Default-deny.
        if not self._config.is_import_origin_allowed("users", peer_origin):
            log_msg(f"SYNC: skipping registry sync for origin '{peer_origin}': not in users import allowlist")
            return

        origin_pubkey = self._sync_db.get_peer_pubkey(peer_origin)
        if origin_pubkey is None:
            log_msg(f"SYNC: no pinned key for origin '{peer_origin}', skipping registry sync")
            return

        log_msg(f"SYNC: starting registry sync for origin '{peer_origin}'")

        from core.user_registry import (
            decode_head, verify_head, compute_registry_key, compute_value_hash,
            CSMT, DEFAULT_HASHES, TREE_DEPTH, verify_node_children,
            AcceptResult,
        )
        from engine.ume import User, RECORD_SIZE

        # 1. Fetch the peer's origin head
        try:
            cmd = build_user_registry_head(peer_origin, 0)
            payload = await client._send_command(cmd)
        except Exception as e:
            log_msg(f"SYNC: USER_REGISTRY_HEAD failed for {peer_origin}: {e}")
            return

        try:
            encoded_head = parse_user_registry_head_resp(payload)
            head = decode_head(encoded_head)
        except Exception as e:
            log_msg(f"SYNC: failed to decode registry head from {peer_origin}: {e}")
            return

        # 2. Verify head signature
        if not verify_head(head, origin_pubkey):
            log_msg(f"SYNC: registry head signature verification failed for {peer_origin}")
            return

        if head.origin != peer_origin:
            log_msg(f"SYNC: head origin '{head.origin}' != requested '{peer_origin}'")
            return

        # 3. Check if we already have this root
        state = self._registry_store.get_state(peer_origin)
        if state is not None and state["current_merkle_root"] == head.merkle_root:
            return

        # 4. Fetch records and build store entries
        records_for_store: list[tuple[bytes, str, bytes, bytes]] = []
        nodes_for_store: list[tuple[int, bytes, bytes]] = []
        actual_seq = head.registry_seq

        # Fetch all records from the peer — simple and correct for both
        # first sync and subsequent syncs.  The subtree comparison optimization
        # can be added later once the 256-level traversal is batched.
        try:
            cmd = build_user_registry_records(peer_origin, actual_seq, [], include_proofs=False)
            payload = await client._send_command(cmd)
        except Exception as e:
            log_msg(f"SYNC: USER_REGISTRY_RECORDS (all) failed for {peer_origin}: {e}")
            return

        try:
            record_entries = parse_user_registry_records_resp(payload)
        except Exception as e:
            log_msg(f"SYNC: failed to parse records response from {peer_origin}: {e}")
            return

        for entry in record_entries:
            if entry["present"] != 1:
                continue
            raw_record = entry["raw_record"]
            if len(raw_record) != RECORD_SIZE:
                continue
            try:
                user = User.decode(raw_record)
            except Exception:
                continue
            if user.record_origin != peer_origin:
                continue
            if len(user.publickey) != 32:
                continue
            key = compute_registry_key(peer_origin, user.username)
            vh = compute_value_hash(raw_record)
            if key != entry["registry_key"]:
                continue
            records_for_store.append((key, user.username, raw_record, vh))

        log_msg(f"SYNC: fetched {len(records_for_store)} records for {peer_origin}")

        # 6. Atomically accept the remote head
        result = self._registry_store.accept_remote_head(
            origin=peer_origin,
            head=head,
            origin_pubkey=origin_pubkey,
            records=records_for_store,
            nodes=nodes_for_store,
        )

        if not result.accepted:
            log_msg(f"SYNC: registry head rejected for {peer_origin}: {result.reason}")
            return

        log_msg(f"SYNC: registry head accepted for {peer_origin} seq {head.registry_seq}")

        # 7. Normalize records into UME
        total_normalized = 0
        max_creation_time_correction = getattr(self._config, 'max_creation_time_correction', 86400)

        for key, username, raw_record, vh in records_for_store:
            user = User.decode(raw_record)
            try:
                status = self._ume.upsert_remote_user(
                    username=user.username,
                    registrar=user.registrar,
                    publickey=user.publickey,
                    record_origin=user.record_origin,
                    relay=peer_hostname,
                    creation_time=user.creation_time,
                    max_creation_time_correction=max_creation_time_correction,
                )
                if status > 0:
                    total_normalized += 1
            except ValueError as e:
                log_msg(f"SYNC: upsert_remote_user failed for '{user.username}': {e}")

        log_msg(f"SYNC: normalized {total_normalized} users into UME from {peer_origin} registry")

    # ------------------------------------------------------------------
    # Relay origin discovery (Phase 6)
    # ------------------------------------------------------------------

    async def _sync_relayed_origins(self, client, peer_hostname):
        """Discover cached origin heads advertised by a relay and sync any
        origins we already trust (have a pinned key for).

        This does NOT TOFU new origins — a relay cannot introduce trust in
        an origin the receiver has not already pinned.  The receiver verifies
        each head against the pinned origin key, never against the relay key.
        """

        if self._registry_store is None:
            return

        peer_origin = getattr(client, '_server_origin', None)
        if not peer_origin:
            return

        # Fetch the relay's advertised head list
        try:
            cmd = build_user_registry_heads(offset=0, limit=100)
            payload = await client._send_command(cmd)
        except Exception as e:
            log_msg(f"SYNC: USER_REGISTRY_HEADS failed for {peer_hostname}: {e}")
            return

        try:
            encoded_heads = parse_user_registry_heads_resp(payload)
        except Exception as e:
            log_msg(f"SYNC: failed to parse heads list from {peer_hostname}: {e}")
            return

        if not encoded_heads:
            return

        from core.user_registry import decode_head

        for encoded in encoded_heads:
            try:
                head = decode_head(encoded)
            except Exception:
                continue

            # Skip our own origin and the peer's own origin (already synced)
            if head.origin == self._config.origin:
                continue
            if head.origin == peer_origin:
                continue

            # Import allowlist (§13): skip advertised origins not in the users
            # allowlist before expensive head/record fetches. Default-deny.
            if not self._config.is_import_origin_allowed("users", head.origin):
                log_msg(f"SYNC: relay advertises origin '{head.origin}' but not in users import allowlist, skipping")
                continue

            # Only sync origins we already have a pinned key for
            origin_pubkey = self._sync_db.get_peer_pubkey(head.origin)
            if origin_pubkey is None:
                log_msg(f"SYNC: relay advertises origin '{head.origin}' but no pinned key, skipping")
                continue

            # Check if we already have this root
            state = self._registry_store.get_state(head.origin)
            if state is not None and state["current_merkle_root"] == head.merkle_root:
                continue

            log_msg(f"SYNC: syncing relayed origin '{head.origin}' from relay {peer_hostname}")

            # Fetch the full head (the list may have a summary; get the real one)
            try:
                cmd = build_user_registry_head(head.origin, 0)
                head_payload = await client._send_command(cmd)
            except Exception as e:
                log_msg(f"SYNC: relayed HEAD fetch failed for {head.origin}: {e}")
                continue

            from core.user_registry import (
                verify_head, compute_registry_key, compute_value_hash,
            )
            from engine.ume import User, RECORD_SIZE

            try:
                full_encoded = parse_user_registry_head_resp(head_payload)
                full_head = decode_head(full_encoded)
            except Exception:
                continue

            if not verify_head(full_head, origin_pubkey):
                log_msg(f"SYNC: relayed head signature failed for {head.origin}")
                continue

            if full_head.origin != head.origin:
                continue

            # Fetch all records for this origin from the relay
            actual_seq = full_head.registry_seq
            try:
                cmd = build_user_registry_records(head.origin, actual_seq, [], include_proofs=False)
                rec_payload = await client._send_command(cmd)
            except Exception as e:
                log_msg(f"SYNC: relayed records fetch failed for {head.origin}: {e}")
                continue

            try:
                record_entries = parse_user_registry_records_resp(rec_payload)
            except Exception:
                continue

            records_for_store: list[tuple[bytes, str, bytes, bytes]] = []
            for entry in record_entries:
                if entry["present"] != 1:
                    continue
                raw_record = entry["raw_record"]
                if len(raw_record) != RECORD_SIZE:
                    continue
                try:
                    user = User.decode(raw_record)
                except Exception:
                    continue
                if user.record_origin != head.origin:
                    continue
                if len(user.publickey) != 32:
                    continue
                key = compute_registry_key(head.origin, user.username)
                vh = compute_value_hash(raw_record)
                if key != entry["registry_key"]:
                    continue
                records_for_store.append((key, user.username, raw_record, vh))

            # Accept atomically
            result = self._registry_store.accept_remote_head(
                origin=head.origin,
                head=full_head,
                origin_pubkey=origin_pubkey,
                records=records_for_store,
                nodes=[],
            )

            if not result.accepted:
                log_msg(f"SYNC: relayed head rejected for {head.origin}: {result.reason}")
                continue

            log_msg(f"SYNC: relayed head accepted for {head.origin} seq {full_head.registry_seq}")

            # Normalize into UME
            max_ct_correction = getattr(self._config, 'max_creation_time_correction', 86400)
            for key, username, raw_record, vh in records_for_store:
                user = User.decode(raw_record)
                try:
                    self._ume.upsert_remote_user(
                        username=user.username,
                        registrar=user.registrar,
                        publickey=user.publickey,
                        record_origin=user.record_origin,
                        relay=peer_hostname,
                        creation_time=user.creation_time,
                        max_creation_time_correction=max_ct_correction,
                    )
                except ValueError as e:
                    log_msg(f"SYNC: relayed upsert failed for '{user.username}': {e}")

    # ------------------------------------------------------------------
    # Report registry sync (Phase 4)
    # ------------------------------------------------------------------

    async def _sync_report_registry(self, client, peer_hostname):
        """Fetch and verify the peer's report registry head, fetch records,
        accept atomically into the report registry store."""
        store = getattr(self._engine, 'report_registry_store', None)
        if store is None:
            log_msg("SYNC: report registry store not available, skipping report registry sync")
            return

        peer_origin = getattr(client, '_server_origin', None)
        if not peer_origin:
            log_msg("SYNC: cannot determine peer origin for report registry sync")
            return

        if peer_origin == self._config.origin:
            log_msg("SYNC: skipping report registry sync for own origin")
            return

        # Import allowlist (§13): skip origins not in the reports allowlist
        if not self._config.is_import_origin_allowed("reports", peer_origin):
            log_msg(f"SYNC: skipping report registry sync for origin '{peer_origin}': not in reports import allowlist")
            return

        origin_pubkey = self._sync_db.get_peer_pubkey(peer_origin)
        if origin_pubkey is None:
            log_msg(f"SYNC: no pinned key for origin '{peer_origin}', skipping report registry sync")
            return

        log_msg(f"SYNC: starting report registry sync for origin '{peer_origin}'")

        from core.report_registry import decode_report_head, verify_report_head

        # 1. Fetch the peer's report registry head
        try:
            cmd = build_report_registry_head(peer_origin, 0)
            payload = await client._send_command(cmd)
        except Exception as e:
            log_msg(f"SYNC: REPORT_REGISTRY_HEAD failed for {peer_origin}: {e}")
            return

        try:
            encoded_head = parse_report_registry_head_resp(payload)
            head = decode_report_head(encoded_head)
        except Exception as e:
            log_msg(f"SYNC: failed to decode report registry head from {peer_origin}: {e}")
            return

        # 2. Verify head signature
        if not verify_report_head(head, origin_pubkey):
            log_msg(f"SYNC: report registry head signature verification failed for {peer_origin}")
            return

        if head.origin != peer_origin:
            log_msg(f"SYNC: report head origin '{head.origin}' != requested '{peer_origin}'")
            return

        # 3. Check if we already have this root
        state = store.get_state(peer_origin)
        if state is not None and state["current_merkle_root"] == head.merkle_root:
            return

        # 4. Fetch all records
        actual_seq = head.registry_seq
        try:
            cmd = build_report_registry_records(peer_origin, actual_seq, [], include_proofs=False)
            payload = await client._send_command(cmd)
        except Exception as e:
            log_msg(f"SYNC: REPORT_REGISTRY_RECORDS failed for {peer_origin}: {e}")
            return

        try:
            record_entries = parse_report_registry_records_resp(payload)
        except Exception as e:
            log_msg(f"SYNC: failed to parse report records response from {peer_origin}: {e}")
            return

        from core.report_registry import report_registry_key, compute_report_value_hash

        records_for_store: list[tuple[bytes, str, bytes, bytes]] = []
        for entry in record_entries:
            if entry["present"] != 1:
                continue
            raw_record = entry["raw_record"]
            # Store the record as-is. The key in the registry is the
            # report_registry_key, which the exporter includes in the
            # records response. We trust the key from the response.
            key = entry["registry_key"]
            vh = compute_report_value_hash(raw_record)
            records_for_store.append((key, "", raw_record, vh))

        log_msg(f"SYNC: fetched {len(records_for_store)} report records for {peer_origin}")

        # 6. Atomically accept the remote head
        result = store.accept_remote_head(
            origin=peer_origin,
            head=head,
            origin_pubkey=origin_pubkey,
            records=records_for_store,
            nodes=[],
        )

        if not result.accepted:
            log_msg(f"SYNC: report registry head rejected for {peer_origin}: {result.reason}")
            return

        log_msg(f"SYNC: report registry head accepted for {peer_origin} seq {head.registry_seq}")

    async def _sync_report_relayed_origins(self, client, peer_hostname):
        """Discover cached report registry heads advertised by a relay and
        sync any origins we already trust (have a pinned key for)."""
        store = getattr(self._engine, 'report_registry_store', None)
        if store is None:
            return

        peer_origin = getattr(client, '_server_origin', None)
        if not peer_origin:
            return

        # Fetch the relay's advertised report head list
        try:
            cmd = build_report_registry_heads(offset=0, limit=100)
            payload = await client._send_command(cmd)
        except Exception as e:
            log_msg(f"SYNC: REPORT_REGISTRY_HEADS failed for {peer_hostname}: {e}")
            return

        try:
            encoded_heads = parse_report_registry_heads_resp(payload)
        except Exception as e:
            log_msg(f"SYNC: failed to parse report heads list from {peer_hostname}: {e}")
            return

        if not encoded_heads:
            return

        from core.report_registry import decode_report_head, verify_report_head, compute_report_value_hash
        from client.protocol import build_report_registry_records, parse_report_registry_records_resp

        for encoded in encoded_heads:
            try:
                head = decode_report_head(encoded)
            except Exception:
                continue

            # Skip our own origin and the peer's own origin (already synced)
            if head.origin == self._config.origin:
                continue
            if head.origin == peer_origin:
                continue

            # Import allowlist (§13)
            if not self._config.is_import_origin_allowed("reports", head.origin):
                log_msg(f"SYNC: relay advertises report origin '{head.origin}' but not in reports import allowlist, skipping")
                continue

            # Only sync origins we already have a pinned key for
            origin_pubkey = self._sync_db.get_peer_pubkey(head.origin)
            if origin_pubkey is None:
                log_msg(f"SYNC: relay advertises report origin '{head.origin}' but no pinned key, skipping")
                continue

            # Check if we already have this root
            state = store.get_state(head.origin)
            if state is not None and state["current_merkle_root"] == head.merkle_root:
                continue

            log_msg(f"SYNC: syncing relayed report origin '{head.origin}' from relay {peer_hostname}")

            # Fetch the full head
            try:
                cmd = build_report_registry_head(head.origin, 0)
                head_payload = await client._send_command(cmd)
            except Exception as e:
                log_msg(f"SYNC: relayed report HEAD fetch failed for {head.origin}: {e}")
                continue

            try:
                full_encoded = parse_report_registry_head_resp(head_payload)
                full_head = decode_report_head(full_encoded)
            except Exception:
                continue

            if not verify_report_head(full_head, origin_pubkey):
                log_msg(f"SYNC: relayed report head signature failed for {head.origin}")
                continue

            if full_head.origin != head.origin:
                continue

            # Fetch all records for this origin from the relay
            actual_seq = full_head.registry_seq
            try:
                cmd = build_report_registry_records(head.origin, actual_seq, [], include_proofs=False)
                rec_payload = await client._send_command(cmd)
            except Exception as e:
                log_msg(f"SYNC: relayed report records fetch failed for {head.origin}: {e}")
                continue

            try:
                record_entries = parse_report_registry_records_resp(rec_payload)
            except Exception:
                continue

            records_for_store: list[tuple[bytes, str, bytes, bytes]] = []
            for entry in record_entries:
                if entry["present"] != 1:
                    continue
                raw_record = entry["raw_record"]
                key = entry["registry_key"]
                vh = compute_report_value_hash(raw_record)
                records_for_store.append((key, "", raw_record, vh))

            # Accept atomically
            result = store.accept_remote_head(
                origin=head.origin,
                head=full_head,
                origin_pubkey=origin_pubkey,
                records=records_for_store,
                nodes=[],
            )

            if not result.accepted:
                log_msg(f"SYNC: relayed report head rejected for {head.origin}: {result.reason}")
                continue

            log_msg(f"SYNC: relayed report head accepted for {head.origin} seq {full_head.registry_seq}")

    # ------------------------------------------------------------------
    # Punishment registry sync (Phase 5)
    # ------------------------------------------------------------------

    async def _sync_punishment_registry(self, client, peer_hostname):
        """Fetch and verify the peer's punishment registry head, fetch records,
        accept atomically into the punishment registry store."""
        store = getattr(self._engine, 'punishment_registry_store', None)
        if store is None:
            return

        peer_origin = getattr(client, '_server_origin', None)
        if not peer_origin:
            return

        if peer_origin == self._config.origin:
            return

        if not self._config.is_import_origin_allowed("punishments", peer_origin):
            log_msg(f"SYNC: skipping punishment registry sync for origin '{peer_origin}': not in punishments import allowlist")
            return

        origin_pubkey = self._sync_db.get_peer_pubkey(peer_origin)
        if origin_pubkey is None:
            return

        from core.punishment_registry import decode_punishment_head, verify_punishment_head, compute_punishment_value_hash

        try:
            cmd = build_punishment_registry_head(peer_origin, 0)
            payload = await client._send_command(cmd)
        except Exception as e:
            log_msg(f"SYNC: PUNISHMENT_REGISTRY_HEAD failed for {peer_origin}: {e}")
            return

        try:
            encoded_head = parse_punishment_registry_head_resp(payload)
            head = decode_punishment_head(encoded_head)
        except Exception as e:
            log_msg(f"SYNC: failed to decode punishment registry head from {peer_origin}: {e}")
            return

        if not verify_punishment_head(head, origin_pubkey):
            log_msg(f"SYNC: punishment registry head signature verification failed for {peer_origin}")
            return

        if head.origin != peer_origin:
            return

        state = store.get_state(peer_origin)
        if state is not None and state["current_merkle_root"] == head.merkle_root:
            return

        actual_seq = head.registry_seq
        try:
            cmd = build_punishment_registry_records(peer_origin, actual_seq, [], include_proofs=False)
            payload = await client._send_command(cmd)
        except Exception as e:
            log_msg(f"SYNC: PUNISHMENT_REGISTRY_RECORDS failed for {peer_origin}: {e}")
            return

        try:
            record_entries = parse_punishment_registry_records_resp(payload)
        except Exception as e:
            log_msg(f"SYNC: failed to parse punishment records response from {peer_origin}: {e}")
            return

        records_for_store: list[tuple[bytes, str, bytes, bytes]] = []
        for entry in record_entries:
            if entry["present"] != 1:
                continue
            raw_record = entry["raw_record"]
            key = entry["registry_key"]
            vh = compute_punishment_value_hash(raw_record)
            records_for_store.append((key, "", raw_record, vh))

        result = store.accept_remote_head(
            origin=peer_origin,
            head=head,
            origin_pubkey=origin_pubkey,
            records=records_for_store,
            nodes=[],
        )

        if not result.accepted:
            log_msg(f"SYNC: punishment registry head rejected for {peer_origin}: {result.reason}")
            return

        log_msg(f"SYNC: punishment registry head accepted for {peer_origin} seq {head.registry_seq}")

    async def _sync_punishment_relayed_origins(self, client, peer_hostname):
        """Discover cached punishment registry heads advertised by a relay."""
        store = getattr(self._engine, 'punishment_registry_store', None)
        if store is None:
            return

        peer_origin = getattr(client, '_server_origin', None)
        if not peer_origin:
            return

        try:
            cmd = build_punishment_registry_heads(offset=0, limit=100)
            payload = await client._send_command(cmd)
        except Exception as e:
            log_msg(f"SYNC: PUNISHMENT_REGISTRY_HEADS failed for {peer_hostname}: {e}")
            return

        try:
            encoded_heads = parse_punishment_registry_heads_resp(payload)
        except Exception as e:
            log_msg(f"SYNC: failed to parse punishment heads list from {peer_hostname}: {e}")
            return

        if not encoded_heads:
            return

        from core.punishment_registry import decode_punishment_head, verify_punishment_head, compute_punishment_value_hash

        for encoded in encoded_heads:
            try:
                head = decode_punishment_head(encoded)
            except Exception:
                continue

            if head.origin == self._config.origin:
                continue
            if head.origin == peer_origin:
                continue

            if not self._config.is_import_origin_allowed("punishments", head.origin):
                log_msg(f"SYNC: relay advertises punishment origin '{head.origin}' but not in punishments import allowlist, skipping")
                continue

            origin_pubkey = self._sync_db.get_peer_pubkey(head.origin)
            if origin_pubkey is None:
                continue

            state = store.get_state(head.origin)
            if state is not None and state["current_merkle_root"] == head.merkle_root:
                continue

            log_msg(f"SYNC: syncing relayed punishment origin '{head.origin}' from relay {peer_hostname}")

            try:
                cmd = build_punishment_registry_head(head.origin, 0)
                head_payload = await client._send_command(cmd)
            except Exception as e:
                log_msg(f"SYNC: relayed punishment HEAD fetch failed for {head.origin}: {e}")
                continue

            try:
                full_encoded = parse_punishment_registry_head_resp(head_payload)
                full_head = decode_punishment_head(full_encoded)
            except Exception:
                continue

            if not verify_punishment_head(full_head, origin_pubkey):
                continue

            if full_head.origin != head.origin:
                continue

            actual_seq = full_head.registry_seq
            try:
                cmd = build_punishment_registry_records(head.origin, actual_seq, [], include_proofs=False)
                rec_payload = await client._send_command(cmd)
            except Exception as e:
                log_msg(f"SYNC: relayed punishment records fetch failed for {head.origin}: {e}")
                continue

            try:
                record_entries = parse_punishment_registry_records_resp(rec_payload)
            except Exception:
                continue

            records_for_store: list[tuple[bytes, str, bytes, bytes]] = []
            for entry in record_entries:
                if entry["present"] != 1:
                    continue
                raw_record = entry["raw_record"]
                key = entry["registry_key"]
                vh = compute_punishment_value_hash(raw_record)
                records_for_store.append((key, "", raw_record, vh))

            result = store.accept_remote_head(
                origin=head.origin,
                head=full_head,
                origin_pubkey=origin_pubkey,
                records=records_for_store,
                nodes=[],
            )

            if not result.accepted:
                log_msg(f"SYNC: relayed punishment head rejected for {head.origin}: {result.reason}")
                continue

            log_msg(f"SYNC: relayed punishment head accepted for {head.origin} seq {full_head.registry_seq}")
