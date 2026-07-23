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
from core.article_feed import normalize_origin
from core.logging import log_msg

from client.protocol import (
    build_board_list,
    parse_response, ResponseStatus,
    build_feed_heads, parse_feed_heads_resp,
    build_feed_events, parse_feed_events_resp,
)

# Strict hostname regex: dot-separated labels of [a-zA-Z0-9-], each label 1-63
# chars, no leading/trailing dash, total length <= 253.
_HOSTNAME_RE = re.compile(
    r'^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)'
    r'(\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
)


def _is_dialable_host(hostname, allow_private=False):
    """Return True if `hostname` is a safe outbound dial/relay target (string gate).

    Rejects empty strings, IP literals in private/loopback/link-local/reserved/
    multicast/unspecified ranges (SSRF defense), the special-use name `localhost`
    and the `.localhost` TLD, and strings that are not valid hostnames. Public IPs
    and well-formed public-style hostnames are accepted.

    When allow_private=True, the private/loopback/link-local/reserved/multicast/
    unspecified IP rejection is skipped. The `localhost`/`.localhost` string
    rejection remains as a sanity check.

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
        if allow_private:
            return True
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


def _resolves_to_global_only(hostname, allow_private=False):
    """Return True only if `hostname` resolves and EVERY resolved address is
    globally routable (SSRF dial-site gate).

    Resolves A/AAAA via `socket.getaddrinfo(hostname, None, proto=IPPROTO_TCP)`
    and returns True only if there is at least one result and all results are
    public (none of is_private/is_loopback/is_link_local/is_reserved/
    is_multicast/is_unspecified). On resolution failure (gaierror/OSError),
    empty results, or any non-global address, returns False. No caching; re-
    resolved per dial (IP pinning belongs with the #3 TOFU-overhaul follow-up).

    When allow_private=True, the global-routability check on resolved IPs is
    skipped — only DNS resolution success is required.
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
            if not allow_private:
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
        return self._trust.get_pin(normalize_origin(origin) if origin else origin)

    def set_peer_pubkey_tofu(self, origin, publickey) -> bool:
        return self._trust.tofu_pin(normalize_origin(origin) if origin else origin, publickey)

    def rotate_peer_pubkey(self, origin, old_publickey, new_publickey, signature) -> bool:
        return self._trust.verify_rotation(normalize_origin(origin) if origin else origin, old_publickey, new_publickey, signature)

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

        # Periodic scheduler (§16.2): bounded interval with jitter + backoff
        sync_interval = getattr(engine.config, 'sync_interval_seconds', 300)
        self._sync_interval = sync_interval if isinstance(sync_interval, (int, float)) else 300
        backoff_max = getattr(engine.config, 'sync_backoff_max_seconds', 3600)
        self._backoff_max = backoff_max if isinstance(backoff_max, (int, float)) else 3600
        max_events = getattr(engine.config, 'sync_max_events_per_cycle', 5000)
        self._sync_max_events_per_cycle = max_events if isinstance(max_events, (int, float)) else 5000
        self._allow_private_dial = getattr(engine.config, 'allow_private_dial', False)
        self._peer_backoff: dict = {}  # peer -> current backoff seconds (0 = no backoff)
        self._peer_last_success: dict = {}
        self._peer_last_failure: dict = {}
        self._scheduler_task = None
        self._shutdown = False

        # Start the periodic scheduler alongside the event-driven worker
        if self._sync_interval > 0:
            self._scheduler_task = asyncio.create_task(self._periodic_scheduler())

    def shutdown(self):
        """Signal the periodic scheduler to stop cleanly."""
        self._shutdown = True

    async def _periodic_scheduler(self):
        """Periodically enumerate relay candidates and queue syncs.

        Runs on a configurable interval with jitter. Applies exponential
        backoff per peer on failure. Does not let one failing peer block
        the queue permanently.
        """
        import random
        while not self._shutdown:
            # Sleep with jitter (0.75x to 1.25x the interval)
            jitter = self._sync_interval * (0.75 + random.random() * 0.5)
            try:
                await asyncio.sleep(jitter)
            except asyncio.CancelledError:
                break
            if self._shutdown:
                break

            # Enumerate relay candidates from feed subscriptions + known board relays
            relay_candidates = set()

            # From feed subscriptions
            for sub in getattr(self._config, 'feed_subscriptions', []):
                for relay in sub.relays:
                    if _is_dialable_host(relay, allow_private=self._allow_private_dial):
                        relay_candidates.add(relay)

            # From nav (known board relays)
            try:
                peers = self._ame.list_peers()
                for peer in peers:
                    if _is_dialable_host(peer, allow_private=self._allow_private_dial):
                        relay_candidates.add(peer)
            except Exception:
                pass

            for peer in relay_candidates:
                # Check backoff
                backoff = self._peer_backoff.get(peer, 0)
                if backoff > 0:
                    last_fail = self._peer_last_failure.get(peer, 0)
                    if time.time() - last_fail < backoff:
                        continue

                await self.queue_sync(peer)

    def _record_peer_success(self, peer_hostname):
        """Record a successful sync and reset backoff."""
        self._peer_last_success[peer_hostname] = time.time()
        self._peer_backoff[peer_hostname] = 0

    def _record_peer_failure(self, peer_hostname):
        """Record a failed sync and increase backoff exponentially."""
        self._peer_last_failure[peer_hostname] = time.time()
        current = self._peer_backoff.get(peer_hostname, 0)
        if current == 0:
            # In lazy-only mode (interval=0), seed from a small constant so
            # on-demand requests don't hammer a dead peer on every call.
            new_backoff = self._sync_interval if self._sync_interval > 0 else 30
        else:
            new_backoff = min(current * 2, self._backoff_max)
        self._peer_backoff[peer_hostname] = new_backoff
        log_msg(f"SYNC: backoff for {peer_hostname} increased to {new_backoff}s")

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
                self._record_peer_success(peer_hostname)
            except Exception as e:
                log_msg(f"SYNC_WORKER: Error syncing from {peer_hostname}: {e}")
                self._record_peer_failure(peer_hostname)
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
        if not _is_dialable_host(peer_hostname, allow_private=self._allow_private_dial) or not _resolves_to_global_only(peer_hostname, allow_private=self._allow_private_dial):
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

            # Capability check (§16.1): require protocol version 3 and
            # immutable-article-feed-v1. If absent, stop without issuing v3
            # commands. Capability mismatch must not alter pins or accepted data.
            peer_info = None
            try:
                peer_info = await client.discover()
            except Exception:
                pass
            if peer_info:
                peer_versions = peer_info.get("protocol_versions", [])
                peer_caps = peer_info.get("capabilities", [])
                if 3 not in peer_versions or "immutable-article-feed-v1" not in peer_caps:
                    log_msg(f"SYNC: peer {peer_hostname} does not support v3 article feed (versions={peer_versions}, caps missing 'immutable-article-feed-v1'), skipping v3 sync")
                    await client.close()
                    return

            # Sync using multiple commands over one HTTP client (fixes v1 lifecycle mismatch)
            await self._sync_boards(client, peer_hostname)
            await self._sync_article_feeds(client, peer_hostname)
            await self._sync_relayed_article_feeds(client, peer_hostname)

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
            if not _is_dialable_host(origin, allow_private=self._allow_private_dial) or not _is_dialable_host(peer_hostname, allow_private=self._allow_private_dial):
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
    # Article feed sync (Phase 4 — v3)
    # ------------------------------------------------------------------

    async def _sync_article_feeds(self, client, peer_hostname):
        """Sync article feeds from the peer's own origin.

        Per §16.1: fetch FEED_HEADS, for each advertised (origin, board):
        skip local authoritative feeds, check feed subscription, require pinned
        origin key, verify signed head, fetch missing FEED_EVENTS range,
        validate and atomically accept.
        """
        article_service = getattr(self._engine, 'article_service', None)
        if article_service is None:
            return

        store = article_service.store
        peer_origin = getattr(client, '_server_origin', None)

        # Fetch FEED_HEADS from the peer
        try:
            cmd = build_feed_heads(offset=0, limit=100)
            payload = await client._send_command_v3(cmd)
        except Exception as e:
            log_msg(f"SYNC: FEED_HEADS failed for {peer_hostname}: {e}")
            return

        try:
            entries = parse_feed_heads_resp(payload)
        except Exception as e:
            log_msg(f"SYNC: failed to parse FEED_HEADS from {peer_hostname}: {e}")
            return

        for entry in entries:
            origin = entry["origin"]
            board = entry["board"]
            head_bytes = entry["head_bytes"]

            # Skip our own origin
            if origin == self._config.origin:
                continue

            # Check feed subscription
            sub = self._config.get_feed_subscription(origin, board)
            if sub is None:
                continue

            # Require pinned origin key
            origin_pubkey = self._sync_db.get_peer_pubkey(origin)
            if origin_pubkey is None:
                log_msg(f"SYNC: no pinned key for article feed origin '{origin}', skipping")
                continue

            await self._sync_single_feed(client, origin, board, head_bytes,
                                         origin_pubkey, peer_hostname, store)

    async def _sync_relayed_article_feeds(self, client, peer_hostname):
        """Sync article feeds for relayed origins (not the peer's own).

        Same as _sync_article_feeds but skips the peer's own origin (already
        synced in _sync_article_feeds). A relay cannot introduce trust in an
        unpinned origin.
        """
        article_service = getattr(self._engine, 'article_service', None)
        if article_service is None:
            return

        store = article_service.store
        peer_origin = getattr(client, '_server_origin', None)

        try:
            cmd = build_feed_heads(offset=0, limit=100)
            payload = await client._send_command_v3(cmd)
        except Exception as e:
            return

        try:
            entries = parse_feed_heads_resp(payload)
        except Exception:
            return

        for entry in entries:
            origin = entry["origin"]
            board = entry["board"]
            head_bytes = entry["head_bytes"]

            # Skip our own origin and the peer's own origin (already synced)
            if origin == self._config.origin:
                continue
            if origin == peer_origin:
                continue

            sub = self._config.get_feed_subscription(origin, board)
            if sub is None:
                continue

            origin_pubkey = self._sync_db.get_peer_pubkey(origin)
            if origin_pubkey is None:
                continue

            await self._sync_single_feed(client, origin, board, head_bytes,
                                         origin_pubkey, peer_hostname, store)

    async def _sync_single_feed(self, client, origin, board, head_bytes,
                                origin_pubkey, peer_hostname, store):
        """Sync a single (origin, board) feed from a peer.

        1. Decode and verify the signed head
        2. Compare with local feed_state
        3. Fetch the missing FEED_EVENTS range (bounded by max_events_per_cycle)
        4. Validate and atomically accept via accept_remote_range
        """
        from core.article_feed import (
            decode_head, verify_head_signature, decode_event,
            compute_event_hash, encode_event, compute_head_hash,
            encode_head, AcceptResult,
        )

        try:
            head = decode_head(head_bytes)
        except Exception as e:
            log_msg(f"SYNC: failed to decode feed head for ({origin}, {board}): {e}")
            return

        if head.origin != origin or head.board != board:
            log_msg(f"SYNC: feed head origin/board mismatch for ({origin}, {board})")
            return

        if not verify_head_signature(head, origin_pubkey):
            log_msg(f"SYNC: feed head signature verification failed for ({origin}, {board})")
            return

        # Check local state
        state = store.get_feed_state(origin, board)
        highest_seq = state["highest_accepted_seq"] if state else 0

        if head.latest_feed_seq <= highest_seq:
            return  # already up to date or rollback

        # Fetch the missing event range (bounded by max_events_per_cycle)
        start_seq = highest_seq + 1
        total_accepted = 0
        max_events = getattr(self, '_sync_max_events_per_cycle', 5000)

        while start_seq <= head.latest_feed_seq:
            if max_events > 0 and total_accepted >= max_events:
                log_msg(f"SYNC: hit max_events_per_cycle cap ({max_events}) for ({origin}, {board}), continuing next cycle")
                break

            try:
                cmd = build_feed_events(board, start_seq, max_count=50)
                payload = await client._send_command_v3(cmd)
            except Exception as e:
                log_msg(f"SYNC: FEED_EVENTS failed for ({origin}, {board}) at seq {start_seq}: {e}")
                return

            try:
                event_bytes_list = parse_feed_events_resp(payload)
            except Exception as e:
                log_msg(f"SYNC: failed to parse FEED_EVENTS from ({origin}, {board}): {e}")
                return

            if not event_bytes_list:
                break

            events = []
            for entry in event_bytes_list:
                try:
                    events.append(decode_event(entry["event_bytes"]))
                except Exception as e:
                    log_msg(f"SYNC: failed to decode event from ({origin}, {board}): {e}")
                    return

            # Accept the range atomically
            result = store.accept_remote_range(
                origin, board, head, events, origin_pubkey,
                source_relay=peer_hostname,
            )

            if not result.accepted:
                log_msg(f"SYNC: feed range rejected for ({origin}, {board}): {result.reason}")
                return

            total_accepted += len(events)
            start_seq = events[-1].feed_seq + 1

            # If we got fewer events than requested, we're done or at a byte limit
            if len(event_bytes_list) < 50:
                break

        log_msg(f"SYNC: accepted {total_accepted} events for feed ({origin}, {board}) from {peer_hostname}")

        # Normalize user registration events into the local UME
        if total_accepted > 0:
            await self._normalize_users_from_feed(origin, board, store, start_seq - total_accepted, start_seq - 1)

    async def _normalize_users_from_feed(self, origin: str, board: str,
                                          store, start_seq: int, end_seq: int):
        """Normalize user registration events from a synced feed into the UME.

        After accepting feed events for the users.registry board, iterate the
        new events and upsert registered users into the local UME so that
        LIST_USERS, GET_USERS_BY_PUBKEY, and ban enforcement work for
        federated users.
        """
        users_board = getattr(self._config, 'moderation_boards', None)
        if users_board is not None:
            users_board = users_board.users
        else:
            users_board = "users.registry"

        if board != users_board:
            return

        from core.article_feed import EVENT_USER_REGISTER, EVENT_USER_REVOKE

        ume = getattr(self._engine, 'ume', None)
        if ume is None:
            return

        events = store.get_events_range(origin, board, start_seq, end_seq - start_seq + 1)
        inserted = 0
        updated = 0
        skipped = 0

        for ev in events:
            if ev.event_type == EVENT_USER_REGISTER:
                if ev.headers is None:
                    continue
                try:
                    result = ume.upsert_remote_user(
                        username=ev.headers.username,
                        registrar=ev.origin,
                        publickey=ev.headers.publickey,
                        record_origin=ev.origin,
                        relay="",
                        creation_time=ev.headers.creation_time or ev.created_at,
                        max_creation_time_correction=getattr(self._config, 'max_creation_time_correction', 86400),
                    )
                    if result == 1:
                        inserted += 1
                    elif result == 2:
                        updated += 1
                    else:
                        skipped += 1
                except Exception as e:
                    log_msg(f"SYNC: user upsert failed for '{ev.headers.username}' from {origin}: {e}")
                    skipped += 1
            elif ev.event_type == EVENT_USER_REVOKE:
                # Revocation is tracked in user_projection (revoked=1).
                # UME deletion is destructive and not appropriate for federated
                # revocation — the projection-based auth fallback handles this.
                pass

        if inserted or updated:
            log_msg(f"SYNC: normalized {inserted} new + {updated} updated users from feed ({origin}, {board})")
