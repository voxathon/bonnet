"""Federation sync manager for the Bonnet Firehose Protocol (PROTOCOL.md §17).

Pulls the global firehose from remote origins: fetches signed heads,
requests contiguous event ranges, verifies chain continuity and signatures,
creates local relay witnesses, and stores accepted records.

Each imported record retains the origin record unchanged. The receiving
relay creates its own witness naming the contacted server as immediate
upstream.
"""

from __future__ import annotations

import asyncio
import struct
import time
import threading
from typing import Optional

from core.crypto import Identity
from core.logging import log_msg
from core.record import (
    Record, Head, Witness,
    encode_record, decode_record,
    encode_head, decode_head,
    encode_unsigned_witness, encode_witness,
    compute_event_hash, compute_head_hash,
    verify_record_signature, verify_head_signature,
    verify_witness_signature,
    ZERO_ID, ZERO_HASH, SIG_SIZE,
)
from core.firehose import (
    FirehoseStore, AcceptResult,
    FirehoseError, ChainBreak, SignatureInvalid, HeadMismatch,
    EventIdCollision, ArticleIdCollision,
)


# ---------------------------------------------------------------------------
# Sync client interface
# ---------------------------------------------------------------------------

class SyncClient:
    """Abstract interface for a federation sync client."""

    async def fetch_head(self, origin: str) -> tuple[Head, bytes]:
        """Fetch the signed head for an origin. Returns (head, raw_bytes)."""
        raise NotImplementedError

    async def fetch_range(self, origin: str, start_seq: int, max_count: int) -> list[tuple[Record, Witness]]:
        """Fetch a range of records with witnesses. Returns list of (record, witness)."""
        raise NotImplementedError

    async def close(self) -> None:
        pass


class HttpSyncClient(SyncClient):
    """Concrete SyncClient using FirehoseHTTPClient over HTTP.

    Connects anonymously, performs TOFU key pinning via discovery,
    and wraps the firehose protocol commands EVENT_HEAD and EVENT_RANGE.
    """

    def __init__(self, base_url: str, verify_tls: bool = False):
        from client.firehose_client import FirehoseHTTPClient
        self._client = FirehoseHTTPClient(base_url, verify=verify_tls)
        self._connected = False

    async def _ensure_connected(self) -> None:
        if not self._connected:
            await self._client.connect_anonymous()
            self._connected = True
            log_msg(f"SYNC_CLIENT: connected to server origin='{self._client._server_origin}' pubkey={self._client._server_pubkey.hex()[:16]}...")

    async def fetch_head(self, origin: str) -> tuple[Head, bytes]:
        from client.firehose_protocol import build_event_head, parse_event_head_response_raw
        await self._ensure_connected()
        cmd = build_event_head(origin)
        resp = await self._client._send_command(cmd)
        head = parse_event_head_response_raw(resp)
        return head, encode_head(head)

    async def fetch_range(self, origin: str, start_seq: int, max_count: int) -> list[tuple[Record, Witness]]:
        from client.firehose_protocol import build_event_range, parse_event_range_response
        await self._ensure_connected()
        cmd = build_event_range(origin, start_seq, max_count)
        resp = await self._client._send_command(cmd)
        return parse_event_range_response(resp)

    async def close(self) -> None:
        await self._client.close()


# ---------------------------------------------------------------------------
# Sync manager
# ---------------------------------------------------------------------------

class SyncManager:
    """Manages background firehose synchronization from remote origins.

    Supports both periodic sync loops (start_origin) and on-demand sync
    triggered by read requests for remote origins (queue_sync). Both paths
    feed into a single asyncio.Queue consumed by a background worker.

    The sync manager:
    1. Fetches the signed head for an origin.
    2. Compares against the local highest sequence.
    3. Requests the missing contiguous range.
    4. Verifies and accepts the range.
    5. Creates local relay witnesses.
    """

    def __init__(
        self,
        firehose: FirehoseStore,
        server_identity: Identity,
        hostname: str,
        dispatcher=None,
    ):
        self._firehose = firehose
        self._identity = server_identity
        self._hostname = hostname
        self._dispatcher = dispatcher
        self._lock = threading.RLock()
        self._running = False
        self._tasks: dict[str, asyncio.Task] = {}
        self._clients: dict[str, SyncClient] = {}
        self._inflight: set[str] = set()
        self._sync_queue: asyncio.Queue = asyncio.Queue()
        self._worker_task: Optional[asyncio.Task] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._peer_backoff: dict[str, float] = {}
        self._peer_last_failure: dict[str, float] = {}
        self._backoff_max = 3600

    def start_origin(self, origin: str, client: SyncClient, interval: int = 300) -> None:
        """Start syncing an origin in the background (periodic + on-demand)."""
        if self._loop is None:
            self._loop = asyncio.get_running_loop()
        with self._lock:
            if origin in self._tasks:
                return
            self._clients[origin] = client
            self._tasks[origin] = asyncio.ensure_future(
                self._sync_loop(origin, client, interval)
            )
            if self._worker_task is None:
                self._worker_task = asyncio.ensure_future(self._sync_worker())
                self._running = True

    async def queue_sync(self, origin: str) -> None:
        """Queue an on-demand sync. Must be called from the event loop thread."""
        if origin not in self._clients or origin in self._inflight:
            return
        self._inflight.add(origin)
        await self._sync_queue.put(origin)

    def queue_sync_threadsafe(self, origin: str) -> None:
        """Thread-safe queue — call from sync context (asyncio.to_thread)."""
        if origin not in self._clients or origin in self._inflight:
            return
        if self._loop is not None:
            asyncio.run_coroutine_threadsafe(self.queue_sync(origin), self._loop)

    def _record_peer_success(self, origin: str) -> None:
        self._peer_backoff[origin] = 0

    def _record_peer_failure(self, origin: str) -> None:
        current = self._peer_backoff.get(origin, 0)
        new_backoff = (current * 2) if current > 0 else 30
        self._peer_backoff[origin] = min(new_backoff, self._backoff_max)
        self._peer_last_failure[origin] = time.time()
        log_msg(f"SYNC: backoff for '{origin}' increased to {self._peer_backoff[origin]}s")

    def stop_origin(self, origin: str) -> None:
        """Stop syncing an origin."""
        with self._lock:
            task = self._tasks.pop(origin, None)
            self._clients.pop(origin, None)
            if task:
                task.cancel()

    async def stop_all(self) -> None:
        with self._lock:
            tasks = list(self._tasks.values())
            self._tasks.clear()
            self._clients.clear()
            if self._worker_task:
                self._worker_task.cancel()
                tasks.append(self._worker_task)
                self._worker_task = None
            self._running = False
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except asyncio.CancelledError:
                pass

    async def _sync_worker(self) -> None:
        """Background worker consuming on-demand sync requests."""
        while True:
            try:
                origin = await self._sync_queue.get()
                client = self._clients.get(origin)
                if client is None:
                    continue
                try:
                    await self._sync_once(origin, client)
                    self._record_peer_success(origin)
                except Exception as e:
                    log_msg(f"SYNC_WORKER: error syncing origin '{origin}': {e}")
                    self._record_peer_failure(origin)
                finally:
                    self._inflight.discard(origin)
                    self._sync_queue.task_done()
            except asyncio.CancelledError:
                break

    async def _sync_loop(self, origin: str, client: SyncClient, interval: int) -> None:
        import random
        while True:
            backoff = self._peer_backoff.get(origin, 0)
            if backoff > 0:
                last_fail = self._peer_last_failure.get(origin, 0)
                if time.time() - last_fail < backoff:
                    jitter = backoff * (0.75 + random.random() * 0.5)
                    await asyncio.sleep(jitter)
                    continue

            try:
                await self._sync_once(origin, client)
                self._record_peer_success(origin)
            except Exception as e:
                log_msg(f"SYNC_LOOP: error syncing origin '{origin}': {e}")
                self._record_peer_failure(origin)

            jitter = interval * (0.75 + random.random() * 0.5)
            await asyncio.sleep(jitter)

    async def _sync_once(self, origin: str, client: SyncClient) -> AcceptResult:
        """Perform one sync cycle for an origin."""
        head, head_bytes = await client.fetch_head(origin)

        local_seq = self._firehose.get_highest_seq(origin)

        log_msg(f"SYNC_ONCE: origin='{origin}' remote_seq={head.latest_origin_seq} local_seq={local_seq}")

        if head.latest_origin_seq <= local_seq:
            log_msg(f"SYNC_ONCE: origin='{origin}' already up to date")
            if self._dispatcher:
                try:
                    dispatched = self._dispatcher.dispatch_origin(origin)
                    if dispatched:
                        log_msg(f"SYNC_ONCE: origin='{origin}' dispatched {dispatched} pending records (catch-up)")
                except Exception as e:
                    log_msg(f"SYNC_ONCE: origin='{origin}' dispatch failed: {e}")
            return AcceptResult(accepted=False, reason="already up to date")

        start = local_seq + 1
        count = head.latest_origin_seq - local_seq

        all_records = []
        all_witnesses = []
        current_start = start
        remaining = count

        while remaining > 0:
            batch = min(remaining, 100)
            items = await client.fetch_range(origin, current_start, batch)
            if not items:
                log_msg(f"SYNC_ONCE: origin='{origin}' fetch_range returned empty at seq {current_start}")
                break
            all_records.extend(r for r, w in items)
            all_witnesses.extend(w for r, w in items)
            current_start += len(items)
            remaining -= len(items)

        log_msg(f"SYNC_ONCE: origin='{origin}' fetched {len(all_records)} records (expected {count})")

        if not all_records:
            return AcceptResult(accepted=False, reason="no records fetched")

        log_msg(f"SYNC_ONCE: origin='{origin}' head.origin_pubkey={head.origin_pubkey.hex()[:16]}...")

        self._firehose.init_origin_key(origin, head.origin_pubkey)
        existing_key = self._firehose.get_key_for_seq(origin, 1)
        if existing_key is not None:
            log_msg(f"SYNC_ONCE: origin='{origin}' key_epoch for seq 1: {existing_key.hex()[:16]}...")
            if existing_key != head.origin_pubkey:
                log_msg(f"SYNC_ONCE: origin='{origin}' KEY MISMATCH — pinned={existing_key.hex()[:16]}... head={head.origin_pubkey.hex()[:16]}... — refusing to sync (stale key epoch, operator must reset)")
                return AcceptResult(accepted=False, reason="key epoch mismatch — operator must reset_origin_key")
        else:
            log_msg(f"SYNC_ONCE: origin='{origin}' no key epoch found, using head.origin_pubkey as fallback")

        result = self._firehose.accept_remote_range(
            origin=origin,
            records=all_records,
            head=head,
            origin_pubkey=head.origin_pubkey,
            source=self._hostname,
        )

        log_msg(f"SYNC_ONCE: origin='{origin}' accept_remote_range: accepted={result.accepted} count={result.accepted_count} reason='{result.reason}'")

        if result.accepted:
            for rec, upstream_witness in zip(all_records, all_witnesses):
                if self._firehose.get_event_by_id(origin, rec.event_id) is not None:
                    local_witness = self._create_local_witness(rec, upstream_witness)
                    if local_witness:
                        self._firehose.store_witness(local_witness)

            if self._dispatcher:
                try:
                    dispatched = self._dispatcher.dispatch_origin(origin)
                    log_msg(f"SYNC_ONCE: origin='{origin}' dispatched {dispatched} records to projections")
                except Exception as e:
                    log_msg(f"SYNC_ONCE: origin='{origin}' dispatch failed: {e}")

        return result

    def _create_local_witness(self, rec: Record, upstream: Witness) -> Optional[Witness]:
        """Create a local relay witness naming the upstream as immediate source."""
        encoded = encode_record(rec)
        event_hash = compute_event_hash(encoded)

        w = Witness(
            event_origin=rec.origin,
            event_id=rec.event_id,
            event_hash=event_hash,
            relay_pubkey=self._identity.public_key,
            relay_hostname=self._hostname,
            received_from_pubkey=upstream.relay_pubkey,
            received_from_hostname=upstream.relay_hostname,
            seen_at=int(time.time()),
        )
        from core.record import sign_witness
        w.relay_signature = sign_witness(self._identity, encode_unsigned_witness(w))
        return w

    # ------------------------------------------------------------------
    # Manual sync (for testing or operator triggers)
    # ------------------------------------------------------------------

    def sync_manual(self, origin: str, client: SyncClient) -> AcceptResult:
        """Synchronously sync an origin once. For tests/operator use."""
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(self._sync_once(origin, client))
        finally:
            loop.close()
