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


# ---------------------------------------------------------------------------
# Sync manager
# ---------------------------------------------------------------------------

class SyncManager:
    """Manages background firehose synchronization from remote origins.

    The sync manager runs periodic tasks that:
    1. Fetch the signed head for a subscribed origin.
    2. Compare against the local highest sequence.
    3. Request the missing contiguous range.
    4. Verify and accept the range.
    5. Create local relay witnesses.
    """

    def __init__(
        self,
        firehose: FirehoseStore,
        server_identity: Identity,
        hostname: str,
    ):
        self._firehose = firehose
        self._identity = server_identity
        self._hostname = hostname
        self._lock = threading.RLock()
        self._running = False
        self._tasks: dict[str, asyncio.Task] = {}

    def start_origin(self, origin: str, client: SyncClient, interval: int = 300) -> None:
        """Start syncing an origin in the background."""
        with self._lock:
            if origin in self._tasks:
                return
            self._tasks[origin] = asyncio.ensure_future(
                self._sync_loop(origin, client, interval)
            )

    def stop_origin(self, origin: str) -> None:
        """Stop syncing an origin."""
        with self._lock:
            task = self._tasks.pop(origin, None)
            if task:
                task.cancel()

    async def stop_all(self) -> None:
        with self._lock:
            tasks = list(self._tasks.values())
            self._tasks.clear()
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except asyncio.CancelledError:
                pass

    async def _sync_loop(self, origin: str, client: SyncClient, interval: int) -> None:
        while True:
            try:
                await self._sync_once(origin, client)
            except Exception as e:
                pass
            await asyncio.sleep(interval)

    async def _sync_once(self, origin: str, client: SyncClient) -> AcceptResult:
        """Perform one sync cycle for an origin."""
        head, head_bytes = await client.fetch_head(origin)

        local_seq = self._firehose.get_highest_seq(origin)

        if head.latest_origin_seq <= local_seq:
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
                break
            all_records.extend(r for r, w in items)
            all_witnesses.extend(w for r, w in items)
            current_start += len(items)
            remaining -= len(items)

        if not all_records:
            return AcceptResult(accepted=False, reason="no records fetched")

        result = self._firehose.accept_remote_range(
            origin=origin,
            records=all_records,
            head=head,
            origin_pubkey=head.origin_pubkey,
            source=self._hostname,
        )

        if result.accepted:
            for rec, upstream_witness in zip(all_records, all_witnesses):
                if self._firehose.get_event_by_id(origin, rec.event_id) is not None:
                    local_witness = self._create_local_witness(rec, upstream_witness)
                    if local_witness:
                        self._firehose.store_witness(local_witness)

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
