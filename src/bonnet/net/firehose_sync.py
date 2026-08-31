"""Federation sync manager for the firehose protocol.

Pulls the global firehose from remote origins: fetches signed heads,
requests contiguous event ranges, verifies chain continuity and signatures,
creates local relay witnesses, and stores accepted records.

Each imported record retains the origin record unchanged. The receiving
relay creates its own witness naming the contacted server as immediate
upstream.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import threading
import time
from urllib.parse import urlparse

from bonnet.core.crypto import Identity
from bonnet.core.firehose import (
    KIND_ORIGIN_KEY_ROTATE,
    AcceptResult,
    ChainBreak,
    FirehoseStore,
)
from bonnet.core.logging import log_msg
from bonnet.core.record import (
    Head,
    Record,
    Witness,
    compute_event_hash,
    encode_head,
    encode_record,
    encode_unsigned_record,
    encode_unsigned_witness,
    verify_key_rotation_proof,
    verify_record_signature,
)
from bonnet.net.firehose_transport import FirehoseClientError, FirehoseTransport
from bonnet.net.firehose_wire import (
    ProtocolError,
    build_event_head,
    build_event_range,
    build_key_epochs,
    parse_event_head_response_raw,
    parse_event_range_response,
    parse_key_epochs_response,
)


def is_safe_dial_target(hostname: str | None, port: int, allow_private: bool = False) -> bool:
    """Validate a dial target against SSRF protections.

    Rejects non-global addresses by default. When allow_private is True,
    loopback, private, and link-local addresses are permitted for
    development or LAN federation. hostname may be None — urlparse(...).hostname
    is None for a URL with no host — and that is rejected here rather than
    pushed onto every caller as a pre-check.
    """
    if not hostname:
        return False
    if port < 1 or port > 65535:
        return False

    try:
        addr = ipaddress.ip_address(hostname)
        if not allow_private:
            if addr.is_loopback or addr.is_private or addr.is_link_local:
                return False
            if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
                return False
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False

    for family, _, _, _, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if not allow_private:
            if addr.is_loopback or addr.is_private or addr.is_link_local:
                return False
            if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
                return False

    return True


# ---------------------------------------------------------------------------
# Sync client interface
# ---------------------------------------------------------------------------


class SyncClient:
    """Abstract interface for a federation sync client."""

    async def fetch_head(self, origin: str) -> tuple[Head, bytes]:
        """Fetch the signed head for an origin. Returns (head, raw_bytes)."""
        raise NotImplementedError

    async def fetch_range(
        self, origin: str, start_seq: int, max_count: int
    ) -> list[tuple[Record, Witness]]:
        """Fetch a range of records with witnesses. Returns list of (record, witness)."""
        raise NotImplementedError

    async def fetch_key_epochs(self, origin: str) -> list[tuple[int, int | None, bytes]] | None:
        """Fetch the server's key epoch table.

        Returns [(start_seq, end_seq_or_None, pubkey)] ascending, or None
        when the server does not implement KEY_EPOCHS (pre-0x05 peer).
        """
        return None

    async def close(self) -> None:
        pass


class HttpSyncClient(SyncClient):
    """Concrete SyncClient using FirehoseTransport over HTTP.

    Connects anonymously, performs TOFU key pinning via discovery,
    and wraps the firehose protocol commands EVENT_HEAD and EVENT_RANGE.
    """

    def __init__(self, base_url: str, verify_tls: bool = False, allow_private_dial: bool = False):
        parsed = urlparse(base_url)
        self._dial_host = parsed.hostname
        self._dial_port = parsed.port or 443
        self._allow_private_dial = allow_private_dial
        if not is_safe_dial_target(
            self._dial_host, self._dial_port, allow_private=self._allow_private_dial
        ):
            raise ValueError(f"unsafe dial target: {self._dial_host}:{self._dial_port}")
        self._client = FirehoseTransport(base_url, verify=verify_tls)
        self._connected = False

    async def _ensure_connected(self) -> None:
        if not is_safe_dial_target(
            self._dial_host, self._dial_port, allow_private=self._allow_private_dial
        ):
            self._connected = False
            raise ValueError(f"unsafe dial target: {self._dial_host}:{self._dial_port}")
        if not self._connected:
            await self._client.connect_anonymous()
            self._connected = True
            server_pubkey = self._client._server_pubkey
            assert server_pubkey is not None  # set by connect_anonymous()'s discover()
            log_msg(
                f"SYNC_CLIENT: connected to server origin='{self._client._server_origin}' pubkey={server_pubkey.hex()[:16]}..."
            )

    async def fetch_head(self, origin: str) -> tuple[Head, bytes]:
        await self._ensure_connected()
        cmd = build_event_head(origin)
        resp = await self._client.send_command(cmd)
        head = parse_event_head_response_raw(resp)
        return head, encode_head(head)

    async def fetch_range(
        self, origin: str, start_seq: int, max_count: int
    ) -> list[tuple[Record, Witness]]:
        await self._ensure_connected()
        cmd = build_event_range(origin, start_seq, max_count)
        resp = await self._client.send_command(cmd)
        return parse_event_range_response(resp)

    async def fetch_key_epochs(self, origin: str) -> list[tuple[int, int | None, bytes]] | None:
        await self._ensure_connected()
        cmd = build_key_epochs(origin)
        try:
            resp = await self._client.send_command(cmd)
        except FirehoseClientError as e:
            # unknown opcode on a pre-0x05 server arrives as an error frame,
            # not a transport failure
            log_msg(f"SYNC_CLIENT: KEY_EPOCHS unsupported by peer '{origin}': {e}")
            return None
        try:
            return parse_key_epochs_response(resp)
        except ProtocolError as e:
            log_msg(f"SYNC_CLIENT: malformed KEY_EPOCHS response from '{origin}': {e}")
            return None

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
        self._worker_task: asyncio.Task | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._peer_backoff: dict[str, float] = {}
        self._peer_last_failure: dict[str, float] = {}
        self._backoff_max = 3600

    def set_identity(self, identity: Identity) -> None:
        """Hot-swap the identity used to sign relay witnesses for future
        accepted federation batches. Used by BonnetServer.apply_key_rotation
        — witnesses already recorded under the old key stay as they were;
        this only affects _create_witness for records accepted after the
        call."""
        self._identity = identity

    def start_origin(self, origin: str, client: SyncClient, interval: int = 300) -> None:
        """Start syncing an origin in the background (periodic + on-demand)."""
        if self._loop is None:
            self._loop = asyncio.get_running_loop()
        with self._lock:
            if origin in self._tasks:
                return
            self._clients[origin] = client
            self._tasks[origin] = asyncio.ensure_future(self._sync_loop(origin, client, interval))
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
            client = self._clients.pop(origin, None)
            if task:
                task.cancel()
        if client is not None:
            if self._loop is not None and self._loop.is_running():
                asyncio.run_coroutine_threadsafe(client.close(), self._loop)
            self._inflight.discard(origin)

    async def stop_all(self) -> None:
        with self._lock:
            tasks = list(self._tasks.values())
            self._tasks.clear()
            clients = list(self._clients.values())
            self._clients.clear()
            self._inflight.clear()
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
        for client in clients:
            try:
                await client.close()
            except Exception:
                pass

    async def _sync_worker(self) -> None:
        """Background worker consuming on-demand sync requests."""
        while True:
            try:
                origin = await self._sync_queue.get()
                # Every exit below this point must release _inflight, not
                # just the ones that ran a sync: queue_sync refuses an origin
                # already in the set, so an entry left behind by a skip is
                # not a stalled sync but a permanently dead on-read trigger
                # for that peer. The skips used to `continue` past the
                # release, which is why this try covers all of them.
                try:
                    client = self._clients.get(origin)
                    if client is None:
                        continue
                    backoff = self._peer_backoff.get(origin, 0)
                    if backoff > 0:
                        last_fail = self._peer_last_failure.get(origin, 0)
                        if time.time() - last_fail < backoff:
                            log_msg(
                                f"SYNC_WORKER: origin='{origin}' in backoff ({backoff}s), "
                                "skipping on-demand sync"
                            )
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

    async def _sync_once(
        self, origin: str, client: SyncClient, skip_allowlist: bool = False
    ) -> AcceptResult:
        """Perform one sync cycle for an origin.

        When skip_allowlist is False (default), the origin must be a
        configured peer. When True, the check is bypassed for manual
        operator-triggered sync.

        Records are fetched and accepted in bounded batches of 100. Each
        batch is committed before the next is fetched. If a batch conflicts
        or fails, committed batches are kept and the cycle stops — the next
        cycle resumes from where it stopped.
        """
        if not skip_allowlist and origin not in self._clients:
            log_msg(
                f"SYNC_ONCE: origin='{origin}' is not a configured peer, refusing to accept records"
            )
            return AcceptResult(accepted=False, reason="origin not in peer allowlist")

        sync_status = self._firehose.get_sync_status(origin)
        if sync_status["status"] == "diverged":
            log_msg(f"SYNC_ONCE: origin='{origin}' halted (diverged): {sync_status['detail']}")
            return AcceptResult(accepted=False, reason="origin diverged; sync halted")

        head, head_bytes = await client.fetch_head(origin)

        local_seq = self._firehose.get_highest_seq(origin)

        log_msg(
            f"SYNC_ONCE: origin='{origin}' remote_seq={head.latest_origin_seq} local_seq={local_seq}"
        )

        if head.latest_origin_seq <= local_seq:
            log_msg(f"SYNC_ONCE: origin='{origin}' already up to date")
            if self._dispatcher:
                try:
                    dispatched = self._dispatcher.dispatch_origin(origin)
                    if dispatched:
                        log_msg(
                            f"SYNC_ONCE: origin='{origin}' dispatched {dispatched} pending records (catch-up)"
                        )
                except Exception as e:
                    log_msg(f"SYNC_ONCE: origin='{origin}' dispatch failed: {e}")
            return AcceptResult(accepted=False, reason="already up to date")

        if head.latest_origin_seq > local_seq + 100000:
            log_msg(
                f"SYNC_ONCE: origin='{origin}' remote claims {head.latest_origin_seq} but local is {local_seq} — capping cycle at 10000 records"
            )
            count = 10000
        else:
            count = head.latest_origin_seq - local_seq

        # TOFU bootstrap only: establish an epoch table for fresh peers.
        # Continuity and key legitimacy are enforced per-record by
        # accept_remote_range (chain links, per-seq epoch keys, rotation
        # proofs signed over the pinned old key, head match at the tip).
        # A pre-fetch pin comparison here would deadlock on rotation:
        # the rotate record travels through sync itself.
        self._firehose.init_origin_key(origin, head.origin_pubkey)

        key_intervals = await self._verify_epoch_hints(origin, client, head)

        total_accepted = 0
        current_start = local_seq + 1
        remaining = count
        last_result = AcceptResult(accepted=False, reason="no records fetched")

        while remaining > 0:
            batch_size = min(remaining, 100)
            items = await client.fetch_range(origin, current_start, batch_size)
            if not items:
                log_msg(
                    f"SYNC_ONCE: origin='{origin}' fetch_range returned empty at seq {current_start}"
                )
                break

            batch_records = [r for r, w in items]
            batch_witnesses = [w for r, w in items]

            # A peer that answers a range request with the wrong starting
            # sequence has not forked — it is buggy or hostile. Catching it
            # here keeps it out of the ChainBreak path below, where it would
            # otherwise be indistinguishable from a genuine divergence.
            if batch_records[0].origin_seq != current_start:
                log_msg(
                    f"SYNC_ONCE: origin='{origin}' asked for seq {current_start} but got "
                    f"{batch_records[0].origin_seq}; abandoning cycle"
                )
                last_result = AcceptResult(accepted=False, reason="peer served the wrong range")
                break

            # Only the batch that reaches the advertised head carries it;
            # intermediate batches are anchored by chain continuity.
            last_seq_in_batch = current_start + len(batch_records) - 1
            is_final = last_seq_in_batch >= head.latest_origin_seq

            try:
                result = self._firehose.accept_remote_range(
                    origin=origin,
                    records=batch_records,
                    head=head if is_final else None,
                    origin_pubkey=head.origin_pubkey,
                    source=self._hostname,
                    key_intervals=key_intervals,
                )
            except ChainBreak as e:
                return await self._diagnose_chain_break(origin, client, local_seq, e)

            log_msg(
                f"SYNC_ONCE: origin='{origin}' batch seq {current_start}-{current_start + len(batch_records) - 1}: accepted={result.accepted} count={result.accepted_count} reason='{result.reason}'"
            )

            if result.accepted:
                total_accepted += result.accepted_count

                for rec, upstream_witness in zip(batch_records, batch_witnesses):
                    if self._firehose.get_event_by_id(origin, rec.event_id) is not None:
                        local_witness = self._create_local_witness(rec, upstream_witness)
                        if local_witness:
                            self._firehose.store_witness(local_witness)

                if result.conflicts:
                    log_msg(
                        f"SYNC_ONCE: origin='{origin}' conflict detected, stopping cycle — {total_accepted} records accepted so far"
                    )
                    last_result = result
                    break

                last_result = result
                current_start += len(batch_records)
                remaining -= len(batch_records)
            else:
                log_msg(
                    f"SYNC_ONCE: origin='{origin}' batch rejected, stopping cycle: {result.reason}"
                )
                last_result = result
                break

        if total_accepted > 0 and self._dispatcher:
            try:
                dispatched = self._dispatcher.dispatch_origin(origin)
                log_msg(
                    f"SYNC_ONCE: origin='{origin}' dispatched {dispatched} records to projections"
                )
            except Exception as e:
                log_msg(f"SYNC_ONCE: origin='{origin}' dispatch failed: {e}")

        if total_accepted > 0:
            return AcceptResult(
                accepted=True,
                accepted_count=total_accepted,
                idempotent=last_result.idempotent,
                conflicts=last_result.conflicts,
                reason=last_result.reason,
            )
        return last_result

    async def _diagnose_chain_break(
        self, origin: str, client: SyncClient, local_seq: int, err: ChainBreak
    ) -> AcceptResult:
        """Decide whether a chain break is ours, theirs, or terminal.

        A break means the incoming record's previous_event_hash disagreed with
        our recorded tip. That has two very different causes and they were
        previously treated the same — raised, rolled back, backed off, retried
        forever.

        If our own tip is inconsistent with the record we have stored at it,
        the peer is fine and we were comparing against a wrong value; repair
        and let the next cycle proceed.

        Otherwise the peer's history genuinely differs from ours at the last
        sequence we hold. Hashes chain forward, so that can never re-converge
        by retrying: the fix has to happen at the origin. Store the
        conflicting record as evidence and halt, rather than spending an
        hourly request on something with no path to success. Halting is
        chosen over depeering because it is reversible and keeps both the
        accepted records and the proof — what to do about a forked peer stays
        the operator's call.
        """
        consistent, recorded, actual = self._firehose.check_tip(origin)
        if not consistent:
            repaired = self._firehose.repair_tip(origin)
            log_msg(
                f"SYNC_ONCE: origin='{origin}' local tip was inconsistent "
                f"(recorded={recorded.hex()[:16] if recorded else None} "
                f"actual={actual.hex()[:16] if actual else None}); "
                f"repaired={repaired}. Not blaming the peer."
            )
            return AcceptResult(accepted=False, reason="local tip repaired; retry next cycle")

        detail = f"chain diverged at seq {local_seq}"
        try:
            snatched = await client.fetch_range(origin, local_seq, 1)
        except Exception as e:
            log_msg(f"SYNC_ONCE: origin='{origin}' could not fetch seq {local_seq}: {e}")
            snatched = []

        if len(snatched) == 1 and snatched[0][0].origin_seq == local_seq:
            peer_rec = snatched[0][0]
            encoded = encode_record(peer_rec)
            peer_hash = compute_event_hash(encoded)
            if peer_hash == recorded:
                # Same record at our tip, yet the next one did not chain onto
                # it. Not a fork — a malformed range from this peer.
                log_msg(
                    f"SYNC_ONCE: origin='{origin}' tip matches peer at seq {local_seq} "
                    f"but the following record does not chain onto it: {err}"
                )
                return AcceptResult(accepted=False, reason="peer served a non-contiguous range")
            self._firehose.record_conflict(
                origin,
                local_seq,
                encoded,
                self._hostname,
                "divergence: peer holds a different record at our tip",
            )
            detail = (
                f"seq {local_seq}: ours {recorded.hex()[:16] if recorded else None}, "
                f"theirs {peer_hash.hex()[:16]}"
            )

        self._firehose.set_sync_status(origin, "diverged", detail)
        log_msg(
            f"SYNC_ONCE: origin='{origin}' DIVERGED — {detail}. Sync halted; "
            f"an operator must resolve this (resume-origin, depeer, or reset)."
        )
        return AcceptResult(accepted=False, reason=f"origin diverged ({detail})")

    async def _verify_epoch_hints(
        self, origin: str, client: SyncClient, head: Head
    ) -> list[tuple[int, int | None, bytes]] | None:
        """Fetch and verify the peer's advertised key epoch table.

        Hints are never trusted directly: every internal boundary is
        snatched as a record and must be a genuine rotate — actor equal to
        the previous epoch's key, origin signature under that key, proof
        chaining it to the advertised successor. The chain must terminate
        at the head's pubkey, and hints are only consumed when local state
        is a fresh blanket bootstrap (veteran peers already hold
        authoritative epochs; their in-batch derivation covers rotation).
        Returns verified intervals, or None to fall back.
        """
        try:
            epochs = await client.fetch_key_epochs(origin)
        except Exception as e:
            log_msg(f"SYNC_ONCE: epoch hint fetch failed for '{origin}': {e}")
            return None
        if not epochs:
            return None

        if not self._firehose.is_blanket_bootstrap(origin, head.origin_pubkey):
            return None

        epochs = sorted(epochs, key=lambda e: e[0])
        if epochs[0][0] != 1:
            return None
        if epochs[-1][1] is not None:
            return None
        if epochs[-1][2] != head.origin_pubkey:
            return None

        for prev, nxt in zip(epochs, epochs[1:]):
            boundary = prev[1]
            start_i, _, pk_i = nxt
            _, _, pk_prev = prev
            if boundary is None or boundary != start_i - 1:
                log_msg(f"SYNC_ONCE: incoherent epoch boundary from '{origin}'")
                return None

            snatched = await client.fetch_range(origin, boundary, 1)
            if len(snatched) != 1:
                return None
            rec = snatched[0][0]
            if rec.kind != KIND_ORIGIN_KEY_ROTATE:
                log_msg(f"SYNC_ONCE: advertised boundary seq={boundary} is not a rotate")
                return None
            if rec.actor_pubkey != pk_prev:
                return None
            new_key = rec.metadata.get_bytes(1)
            proof = rec.metadata.get_bytes(2)
            if new_key != pk_i or proof is None:
                return None
            if not verify_record_signature(
                pk_prev, encode_unsigned_record(rec), rec.origin_signature
            ):
                return None
            if not verify_key_rotation_proof(pk_i, origin, pk_prev, proof):
                return None

        return [(start, end, pk) for start, end, pk in epochs]

    def _create_local_witness(self, rec: Record, upstream: Witness) -> Witness | None:
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
        from bonnet.core.record import sign_witness

        w.relay_signature = sign_witness(self._identity, encode_unsigned_witness(w))
        return w

    # ------------------------------------------------------------------
    # Manual sync (for testing or operator triggers)
    # ------------------------------------------------------------------

    def sync_manual(self, origin: str, client: SyncClient) -> AcceptResult:
        """Synchronously sync an origin once. For tests/operator use.

        Bypasses the peer allowlist check since this is an explicit operator
        action, not an automated sync.
        """
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(self._sync_once(origin, client, skip_allowlist=True))
        finally:
            loop.close()
