"""The on-demand sync queue must not strand an origin in _inflight.

`queue_sync` refuses to enqueue an origin already in `_inflight`, so the set
is what stops a burst of reads from queueing the same peer twice. It is
cleared in `_sync_worker`'s `finally` — but two `continue` paths in that
worker return before the `try` is entered, and an origin dropped on either
one stays in `_inflight` for the life of the process.

The consequence is not a stalled sync but a silently dead trigger: the
periodic `_sync_loop` keeps running, while the on-read trigger
(`_maybe_queue_remote_sync` in firehose_commands) never fires for that
origin again.
"""

import asyncio

import pytest

from bonnet.net.firehose_sync import SyncManager


class _StubClient:
    async def close(self):
        pass


@pytest.fixture
def manager():
    m = SyncManager.__new__(SyncManager)
    m._lock = __import__("threading").RLock()
    m._clients = {}
    m._tasks = {}
    m._inflight = set()
    m._peer_backoff = {}
    m._peer_last_failure = {}
    m._sync_queue = asyncio.Queue()
    m._worker_task = None
    m._running = False
    m._loop = None
    m._firehose = None
    m._dispatcher = None
    m._backoff_max = 3600
    return m


def test_backoff_skip_releases_inflight(manager):
    """An origin queued while its peer is in backoff must be requeueable.

    The worker's backoff branch `continue`s before the try/finally, so the
    origin was left in _inflight permanently and every later queue_sync for
    it returned early.
    """
    origin = "peer.test"
    manager._clients[origin] = _StubClient()
    # Peer just failed: backoff is active and the window has not elapsed.
    manager._peer_backoff[origin] = 30
    manager._peer_last_failure[origin] = __import__("time").time()

    async def run():
        await manager.queue_sync(origin)
        assert origin in manager._inflight
        assert manager._sync_queue.qsize() == 1

        worker = asyncio.ensure_future(manager._sync_worker())
        await asyncio.sleep(0.05)
        worker.cancel()
        try:
            await worker
        except asyncio.CancelledError:
            pass

        # The work was skipped, so the origin must be free to queue again.
        assert origin not in manager._inflight, "origin stranded in _inflight"

        await manager.queue_sync(origin)
        assert manager._sync_queue.qsize() == 1, "a later queue_sync was refused"

    asyncio.run(run())


def test_unknown_client_releases_inflight(manager):
    """An origin whose client disappears between enqueue and dequeue.

    `stop_origin` discards from _inflight only when it found a client to
    close, so a second stop, or a stop racing the worker, leaves the entry
    behind. The worker's own `continue` must clear it either way.
    """
    origin = "peer.test"
    manager._clients[origin] = _StubClient()

    async def run():
        await manager.queue_sync(origin)
        assert origin in manager._inflight

        # Peer goes away after being queued.
        del manager._clients[origin]

        worker = asyncio.ensure_future(manager._sync_worker())
        await asyncio.sleep(0.05)
        worker.cancel()
        try:
            await worker
        except asyncio.CancelledError:
            pass

        assert origin not in manager._inflight, "origin stranded in _inflight"

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Lane 6: the staged-body sweep ran only at startup, so a process that stayed
# up accrued orphans until someone restarted it.
# ---------------------------------------------------------------------------


def test_staged_body_sweep_repeats_while_the_process_runs():
    from bonnet.app.server import BonnetServer

    calls = []

    class _Server:
        def _sweep_orphaned_staged_bodies(self):
            calls.append(1)

    server = _Server()
    loop_fn = BonnetServer._sweep_staged_bodies_periodically

    async def run():
        task = asyncio.ensure_future(loop_fn(server, interval_seconds=0.01))
        await asyncio.sleep(0.08)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(run())
    assert len(calls) >= 2, f"sweep ran {len(calls)} time(s); it must repeat"


def test_staged_body_sweep_survives_a_failing_sweep():
    """One bad sweep must not kill the loop for the life of the process."""
    from bonnet.app.server import BonnetServer

    calls = []

    class _Server:
        def _sweep_orphaned_staged_bodies(self):
            calls.append(1)
            raise OSError("staging tree unreadable")

    async def run():
        task = asyncio.ensure_future(
            BonnetServer._sweep_staged_bodies_periodically(_Server(), interval_seconds=0.01)
        )
        await asyncio.sleep(0.08)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(run())
    assert len(calls) >= 2, "loop stopped after the first failure"
