"""Tests for federation sync: SSRF validation, backoff, resource cleanup."""

import asyncio
import pytest

from net.firehose_sync import is_safe_dial_target, SyncManager, SyncClient
from core.crypto import Identity
from core.firehose import FirehoseStore, AcceptResult
from core.record import Head, ZERO_HASH


ORIGIN_PUB = Identity.from_private_key(bytes(range(1, 33))).public_key


# ---------------------------------------------------------------------------
# SSRF validation
# ---------------------------------------------------------------------------

def test_safe_dial_target_rejects_loopback():
    assert not is_safe_dial_target("127.0.0.1", 2272)


def test_safe_dial_target_rejects_localhost():
    assert not is_safe_dial_target("localhost", 2272)


def test_safe_dial_target_rejects_private():
    assert not is_safe_dial_target("10.0.0.1", 2272)
    assert not is_safe_dial_target("192.168.1.1", 2272)
    assert not is_safe_dial_target("172.16.0.1", 2272)


def test_safe_dial_target_rejects_link_local():
    assert not is_safe_dial_target("169.254.1.1", 2272)


def test_safe_dial_target_rejects_empty():
    assert not is_safe_dial_target("", 2272)


def test_safe_dial_target_rejects_bad_port():
    assert not is_safe_dial_target("example.com", 0)
    assert not is_safe_dial_target("example.com", 99999)


def test_safe_dial_target_allows_private_when_flagged():
    assert is_safe_dial_target("127.0.0.1", 2272, allow_private=True)
    assert is_safe_dial_target("10.0.0.1", 2272, allow_private=True)


def test_safe_dial_target_allows_public_hostname():
    assert is_safe_dial_target("example.com", 443)


# ---------------------------------------------------------------------------
# Mock sync client for SyncManager tests
# ---------------------------------------------------------------------------

class MockClient(SyncClient):
    """Mock sync client for testing."""

    def __init__(self, head=None, ranges=None):
        self._head = head
        self._ranges = ranges or {}
        self._closed = False

    async def fetch_head(self, origin):
        return self._head, b""

    async def fetch_range(self, origin, start_seq, max_count):
        return self._ranges.get(start_seq, [])

    async def close(self):
        self._closed = True


# ---------------------------------------------------------------------------
# Backoff
# ---------------------------------------------------------------------------

@pytest.mark.xdist_group("sync_backoff")
def test_backoff_increases_on_failure(tmp_path):
    firehose = FirehoseStore(str(tmp_path / "events.db"))
    firehose.init_origin_key("peer.test", ORIGIN_PUB)
    identity = Identity.generate()

    mgr = SyncManager(firehose, identity, "local.test")
    mgr._record_peer_failure("peer.test")
    assert mgr._peer_backoff["peer.test"] == 30

    mgr._record_peer_failure("peer.test")
    assert mgr._peer_backoff["peer.test"] == 60

    mgr._record_peer_success("peer.test")
    assert mgr._peer_backoff["peer.test"] == 0

    firehose.close()


# ---------------------------------------------------------------------------
# Resource cleanup
# ---------------------------------------------------------------------------

@pytest.mark.xdist_group("sync_cleanup")
async def test_stop_all_closes_clients(tmp_path):
    firehose = FirehoseStore(str(tmp_path / "events.db"))
    firehose.init_origin_key("local.test", ORIGIN_PUB)
    identity = Identity.generate()

    mgr = SyncManager(firehose, identity, "local.test")

    mock = MockClient()
    mgr._clients["peer.test"] = mock
    mgr._loop = asyncio.get_running_loop()

    await mgr.stop_all()

    assert mock._closed
    firehose.close()


@pytest.mark.xdist_group("sync_cleanup")
async def test_stop_origin_closes_client(tmp_path):
    firehose = FirehoseStore(str(tmp_path / "events.db"))
    firehose.init_origin_key("local.test", ORIGIN_PUB)
    identity = Identity.generate()

    mgr = SyncManager(firehose, identity, "local.test")

    mock = MockClient()
    mgr._clients["peer.test"] = mock
    mgr._loop = asyncio.get_running_loop()

    mgr.stop_origin("peer.test")

    await asyncio.sleep(0.1)
    assert mock._closed
    assert "peer.test" not in mgr._clients
    firehose.close()
