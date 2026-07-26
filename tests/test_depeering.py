"""Tests for depeering and origin lifecycle: depeer, purge-origin, reset-key."""

import os

import pytest

from core.bodies import BodyStore
from core.config import FirehoseConfig
from core.crypto import Identity
from core.firehose import KIND_ARTICLE, FirehoseStore
from core.record import (
    Intent,
    MetadataMap,
    compute_body_hash,
    encode_intent,
    metadata_bytes,
    metadata_text,
    sign_intent,
)
from net.firehose_sync import SyncClient

ORIGIN = Identity.from_private_key(bytes(range(1, 33)))
ACTOR = Identity.from_private_key(bytes(range(10, 42)))
ORIGIN_PUB = ORIGIN.public_key
ACTOR_PUB = ACTOR.public_key


def _rid(seed):
    return bytes([(seed + i) % 256 for i in range(32)])


def _make_article_intent(origin, eid, board="general", body=b"hello", aid_seed=99):
    return Intent(
        event_id=eid, kind=KIND_ARTICLE, origin=origin,
        actor_pubkey=ACTOR_PUB, board=board, article_id=_rid(aid_seed),
        metadata=MetadataMap([
            metadata_text(1, "Test"),
            metadata_text(4, "text/plain"),
        ]),
        body_hash=compute_body_hash(body), body_size=len(body),
    )


def _make_board_create_intent(origin, eid, board, owner_pubkey):
    return Intent(
        event_id=eid, kind="bonnet.board.create", origin=origin,
        actor_pubkey=ACTOR_PUB, board=board,
        metadata=MetadataMap([
            metadata_bytes(1, owner_pubkey),
            metadata_text(2, "Test Board"),
        ]),
    )


def _append(firehose, origin_identity, intent, body=b""):
    sig = sign_intent(ACTOR, encode_intent(intent))
    return firehose.append_record(origin_identity, intent, sig, body)


class MockSyncClient(SyncClient):
    async def fetch_head(self, origin):
        from core.record import ZERO_HASH, Head
        return Head(
            origin=origin, latest_origin_seq=0,
            latest_event_hash=ZERO_HASH, event_count=0,
            generated_at=0, origin_pubkey=ORIGIN_PUB,
            origin_signature=b"\x00" * 64,
            head_hash=ZERO_HASH,
        ), b""

    async def fetch_range(self, origin, start_seq, max_count):
        return []

    async def close(self):
        pass


@pytest.fixture
def server(tmp_path):
    os.makedirs(tmp_path / "data", exist_ok=True)
    os.makedirs(tmp_path / "boards", exist_ok=True)
    os.makedirs(tmp_path / "event_bodies", exist_ok=True)

    from app.server import BonnetFirehoseServer
    config = FirehoseConfig(
        origin="bbs.test",
        hostname="bbs.test",
        data_dir=str(tmp_path / "data"),
        boards_dir=str(tmp_path / "boards"),
        events_bodies_dir=str(tmp_path / "event_bodies"),
        port=2272,
        tls_enabled=False,
    )
    s = BonnetFirehoseServer(config)
    yield s
    try:
        s.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# FirehoseStore methods
# ---------------------------------------------------------------------------

@pytest.fixture
def firehose_with_remote_data(tmp_path):
    """FirehoseStore with local origin and a remote origin with data."""
    firehose = FirehoseStore(str(tmp_path / "events.db"))
    firehose.init_origin_key("bbs.test", ORIGIN_PUB)

    remote_identity = Identity.generate()
    firehose.init_origin_key("peer.test", remote_identity.public_key)

    for i in range(3):
        intent = _make_article_intent("peer.test", _rid(i + 1), aid_seed=i + 10)
        body = f"body{i}".encode()
        intent.body_hash = compute_body_hash(body)
        intent.body_size = len(body)
        sig = sign_intent(ACTOR, encode_intent(intent))
        firehose.append_record(remote_identity, intent, sig, body)

    yield firehose, remote_identity
    firehose.close()


def test_get_origin_summary(firehose_with_remote_data):
    firehose, _ = firehose_with_remote_data
    summary = firehose.get_origin_summary("peer.test")
    assert summary["origin"] == "peer.test"
    assert summary["event_count"] == 3
    assert summary["board_count"] == 1


def test_get_origin_summary_empty(firehose_with_remote_data):
    firehose, _ = firehose_with_remote_data
    summary = firehose.get_origin_summary("nonexistent.test")
    assert summary["event_count"] == 0


def test_reset_origin_key(firehose_with_remote_data):
    firehose, remote_identity = firehose_with_remote_data
    assert firehose.get_key_for_seq("peer.test", 1) == remote_identity.public_key

    firehose.reset_origin_key("peer.test")

    assert firehose.get_key_for_seq("peer.test", 1) is None
    assert firehose.get_highest_seq("peer.test") == 0
    events = firehose.get_events_range("peer.test", 1, 10)
    assert len(events) == 3


def test_delete_origin_data(firehose_with_remote_data):
    firehose, _ = firehose_with_remote_data
    counts = firehose.delete_origin_data("peer.test")

    assert counts["events"] == 3
    assert "peer.test" not in firehose.list_origins()
    assert firehose.get_events_range("peer.test", 1, 10) == []


def test_delete_origin_data_preserves_local(firehose_with_remote_data):
    firehose, remote_identity = firehose_with_remote_data
    for i in range(2):
        intent = _make_article_intent("bbs.test", _rid(i + 50), aid_seed=i + 50)
        body = f"local{i}".encode()
        intent.body_hash = compute_body_hash(body)
        intent.body_size = len(body)
        sig = sign_intent(ACTOR, encode_intent(intent))
        firehose.append_record(ORIGIN, intent, sig, body)

    firehose.delete_origin_data("peer.test")

    assert "bbs.test" in firehose.list_origins()
    local_events = firehose.get_events_range("bbs.test", 1, 10)
    assert len(local_events) == 2


# ---------------------------------------------------------------------------
# BodyStore.delete_origin_bodies
# ---------------------------------------------------------------------------

def test_delete_origin_bodies(tmp_path):
    bs = BodyStore(
        boards_dir=str(tmp_path / "boards"),
        events_dir=str(tmp_path / "event_bodies"),
    )
    body = b"test body"
    bh = compute_body_hash(body)
    bs.write_article_body("peer.test", "general", 1, body, bh, len(body))
    bs.write_article_body("peer.test", "general", 2, body, bh, len(body))
    bs.write_article_body("bbs.test", "general", 1, body, bh, len(body))

    count = bs.delete_origin_bodies("peer.test")
    assert count >= 2
    assert not bs.article_body_exists("peer.test", "general", 1)
    assert bs.article_body_exists("bbs.test", "general", 1)


# ---------------------------------------------------------------------------
# depeer REPL command
# ---------------------------------------------------------------------------

def test_depeer_rejects_local_origin(server):
    result = server._cmd_depeer(["depeer", "bbs.test"])
    assert "Cannot depeer" in result


def test_depeer_unknown_origin(server):
    result = server._cmd_depeer(["depeer", "unknown.test"])
    assert "not a configured peer" in result


# ---------------------------------------------------------------------------
# purge-origin REPL command
# ---------------------------------------------------------------------------

def test_purge_origin_rejects_local(server):
    result = server._cmd_purge_origin(["purge-origin", "bbs.test"])
    assert "Cannot purge" in result


@pytest.mark.xdist_group("sync_lifecycle")
async def test_purge_origin_rejects_active_sync(server):
    mock = MockSyncClient()
    server.sync_manager.start_origin("peer.test", mock, interval=999)

    result = server._cmd_purge_origin(["purge-origin", "peer.test"])
    assert "active sync" in result
    assert "depeer" in result

    await server.sync_manager.stop_all()


def test_purge_origin_no_data(server):
    result = server._cmd_purge_origin(["purge-origin", "empty.test"])
    assert "no data" in result


def test_purge_origin_removes_data(server, tmp_path):
    remote_identity = Identity.generate()
    server.firehose.init_origin_key("peer.test", remote_identity.public_key)

    for i in range(3):
        intent = _make_article_intent("peer.test", _rid(i + 1), aid_seed=i + 10)
        body = f"body{i}".encode()
        intent.body_hash = compute_body_hash(body)
        intent.body_size = len(body)
        sig = sign_intent(ACTOR, encode_intent(intent))
        server.body_store.stage_article_body(
            "peer.test", "general", intent.event_id, body,
            intent.body_hash, intent.body_size,
        )
        server.firehose.append_record(remote_identity, intent, sig, body)
        server.body_store.finalize_article_body(
            "peer.test", "general", intent.event_id, i + 1,
        )

    server.dispatcher.dispatch_origin("peer.test")

    result = server._cmd_purge_origin(["purge-origin", "peer.test"])
    assert "Purged" in result
    assert "peer.test" not in server.firehose.list_origins()
    assert server.firehose.get_events_range("peer.test", 1, 10) == []


def test_purge_origin_preserves_local(server):
    result = server._cmd_purge_origin(["purge-origin", "empty.test"])
    assert "bbs.test" in server.firehose.list_origins()


# ---------------------------------------------------------------------------
# reset-key REPL command
# ---------------------------------------------------------------------------

def test_reset_key_rejects_local(server):
    result = server._cmd_reset_key(["reset-key", "bbs.test"])
    assert "Cannot reset" in result


def test_reset_key_no_data(server):
    result = server._cmd_reset_key(["reset-key", "empty.test"])
    assert "no data" in result


def test_reset_key_clears_pinning(server):
    remote_identity = Identity.generate()
    server.firehose.init_origin_key("peer.test", remote_identity.public_key)

    for i in range(2):
        intent = _make_article_intent("peer.test", _rid(i + 1), aid_seed=i + 10)
        body = f"body{i}".encode()
        intent.body_hash = compute_body_hash(body)
        intent.body_size = len(body)
        sig = sign_intent(ACTOR, encode_intent(intent))
        server.firehose.append_record(remote_identity, intent, sig, body)

    assert server.firehose.get_key_for_seq("peer.test", 1) == remote_identity.public_key

    result = server._cmd_reset_key(["reset-key", "peer.test"])
    assert "Reset key" in result

    assert server.firehose.get_key_for_seq("peer.test", 1) is None
    events = server.firehose.get_events_range("peer.test", 1, 10)
    assert len(events) == 2
