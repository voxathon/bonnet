"""Tests for federation sync: SSRF validation, backoff, resource cleanup,
and key-rotation behavior across the sync boundary."""

import asyncio
import os
import time

import pytest

from bonnet.core.crypto import Identity
from bonnet.core.firehose import (
    KIND_ARTICLE,
    KIND_ORIGIN_KEY_ROTATE,
    FirehoseError,
    FirehoseStore,
)
from bonnet.core.record import (
    DOMAIN_ORIGIN_SIG,
    HEAD_FORMAT,
    RECORD_FORMAT,
    SIG_SIZE,
    ZERO_HASH,
    ZERO_ID,
    Head,
    Intent,
    MetadataMap,
    Record,
    compute_body_hash,
    compute_event_hash,
    encode_intent,
    encode_record,
    encode_unsigned_head,
    encode_unsigned_record,
    make_origin_witness,
    metadata_bytes,
    metadata_text,
    reconstruct_intent_from_record,
    sign_head,
    sign_intent,
    sign_key_rotation_proof,
)
from bonnet.net.firehose_sync import SyncClient, SyncManager, is_safe_dial_target

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


# ---------------------------------------------------------------------------
# Key rotation across the sync boundary
# ---------------------------------------------------------------------------


class _OriginServer:
    """Authoritative origin backed by a real FirehoseStore."""

    def __init__(self, tmp_path, name="rot.test"):
        self.origin = name
        self.identity = Identity.generate()
        self.store = FirehoseStore(str(tmp_path / f"{name}.db"))
        self.store.init_origin_key(self.origin, self.identity.public_key)

    def publish_articles(self, n):
        for _ in range(n):
            body = os.urandom(16).hex().encode("utf-8")
            intent = Intent(
                event_id=os.urandom(32),
                kind=KIND_ARTICLE,
                origin=self.origin,
                actor_pubkey=self.identity.public_key,
                actor_username="root",
                actor_registrar=self.origin,
                board="general",
                article_id=os.urandom(32),
                metadata=MetadataMap(fields=[metadata_text(1, "hello")]),
                body_hash=compute_body_hash(body),
                body_size=len(body),
            )
            self.store.append_record(
                self.identity,
                intent,
                sign_intent(self.identity, encode_intent(intent)),
                body,
            )

    def rotate(self):
        """Append a rotate record under the old key; epoch flips to a new key."""
        new = Identity.generate()
        proof = sign_key_rotation_proof(new, self.origin, self.identity.public_key, new.public_key)
        intent = Intent(
            event_id=os.urandom(32),
            kind=KIND_ORIGIN_KEY_ROTATE,
            origin=self.origin,
            actor_pubkey=self.identity.public_key,
            actor_username="root",
            actor_registrar=self.origin,
            metadata=MetadataMap(
                fields=[
                    metadata_bytes(1, new.public_key),
                    metadata_bytes(2, proof),
                ]
            ),
        )
        self.store.append_record(
            self.identity,
            intent,
            sign_intent(self.identity, encode_intent(intent)),
            b"",
        )
        self.identity = new

    def serving_client(self):
        return _ServingClient(self)


class _ServingClient(SyncClient):
    """Serves heads and record ranges from an authoritative store."""

    def __init__(self, server: _OriginServer):
        self._server = server
        self.page_size = 100

    async def fetch_head(self, origin):
        return self._server.store.get_head(origin), b""

    async def fetch_range(self, origin, start_seq, max_count):
        recs = self._server.store.get_events_range(
            origin, start_seq, min(max_count, self.page_size)
        )
        out = []
        for rec in recs:
            w = make_origin_witness(
                origin,
                rec.event_id,
                compute_event_hash(encode_record(rec)),
                self._server.identity,
                self._server.origin,
                int(time.time()),
            )
            out.append((rec, w))
        return out

    async def close(self):
        pass


def _make_peer(tmp_path):
    peer_store = FirehoseStore(str(tmp_path / "peer.db"))
    mgr = SyncManager(peer_store, Identity.generate(), "peer.test")
    return peer_store, mgr


@pytest.mark.xdist_group("rotation_sync")
async def test_rotation_then_sync_continues(tmp_path):
    """A peer that witnessed a rotation keeps syncing under the new key."""
    origin = _OriginServer(tmp_path)
    k1 = origin.identity.public_key
    origin.publish_articles(3)

    peer_store, mgr = _make_peer(tmp_path)
    client = origin.serving_client()

    first = await mgr._sync_once(origin.origin, client, skip_allowlist=True)
    assert first.accepted and first.accepted_count == 3
    assert peer_store.get_current_key(origin.origin) == k1

    origin.rotate()
    origin.publish_articles(2)

    second = await mgr._sync_once(origin.origin, client, skip_allowlist=True)
    assert second.accepted, second.reason
    assert second.accepted_count == 3

    assert peer_store.get_highest_seq(origin.origin) == 6
    assert peer_store.get_current_key(origin.origin) != k1

    third = await mgr._sync_once(origin.origin, client, skip_allowlist=True)
    assert third.reason == "already up to date"


@pytest.mark.xdist_group("rotation_sync")
async def test_missed_rotation_caught_up_across_batches(tmp_path):
    """A stale peer catches up through a rotate record delivered mid-cycle."""
    origin = _OriginServer(tmp_path)
    origin.publish_articles(3)

    peer_store, mgr = _make_peer(tmp_path)
    client = origin.serving_client()

    first = await mgr._sync_once(origin.origin, client, skip_allowlist=True)
    assert first.accepted and first.accepted_count == 3

    origin.rotate()
    origin.publish_articles(4)

    # force small pages so batches straddle the rotate record's sequence
    client.page_size = 2

    result = await mgr._sync_once(origin.origin, client, skip_allowlist=True)
    assert result.accepted, result.reason
    assert result.accepted_count == 5

    assert peer_store.get_highest_seq(origin.origin) == 8
    assert peer_store.get_current_key(origin.origin) == origin.identity.public_key


@pytest.mark.xdist_group("rotation_sync")
async def test_hostile_substitution_refused_at_acceptance(tmp_path):
    """A foreign key forging records past our tip is rejected; state unchanged."""
    real = _OriginServer(tmp_path)
    real.publish_articles(3)

    peer_store, mgr = _make_peer(tmp_path)
    client = real.serving_client()

    first = await mgr._sync_once(real.origin, client, skip_allowlist=True)
    assert first.accepted and first.accepted_count == 3
    k1 = real.identity.public_key

    tip_rec = real.store.get_events_range(real.origin, 3, 1)[0]
    tip_hash = compute_event_hash(encode_record(tip_rec))

    attacker = Identity.generate()

    def forge(seq, prev_hash):
        rec = Record(
            record_format=RECORD_FORMAT,
            origin=real.origin,
            origin_seq=seq,
            previous_event_hash=prev_hash,
            event_id=os.urandom(32),
            kind=KIND_ARTICLE,
            schema_version=1,
            created_at=int(time.time()),
            actor_pubkey=attacker.public_key,
            actor_username="evil",
            actor_registrar=real.origin,
            board="general",
            article_id=os.urandom(32),
            article_num=0,
            metadata=MetadataMap(fields=[metadata_text(1, "forged")]),
            body_hash=ZERO_HASH,
            body_size=0,
            actor_signature=b"\x00" * SIG_SIZE,
            origin_signature=b"\x00" * SIG_SIZE,
        )
        rec.actor_signature = sign_intent(
            attacker, encode_intent(reconstruct_intent_from_record(rec))
        )
        rec.origin_signature = attacker.sign(DOMAIN_ORIGIN_SIG + encode_unsigned_record(rec))
        return rec

    f4 = forge(4, tip_hash)
    f5 = forge(5, compute_event_hash(encode_record(f4)))

    head = Head(
        head_format=HEAD_FORMAT,
        origin=real.origin,
        latest_origin_seq=5,
        latest_event_hash=compute_event_hash(encode_record(f5)),
        event_count=5,
        generated_at=int(time.time()),
        origin_pubkey=attacker.public_key,
    )
    head.origin_signature = sign_head(attacker, encode_unsigned_head(head))

    evil = MockClient(head=head, ranges={4: [(f4, None)], 5: [(f5, None)]})

    with pytest.raises(FirehoseError):
        await mgr._sync_once(real.origin, evil, skip_allowlist=True)

    assert peer_store.get_highest_seq(real.origin) == 3
    assert peer_store.get_current_key(real.origin) == k1


@pytest.mark.xdist_group("rotation_sync")
async def test_fresh_peer_syncs_history_containing_rotation(tmp_path):
    """A peer with no prior history bootstraps pre-rotation trust from the
    rotate record's proof alone."""
    origin = _OriginServer(tmp_path)
    origin.publish_articles(3)
    origin.rotate()
    origin.publish_articles(2)

    peer_store, mgr = _make_peer(tmp_path)

    result = await mgr._sync_once(origin.origin, origin.serving_client(), skip_allowlist=True)
    assert result.accepted, result.reason
    assert result.accepted_count == 6

    assert peer_store.get_highest_seq(origin.origin) == 6
    assert peer_store.get_current_key(origin.origin) == origin.identity.public_key


@pytest.mark.xdist_group("rotation_sync")
async def test_fresh_peer_two_chained_rotations(tmp_path):
    """Backward derivation walks through multiple chained rotate proofs."""
    origin = _OriginServer(tmp_path)
    origin.publish_articles(2)
    origin.rotate()
    origin.publish_articles(2)
    origin.rotate()
    origin.publish_articles(2)

    peer_store, mgr = _make_peer(tmp_path)

    result = await mgr._sync_once(origin.origin, origin.serving_client(), skip_allowlist=True)
    assert result.accepted, result.reason
    assert result.accepted_count == 8

    assert peer_store.get_highest_seq(origin.origin) == 8
    assert peer_store.get_current_key(origin.origin) == origin.identity.public_key

    followup = await mgr._sync_once(origin.origin, origin.serving_client(), skip_allowlist=True)
    assert followup.reason == "already up to date"


@pytest.mark.xdist_group("rotation_sync")
async def test_unlinked_rotate_rejected(tmp_path):
    """A self-consistent rotate record that does not chain to a trusted key
    cannot bootstrap trust; the batch is refused."""
    real = _OriginServer(tmp_path)
    k0 = real.identity.public_key
    real.publish_articles(3)

    peer_store, mgr = _make_peer(tmp_path)
    client = real.serving_client()
    await mgr._sync_once(real.origin, client, skip_allowlist=True)

    tip_rec = real.store.get_events_range(real.origin, 3, 1)[0]
    tip_hash = compute_event_hash(encode_record(tip_rec))

    attacker = Identity.generate()
    attacker_new = Identity.generate()

    rot = Record(
        record_format=RECORD_FORMAT,
        origin=real.origin,
        origin_seq=4,
        previous_event_hash=tip_hash,
        event_id=os.urandom(32),
        kind=KIND_ORIGIN_KEY_ROTATE,
        schema_version=1,
        created_at=int(time.time()),
        actor_pubkey=attacker.public_key,
        actor_username="evil",
        actor_registrar=real.origin,
        board="",
        article_id=ZERO_ID,
        article_num=0,
        metadata=MetadataMap(
            fields=[
                metadata_bytes(
                    1,
                    attacker_new.public_key,
                ),
                metadata_bytes(
                    2,
                    sign_key_rotation_proof(
                        attacker_new, real.origin, attacker.public_key, attacker_new.public_key
                    ),
                ),
            ]
        ),
        body_hash=ZERO_HASH,
        body_size=0,
        actor_signature=b"\x00" * SIG_SIZE,
        origin_signature=b"\x00" * SIG_SIZE,
    )
    intent = reconstruct_intent_from_record(rot)
    rot.actor_signature = sign_intent(attacker, encode_intent(intent))
    rot.origin_signature = attacker.sign(DOMAIN_ORIGIN_SIG + encode_unsigned_record(rot))

    head = Head(
        head_format=HEAD_FORMAT,
        origin=real.origin,
        latest_origin_seq=4,
        latest_event_hash=compute_event_hash(encode_record(rot)),
        event_count=4,
        generated_at=int(time.time()),
        origin_pubkey=attacker_new.public_key,
    )
    head.origin_signature = sign_head(attacker_new, encode_unsigned_head(head))

    evil = MockClient(head=head, ranges={4: [(rot, None)]})

    with pytest.raises(FirehoseError):
        await mgr._sync_once(real.origin, evil, skip_allowlist=True)

    assert peer_store.get_highest_seq(real.origin) == 3
    assert peer_store.get_current_key(real.origin) == k0
