"""Provenance: who carried a record, and who says so.

A witness is one relay's signed report of one observation - that a particular
party handed it a particular record. Three properties have to hold or the
chain is worse than nothing, because a relay's signature would be lending
weight to someone else's claim:

  - A relay names the peer it actually authenticated to, never the upstream's
    account of itself.
  - Witnesses received from a peer are kept only if they verify under the
    relay they name, so a forgery cannot be laundered through an honest relay.
  - The chain travels with the record, so it stays readable when the relays in
    it are offline or simply refusing to answer - which, from outside, look
    identical.
"""

import os
import time

import pytest

from bonnet.core.crypto import Identity
from bonnet.core.firehose import FirehoseStore
from bonnet.core.record import (
    Witness,
    compute_event_hash,
    encode_record,
    encode_unsigned_witness,
    is_origin_witness,
    make_origin_witness,
    sign_witness,
    verify_witness_signature,
)
from bonnet.net.firehose_sync import SyncClient, SyncManager
from tests.test_federation import _OriginServer


class _RelayClient(SyncClient):
    """Serves a store's records together with the chain it holds for each.

    Mirrors what `FirehoseCommandHandler._witness_set` puts on the wire: the
    relay's own witness plus every upstream one it retained.
    """

    def __init__(self, store, identity, hostname):
        self._store = store
        self._identity = identity
        self._hostname = hostname

    async def fetch_head(self, origin):
        return self._store.get_head(origin), b""

    async def fetch_range(self, origin, start_seq, max_count):
        out = []
        for rec in self._store.get_events_range(origin, start_seq, max_count):
            out.append((rec, self._store.get_witnesses(origin, rec.event_id)))
        return out

    def peer_identity(self):
        return self._identity.public_key, self._hostname

    async def close(self):
        pass


def _origin_with_witness(tmp_path, name="origin.test"):
    """An origin that has signed a terminating witness for its own record."""
    server = _OriginServer(tmp_path, name)
    server.publish_articles(1)
    rec = server.store.get_events_range(name, 1, 1)[0]
    server.store.store_witness(
        make_origin_witness(
            origin=name,
            event_id=rec.event_id,
            event_hash=compute_event_hash(encode_record(rec)),
            origin_identity=server.identity,
            hostname=name,
            seen_at=int(time.time()),
        )
    )
    return server, rec


# ---------------------------------------------------------------------------
# naming the peer you actually spoke to
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_a_forged_upstream_witness_cannot_be_laundered(tmp_path):
    """The attack this phase exists to close.

    A peer serves a genuine record with a witness naming an uninvolved relay,
    signed with garbage. Previously the local relay copied those two fields
    into its own witness and signed it - so its signature vouched for a hop
    that never happened, and the innocent party was on the hook.
    """
    origin, rec = _origin_with_witness(tmp_path)
    patsy = Identity.generate()
    me = Identity.generate()
    store = FirehoseStore(str(tmp_path / "mine.db"))

    class Hostile(SyncClient):
        async def fetch_head(self, o):
            return origin.store.get_head(o), b""

        async def fetch_range(self, o, start, count):
            out = []
            for r in origin.store.get_events_range(o, start, count):
                forged = Witness(
                    event_origin=r.origin,
                    event_id=r.event_id,
                    event_hash=compute_event_hash(encode_record(r)),
                    relay_pubkey=patsy.public_key,
                    relay_hostname="innocent-relay.test",
                    received_from_pubkey=b"\x00" * 32,
                    received_from_hostname="",
                    seen_at=0,
                    relay_signature=b"\xaa" * 64,
                )
                out.append((r, [forged]))
            return out

        def peer_identity(self):
            return b"\x99" * 32, "hostile.test"

        async def close(self):
            pass

    mgr = SyncManager(store, me, "myrelay.test")
    peer = Hostile()
    mgr._clients[origin.origin] = peer
    assert (await mgr._sync_once(origin.origin, peer)).accepted

    chain = store.get_witnesses(origin.origin, rec.event_id)

    # our own witness names the party we actually authenticated to
    ours = [w for w in chain if w.relay_pubkey == me.public_key]
    assert len(ours) == 1
    assert ours[0].received_from_hostname == "hostile.test"
    assert ours[0].received_from_pubkey == b"\x99" * 32

    # and the forgery was never kept, so it is never served onward
    assert all(w.relay_pubkey != patsy.public_key for w in chain)

    store.close()
    origin.store.close()


@pytest.mark.anyio
async def test_the_source_column_names_the_peer_not_ourselves(tmp_path):
    origin, rec = _origin_with_witness(tmp_path)
    store = FirehoseStore(str(tmp_path / "mine.db"))
    mgr = SyncManager(store, Identity.generate(), "myrelay.test")
    peer = _RelayClient(origin.store, origin.identity, origin.origin)
    mgr._clients[origin.origin] = peer
    assert (await mgr._sync_once(origin.origin, peer)).accepted

    source = store._conn.execute(
        "SELECT source FROM events WHERE origin=? AND origin_seq=1", (origin.origin,)
    ).fetchone()[0]
    assert source == origin.origin

    store.close()
    origin.store.close()


# ---------------------------------------------------------------------------
# the chain accumulates and survives
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_the_chain_accumulates_across_relays(tmp_path):
    """A -> B -> C. C ends up holding all three links, each verifying under
    the relay that made it."""
    origin, rec = _origin_with_witness(tmp_path)

    b_identity = Identity.generate()
    b_store = FirehoseStore(str(tmp_path / "b.db"))
    b_mgr = SyncManager(b_store, b_identity, "relay-b.test")
    a_client = _RelayClient(origin.store, origin.identity, origin.origin)
    b_mgr._clients[origin.origin] = a_client
    assert (await b_mgr._sync_once(origin.origin, a_client)).accepted

    c_identity = Identity.generate()
    c_store = FirehoseStore(str(tmp_path / "c.db"))
    c_mgr = SyncManager(c_store, c_identity, "relay-c.test")
    b_client = _RelayClient(b_store, b_identity, "relay-b.test")
    c_mgr._clients[origin.origin] = b_client
    assert (await c_mgr._sync_once(origin.origin, b_client)).accepted

    chain = c_store.get_witnesses(origin.origin, rec.event_id)
    by_key = {w.relay_pubkey: w for w in chain}
    assert set(by_key) == {origin.identity.public_key, b_identity.public_key, c_identity.public_key}

    # every link is a genuine signed statement by the relay it names
    for w in chain:
        assert verify_witness_signature(
            w.relay_pubkey, encode_unsigned_witness(w), w.relay_signature
        )

    # and the edges join up, origin-terminated
    assert is_origin_witness(by_key[origin.identity.public_key])
    assert by_key[b_identity.public_key].received_from_pubkey == origin.identity.public_key
    assert by_key[c_identity.public_key].received_from_pubkey == b_identity.public_key

    c_store.close()
    b_store.close()
    origin.store.close()


@pytest.mark.anyio
async def test_the_chain_outlives_the_relays_in_it(tmp_path):
    """The property a lookup-on-demand design cannot have: B going away does
    not erase the hop through B."""
    origin, rec = _origin_with_witness(tmp_path)

    b_identity = Identity.generate()
    b_store = FirehoseStore(str(tmp_path / "b.db"))
    b_mgr = SyncManager(b_store, b_identity, "relay-b.test")
    a_client = _RelayClient(origin.store, origin.identity, origin.origin)
    b_mgr._clients[origin.origin] = a_client
    await b_mgr._sync_once(origin.origin, a_client)

    c_store = FirehoseStore(str(tmp_path / "c.db"))
    c_mgr = SyncManager(c_store, Identity.generate(), "relay-c.test")
    b_client = _RelayClient(b_store, b_identity, "relay-b.test")
    c_mgr._clients[origin.origin] = b_client
    await c_mgr._sync_once(origin.origin, b_client)

    # B and the origin both go dark
    b_store.close()
    origin.store.close()

    chain = c_store.get_witnesses(origin.origin, rec.event_id)
    assert len(chain) == 3
    assert any(w.relay_hostname == "relay-b.test" for w in chain)
    assert any(is_origin_witness(w) for w in chain)

    c_store.close()


# ---------------------------------------------------------------------------
# storage refuses what it cannot attribute
# ---------------------------------------------------------------------------


def test_store_witness_refuses_an_unverifiable_witness(tmp_path):
    store = FirehoseStore(str(tmp_path / "s.db"))
    relay = Identity.generate()
    w = Witness(
        event_origin="bbs.test",
        event_id=os.urandom(32),
        event_hash=os.urandom(32),
        relay_pubkey=relay.public_key,
        relay_hostname="relay.test",
        received_from_pubkey=b"\x00" * 32,
        received_from_hostname="",
        seen_at=1,
        relay_signature=b"\x00" * 64,
    )

    assert store.store_witness(w) is False
    assert store.get_witnesses("bbs.test", w.event_id) == []

    w.relay_signature = sign_witness(relay, encode_unsigned_witness(w))
    assert store.store_witness(w) is True
    assert len(store.get_witnesses("bbs.test", w.event_id)) == 1

    store.close()


def test_a_witness_about_another_record_is_not_retained(tmp_path):
    """Retention is scoped to the record the witness arrived with; a witness
    naming a different event hash is a statement about something else."""
    origin, rec = _origin_with_witness(tmp_path)
    store = FirehoseStore(str(tmp_path / "mine.db"))
    mgr = SyncManager(store, Identity.generate(), "myrelay.test")

    stranger = Identity.generate()
    w = Witness(
        event_origin=rec.origin,
        event_id=rec.event_id,
        event_hash=os.urandom(32),  # not this record
        relay_pubkey=stranger.public_key,
        relay_hostname="stranger.test",
        received_from_pubkey=b"\x00" * 32,
        received_from_hostname="",
        seen_at=1,
    )
    w.relay_signature = sign_witness(stranger, encode_unsigned_witness(w))

    kept = mgr._retain_upstream(rec, compute_event_hash(encode_record(rec)), [w])
    assert kept == 0
    assert store.get_witnesses(rec.origin, rec.event_id) == []

    store.close()
    origin.store.close()
