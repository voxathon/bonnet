# Copyright 2026 The Bonnet Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Key epochs: our own state, checked against our own records.

`origin_key_epochs` decides which key verifies which record. Like
`origin_state` it is maintained alongside `events` rather than derived from
them, so a crash or a restored database can leave the two disagreeing - and
unlike `origin_state` it had no consistency check at all.

Its failure mode is the worse of the two. A drifted tip raises ChainBreak,
which `_diagnose_chain_break` recognises as ours and repairs. A drifted epoch
table raises SignatureInvalid, which looks exactly like a peer serving forged
records: before this, the relay blamed an honest peer and retried forever,
with sync status reading clean the whole time.

Epoch 1's key is the TOFU anchor and cannot be re-derived - it entered from a
head, not a record. So what is checked is whether the rest follows from it.
"""

import pytest

from bonnet.core.crypto import Identity
from bonnet.core.firehose import FirehoseStore
from bonnet.net.firehose_sync import SyncManager
from tests.test_federation import _OriginServer, _ServingClient


def _synced_peer(tmp_path, rotations=0, articles=2):
    """A peer that has synced an origin's history, rotations included."""
    origin = _OriginServer(tmp_path, "rot.test")
    origin.publish_articles(articles)
    for _ in range(rotations):
        origin.rotate()
        origin.publish_articles(articles)

    store = FirehoseStore(str(tmp_path / "peer.db"))
    mgr = SyncManager(store, Identity.generate(), "peer.test")
    client = _ServingClient(origin)
    mgr._clients[origin.origin] = client
    return origin, store, mgr, client


# ---------------------------------------------------------------------------
# derivation
# ---------------------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("rotations", [0, 1, 3])
async def test_the_derivation_agrees_with_what_sync_recorded(tmp_path, rotations):
    """The table sync builds record-by-record and the table derived in one
    pass from the same records must be the same table."""
    origin, store, mgr, client = _synced_peer(tmp_path, rotations=rotations)
    assert (await mgr._sync_once(origin.origin, client)).accepted

    consistent, stored, derived = store.check_key_epochs(origin.origin)
    assert consistent, f"stored={stored} derived={derived}"
    assert len(stored) == rotations + 1

    store.close()
    origin.store.close()


@pytest.mark.anyio
async def test_a_corrupted_epoch_table_is_detected_and_repaired(tmp_path):
    origin, store, mgr, client = _synced_peer(tmp_path, rotations=2)
    assert (await mgr._sync_once(origin.origin, client)).accepted
    good = store.get_key_epochs(origin.origin)

    # Corrupt the live epoch: a key nothing in the log accounts for. This is
    # what a half-applied write or a restored database looks like from here.
    store._conn.execute(
        "UPDATE origin_key_epochs SET publickey=? WHERE origin=? AND end_seq IS NULL",
        (Identity.generate().public_key, origin.origin),
    )
    store._conn.commit()

    consistent, _stored, _derived = store.check_key_epochs(origin.origin)
    assert not consistent
    assert store.repair_key_epochs(origin.origin) is True
    assert store.get_key_epochs(origin.origin) == good

    store.close()
    origin.store.close()


@pytest.mark.anyio
async def test_the_anchor_is_not_second_guessed(tmp_path):
    """Epoch 1's key came from a head, not from any record, so nothing local
    can contradict it. Corrupting it makes the *derivation* follow it - the
    check answers "given the anchor, does the rest follow", and cannot answer
    more than that."""
    origin, store, mgr, client = _synced_peer(tmp_path, rotations=1)
    assert (await mgr._sync_once(origin.origin, client)).accepted

    store._conn.execute(
        "UPDATE origin_key_epochs SET publickey=? WHERE origin=? AND start_seq=1",
        (Identity.generate().public_key, origin.origin),
    )
    store._conn.commit()

    # The first rotate no longer chains from the (wrong) anchor, so derivation
    # stops there rather than inventing a history.
    derived = store.derive_key_epochs(origin.origin)
    assert derived is not None
    assert len(derived) == 1
    assert derived[0][1] is None

    store.close()
    origin.store.close()


def test_nothing_to_derive_is_not_an_inconsistency(tmp_path):
    store = FirehoseStore(str(tmp_path / "s.db"))
    consistent, stored, derived = store.check_key_epochs("never-seen.test")
    assert consistent and stored == [] and derived == []
    store.close()


# ---------------------------------------------------------------------------
# what sync does about it
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_a_drifted_epoch_table_is_repaired_not_blamed_on_the_peer(tmp_path):
    """The honest-peer case. Our table is wrong, so records verify against the
    wrong key - and the peer is serving exactly what it should."""
    origin, store, mgr, client = _synced_peer(tmp_path, rotations=1)
    assert (await mgr._sync_once(origin.origin, client)).accepted

    store._conn.execute(
        "UPDATE origin_key_epochs SET publickey=? WHERE origin=? AND end_seq IS NULL",
        (Identity.generate().public_key, origin.origin),
    )
    store._conn.commit()

    origin.publish_articles(2)
    result = await mgr._sync_once(origin.origin, client)

    assert "repaired" in result.reason
    assert store.get_sync_status(origin.origin)["status"] != "diverged"
    assert store.check_key_epochs(origin.origin)[0]

    # and the next cycle proceeds, which is the point of not halting
    assert (await mgr._sync_once(origin.origin, client)).accepted

    store.close()
    origin.store.close()


@pytest.mark.anyio
async def test_a_key_we_cannot_account_for_halts_and_is_marked(tmp_path):
    """The takeover case: our table is fine, and the peer is signing with a
    key no rotation record connects to the one we hold. Retrying cannot help,
    so it stops and says so instead of failing quietly forever."""
    origin, store, mgr, client = _synced_peer(tmp_path, rotations=0)
    assert (await mgr._sync_once(origin.origin, client)).accepted
    assert store.check_key_epochs(origin.origin)[0]

    # New operator on the same origin: fresh key, no rotation record linking it.
    origin.identity = Identity.generate()
    origin.publish_articles(1)

    result = await mgr._sync_once(origin.origin, client)

    assert not result.accepted
    assert "diverged" in result.reason
    status = store.get_sync_status(origin.origin)
    assert status["status"] == "diverged"

    # halting keeps what was already accepted, and is reversible
    assert store.get_highest_seq(origin.origin) == 2

    store.close()
    origin.store.close()


@pytest.mark.anyio
async def test_a_halted_origin_is_not_refetched(tmp_path):
    """Same contract the ChainBreak path already has: once halted, stop
    spending a request an hour on something with no path to success."""
    origin, store, mgr, client = _synced_peer(tmp_path, rotations=0)
    await mgr._sync_once(origin.origin, client)
    origin.identity = Identity.generate()
    origin.publish_articles(1)
    await mgr._sync_once(origin.origin, client)

    again = await mgr._sync_once(origin.origin, client)
    assert "halted" in again.reason or "diverged" in again.reason

    store.close()
    origin.store.close()
