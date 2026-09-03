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

"""Readers can check a record themselves.

Before this, nothing on the reading side verified anything: `core.record`
exported the verifiers, the wire delivered both signatures, and no client
called them — while `get_article` told callers to use the event tools "when
you need the signed artifact", and those tools dropped the signatures from
their output.

The two checks answer different questions and have different requirements,
which is why they are reported separately rather than as one verdict.
"""

import os

import pytest

from bonnet.core.crypto import Identity
from bonnet.core.firehose import FirehoseStore
from bonnet.core.record import (
    Intent,
    MetadataMap,
    compute_body_hash,
    encode_intent,
    metadata_text,
    sign_intent,
)
from bonnet.core.trust import TrustStore
from bonnet.gateway.firehose_client import FirehoseHTTPClient

ORIGIN = "bbs.test"


@pytest.fixture
def store(tmp_path):
    s = FirehoseStore(str(tmp_path / "events.db"))
    yield s
    s.close()


@pytest.fixture
def client(tmp_path):
    c = FirehoseHTTPClient(
        "https://bbs.test", verify=False, trust_store_path=str(tmp_path / "trust.db")
    )
    c._server_origin = ORIGIN
    yield c


def _publish(store, origin_identity, actor, seq_hint=1):
    body = b"hello"
    intent = Intent(
        event_id=os.urandom(32),
        kind="bonnet.article",
        origin=ORIGIN,
        actor_pubkey=actor.public_key,
        board="general",
        article_id=os.urandom(32),
        metadata=MetadataMap([metadata_text(1, "Subject"), metadata_text(4, "text/plain")]),
        body_hash=compute_body_hash(body),
        body_size=len(body),
    )
    return store.append_record(
        origin_identity, intent, sign_intent(actor, encode_intent(intent)), body
    )


# ---------------------------------------------------------------------------
# author: always answerable
# ---------------------------------------------------------------------------


def test_the_author_signature_is_checkable_with_no_key_lookup(store, client):
    """The author's key is in the record, so this has an answer even for an
    origin this client knows nothing about."""
    origin_identity = Identity.generate()
    actor = Identity.generate()
    store.init_origin_key(ORIGIN, origin_identity.public_key)
    rec = _publish(store, origin_identity, actor)

    result = client.verify_record(rec)
    assert result["author"] == "valid"


def test_a_tampered_body_hash_breaks_the_author_signature(store, client):
    """What the author signature actually protects: the content is what that
    key signed, and no relay in between changed it."""
    origin_identity = Identity.generate()
    actor = Identity.generate()
    store.init_origin_key(ORIGIN, origin_identity.public_key)
    rec = _publish(store, origin_identity, actor)

    rec.body_hash = os.urandom(32)

    assert client.verify_record(rec)["author"] == "invalid"


def test_a_relay_cannot_reattribute_a_record(store, client):
    """Swapping author_pubkey does not move authorship; it just stops
    verifying, which is the point."""
    origin_identity = Identity.generate()
    actor = Identity.generate()
    store.init_origin_key(ORIGIN, origin_identity.public_key)
    rec = _publish(store, origin_identity, actor)

    rec.actor_pubkey = Identity.generate().public_key

    assert client.verify_record(rec)["author"] == "invalid"


# ---------------------------------------------------------------------------
# origin: needs the epoch cache
# ---------------------------------------------------------------------------


def test_without_a_cached_epoch_the_origin_check_is_unverifiable_not_invalid(store, client):
    """The distinction that keeps this client's missing state from becoming an
    accusation: a signature checked against the wrong key fails exactly like a
    forged one."""
    origin_identity = Identity.generate()
    actor = Identity.generate()
    store.init_origin_key(ORIGIN, origin_identity.public_key)
    rec = _publish(store, origin_identity, actor)

    result = client.verify_record(rec)
    assert result["origin"] == "unverifiable"
    assert result["origin_key_known_for_seq"] is False


def test_with_the_epoch_cached_the_countersignature_verifies(store, client):
    origin_identity = Identity.generate()
    actor = Identity.generate()
    store.init_origin_key(ORIGIN, origin_identity.public_key)
    rec = _publish(store, origin_identity, actor)

    client._trust_store.cache_epochs(ORIGIN, [(1, None, origin_identity.public_key)])

    result = client.verify_record(rec)
    assert result == {"author": "valid", "origin": "valid", "origin_key_known_for_seq": True}


def test_a_forged_countersignature_is_reported_as_invalid(store, client):
    """Once a key *is* known for the sequence, a failure is a real finding."""
    origin_identity = Identity.generate()
    actor = Identity.generate()
    store.init_origin_key(ORIGIN, origin_identity.public_key)
    rec = _publish(store, origin_identity, actor)

    rec.origin_signature = os.urandom(64)
    client._trust_store.cache_epochs(ORIGIN, [(1, None, origin_identity.public_key)])

    assert client.verify_record(rec)["origin"] == "invalid"


def test_the_key_for_a_sequence_comes_from_the_epoch_it_falls_in(store, client):
    """After a rotation the pin is not the key that countersigned older
    records — the whole reason a pin alone cannot verify a log."""
    old_key = Identity.generate()
    new_key = Identity.generate()
    client._trust_store.cache_epochs(
        ORIGIN,
        [(1, 10, old_key.public_key), (11, None, new_key.public_key)],
    )

    assert client.origin_key_for_seq(ORIGIN, 1) == old_key.public_key
    assert client.origin_key_for_seq(ORIGIN, 10) == old_key.public_key
    assert client.origin_key_for_seq(ORIGIN, 11) == new_key.public_key
    assert client.origin_key_for_seq(ORIGIN, 9999) == new_key.public_key


# ---------------------------------------------------------------------------
# the property the cache exists for
# ---------------------------------------------------------------------------


def test_verification_survives_the_origin_going_away(tmp_path, store):
    """The reason this is a cache and not a lookup. An origin that has gone
    quiet is indistinguishable from one refusing to answer, so a client that
    fetched key history on demand could not tell a forgery from an outage."""
    origin_identity = Identity.generate()
    actor = Identity.generate()
    store.init_origin_key(ORIGIN, origin_identity.public_key)
    rec = _publish(store, origin_identity, actor)

    trust_path = str(tmp_path / "trust.db")
    first = FirehoseHTTPClient("https://bbs.test", trust_store_path=trust_path)
    first._server_origin = ORIGIN
    first._trust_store.cache_epochs(ORIGIN, [(1, None, origin_identity.public_key)])
    first._trust_store.close()

    # A fresh client, later, with the origin unreachable — no network here at
    # all, and the record still verifies.
    later = FirehoseHTTPClient("https://bbs.test", trust_store_path=trust_path)
    later._server_origin = ORIGIN
    assert later.verify_record(rec)["origin"] == "valid"


def test_a_failed_refresh_leaves_a_good_cache_alone(tmp_path):
    """Best-effort means best-effort: the point of caching is that
    verification keeps working when the origin does not, so a refresh that
    cannot reach anyone must not invalidate what is already known."""
    key = Identity.generate()
    trust_path = str(tmp_path / "trust.db")
    ts = TrustStore(trust_path)
    ts.configured_pin(ORIGIN, key.public_key)
    ts.cache_epochs(ORIGIN, [(1, None, key.public_key)])
    ts.close()

    client = FirehoseHTTPClient("https://nowhere.invalid", trust_store_path=trust_path)
    client._server_origin = ORIGIN

    import asyncio

    assert asyncio.run(client.refresh_epoch_cache(ORIGIN)) is False
    assert client._trust_store.get_cached_epochs(ORIGIN) == [(1, None, key.public_key)]


def test_epochs_are_replaced_wholesale_not_merged(tmp_path):
    """An epoch table is one coherent account of a key history; splicing two
    together could produce a chain neither party ever attested to."""
    ts = TrustStore(str(tmp_path / "trust.db"))
    a, b, c = (Identity.generate().public_key for _ in range(3))

    ts.cache_epochs(ORIGIN, [(1, 5, a), (6, None, b)])
    ts.cache_epochs(ORIGIN, [(1, None, c)])

    assert ts.get_cached_epochs(ORIGIN) == [(1, None, c)]
    assert ts.key_for_seq(ORIGIN, 3) == c
    ts.close()
