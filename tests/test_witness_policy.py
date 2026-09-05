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

"""Global [witnesses] policy: first/last rewrite, cap, retain flag, wire_max."""

import struct

import pytest

from bonnet.core.config import FirehoseConfig, WitnessConfig
from bonnet.core.crypto import Identity
from bonnet.core.firehose import FirehoseStore
from bonnet.core.record import (
    Witness,
    compute_event_hash,
    encode_record,
    encode_unsigned_witness,
    make_origin_witness,
    sign_witness,
)
from bonnet.net.firehose_sync import SyncManager
from tests.test_federation import _OriginServer


def _witness_for(
    origin, event_id, event_hash, relay: Identity, hostname, seen_at, frm=None, frm_host=""
):
    w = Witness(
        event_origin=origin,
        event_id=event_id,
        event_hash=event_hash,
        relay_pubkey=relay.public_key,
        relay_hostname=hostname,
        received_from_pubkey=frm if frm is not None else b"\x00" * 32,
        received_from_hostname=frm_host,
        seen_at=seen_at,
    )
    w.relay_signature = sign_witness(relay, encode_unsigned_witness(w))
    return w


def _origin_rec(tmp_path):
    server = _OriginServer(tmp_path, "origin.test")
    server.publish_articles(1)
    rec = server.store.get_events_range("origin.test", 1, 1)[0]
    eh = compute_event_hash(encode_record(rec))
    return server, rec, eh


def test_first_wins_drops_rewrite(tmp_path):
    server, rec, eh = _origin_rec(tmp_path)
    store = FirehoseStore(str(tmp_path / "s.db"))  # default policy "first"
    relay = Identity.generate()
    w1 = _witness_for("origin.test", rec.event_id, eh, relay, "r.test", 100)
    w2 = _witness_for("origin.test", rec.event_id, eh, relay, "renamed.test", 200)
    assert store.store_witness(w1)
    assert store.store_witness(w2)
    got = store.get_witness("origin.test", rec.event_id, relay.public_key)
    assert got is not None
    assert got.relay_hostname == "r.test"
    assert got.seen_at == 100


def test_last_wins_replaces(tmp_path):
    server, rec, eh = _origin_rec(tmp_path)
    store = FirehoseStore(str(tmp_path / "s.db"), witness_update_policy="last")
    relay = Identity.generate()
    w1 = _witness_for("origin.test", rec.event_id, eh, relay, "r.test", 100)
    w2 = _witness_for("origin.test", rec.event_id, eh, relay, "renamed.test", 200)
    store.store_witness(w1)
    store.store_witness(w2)
    got = store.get_witness("origin.test", rec.event_id, relay.public_key)
    assert got.relay_hostname == "renamed.test"
    assert got.seen_at == 200


def test_max_per_event_keeps_origin_self_newest(tmp_path):
    server, rec, eh = _origin_rec(tmp_path)
    me = Identity.generate()
    store = FirehoseStore(str(tmp_path / "s.db"), witness_max_per_event=4)
    origin_w = make_origin_witness(
        "origin.test", rec.event_id, eh, server.identity, "origin.test", 1
    )
    store.store_witness(origin_w)
    own = _witness_for(
        "origin.test",
        rec.event_id,
        eh,
        me,
        "me.test",
        2,
        frm=server.identity.public_key,
        frm_host="origin.test",
    )
    store.store_witness(own, keep_pubkeys={me.public_key})
    olds = []
    for i in range(5):
        r = Identity.generate()
        olds.append(r)
        w = _witness_for(
            "origin.test",
            rec.event_id,
            eh,
            r,
            f"u{i}.test",
            10 + i,
            frm=server.identity.public_key,
            frm_host="origin.test",
        )
        store.store_witness(w, keep_pubkeys={me.public_key})
    rows = store.get_witnesses("origin.test", rec.event_id, limit=100)
    assert len(rows) == 4
    by_key = {w.relay_pubkey: w for w in rows}
    # origin + self pinned
    assert server.identity.public_key in by_key
    assert me.public_key in by_key
    # newest two upstream survive (u4, u3), oldest evicted
    assert olds[4].public_key in by_key
    assert olds[3].public_key in by_key
    assert olds[0].public_key not in by_key


def test_retain_upstream_disabled(tmp_path):
    server, rec = _origin_rec(tmp_path)[:2]
    me = Identity.generate()
    store = FirehoseStore(str(tmp_path / "mine.db"))
    mgr = SyncManager(store, me, "me.test", retain_upstream=False)
    upstream_relay = Identity.generate()
    eh = compute_event_hash(encode_record(rec))
    uw = _witness_for(
        "origin.test",
        rec.event_id,
        eh,
        upstream_relay,
        "up.test",
        50,
        frm=server.identity.public_key,
        frm_host="origin.test",
    )
    kept = mgr._retain_upstream(rec, eh, [uw])
    assert kept == 0
    assert store.get_witness("origin.test", rec.event_id, upstream_relay.public_key) is None


def test_wire_max_truncation_deterministic(tmp_path):
    from bonnet.core.acl import ACLEvaluator
    from bonnet.core.board_projection import BoardProjection  # noqa: F401
    from bonnet.core.bodies import BodyStore
    from bonnet.core.global_projections import NavProjection, PolicyProjection, UserProjection
    from bonnet.core.kind_validator import KindValidator
    from bonnet.core.search import SearchService
    from bonnet.net.firehose_commands import FirehoseCommandHandler

    server, rec, eh = _origin_rec(tmp_path)
    me = Identity.generate()
    store = FirehoseStore(str(tmp_path / "h.db"))
    origin_w = make_origin_witness(
        "origin.test", rec.event_id, eh, server.identity, "origin.test", 1
    )
    store.store_witness(origin_w)
    own = _witness_for(
        "origin.test",
        rec.event_id,
        eh,
        me,
        "me.test",
        2,
        frm=server.identity.public_key,
        frm_host="origin.test",
    )
    store.store_witness(own, keep_pubkeys={me.public_key})
    for i in range(5):
        r = Identity.generate()
        store.store_witness(
            _witness_for(
                "origin.test",
                rec.event_id,
                eh,
                r,
                f"u{i}.test",
                10 + i,
                frm=server.identity.public_key,
                frm_host="origin.test",
            )
        )
    handler = FirehoseCommandHandler(
        firehose=store,
        server_identity=me,
        config_origin="origin.test",
        nav=NavProjection(str(tmp_path / "nav.db")),
        users=UserProjection(str(tmp_path / "users.db")),
        policy=PolicyProjection(str(tmp_path / "policy.db")),
        body_store=BodyStore(boards_dir=str(tmp_path / "boards"), events_dir=str(tmp_path / "ev")),
        boards_dir=str(tmp_path / "boards"),
        acl=ACLEvaluator([]),
        validator=KindValidator(),
        search=SearchService(
            boards_dir=str(tmp_path / "boards"),
            body_store=BodyStore(
                boards_dir=str(tmp_path / "boards"), events_dir=str(tmp_path / "ev")
            ),
        ),
        hostname="me.test",
        wire_max=3,
    )
    from bonnet.core.record import decode_witness

    raw = handler._witness_set("origin.test", rec, eh)
    count = struct.unpack(">H", raw[:2])[0]
    assert count == 3
    # first entry is own
    ln = struct.unpack(">H", raw[2:4])[0]
    first = decode_witness(raw[4 : 4 + ln])
    assert first.relay_pubkey == me.public_key


def test_config_validation(tmp_path):
    cfg = FirehoseConfig(witness=WitnessConfig(max_per_event=1))
    with pytest.raises(ValueError, match="max_per_event"):
        cfg.validate()
    cfg = FirehoseConfig(witness=WitnessConfig(update_policy="newer"))
    with pytest.raises(ValueError, match="update_policy"):
        cfg.validate()
    cfg = FirehoseConfig(witness=WitnessConfig(wire_max=33))
    with pytest.raises(ValueError, match="wire_max"):
        cfg.validate()


def test_config_load_witnesses(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text(
        '[server]\norigin = "a.test"\n'
        "[witnesses]\nretain_upstream = false\nmax_per_event = 5\n"
        'update_policy = "last"\nwire_max = 10\n'
    )
    cfg = FirehoseConfig.load(str(p))
    cfg.validate()
    assert cfg.witness.retain_upstream is False
    assert cfg.witness.max_per_event == 5
    assert cfg.witness.update_policy == "last"
    assert cfg.witness.wire_max == 10
