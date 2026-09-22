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

"""Transitive peer discovery: bonnet.route.* records.

Covers kind validation, the RouteProjection (latest-wins + withdraw
tombstones), dispatcher integration incl. rebuild, the sync manager's
opt-in learner, and [routing] config parsing.
"""

import pytest

from bonnet.core.bodies import BodyStore
from bonnet.core.config import FirehoseConfig, RoutingConfig, _parse_routing
from bonnet.core.crypto import Identity
from bonnet.core.dispatcher import Dispatcher
from bonnet.core.firehose import FirehoseStore
from bonnet.core.global_projections import (
    NavProjection,
    PolicyProjection,
    RouteProjection,
    UserProjection,
    parse_route_announce,
)
from bonnet.core.kind_validator import KindValidator, ValidationError
from bonnet.core.kinds import (
    ALL_KNOWN_KINDS,
    KIND_ROUTE_ANNOUNCE,
    KIND_ROUTE_WITHDRAW,
    ROUTE_KINDS,
)
from bonnet.core.record import (
    Intent,
    MetadataMap,
    Record,
    encode_intent,
    metadata_bool,
    metadata_text,
    metadata_u64,
    sign_intent,
)
from bonnet.net.firehose_sync import SyncManager

ORIGIN_A = Identity.from_private_key(bytes(range(1, 33)))
ORIGIN_B = Identity.from_private_key(bytes(range(50, 82)))
ACTOR = Identity.from_private_key(bytes(range(10, 42)))
ORIGIN_A_PUB = ORIGIN_A.public_key
ACTOR_PUB = ACTOR.public_key


def _rid(seed: int) -> bytes:
    return bytes([(seed + i) % 256 for i in range(32)])


def _announce_intent(
    origin, eid, hostname="c.example", port=2272, scheme="https", verify_tls=False, priority=0, **kw
):
    fields = [metadata_text(1, hostname), metadata_u64(2, port)]
    if scheme is not None:
        fields.append(metadata_text(3, scheme))
    fields.append(metadata_bool(4, verify_tls))
    fields.append(metadata_u64(5, priority))
    return Intent(
        event_id=eid,
        kind=KIND_ROUTE_ANNOUNCE,
        origin=origin,
        actor_pubkey=ACTOR_PUB,
        **kw,
        metadata=MetadataMap(fields),
    )


def _announce_record(origin, seq, eid, **kw):
    return Record(
        origin=origin,
        origin_seq=seq,
        event_id=eid,
        kind=KIND_ROUTE_ANNOUNCE,
        actor_pubkey=ACTOR_PUB,
        metadata=kw.pop("metadata", None) or _announce_intent(origin, eid, **kw).metadata,
        created_at=0,
    )


def _withdraw_record(origin, seq, eid, target_origin, target_event):
    return Record(
        origin=origin,
        origin_seq=seq,
        event_id=eid,
        kind=KIND_ROUTE_WITHDRAW,
        actor_pubkey=ACTOR_PUB,
        target_origin=target_origin,
        target_event_id=target_event,
        created_at=0,
    )


@pytest.fixture
def routes(tmp_path):
    r = RouteProjection(str(tmp_path / "routes.db"))
    yield r
    r.close()


# ---------------------------------------------------------------------------
# Kind registry
# ---------------------------------------------------------------------------


def test_route_kinds_registered():
    assert KIND_ROUTE_ANNOUNCE == "bonnet.route.announce"
    assert KIND_ROUTE_WITHDRAW == "bonnet.route.withdraw"
    assert ROUTE_KINDS <= ALL_KNOWN_KINDS


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_validate_announce_ok():
    KindValidator().validate(_announce_intent("bbs.a", _rid(1)))


def test_validate_announce_missing_hostname():
    intent = Intent(
        event_id=_rid(1),
        kind=KIND_ROUTE_ANNOUNCE,
        origin="bbs.a",
        actor_pubkey=ACTOR_PUB,
        metadata=MetadataMap([metadata_u64(2, 2272)]),
    )
    with pytest.raises(ValidationError, match="field 1"):
        KindValidator().validate(intent)


@pytest.mark.parametrize("port", [0, 65536])
def test_validate_announce_bad_port(port):
    with pytest.raises(ValidationError, match="port"):
        KindValidator().validate(_announce_intent("bbs.a", _rid(1), port=port))


def test_validate_announce_bad_scheme():
    with pytest.raises(ValidationError, match="scheme"):
        KindValidator().validate(_announce_intent("bbs.a", _rid(1), scheme="gopher"))


def test_validate_announce_rejects_board_and_targets():
    with pytest.raises(ValidationError):
        KindValidator().validate(_announce_intent("bbs.a", _rid(1), board="general"))


def test_validate_withdraw_ok():
    intent = Intent(
        event_id=_rid(2),
        kind=KIND_ROUTE_WITHDRAW,
        origin="bbs.a",
        actor_pubkey=ACTOR_PUB,
        target_origin="bbs.a",
        target_event_id=_rid(1),
    )
    KindValidator().validate(intent)


def test_validate_withdraw_requires_target():
    intent = Intent(
        event_id=_rid(2),
        kind=KIND_ROUTE_WITHDRAW,
        origin="bbs.a",
        actor_pubkey=ACTOR_PUB,
    )
    with pytest.raises(ValidationError, match="target_origin"):
        KindValidator().validate(intent)


# ---------------------------------------------------------------------------
# Metadata parsing (shared by projection, sync learner, gateway)
# ---------------------------------------------------------------------------


def test_parse_route_announce_defaults():
    m = MetadataMap([metadata_text(1, "C.Example."), metadata_u64(2, 2272)])
    parsed = parse_route_announce(m)
    assert parsed is not None
    assert parsed["hostname"] == "c.example"
    assert parsed["scheme"] == "https"
    assert parsed["verify_tls"] is False
    assert parsed["priority"] == 0
    assert parsed["endpoint"] == "https://c.example:2272"


@pytest.mark.parametrize(
    "fields",
    [
        [],
        [metadata_u64(2, 2272)],
        [metadata_text(1, "c.example")],
        [metadata_text(1, "c.example"), metadata_u64(2, 0)],
        [metadata_text(1, "c.example"), metadata_u64(2, 2272), metadata_text(3, "gopher")],
        [metadata_text(1, "has space.example"), metadata_u64(2, 2272)],
    ],
)
def test_parse_route_announce_malformed(fields):
    assert parse_route_announce(MetadataMap(fields)) is None


# ---------------------------------------------------------------------------
# Projection
# ---------------------------------------------------------------------------


def test_announce_projects(routes):
    routes.apply_route_announce(_announce_record("bbs.a", 1, _rid(1)))
    row = routes.get_route("bbs.a")
    assert row is not None
    assert row["hostname"] == "c.example"
    assert row["port"] == 2272
    assert row["endpoint"] == "https://c.example:2272"
    assert row["withdrawn"] is False
    assert row["announced_seq"] == 1


def test_announce_latest_wins_and_stale_loses(routes):
    routes.apply_route_announce(_announce_record("bbs.a", 1, _rid(1), hostname="old.example"))
    routes.apply_route_announce(_announce_record("bbs.a", 2, _rid(2), hostname="new.example"))
    assert routes.get_route("bbs.a")["hostname"] == "new.example"
    # Replaying the older record must not move the row backwards.
    routes.apply_route_announce(_announce_record("bbs.a", 1, _rid(1), hostname="old.example"))
    assert routes.get_route("bbs.a")["hostname"] == "new.example"


def test_announce_is_idempotent(routes):
    rec = _announce_record("bbs.a", 1, _rid(1))
    routes.apply_route_announce(rec)
    routes.apply_route_announce(rec)
    assert routes.get_route("bbs.a")["announced_seq"] == 1


def test_malformed_announce_marked_applied_but_not_projected(routes):
    bad = Record(
        origin="bbs.a",
        origin_seq=1,
        event_id=_rid(9),
        kind=KIND_ROUTE_ANNOUNCE,
        actor_pubkey=ACTOR_PUB,
        metadata=MetadataMap([metadata_text(1, "only-hostname")]),
        created_at=0,
    )
    routes.apply_route_announce(bad)
    assert routes.get_route("bbs.a") is None
    assert routes.is_applied("bbs.a", _rid(9))
    assert routes.get_checkpoint("bbs.a") == 1


def test_withdraw_tombstones_and_reannounce_revives(routes):
    routes.apply_route_announce(_announce_record("bbs.a", 1, _rid(1)))
    routes.apply_route_withdraw(_withdraw_record("bbs.a", 2, _rid(2), "bbs.a", _rid(1)))
    assert routes.get_route("bbs.a") is None
    tomb = routes.get_route("bbs.a", include_withdrawn=True)
    assert tomb is not None and tomb["withdrawn"] is True
    assert routes.list_routes() == []
    assert len(routes.list_routes(include_withdrawn=True)) == 1
    # Second withdraw is a success no-op.
    routes.apply_route_withdraw(_withdraw_record("bbs.a", 3, _rid(3), "bbs.a", _rid(1)))
    assert routes.get_route("bbs.a") is None
    # Later announce revives.
    routes.apply_route_announce(_announce_record("bbs.a", 4, _rid(4), hostname="back.example"))
    row = routes.get_route("bbs.a")
    assert row["hostname"] == "back.example" and row["withdrawn"] is False


def test_withdraw_unknown_event_and_cross_origin_are_noops(routes):
    routes.apply_route_announce(_announce_record("bbs.a", 1, _rid(1)))
    # Unknown event ID: no-op but marked applied.
    routes.apply_route_withdraw(_withdraw_record("bbs.a", 2, _rid(2), "bbs.a", _rid(99)))
    assert routes.get_route("bbs.a") is not None
    assert routes.is_applied("bbs.a", _rid(2))
    # Another origin cannot withdraw bbs.a's route.
    routes.apply_route_withdraw(_withdraw_record("bbs.evil", 1, _rid(3), "bbs.a", _rid(1)))
    assert routes.get_route("bbs.a") is not None


def test_clear_origin_isolates(routes):
    routes.apply_route_announce(_announce_record("bbs.a", 1, _rid(1)))
    routes.apply_route_announce(_announce_record("bbs.b", 1, _rid(2)))
    routes.clear_origin("bbs.a")
    assert routes.get_route("bbs.a") is None
    assert routes.get_route("bbs.b") is not None


def test_list_live_routes_priority_order(routes):
    routes.apply_route_announce(_announce_record("bbs.b", 1, _rid(1), priority=1))
    routes.apply_route_announce(_announce_record("bbs.a", 1, _rid(2), priority=9))
    live = routes.list_live_routes()
    assert [r["origin"] for r in live] == ["bbs.a", "bbs.b"]


# ---------------------------------------------------------------------------
# Dispatcher integration
# ---------------------------------------------------------------------------


def _stack(tmp_path, with_routes=True):
    firehose = FirehoseStore(str(tmp_path / "events.db"))
    firehose.init_origin_key("bbs.a", ORIGIN_A_PUB)
    nav = NavProjection(str(tmp_path / "nav.db"))
    users = UserProjection(str(tmp_path / "users.db"))
    policy = PolicyProjection(str(tmp_path / "policy.db"))
    bs = BodyStore(
        boards_dir=str(tmp_path / "boards"),
        events_dir=str(tmp_path / "event_bodies"),
    )
    route_proj = RouteProjection(str(tmp_path / "routes.db")) if with_routes else None
    d = Dispatcher(
        firehose=firehose,
        nav=nav,
        users=users,
        policy=policy,
        boards_dir=str(tmp_path / "boards"),
        body_store=bs,
        allowed_origins={"bbs.a"},
        local_origin="bbs.a",
        routes=route_proj,
    )
    return d, firehose, nav, users, policy, bs, route_proj


def _append(firehose, origin_identity, intent, body=b""):
    sig = sign_intent(ACTOR, encode_intent(intent))
    return firehose.append_record(origin_identity, intent, sig, body)


def test_dispatcher_projects_routes_and_rebuild_replays(tmp_path):
    d, firehose, nav, users, policy, bs, route_proj = _stack(tmp_path)
    try:
        _append(firehose, ORIGIN_A, _announce_intent("bbs.a", _rid(1)))
        assert d.dispatch_origin("bbs.a") == 1
        assert route_proj.get_route("bbs.a")["hostname"] == "c.example"
        count = d.rebuild_all("bbs.a")
        assert count == 1
        assert route_proj.get_route("bbs.a")["hostname"] == "c.example"
    finally:
        d.close()
        for proj in (nav, users, policy, route_proj):
            proj.close()
        firehose.close()


def test_dispatcher_without_routes_tracks_as_unknown(tmp_path):
    d, firehose, nav, users, policy, bs, _ = _stack(tmp_path, with_routes=False)
    try:
        _append(firehose, ORIGIN_A, _announce_intent("bbs.a", _rid(1)))
        assert d.dispatch_origin("bbs.a") == 1
    finally:
        d.close()
        for proj in (nav, users, policy):
            proj.close()
        firehose.close()


# ---------------------------------------------------------------------------
# Sync manager learner
# ---------------------------------------------------------------------------


def _route(hostname="127.0.0.1", port=2272, scheme="http", verify_tls=False):
    return {
        "origin": "bbs.c",
        "hostname": hostname,
        "port": port,
        "scheme": scheme,
        "verify_tls": verify_tls,
        "priority": 0,
        "endpoint": f"{scheme}://{hostname}:{port}",
    }


def _manager(tmp_path, **kw):
    firehose = FirehoseStore(str(tmp_path / "events.db"))
    m = SyncManager(firehose, ORIGIN_A, "bbs.a", relay_origin="bbs.a")
    params = {
        "auto_dial": "trusted-peers-only",
        "trusted_vias": {"bbs.b"},
        "allow_private_learned": True,
        "max_learned": 32,
        "interval": 300,
    }
    params.update(kw)
    m.set_routing(None, **params)
    return m, firehose


def test_learn_refused_when_disabled(tmp_path):
    m, _ = _manager(tmp_path, auto_dial="off")
    ok, reason = m.learn_transitive_route("bbs.c", _route(), "bbs.b")
    assert ok is False and "disabled" in reason


def test_learn_refused_via_untrusted(tmp_path):
    m, _ = _manager(tmp_path)
    ok, reason = m.learn_transitive_route("bbs.c", _route(), "bbs.evil")
    assert ok is False and "not trusted" in reason


def test_learn_refused_for_self(tmp_path):
    m, _ = _manager(tmp_path)
    ok, _ = m.learn_transitive_route("bbs.a", _route(), "bbs.b")
    assert ok is False


def test_learn_refused_when_cap_reached(tmp_path):
    m, _ = _manager(tmp_path, max_learned=0)
    ok, reason = m.learn_transitive_route("bbs.c", _route(), "bbs.b")
    assert ok is False and "cap" in reason


def test_learn_refused_for_unsafe_target(tmp_path):
    m, _ = _manager(tmp_path, allow_private_learned=False)
    ok, reason = m.learn_transitive_route("bbs.c", _route(hostname=""), "bbs.b")
    assert ok is False and "unsafe" in reason


async def test_learn_starts_sync_and_second_learn_refused(tmp_path):
    m, _ = _manager(tmp_path)
    try:
        ok, base = m.learn_transitive_route("bbs.c", _route(), "bbs.b")
        assert ok is True and base == "http://127.0.0.1:2272"
        ok2, reason2 = m.learn_transitive_route("bbs.c", _route(), "bbs.b")
        assert ok2 is False and "already syncing" in reason2
    finally:
        m.stop_origin("bbs.c")
        await m.stop_all()


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def test_parse_routing_defaults():
    cfg = _parse_routing({})
    assert cfg.auto_dial == "off"
    assert cfg.route_trust == []
    assert cfg.allow_private_learned is False
    assert cfg.max_learned == 32


def test_parse_routing_values():
    cfg = _parse_routing(
        {
            "auto_dial": "trusted-peers-only",
            "route_trust": ["BBS.B"],
            "allow_private_learned": True,
            "max_learned": 4,
        }
    )
    assert cfg.auto_dial == "trusted-peers-only"
    assert cfg.route_trust == ["bbs.b"]
    assert cfg.allow_private_learned is True
    assert cfg.max_learned == 4


def test_parse_routing_rejects_bad_auto_dial():
    with pytest.raises(ValueError, match="auto_dial"):
        _parse_routing({"auto_dial": "yolo"})


def test_config_defaults_routing_off():
    c = FirehoseConfig()
    assert isinstance(c.routing, RoutingConfig)
    assert c.routing.auto_dial == "off"
    c.validate()


def test_load_config_with_routing(tmp_path):
    path = str(tmp_path / "config.toml")
    with open(path, "w", encoding="utf-8") as f:
        f.write(
            '[server]\norigin = "bbs.test"\n\n'
            '[routing]\nauto_dial = "trusted-peers-only"\n'
            'route_trust = ["bbs.b"]\nallow_private_learned = true\nmax_learned = 4\n'
        )
    c = FirehoseConfig.load(path)
    c.validate()
    assert c.unknown_keys == []
    assert c.routing.auto_dial == "trusted-peers-only"
    assert c.routing.route_trust == ["bbs.b"]
    assert c.routing.allow_private_learned is True
    assert c.routing.max_learned == 4


def test_default_acl_does_not_grant_route_kinds(tmp_path):
    path = str(tmp_path / "config.toml")
    FirehoseConfig._write_default(path)
    c = FirehoseConfig.load(path)
    c.validate()
    assert c.unknown_keys == []
    assert c.routing.auto_dial == "off"
