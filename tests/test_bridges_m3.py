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

"""Bridges milestone M3: learning bridge origins from peers' manifests (design doc §13).

A peer's `bridges` section is advisory, like a learned route, unless routing
is `trusted-peers-only` and the peer is trusted. Adopted origins are
recognized after the configured ones, become readable, and are dialed only
through a live learned route.
"""

from __future__ import annotations

import httpx
import pytest

from bonnet.bridges.config import BridgesEntry
from bonnet.core.config import PeerConfig, RoutingConfig
from bonnet.net.firehose_sync import SyncClient
from bonnet.net.firehose_transport import FirehoseTransport
from bonnet.net.firehose_wire import build_article_list, parse_article_list_response
from tests.bridge_fakes import FLATBOARD_VENUE, make_config, read, sync_from
from tests.test_bridges_m2 import B1, B2, BOARD, Scenario

H2 = "far.test"
HOME = "home.test"


class _Advertising(SyncClient):
    """A connected peer whose discovery document carried `entries`."""

    def __init__(self, entries):
        self._entries = entries

    def discovered_bridges(self):
        return self._entries


def _advert(*origins, venue=FLATBOARD_VENUE):
    return [{"type": "flatboard", "venue": venue, "board": BOARD, "origins": list(origins)}]


def _far(tmp_path, auto_dial="trusted-peers-only", bridges=(), route_trust=()):
    """A server peering only with home.test, which advertises bridges to it."""
    from bonnet.app.server import BonnetServer

    config = make_config(
        tmp_path,
        H2,
        peers=[PeerConfig(origin=HOME, hostname=HOME)],
        routing=RoutingConfig(auto_dial=auto_dial, route_trust=list(route_trust)),
        bridges=list(bridges),
    )
    return BonnetServer(config)


class _Syncing:
    """Pretend `origins` already have sync clients (as configured or learned peers would)."""

    def __init__(self, server, *origins):
        for o in origins:
            server.sync_manager._clients[o] = object()


@pytest.fixture
def far(tmp_path):
    server = _far(tmp_path)
    yield server
    server.close()


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


async def test_advisory_when_auto_dial_is_off(tmp_path):
    server = _far(tmp_path, auto_dial="off")
    try:
        _Syncing(server, B1)
        server.sync_manager._maybe_adopt_bridges(HOME, _Advertising(_advert(B1)))
        assert server.command_handler.recognized_origins(FLATBOARD_VENUE) == []
        assert B1 not in server.allowed_origins
    finally:
        server.close()


async def test_advisory_when_carried_by_an_untrusted_origin(far):
    _Syncing(far, B1)
    far.sync_manager._maybe_adopt_bridges("stranger.test", _Advertising(_advert(B1)))
    assert far.command_handler.recognized_origins(FLATBOARD_VENUE) == []


async def test_route_trust_counts_as_trusted(tmp_path):
    server = _far(tmp_path, route_trust=["friend.test"])
    try:
        _Syncing(server, B1)
        server.sync_manager._maybe_adopt_bridges("friend.test", _Advertising(_advert(B1)))
        assert server.command_handler.recognized_origins(FLATBOARD_VENUE) == [B1]
    finally:
        server.close()


async def test_trusted_peer_adoption_of_origins_already_syncing(far):
    _Syncing(far, B1, B2)
    far.sync_manager._maybe_adopt_bridges(HOME, _Advertising(_advert(B1, B2)))
    assert far.command_handler.recognized_origins(FLATBOARD_VENUE) == [B1, B2]
    assert {B1, B2} <= far.allowed_origins
    assert far.bridge_adopter.adopted == {(FLATBOARD_VENUE, B1): HOME, (FLATBOARD_VENUE, B2): HOME}


async def test_no_route_means_advisory(far):
    far.sync_manager._maybe_adopt_bridges(HOME, _Advertising(_advert(B1)))
    assert far.command_handler.recognized_origins(FLATBOARD_VENUE) == []
    assert B1 not in far.allowed_origins


async def test_a_live_route_is_dialed_under_the_route_guards(far, monkeypatch):
    route = {"origin": B1, "hostname": "b1.example", "port": 443, "scheme": "https"}
    monkeypatch.setattr(far.routes, "get_route", lambda o: route if o == B1 else None)
    calls = []

    def learn(origin, r, via):
        calls.append((origin, r, via))
        return True, "https://b1.example:443"

    monkeypatch.setattr(far.sync_manager, "learn_transitive_route", learn)
    far.sync_manager._maybe_adopt_bridges(HOME, _Advertising(_advert(B1)))
    assert calls == [(B1, route, HOME)]
    assert far.command_handler.recognized_origins(FLATBOARD_VENUE) == [B1]


async def test_a_refused_dial_stays_advisory(far, monkeypatch):
    monkeypatch.setattr(far.routes, "get_route", lambda o: {"origin": o})
    monkeypatch.setattr(
        far.sync_manager, "learn_transitive_route", lambda *a: (False, "learned-route cap reached")
    )
    far.sync_manager._maybe_adopt_bridges(HOME, _Advertising(_advert(B1)))
    assert far.command_handler.recognized_origins(FLATBOARD_VENUE) == []


async def test_adopted_origins_follow_configured_ones(tmp_path):
    server = _far(tmp_path, bridges=[BridgesEntry("flatboard", FLATBOARD_VENUE, [B2])])
    try:
        _Syncing(server, B1, B2)
        server.sync_manager._maybe_adopt_bridges(HOME, _Advertising(_advert(B1, B2)))
        assert server.command_handler.recognized_origins(FLATBOARD_VENUE) == [B2, B1]
    finally:
        server.close()


async def test_self_and_malformed_entries_are_ignored(far):
    _Syncing(far, B1)
    far.sync_manager._maybe_adopt_bridges(
        HOME,
        _Advertising(
            [
                {"venue": "no-at-sign", "origins": [B1]},
                {"venue": FLATBOARD_VENUE, "origins": "not-a-list"},
                {"venue": FLATBOARD_VENUE, "origins": [H2, 7, ""]},
            ]
        ),
    )
    assert far.command_handler.recognized_origins(FLATBOARD_VENUE) == []


async def test_a_failing_adopter_never_breaks_sync(far):
    def boom(via, entries):
        raise RuntimeError("adopter bug")

    far.sync_manager.set_bridge_adopter(boom)
    far.sync_manager._maybe_adopt_bridges(HOME, _Advertising(_advert(B1)))  # no raise


# ---------------------------------------------------------------------------
# End to end: learned origins dedup like configured ones
# ---------------------------------------------------------------------------


async def test_learned_bridges_dedup_aggregate_reads(tmp_path):
    sc = Scenario(tmp_path)
    await sc.build()  # home.test recognizes [B1, B2] by config
    far = _far(tmp_path)
    try:
        # home.test's real discovery document, as far.test's sync client sees it.
        t = FirehoseTransport(
            f"https://{HOME}", verify=False, trust_store_path=str(tmp_path / "t.db")
        )
        t._http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=sc.home.http_server), base_url=f"https://{HOME}"
        )
        info = await t.discover()
        await t._http.aclose()
        assert info.bridges[0]["origins"] == [B1, B2]

        _Syncing(far, B1, B2)  # e.g. dialed through learned routes
        far.sync_manager._maybe_adopt_bridges(HOME, _Advertising(info.bridges))
        await sync_from(far, sc.b1.server)
        await sync_from(far, sc.b2.server)

        resp = await read(far, build_article_list("", BOARD, 0, 100))
        rows = parse_article_list_response(resp, aggregate=True).results
        assert len(rows) == 5 and {r.origin for r in rows} == {B1}
        (entry,) = far.command_handler.bridges_manifest()
        assert entry["origins"] == [B1, B2]

        doc = far.http_server
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=doc), base_url=f"https://{H2}")
        known = (await client.get("/.well-known/untp")).json()["known_origins"]
        await client.aclose()
        assert {B1, B2} <= set(known)
    finally:
        far.close()
        await sc.close()


def test_old_discovery_documents_parse_without_bridges():
    from bonnet.net.firehose_models import DiscoveryInfo

    info = DiscoveryInfo(
        protocol="untp",
        origin="o",
        hostname="o",
        public_key="",
        anonymous_key="",
        anonymous_private_key="",
        command_endpoint="/command",
        capabilities=[],
    )
    assert info.bridges == []


def test_unsynced_entries_are_never_adopted():
    from types import SimpleNamespace

    from bonnet.bridges.adoption import BridgeAdopter

    recognized = []
    server = SimpleNamespace(
        sync_manager=SimpleNamespace(routing_policy=("trusted-peers-only", {HOME})),
        command_handler=SimpleNamespace(
            recognized_origins=lambda venue: [],
            recognize_bridge_origin=lambda *a: recognized.append(a),
        ),
        config=SimpleNamespace(origin=H2),
    )
    entry = {"venue": FLATBOARD_VENUE, "status": "unsynced", "board": None, "origins": [B1]}
    BridgeAdopter(server)(HOME, [entry])
    assert recognized == []
