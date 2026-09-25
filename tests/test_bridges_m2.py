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

"""Bridges milestone M2: bridges.db and one canonical copy per post (design doc §13).

The milestone's scenario, with real servers: two bridge origins mirror the
same fake flatboard, the second started after the venue evicted the thread
root. A third server peering with both shows each foreign post once in
aggregate reads, including replies whose parent only one bridge holds, and
every copy in per-origin reads.
"""

from __future__ import annotations

import os

import pytest

from bonnet.bridges.config import BridgesEntry, parse_bridges, recognized_bridges
from bonnet.bridges.model import SourceKey, src_tag
from bonnet.bridges.runtime import BridgeRuntime
from bonnet.core.config import PeerConfig
from bonnet.core.kinds import KIND_ARTICLE_CANCEL
from bonnet.core.record import Intent, MetadataMap
from bonnet.core.record import normalize_origin as _norm
from bonnet.net.firehose_wire import (
    ProtocolError,
    build_article_list,
    build_article_query,
    build_article_search,
    parse_article_list_response,
    parse_article_query_response,
    parse_article_search_response,
)
from tests.bridge_fakes import (
    FLATBOARD_VENUE,
    FakeFlatboard,
    make_config,
    read,
    runtime_config,
    sync_from,
    venue_config,
)

B1 = "bridge-one.test"
B2 = "bridge-two.test"
HOME = "home.test"
BOARD = "~flatboard"
NOW = 1_800_000_000


class _Clock:
    def __call__(self):
        return NOW


class Bridge:
    def __init__(self, tmp_path, origin: str, board: FakeFlatboard):
        from bonnet.app.server import BonnetServer

        rt = runtime_config(tmp_path / origin, [venue_config()])
        self.origin = origin
        self.server = BonnetServer(make_config(tmp_path, origin, rt))
        self.runtime = BridgeRuntime(self.server, adapter_factory=board.adapter, clock=_Clock())

    async def ingest(self):
        await self.runtime.setup()
        venue = self.runtime.venues[0]
        return await self.runtime.ingest_binding(venue, venue.config.bindings[0])

    async def close(self):
        await self.runtime.close()
        self.server.close()


def _home(tmp_path, order: list[str]):
    from bonnet.app.server import BonnetServer

    config = make_config(
        tmp_path,
        HOME,
        peers=[PeerConfig(origin=B1, hostname=B1), PeerConfig(origin=B2, hostname=B2)],
        bridges=[BridgesEntry(type="flatboard", venue=FLATBOARD_VENUE, origins=order)],
    )
    return BonnetServer(config)


class Scenario:
    """Flatboard thread 1 ← 2 ← 3, reply 5 → 1, and a separate post 4.

    B1 sees everything. B2 starts after the venue evicted post 1, so its
    copies of 2, 3 and 5 can't state a root; they join thread 1 through B1's
    copies of the same posts.
    """

    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.venue = FakeFlatboard()
        self.b1 = Bridge(tmp_path, B1, self.venue)
        self.b2 = Bridge(tmp_path, B2, self.venue)
        self.home = None

    async def build(self, order=(B1, B2)):
        v = self.venue
        self.p1 = v.post("thread root", created=NOW - 900)
        self.p2 = v.post("first reply", author="lanternfly", reply_to=self.p1, created=NOW - 800)
        self.p3 = v.post("reply to reply", reply_to=self.p2, created=NOW - 700)
        self.p4 = v.post("separate post", author="moxxie", created=NOW - 600)
        await self.b1.ingest()
        v.evict_below(self.p2)
        self.p5 = v.post("late reply to root", reply_to=self.p1, created=NOW - 500)
        await self.b2.ingest()
        await self.b1.ingest()
        self.home = _home(self.tmp_path, list(order))
        await self.sync()
        return self

    async def sync(self):
        await sync_from(self.home, self.b1.server)
        await sync_from(self.home, self.b2.server)

    async def close(self):
        await self.b1.close()
        await self.b2.close()
        if self.home is not None:
            self.home.close()

    async def aggregate(self, offset=0, limit=100, server=None):
        resp = await read(server or self.home, build_article_list("", BOARD, offset, limit))
        return parse_article_list_response(resp, aggregate=True).results

    async def per_origin(self, origin, server=None):
        resp = await read(server or self.home, build_article_list(origin, BOARD, 0, 100))
        return parse_article_list_response(resp).results

    def foreign_id(self, origin, item) -> str:
        c = self.home.bridges.copy_by_event(origin, bytes.fromhex(item.event_id))
        return c.src.foreign_id


async def _sysop_publish(server, identity, intent):
    import asyncio

    from bonnet.core.record import encode_intent, sign_intent
    from bonnet.net.firehose_commands import derive_context
    from bonnet.net.firehose_wire import build_publish_record, parse_publish_response

    frame = build_publish_record(intent, sign_intent(identity, encode_intent(intent)), b"")
    ctx = derive_context(
        server.users,
        server.config.origin,
        identity.public_key,
        "test",
        server.anonymous_identity.public_key,
    )
    return parse_publish_response(
        await asyncio.to_thread(server.command_handler.handle, frame, ctx)
    )


@pytest.fixture
async def s(tmp_path):
    sc = Scenario(tmp_path)
    await sc.build()
    yield sc
    await sc.close()


def _shown(sc: Scenario, rows) -> dict[str, str]:
    return {sc.foreign_id(r.origin, r): r.origin for r in rows}


# ---------------------------------------------------------------------------
# The M2 scenario
# ---------------------------------------------------------------------------


async def test_aggregate_shows_each_post_once(s):
    rows = await s.aggregate()
    shown = _shown(s, rows)
    assert len(rows) == 5
    assert shown == {str(i): B1 for i in (s.p1, s.p2, s.p3, s.p4, s.p5)}


async def test_per_origin_reads_show_every_copy(s):
    assert len(await s.per_origin(B1)) == 5
    b2 = await s.per_origin(B2)
    assert {s.foreign_id(B2, r) for r in b2} == {str(i) for i in (s.p2, s.p3, s.p4, s.p5)}


async def test_b2_copies_join_the_thread_through_b1(s):
    root, conflict = s.home.bridges.thread_root(SourceKey(FLATBOARD_VENUE, "", str(s.p3)))
    assert (root, conflict) == (str(s.p1), False)
    b2_copy = s.home.bridges.copies_of(SourceKey(FLATBOARD_VENUE, "", str(s.p5)))
    assert {c.origin: c.root_foreign_id for c in b2_copy} == {B1: str(s.p1), B2: None}


async def test_the_thread_stays_with_the_origin_holding_its_root(tmp_path):
    sc = Scenario(tmp_path)
    await sc.build(order=(B2, B1))
    try:
        shown = _shown(sc, await sc.aggregate())
        # Thread 1: only B1 holds the root, so it keeps the whole thread even
        # though B2 is preferred. Post 4 is its own thread: B2 wins it.
        assert shown == {
            str(sc.p1): B1,
            str(sc.p2): B1,
            str(sc.p3): B1,
            str(sc.p5): B1,
            str(sc.p4): B2,
        }
    finally:
        await sc.close()


async def test_paging_is_complete_and_duplicate_free(s):
    everything = await s.aggregate()
    paged = []
    for offset in range(0, 6, 2):
        paged.extend(await s.aggregate(offset=offset, limit=2))
    assert [(r.origin, r.event_id) for r in paged] == [(r.origin, r.event_id) for r in everything]
    # B2 ingested last, so its rows are the newest; every one of them is
    # skipped and the first page still fills.
    first = await s.aggregate(limit=2)
    assert len(first) == 2 and all(r.origin == B1 for r in first)


async def test_cancelled_canonical_copy_falls_back_to_the_next_origin(s):
    b1 = s.b1.server
    copy = s.home.bridges.copies_of(SourceKey(FLATBOARD_VENUE, "", str(s.p4)))
    b1_copy = next(c for c in copy if c.origin == B1)
    # A sysop acting by hand, not the runtime: the runtime's guard refuses cancels.
    root = b1.server_identity
    await _sysop_publish(
        b1,
        root,
        Intent(
            event_id=os.urandom(32),
            kind=KIND_ARTICLE_CANCEL,
            origin=B1,
            actor_pubkey=root.public_key,
            actor_username="root",
            actor_registrar=B1,
            target_origin=B1,
            target_board=BOARD,
            target_article_id=b1_copy.article_id,
            metadata=MetadataMap(),
        ),
    )
    await s.sync()
    shown = _shown(s, await s.aggregate())
    assert shown[str(s.p4)] == B2
    assert len(shown) == 5


async def test_copies_that_disagree_on_digest_both_show(s):
    six = s.venue.post("the honest text", created=NOW - 400)
    await s.b1.ingest()
    s.venue.messages[six]["text"] = "altered text"
    await s.b2.ingest()
    await s.sync()
    rows = [r for r in await s.aggregate() if s.foreign_id(r.origin, r) == str(six)]
    assert {r.origin for r in rows} == {B1, B2}


def _register_crossposter(server, name: str = "mallory"):
    """A key admitted on a bridge origin, registered the way admission does it."""
    from bonnet.bridges import model
    from bonnet.core.crypto import Identity
    from bonnet.core.kinds import KIND_USER_REGISTER
    from bonnet.core.record import (
        encode_intent,
        metadata_bytes,
        metadata_text,
        metadata_u64,
        sign_intent,
    )

    key = Identity.generate()
    root = server.server_identity
    origin = server.config.origin
    reg = Intent(
        event_id=os.urandom(32),
        kind=KIND_USER_REGISTER,
        origin=origin,
        actor_pubkey=root.public_key,
        actor_registrar=origin,
        metadata=MetadataMap(
            [
                metadata_text(1, name),
                metadata_bytes(2, key.public_key),
                metadata_u64(3, 0),
                metadata_text(model.F_HOME_ORIGIN, HOME),
                metadata_text(model.F_HOME_URL, f"https://{HOME}"),
            ]
        ),
    )
    server.firehose.append_record(root, reg, sign_intent(root, encode_intent(reg)), b"")
    server.dispatcher.dispatch_origin(origin)
    return key


def _forged_copy(server, key, name, src, role, digest):
    """An article claiming to be a copy of `src`, with a lowest-possible event id."""
    from bonnet.bridges import model
    from bonnet.core.record import compute_body_hash, metadata_text, metadata_text_list

    body = b"FORGED TEXT"
    meta = model.BridgeMetadata(
        bridge_role=role,
        venue=src.venue,
        channel=src.channel,
        foreign_id=src.foreign_id,
        foreign_author="moxxie",
        foreign_root_id=src.foreign_id,
        foreign_digest=digest,
        home_origin=HOME,
        home_url=f"https://{HOME}",
    )
    fields = [
        metadata_text(1, "separate post"),
        metadata_text_list(2, model.bridge_tags("flatboard", src)),
        metadata_text(4, "text/plain"),
    ]
    intent = Intent(
        event_id=b"\x00" * 31 + b"\x01",
        kind="bonnet.article",
        origin=server.config.origin,
        actor_pubkey=key.public_key,
        actor_username=name,
        actor_registrar=server.config.origin,
        board=BOARD,
        article_id=os.urandom(32),
        metadata=model.merge_metadata(MetadataMap(fields), meta.to_fields()),
        body_hash=compute_body_hash(body),
        body_size=len(body),
    )
    return intent, body


async def _shown_for(s, foreign_id):
    """Aggregate rows that are copies of `foreign_id` (ordinary rows skipped)."""
    out = []
    for r in await s.aggregate():
        c = s.home.bridges.copy_by_event(r.origin, bytes.fromhex(r.event_id))
        if c is not None and c.src.foreign_id == str(foreign_id):
            out.append(r)
    return out


async def test_only_the_runtime_may_publish_a_mirror(s):
    from bonnet.bridges import model
    from tests.bridge_fakes import publish_as

    srv = s.b1.server
    key = _register_crossposter(srv)
    src = SourceKey(FLATBOARD_VENUE, "", str(s.p4))
    real = srv.bridges.copies_of(src)[0]
    intent, body = _forged_copy(srv, key, "mallory", src, model.ROLE_MIRROR, real.digest)
    with pytest.raises(ProtocolError, match="Only the bridge runtime may publish mirrors"):
        await publish_as(srv, key, intent, body)


async def test_an_unobserved_crosspost_hides_nothing(s):
    from bonnet.bridges import model
    from tests.bridge_fakes import publish_as

    srv = s.b1.server
    key = _register_crossposter(srv)
    src = SourceKey(FLATBOARD_VENUE, "", str(s.p4))
    real = srv.bridges.copies_of(src)[0]
    intent, body = _forged_copy(srv, key, "mallory", src, model.ROLE_CROSSPOST, real.digest)
    await publish_as(srv, key, intent, body)
    await s.sync()
    shown = {r.event_id for r in await _shown_for(s, s.p4)}
    # The real mirror stays; the claim shows as the ordinary article it is.
    assert real.event_id.hex() in shown


async def test_a_mirror_by_anyone_but_a_puppet_is_not_a_copy(s):
    from bonnet.bridges import model
    from bonnet.core.record import encode_intent, sign_intent

    # An origin that doesn't enforce the publish check: appended straight
    # to its log, then synced like any record.
    srv = s.b1.server
    key = _register_crossposter(srv)
    src = SourceKey(FLATBOARD_VENUE, "", str(s.p4))
    real = srv.bridges.copies_of(src)[0]
    intent, body = _forged_copy(srv, key, "mallory", src, model.ROLE_MIRROR, real.digest)
    root = srv.server_identity
    srv.firehose.append_record(root, intent, sign_intent(key, encode_intent(intent)), body)
    srv.dispatcher.dispatch_origin(B1)
    await s.sync()
    assert s.home.bridges.copy_by_event(B1, intent.event_id) is None
    shown = [r.event_id for r in await _shown_for(s, s.p4)]
    assert shown == [real.event_id.hex()]


async def test_unrecognized_origins_are_never_deduplicated(tmp_path):
    sc = Scenario(tmp_path)
    await sc.build(order=(B1,))
    try:
        rows = await sc.aggregate()
        assert len(rows) == 9  # 5 from B1 + 4 from B2
    finally:
        await sc.close()


async def test_a_bridge_dedups_its_own_board_against_nothing(s):
    # B1 knows only itself: its aggregate read is just its own copies.
    rows = await s.aggregate(server=s.b1.server)
    assert len(rows) == 5 and {r.origin for r in rows} == {B1}


async def test_aggregate_search_counts_survivors(s):
    resp = await read(s.home, build_article_search("", BOARD, meta_query="flatboard", limit=3))
    result = parse_article_search_response(resp, aggregate=True)
    assert result.total == 5
    assert len(result.results) == 3
    resp = await read(s.home, build_article_search("", BOARD, meta_query="flatboard", offset=3))
    rest = parse_article_search_response(resp, aggregate=True)
    ids = {(r.origin, r.article_id) for r in result.results + rest.results}
    assert len(ids) == 5 and {o for o, _ in ids} == {B1}


async def test_non_tilde_boards_are_untouched(s):
    # The existing merge path, byte for byte: nothing to dedup outside '~'.
    resp = await read(s.home, build_article_list("", "general", 0, 10))
    assert parse_article_list_response(resp, aggregate=True).results == []


# ---------------------------------------------------------------------------
# Queries (§9.5)
# ---------------------------------------------------------------------------


def _src_value(foreign_id) -> str:
    return src_tag(SourceKey(FLATBOARD_VENUE, "", str(foreign_id)))[len("src:") :]


async def _query(server, origin, filters):
    resp = await read(server, build_article_query(origin, BOARD, filters))
    return parse_article_query_response(resp).results


async def test_query_by_src_and_root(s):
    (hit,) = await _query(s.home, B2, [(0x0B, 0x01, 0x02, _src_value(s.p3))])
    assert s.foreign_id(B2, hit) == str(s.p3)

    both = await _query(s.home, B1, [(0x0B, 0x06, 0x02, f"{_src_value(s.p1)},{_src_value(s.p4)}")])
    assert {s.foreign_id(B1, r) for r in both} == {str(s.p1), str(s.p4)}

    thread_b1 = await _query(s.home, B1, [(0x0C, 0x01, 0x02, _src_value(s.p1))])
    assert {s.foreign_id(B1, r) for r in thread_b1} == {str(i) for i in (s.p1, s.p2, s.p3, s.p5)}
    # B2 never stated a root, yet its copies are in thread 1 through B1's.
    thread_b2 = await _query(s.home, B2, [(0x0C, 0x01, 0x02, _src_value(s.p1))])
    assert {s.foreign_id(B2, r) for r in thread_b2} == {str(i) for i in (s.p2, s.p3, s.p5)}

    assert await _query(s.home, B1, [(0x0B, 0x01, 0x02, _src_value(999))]) == []


@pytest.mark.parametrize(
    "flt",
    [(0x0B, 0x05, 0x02, "x##1"), (0x0B, 0x01, 0x02, "no-hashes"), (0x0C, 0x06, 0x02, "a##1")],
)
async def test_bad_bridge_filters_are_errors(s, flt):
    resp = await read(s.home, build_article_query(B1, BOARD, [flt]))
    with pytest.raises(ProtocolError) as e:
        parse_article_query_response(resp)
    assert e.value.code == 0x0006


async def _query_all(sc, filters, offset=0, limit=100):
    resp = await read(sc.home, build_article_query("", BOARD, filters, offset, limit))
    return parse_article_query_response(resp, aggregate=True).results


async def test_aggregate_query_shows_each_post_once_with_its_origin(s):
    """origin="" used to answer nothing; a homeserver asked about a board
    only peers hold showed it empty. It now queries every origin holding
    the board and, on a `~` board, keeps one canonical copy per post."""
    rows = await _query_all(s, [])
    assert _shown(s, rows) == {str(i): B1 for i in (s.p1, s.p2, s.p3, s.p4, s.p5)}
    assert all(r.origin == B1 for r in rows)


async def test_aggregate_query_merges_origins_into_one_order(tmp_path):
    """Both bridges preferred for different threads (see the test above), so
    the canonical copies come from two origins; they interleave by created_at
    rather than one origin's matches following the other's."""
    sc = Scenario(tmp_path)
    await sc.build(order=(B2, B1))
    try:
        for newest_first in (True, False):
            resp = await read(
                sc.home, build_article_query("", BOARD, [], 0, 100, newest_first=newest_first)
            )
            rows = parse_article_query_response(resp, aggregate=True).results
            assert {r.origin for r in rows} == {B1, B2}
            keys = [(r.created_at, r.origin, r.article_num) for r in rows]
            assert keys == sorted(keys, reverse=newest_first)
    finally:
        await sc.close()


async def test_aggregate_query_pages_completely(s):
    everything = await _query_all(s, [])
    paged = []
    for offset in range(0, 6, 2):
        paged.extend(await _query_all(s, [], offset=offset, limit=2))
    assert [(r.origin, r.event_id) for r in paged] == [(r.origin, r.event_id) for r in everything]


async def test_aggregate_query_resolves_bridge_filters_per_origin(s):
    """A src filter names a foreign post, which is a different article id on
    each bridge origin: it has to be resolved against each one."""
    (hit,) = await _query_all(s, [(0x0B, 0x01, 0x02, _src_value(s.p4))])
    assert (hit.origin, s.foreign_id(hit.origin, hit)) == (B1, str(s.p4))


async def test_aggregate_query_of_an_unknown_board_is_empty(s):
    resp = await read(s.home, build_article_query("", "nowhere", []))
    assert parse_article_query_response(resp, aggregate=True).results == []


# ---------------------------------------------------------------------------
# Manifest (§10.1)
# ---------------------------------------------------------------------------


async def test_manifest_lists_synced_bindings_in_preference_order(s):
    (entry,) = s.home.command_handler.bridges_manifest()
    assert entry == {
        "type": "flatboard",
        "venue": FLATBOARD_VENUE,
        "status": "bound",
        "board": BOARD,
        "origins": [B1, B2],
        "local": False,
        "max_body_bytes": 262144,
    }
    assert "bonnet.bridge" in s.home.http_server._capabilities()


async def test_manifest_local_follows_the_live_runtime(s):
    handler = s.b1.server.command_handler
    (entry,) = handler.bridges_manifest()
    assert entry["origins"] == [B1] and entry["local"] is False
    handler.live_bridge_venues.add(FLATBOARD_VENUE)
    assert handler.bridges_manifest()[0]["local"] is True


async def test_manifest_says_what_it_recognizes_before_bindings_arrive(tmp_path):
    home = _home(tmp_path, [B1, B2])
    try:
        assert home.command_handler.bridges_manifest() == [
            {
                "type": "flatboard",
                "venue": FLATBOARD_VENUE,
                "status": "unsynced",
                "board": None,
                "origins": [B1, B2],
                "local": False,
            }
        ]
        # A diagnostic, not a bridge this server can serve.
        assert "bonnet.bridge" not in home.http_server._capabilities()
    finally:
        home.close()


async def test_manifest_says_whether_its_own_bindings_admit(s):
    handler = s.b1.server.command_handler
    assert handler.bridges_manifest()[0]["admission"] is False
    handler._admission = object()
    try:
        assert handler.bridges_manifest()[0]["admission"] is True
    finally:
        handler._admission = None
    # Another origin's admission policy isn't the home's to know.
    assert "admission" not in s.home.command_handler.bridges_manifest()[0]


async def test_manifest_is_served_in_discovery(s):
    import httpx

    t = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=s.home.http_server), base_url=f"https://{HOME}"
    )
    doc = (await t.get("/.well-known/untp")).json()
    await t.aclose()
    assert doc["bridges"][0]["origins"] == [B1, B2]
    assert "bonnet.bridge" in doc["capabilities"]


# ---------------------------------------------------------------------------
# bridges.db lifecycle
# ---------------------------------------------------------------------------


async def test_bridges_db_catches_up_after_being_lost(s):
    from bonnet.app.server import BonnetServer

    config = s.home.config
    s.home.close()
    os.remove(config.bridges_db_path)
    s.home = BonnetServer(config)
    assert len(await s.aggregate()) == 5


async def test_rebuild_all_replays_bridges_db(s):
    s.home.dispatcher.rebuild_all(B2)
    assert len(await s.aggregate()) == 5
    assert len(await s.per_origin(B2)) == 4


async def test_bindings_and_observations_are_recorded(s):
    bindings = s.home.bridges.active_bindings()
    assert {(b["origin"], b["board"]) for b in bindings} == {(B1, BOARD), (B2, BOARD)}
    obs = s.home.bridges._conn.execute(
        "SELECT origin, COUNT(*) FROM observations GROUP BY origin ORDER BY origin"
    ).fetchall()
    assert obs == [(B1, 5), (B2, 4)]


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def test_bridges_config_parses_and_validates():
    entries, unknown = parse_bridges(
        [{"type": "flatboard", "venue": FLATBOARD_VENUE, "origins": ["B.Test", "c.test"], "x": 1}],
        _norm,
    )
    assert entries == [BridgesEntry("flatboard", FLATBOARD_VENUE, ["b.test", "c.test"])]
    assert unknown == ["recognize[0].x"]
    for bad in (
        [{"type": "flatboard", "venue": FLATBOARD_VENUE, "origins": []}],
        [{"type": "flatboard", "venue": FLATBOARD_VENUE, "origins": ["a", "a"]}],
        [{"type": "flatboard", "venue": "nohost", "origins": ["a"]}],
        [{"type": "other", "venue": FLATBOARD_VENUE, "origins": ["a"]}],
        [{"type": "flatboard", "venue": FLATBOARD_VENUE, "origins": ["a"]}] * 2,
    ):
        with pytest.raises(ValueError):
            parse_bridges(bad, _norm)


def test_a_bridge_origin_recognizes_itself_first(tmp_path):
    rt = runtime_config(tmp_path, [venue_config()])
    config = make_config(
        tmp_path,
        B2,
        rt,
        bridges=[BridgesEntry("flatboard", FLATBOARD_VENUE, [B1])],
    )
    assert recognized_bridges(config) == {FLATBOARD_VENUE: [B2, B1]}
    config.bridges = [BridgesEntry("flatboard", FLATBOARD_VENUE, [B1, B2])]
    assert recognized_bridges(config) == {FLATBOARD_VENUE: [B1, B2]}


def test_unpeered_bridge_origins_warn(tmp_path):
    from bonnet.app.main import _bridges_warnings

    config = make_config(
        tmp_path,
        HOME,
        peers=[PeerConfig(origin=B1, hostname=B1)],
        bridges=[BridgesEntry("flatboard", FLATBOARD_VENUE, [B1, B2])],
    )
    (warning,) = _bridges_warnings(config)
    assert B2 in warning
