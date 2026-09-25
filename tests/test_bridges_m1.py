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

"""Bridges milestone M1: the read-only portal (design doc §13).

A real bridge origin (BonnetServer + BridgeRuntime) ingesting a fake
flatboard: config, reservations, bindings, puppets, mirrors and
observations, threading, grace and marker deferral, truncation, restarts
and index rebuilds, eviction, venue failures, startup ordering, and the CLI.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import textwrap
from importlib import metadata

import pytest

from bonnet.bridges import adapter as adapter_module
from bonnet.bridges import model
from bonnet.bridges.adapter import (
    AdapterNotFound,
    Gone,
    ReadLimiter,
    VenueError,
    load_adapter_class,
    missing_adapters,
)
from bonnet.bridges.adapters.flatboard import FlatboardAdapter
from bonnet.bridges.bindings import read_bindings
from bonnet.bridges.config import BindingConfig, VenueConfig, parse_bridge_runtime
from bonnet.bridges.local_publish import LocalPublisher
from bonnet.bridges.model import KIND_BRIDGE_BINDING, KIND_BRIDGE_UNBIND, BridgeMetadata, SourceKey
from bonnet.bridges.runtime import BridgeRuntime, mirror_subject, serve_bridge
from bonnet.core.config import FirehoseConfig
from bonnet.core.crypto import Identity
from bonnet.core.kinds import KIND_ARTICLE, KIND_BOARD_CREATE, KIND_USER_REGISTER
from bonnet.core.record import Intent, MetadataMap, metadata_bytes, metadata_text, metadata_u64
from bonnet.net.firehose_commands import derive_context
from bonnet.net.firehose_wire import ProtocolError, build_publish_record
from tests.bridge_fakes import (
    FLATBOARD_VENUE,
    FakeFlatboard,
    make_config,
    runtime_config,
    venue_config,
)

ORIGIN = "bridge.test"
BOARD = "~flatboard"
NOW = 1_800_000_000


class Clock:
    def __init__(self, t: float = NOW):
        self.t = t

    def __call__(self) -> float:
        return self.t


class Harness:
    """A bridge origin over a fake flatboard, restartable on the same disk."""

    def __init__(self, tmp_path, venues=None, **runtime_kw):
        self.tmp_path = tmp_path
        self.board = FakeFlatboard()
        self.clock = Clock()
        self.venues = venues or [venue_config()]
        self.runtime_kw = runtime_kw
        self.server = None
        self.runtime = None

    async def start(self, venues=None) -> BridgeRuntime:
        from bonnet.app.server import BonnetServer

        if venues is not None:
            self.venues = venues
        rt_cfg = runtime_config(self.tmp_path, self.venues, **self.runtime_kw)
        self.server = BonnetServer(make_config(self.tmp_path, ORIGIN, rt_cfg))
        self.runtime = BridgeRuntime(
            self.server, adapter_factory=self.board.adapter, clock=self.clock
        )
        await self.runtime.setup()
        return self.runtime

    async def stop(self):
        if self.runtime is not None:
            await self.runtime.close()
        if self.server is not None:
            self.server.close()
        self.server = self.runtime = None

    async def poll(self) -> int:
        venue = self.runtime.venues[0]
        return await self.runtime.ingest_binding(venue, venue.config.bindings[0])

    @property
    def firehose(self):
        return self.server.firehose

    def highest(self) -> int:
        return self.firehose.get_highest_seq(ORIGIN)

    def records(self, kind: str) -> list:
        return [r for r in self.firehose.get_events_range(ORIGIN, 1, 100000) if r.kind == kind]

    def mirrors(self) -> dict[str, object]:
        """foreign_id -> latest mirror record."""
        out = {}
        for rec in self.records(KIND_ARTICLE):
            meta = BridgeMetadata.from_metadata(rec.metadata)
            if meta.bridge_role == model.ROLE_MIRROR:
                out[meta.foreign_id] = rec
        return out

    def article(self, rec):
        bp = self.server.dispatcher._get_board_projection(ORIGIN, rec.board)
        return bp.get_article_by_id(ORIGIN, rec.board, rec.article_id)


@pytest.fixture
async def h(tmp_path):
    harness = Harness(tmp_path)
    await harness.start()
    yield harness
    await harness.stop()


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def _table(**over):
    t = {
        "venue": [
            {
                "type": "flatboard",
                "venue": FLATBOARD_VENUE,
                "url": "https://flatboard.test/",
                "binding": [{"board": "~flatboard", "max_body_bytes": 1000}],
            }
        ],
    }
    t.update(over)
    return t


def test_config_parses_venues_and_bindings():
    cfg, unknown = parse_bridge_runtime(_table(surprise=1))
    assert unknown == ["bridges.surprise"]
    (venue,) = cfg.venues
    assert venue.url == "https://flatboard.test"
    assert venue.bindings == [BindingConfig(board="~flatboard", max_body_bytes=1000)]
    assert cfg.venue_types == frozenset({"flatboard"})


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda t: t["venue"][0]["binding"][0].update(board="flatboard"), "board must be"),
        (lambda t: t["venue"][0]["binding"][0].update(board="~other"), "board must be"),
        (lambda t: t["venue"][0].update(type="flat.board"), "type must be"),
        (lambda t: t["venue"][0].pop("url"), "url is required"),
        (lambda t: t["venue"][0].update(venue="nohost"), "venue must look like"),
        (lambda t: t["venue"][0].update(venue="flatboard@"), "venue must look like"),
        (lambda t: t["venue"][0].update(venue="other@host"), "must start with its type"),
        (lambda t: t["venue"][0].update(binding=[]), "at least one"),
        (
            lambda t: t["venue"][0]["binding"].append({"board": "~flatboard"}),
            "bound twice",
        ),
        (lambda t: t.update(grace_seconds=-1), "grace_seconds"),
    ],
)
def test_config_rejects_bad_tables(mutate, message):
    table = _table()
    mutate(table)
    with pytest.raises(ValueError, match=message):
        parse_bridge_runtime(table)


def test_config_file_loads_bridges_and_checks_body_cap(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        textwrap.dedent(
            f"""
            [server]
            origin = "{ORIGIN}"
            [limits]
            max_article_body_size = 500
            [bridges]
            grace_seconds = 30
            [[bridges.venue]]
            type = "flatboard"
            venue = "{FLATBOARD_VENUE}"
            url = "https://flatboard.test"
            [bridges.venue.options]
            flavor = "plain"
            [[bridges.venue.binding]]
            board = "~flatboard"
            max_body_bytes = 1000
            [admission]
            enabled = true
            """
        )
    )
    config = FirehoseConfig.load(str(path))
    assert config.bridge_runtime is not None and not config.unknown_keys
    assert config.bridge_runtime.grace_seconds == 30
    assert config.bridge_runtime.venues[0].options == {"flavor": "plain"}
    assert config.bridge_admission is not None and config.bridge_admission.enabled
    assert config.bridges_state_dir == os.path.join(config.data_dir, "bridges")
    assert config.puppet_secret_path == os.path.join(config.data_dir, "puppet_secret")
    with pytest.raises(ValueError, match="exceeds limits.max_article_body_size"):
        config.validate()


def test_bridges_without_venues_bridge_nothing(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(f'[server]\norigin = "{ORIGIN}"\n[bridges]\ngrace_seconds = 30\n')
    assert FirehoseConfig.load(str(path)).bridge_runtime is None


def test_bridge_config_errors_name_the_table(tmp_path):
    path = tmp_path / "config.toml"
    base = f'[server]\norigin = "{ORIGIN}"\n'
    path.write_text(base + "[admission]\nodd = 2\n")
    assert FirehoseConfig.load(str(path)).unknown_keys == ["admission.odd"]
    path.write_text(base + "[admission]\nmax_chain_hops = 0\n")
    with pytest.raises(ValueError, match="config: admission.max_chain_hops"):
        FirehoseConfig.load(str(path))
    path.write_text(
        base + f'[[bridges.venue]]\ntype = "flatboard"\nvenue = "{FLATBOARD_VENUE}"\n'
        'url = "u"\noptions = 3\n'
    )
    with pytest.raises(ValueError, match="options must be a table"):
        FirehoseConfig.load(str(path))


def test_old_bridge_files_are_not_read(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(f'[server]\norigin = "{ORIGIN}"\n')
    (tmp_path / "bridges.toml").write_text("[admission]\nenabled = true\n")
    config = FirehoseConfig.load(str(path))
    assert config.bridge_admission is None and not config.unknown_keys


def test_recognize_lives_in_config_toml(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        f'[server]\norigin = "{ORIGIN}"\n[[recognize]]\ntype = "flatboard"\n'
        f'venue = "{FLATBOARD_VENUE}"\norigins = ["B.Test"]\n'
    )
    config = FirehoseConfig.load(str(path))
    assert [(e.venue, e.origins) for e in config.bridges] == [(FLATBOARD_VENUE, ["b.test"])]
    assert not config.unknown_keys

    path.write_text(f'[server]\norigin = "{ORIGIN}"\n[[recognize]]\ntype = "flatboard"\n')
    with pytest.raises(ValueError, match="config: recognize\\[0\\]"):
        FirehoseConfig.load(str(path))


def test_venue_options_go_to_the_adapter(monkeypatch):
    from bonnet.bridges import adapter as adapter_mod
    from bonnet.bridges.adapter import venue_option_problems

    class Picky:
        options = frozenset({"relays"})

        @classmethod
        def check_options(cls, options):
            if not isinstance(options.get("relays", []), list):
                raise ValueError("relays must be a list")

    monkeypatch.setattr(adapter_mod, "load_adapter_class", lambda venue_type: Picky)

    def venue(**options):
        return VenueConfig(type="picky", venue="picky@host", url="u", options=options)

    assert venue_option_problems([venue(relays=["a"])]) == ([], [])
    errors, warnings = venue_option_problems([venue(relays="a", typo=1)])
    assert errors == ["picky@host: options: relays must be a list"]
    assert warnings == ["picky@host: the picky adapter has no option 'typo' (ignored)"]


# ---------------------------------------------------------------------------
# Reservations (§8)
# ---------------------------------------------------------------------------


def _register_intent(actor: Identity, name: str, subject: bytes | None = None, flags=0):
    return Intent(
        event_id=os.urandom(32),
        kind=KIND_USER_REGISTER,
        origin=ORIGIN,
        actor_pubkey=actor.public_key,
        actor_registrar=ORIGIN,
        metadata=MetadataMap(
            [
                metadata_text(1, name),
                metadata_bytes(2, subject or actor.public_key),
                metadata_u64(3, flags),
            ]
        ),
    )


def _board_intent(actor: Identity, board: str, origin: str = ORIGIN):
    return Intent(
        event_id=os.urandom(32),
        kind=KIND_BOARD_CREATE,
        origin=origin,
        actor_pubkey=actor.public_key,
        actor_registrar=origin,
        board=board,
        metadata=MetadataMap([metadata_bytes(1, actor.public_key)]),
    )


async def _http_publish(server, identity: Identity, intent: Intent):
    """Publish with the context an HTTP request from `identity` would get."""
    from bonnet.core.record import encode_intent, sign_intent
    from bonnet.net.firehose_wire import parse_publish_response

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


async def test_homeserver_refuses_local_tilde_boards(tmp_path):
    from bonnet.app.server import BonnetServer

    server = BonnetServer(make_config(tmp_path, "home.test"))
    try:
        user = Identity.generate()
        reg = _register_intent(user, "moxxie")
        reg.origin = reg.actor_registrar = "home.test"
        await _http_publish(server, user, reg)
        await _http_publish(server, user, _board_intent(user, "general", "home.test"))
        with pytest.raises(ProtocolError) as e:
            await _http_publish(server, user, _board_intent(user, "~flatboard", "home.test"))
        assert e.value.code == 0x0004 and "reserved" in str(e.value)
        # Even the root console may not squat on bridge names.
        root = server.server_identity
        with pytest.raises(ProtocolError):
            await _http_publish(server, root, _board_intent(root, "~x", "home.test"))
    finally:
        server.close()


async def test_tilde_names_are_reserved_on_servers_without_bridges(tmp_path):
    from bonnet.app.server import BonnetServer

    server = BonnetServer(make_config(tmp_path, ORIGIN))
    try:
        user = Identity.generate()
        with pytest.raises(ProtocolError) as e:
            await _http_publish(server, user, _register_intent(user, "grok~flatboard"))
        assert "reserved for bridge puppets" in str(e.value)
    finally:
        server.close()


async def test_tilde_names_are_reserved_for_puppets(h):
    server = h.server
    for name in ("x~flatboard", "moxxie~sys.knolastna.me"):
        stranger = Identity.generate()
        with pytest.raises(ProtocolError) as e:
            await _http_publish(server, stranger, _register_intent(stranger, name))
        assert "reserved for bridge puppets" in str(e.value)
    # Running bridges doesn't close registration to everyone else.
    user = Identity.generate()
    await _http_publish(server, user, _register_intent(user, "moxxie"))
    assert server.users.username_holder(ORIGIN, "moxxie") == user.public_key

    # The runtime may register puppets for a type it runs, and nothing else.
    pub = h.runtime.publisher
    puppet = Identity.generate()
    await pub.publish(puppet, _register_intent(puppet, "grok~flatboard"))
    for bad in ("plain", "x~lainchan", "a~b~flatboard", "~flatboard"):
        other = Identity.generate()
        with pytest.raises(ProtocolError):
            await pub.publish(other, _register_intent(other, bad))

    # Not even administrators may squat on a puppet's name.
    root = server.server_identity
    squatter = Identity.generate()
    with pytest.raises(ProtocolError):
        await _http_publish(
            server, root, _register_intent(root, "moxxie~flatboard", squatter.public_key)
        )


# ---------------------------------------------------------------------------
# Setup and bindings
# ---------------------------------------------------------------------------


async def test_setup_creates_board_and_binding_as_the_server(h):
    server_key = h.server.server_identity.public_key
    assert h.runtime.daemon.public_key == server_key
    assert h.server.nav.get_board(ORIGIN, BOARD)["owner_pubkey"] == server_key
    (binding,) = h.records(KIND_BRIDGE_BINDING)
    assert binding.actor_pubkey == server_key
    active = read_bindings(h.firehose, ORIGIN)
    meta = active[BOARD].meta
    assert meta.venue == FLATBOARD_VENUE and meta.binding_ingest is True
    assert meta.binding_max_body_bytes == 262144
    assert meta.binding_foreign_capabilities == ("idempotent_post", "read", "threads", "write")
    assert active[BOARD].generation == 0


async def test_restart_with_same_config_publishes_nothing(h):
    before = h.highest()
    await h.stop()
    await h.start()
    assert h.highest() == before


async def test_changed_options_bind_a_new_generation_and_unbind_the_old(h):
    await h.stop()
    await h.start([venue_config(max_body_bytes=1000)])
    active = read_bindings(h.firehose, ORIGIN)
    assert active[BOARD].generation == 1
    assert active[BOARD].meta.binding_max_body_bytes == 1000
    (unbind,) = h.records(KIND_BRIDGE_UNBIND)
    first, second = h.records(KIND_BRIDGE_BINDING)
    assert unbind.target_event_id == first.event_id
    assert unbind.event_id == model.unbind_event_id(first.event_id)


async def test_binding_removed_from_config_is_unbound(h):
    await h.stop()
    await h.start([venue_config("~flatboard.other")])
    active = read_bindings(h.firehose, ORIGIN)
    assert set(active) == {"~flatboard.other"}


async def test_a_binding_removed_then_re_added_is_active_again(h):
    await h.stop()
    await h.start([venue_config("~flatboard.other")])
    await h.stop()
    await h.start([venue_config("~flatboard.other"), venue_config()])
    active = read_bindings(h.firehose, ORIGIN)
    assert set(active) == {"~flatboard", "~flatboard.other"}
    assert active["~flatboard"].generation == 1
    assert "~flatboard" in {b["board"] for b in h.server.bridges.active_bindings()}


# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------


async def test_ingest_mirrors_and_observes_a_thread(h):
    a = h.board.post("root post", created=NOW - 600)
    b = h.board.post("a reply", author="lanternfly", reply_to=a, created=NOW - 500)
    c = h.board.post("reply to the reply", reply_to=b, created=NOW - 400)
    assert await h.poll() == 3

    mirrors = h.mirrors()
    assert set(mirrors) == {str(a), str(b), str(c)}
    ra, rb, rc = (mirrors[str(i)] for i in (a, b, c))

    # Threading: fields 5/6 point at mirrors on this board; roots propagate.
    assert rb.metadata.get_bytes(6) == ra.article_id
    assert rb.metadata.get_bytes(5) == ra.article_id
    assert rc.metadata.get_bytes(6) == rb.article_id
    assert rc.metadata.get_bytes(5) == ra.article_id
    for rec in (ra, rb, rc):
        assert BridgeMetadata.from_metadata(rec.metadata).foreign_root_id == str(a)

    # Puppets: one per author, named <handle>~flatboard, signing their own posts.
    users = h.server.users
    assert users.get_user_by_pubkey(ORIGIN, ra.actor_pubkey)["username"] == "grok~flatboard"
    assert users.get_user_by_pubkey(ORIGIN, rb.actor_pubkey)["username"] == "lanternfly~flatboard"
    assert ra.actor_pubkey == rc.actor_pubkey
    assert ra.actor_username == "grok~flatboard"

    # Articles: subject, tags, body.
    art = h.article(ra)
    assert art.subject == "root post"
    assert f"src:{FLATBOARD_VENUE}##{a}" in art.tags
    assert art.author_check == "registry"

    # One observation per mirror, carrying the venue's bytes.
    obs = h.records(model.KIND_BRIDGE_OBSERVATION)
    assert {o.target_event_id for o in obs} == {ra.event_id, rb.event_id, rc.event_id}
    assert h.runtime.index.cursor(BOARD) == str(c)


async def test_second_poll_is_a_noop_and_new_posts_follow(h):
    h.board.post("one", created=NOW - 600)
    await h.poll()
    before = h.highest()
    assert await h.poll() == 0
    assert h.highest() == before
    four = h.board.post("two", created=NOW - 300)
    assert await h.poll() == 1
    assert str(four) in h.mirrors()


async def test_grace_window_holds_young_posts_in_order(h):
    old = h.board.post("settled", created=NOW - 600)
    young = h.board.post("just posted", created=NOW - 10)
    after = h.board.post("also young", created=NOW - 5)
    assert await h.poll() == 1
    assert set(h.mirrors()) == {str(old)}
    assert h.runtime.index.cursor(BOARD) == str(old)

    h.clock.t = NOW + 200
    assert await h.poll() == 2
    assert set(h.mirrors()) == {str(old), str(young), str(after)}


async def test_marked_post_waits_for_the_marker_timeout(h):
    marked = h.board.post(f"copied {model.make_marker(os.urandom(32))}", created=NOW - 600)
    plain = h.board.post("plain", created=NOW - 500)
    await h.poll()
    assert set(h.mirrors()) == {str(plain)}
    assert len(h.runtime.index.pending(BOARD)) == 1
    assert h.runtime.index.cursor(BOARD) == str(plain)

    h.clock.t = NOW + 1800
    await h.poll()
    assert str(marked) not in h.mirrors()

    h.clock.t = NOW + 3601
    await h.poll()
    assert str(marked) in h.mirrors()
    assert h.runtime.index.pending(BOARD) == []


async def test_a_post_from_the_future_holds_nothing_up(h):
    ahead = h.board.post("clock skew", created=NOW + 86_400)
    after = h.board.post("settled", created=NOW - 600)
    assert await h.poll() == 2
    assert set(h.mirrors()) == {str(ahead), str(after)}
    # Its stated time is still recorded as the venue gave it.
    meta = BridgeMetadata.from_metadata(h.mirrors()[str(ahead)].metadata)
    assert meta.foreign_created_at == NOW + 86_400


async def test_a_slightly_fast_venue_clock_still_gets_the_grace_window(h):
    h.board.post("a little ahead", created=NOW + 60)
    assert await h.poll() == 0
    h.clock.t = NOW + 60 + 200
    assert await h.poll() == 1


async def test_a_reply_waits_for_its_pending_parent_and_threads_under_it(h):
    parent = h.board.post(f"quoting {model.make_marker(os.urandom(32))}", created=NOW - 600)
    reply = h.board.post("a reply", author="lanternfly", reply_to=parent, created=NOW - 500)
    await h.poll()
    assert h.mirrors() == {}
    assert [p.post.foreign_id for p in h.runtime.index.pending(BOARD)] == [str(parent), str(reply)]

    h.clock.t = NOW + 3601
    await h.poll()
    assert set(h.mirrors()) == {str(parent), str(reply)}
    parent_rec, reply_rec = h.mirrors()[str(parent)], h.mirrors()[str(reply)]
    assert reply_rec.metadata.get_bytes(6) == parent_rec.article_id
    assert h.runtime.index.pending(BOARD) == []


async def test_long_posts_are_truncated_with_full_bytes_observed(tmp_path):
    harness = Harness(tmp_path, venues=[venue_config(max_body_bytes=100)])
    await harness.start()
    try:
        text = "é" * 300  # 600 bytes
        mid = harness.board.post(text, created=NOW - 600)
        await harness.poll()
        rec = harness.mirrors()[str(mid)]
        meta = BridgeMetadata.from_metadata(rec.metadata)
        assert meta.truncated is True and meta.original_size == 600
        assert rec.body_size == 100
        assert meta.foreign_digest == model.foreign_digest(text)
        (obs,) = harness.records(model.KIND_BRIDGE_OBSERVATION)
        raw = harness.server.body_store.get_event_body(
            ORIGIN, obs.event_id, obs.body_hash, obs.body_size
        )
        assert text in raw.decode("utf-8")
    finally:
        await harness.stop()


async def test_puppet_name_collision_gets_a_suffix(h):
    # Another author with the same handle got the plain name first.
    other = Identity.generate()
    await h.runtime.publisher.publish(other, _register_intent(other, "grok~flatboard"))
    mid = h.board.post("hi", created=NOW - 600)
    await h.poll()
    rec = h.mirrors()[str(mid)]
    name = h.server.users.get_user_by_pubkey(ORIGIN, rec.actor_pubkey)["username"]
    assert name == f"grok-{model._author_hex('grok', 6)}~flatboard"


async def test_anonymous_author_gets_the_anonymous_puppet(h):
    mid = h.board.post("who", author="", created=NOW - 600)
    await h.poll()
    rec = h.mirrors()[str(mid)]
    assert rec.actor_username == "anonymous~flatboard"


async def test_eviction_changes_nothing(h):
    for i in range(3):
        h.board.post(f"post {i}", created=NOW - 600)
    await h.poll()
    before = h.highest()
    h.board.evict_below(3)
    await h.poll()
    assert h.highest() == before
    assert all(h.article(r).visibility == "active" for r in h.mirrors().values())
    gone = await h.runtime.venues[0].adapter.fetch("", "1")
    assert gone == Gone("1", "evicted")


async def test_restart_resumes_without_duplicates(h):
    for i in range(3):
        h.board.post(f"post {i}", created=NOW - 600)
    await h.poll()
    before = h.highest()
    await h.stop()
    await h.start()
    assert await h.poll() == 0
    assert h.highest() == before


async def test_lost_index_is_rebuilt_from_the_log(h):
    ids = [h.board.post(f"post {i}", created=NOW - 600) for i in range(3)]
    reply = h.board.post("reply", reply_to=ids[0], created=NOW - 600)
    await h.poll()
    before = h.highest()
    state_dir = h.server.config.bridges_state_dir
    await h.stop()
    shutil.rmtree(state_dir)
    await h.start()

    assert h.runtime.rebuild_index() == 4
    assert h.runtime.index.cursor(BOARD) == str(reply)
    entry = h.runtime.index.mirror(BOARD, SourceKey(FLATBOARD_VENUE, "", str(ids[0])))
    assert entry is not None and entry.root_foreign_id == str(ids[0])
    assert await h.poll() == 0
    assert h.highest() == before

    # Even with no cursor at all, re-read posts are recognized and skipped.
    h.runtime.index.set_cursor(BOARD, None)
    await h.poll()
    assert h.highest() == before


async def test_venue_failure_raises_venue_error(h):
    h.board.offline = True
    with pytest.raises(VenueError):
        await h.poll()


async def test_failing_venue_backs_off_while_others_run(tmp_path, monkeypatch):
    import bonnet.bridges.runtime as runtime_mod

    other = venue_config("~flatboard.two")
    other.venue = "flatboard@two.test"
    harness = Harness(tmp_path, venues=[venue_config(), other])
    boards = {FLATBOARD_VENUE: FakeFlatboard(), "flatboard@two.test": FakeFlatboard()}
    boards[FLATBOARD_VENUE].offline = True
    boards["flatboard@two.test"].post("still here", created=NOW - 600)
    harness.board = None

    from bonnet.app.server import BonnetServer

    rt_cfg = runtime_config(tmp_path, harness.venues)
    server = BonnetServer(make_config(tmp_path, ORIGIN, rt_cfg))
    runtime = BridgeRuntime(
        server, adapter_factory=lambda v: boards[v.venue].adapter(v), clock=Clock()
    )
    delays = []
    real_sleep = asyncio.sleep

    async def fast_sleep(delay):
        delays.append(delay)
        await real_sleep(0)

    monkeypatch.setattr(runtime_mod.asyncio, "sleep", fast_sleep)
    task = asyncio.create_task(runtime.run())
    try:
        for _ in range(200):
            await real_sleep(0.01)
            if runtime.index.mirror_count("~flatboard.two") and runtime.venues[0].failures >= 3:
                break
        assert runtime.index.mirror_count("~flatboard.two") == 1
        assert runtime.venues[0].failures >= 3
        assert max(delays) >= 8  # 1s interval doubled per failure
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await runtime.close()
        server.close()


# ---------------------------------------------------------------------------
# Startup ordering (§5.2)
# ---------------------------------------------------------------------------


class _FakeServer:
    def __init__(self, binds: bool):
        self.binds = binds
        self.started = asyncio.Event()
        self.stopped = asyncio.Event()
        self._uvicorn_server = None
        self.run_kwargs = None

    async def run(self, **kwargs):
        self.run_kwargs = kwargs
        if not self.binds:
            return False

        class _Uv:
            should_exit = False

        self._uvicorn_server = _Uv()
        self.started.set()
        while not self._uvicorn_server.should_exit:
            await asyncio.sleep(0.001)
        self.stopped.set()
        return True


class _FakeRuntime:
    def __init__(self, fail: bool = False):
        self.fail = fail
        self.ran = False

    async def run(self):
        self.ran = True
        if self.fail:
            raise RuntimeError("runtime blew up")
        await asyncio.Event().wait()


async def test_serve_bridge_never_starts_runtime_if_server_cannot_bind():
    server, runtime = _FakeServer(binds=False), _FakeRuntime()
    assert await serve_bridge(server, runtime) is False
    assert not runtime.ran
    assert server.run_kwargs == {}


async def test_serve_bridge_runtime_failure_stops_server():
    server, runtime = _FakeServer(binds=True), _FakeRuntime(fail=True)
    with pytest.raises(RuntimeError, match="blew up"):
        await serve_bridge(server, runtime)
    assert server.stopped.is_set()


async def test_serve_bridge_server_exit_cancels_runtime():
    server, runtime = _FakeServer(binds=True), _FakeRuntime()
    task = asyncio.create_task(serve_bridge(server, runtime))
    await server.started.wait()
    await asyncio.sleep(0.01)
    assert runtime.ran
    server._uvicorn_server.should_exit = True
    assert await task is True


async def test_read_limiter_spaces_requests():
    t = [0.0]
    slept = []

    async def sleep(d):
        slept.append(d)
        t[0] += d

    limiter = ReadLimiter(120, clock=lambda: t[0], sleep=sleep)
    for _ in range(3):
        await limiter.wait()
    assert slept == [0.5, 0.5]


def test_adapter_registry_finds_flatboard():
    assert load_adapter_class("flatboard") is FlatboardAdapter
    with pytest.raises(ValueError):
        load_adapter_class("nope")


class _Custom(FlatboardAdapter):
    """A well-formed adapter for a venue type no built-in covers."""

    type = "custom"


def _installed(monkeypatch, *claims):
    eps = [
        metadata.EntryPoint(name, value, adapter_module.ENTRY_POINT_GROUP) for name, value in claims
    ]
    monkeypatch.setattr(
        adapter_module.metadata,
        "entry_points",
        lambda group: [ep for ep in eps if ep.group == group],
    )


def test_builtin_adapters_cannot_be_replaced(monkeypatch):
    _installed(monkeypatch, ("flatboard", f"{__name__}:_Custom"))
    assert load_adapter_class("flatboard") is FlatboardAdapter


def test_a_custom_type_loads_from_its_one_entry_point(monkeypatch):
    _installed(monkeypatch, ("custom", f"{__name__}:_Custom"))
    assert load_adapter_class("custom") is _Custom


def test_a_custom_type_claimed_twice_is_refused(monkeypatch):
    _installed(monkeypatch, ("custom", f"{__name__}:_Custom"), ("custom", "elsewhere:Other"))
    with pytest.raises(AdapterNotFound, match="more than one installed package"):
        load_adapter_class("custom")


def test_missing_adapters_names_each_venue(monkeypatch):
    _installed(monkeypatch, ("custom", "no_such_module_anywhere:Adapter"))
    venues = [
        venue_config(),
        VenueConfig(type="nostr", venue="nostr@relay.test", url="wss://relay.test"),
        VenueConfig(type="custom", venue="custom@x.test", url="https://x.test"),
    ]
    nostr, custom = missing_adapters(venues)
    assert nostr.startswith("nostr@relay.test: no bridge adapter") and "uvx --with" in nostr
    assert custom.startswith("custom@x.test: the adapter for 'custom' failed to load")


def test_mirror_subject():
    assert mirror_subject("  hello\n  world  ") == "hello world"
    long = mirror_subject("x" * 200)
    assert len(long) == 80 and long.endswith("…")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _write_bridge_config(tmp_path) -> str:
    path = tmp_path / "config.toml"
    path.write_text(
        textwrap.dedent(
            f"""
            [server]
            origin = "{ORIGIN}"
            data_dir = "data"
            boards_dir = "boards"
            events_bodies_dir = "event_bodies"
            [[bridges.venue]]
            type = "flatboard"
            venue = "{FLATBOARD_VENUE}"
            url = "https://flatboard.test"
            [[bridges.venue.binding]]
            board = "~flatboard"
            """
        )
    )
    return str(path)


def test_cli_status_and_rebuild(tmp_path, capsys):
    from bonnet.cli import main

    path = _write_bridge_config(tmp_path)
    assert main(["bridge", "status", "--config", path]) == 0
    out = capsys.readouterr().out
    assert "~flatboard" in out and "mirrors=0" in out

    from bonnet.app.server import BonnetServer

    server = BonnetServer(FirehoseConfig.load(path))  # creates the firehose on disk
    server.close()
    assert main(["bridge", "rebuild-index", "--config", path]) == 0
    assert "rebuilt index from 0" in capsys.readouterr().out


def test_cli_status_needs_venues(tmp_path, capsys):
    from bonnet.cli import main

    path = tmp_path / "config.toml"
    path.write_text(f'[server]\norigin = "{ORIGIN}"\n')
    with pytest.raises(SystemExit) as e:
        main(["bridge", "status", "--config", str(path)])
    assert e.value.code == 1
    assert "bridges no venues" in capsys.readouterr().err


def test_server_refuses_a_venue_type_with_no_adapter(tmp_path, capsys, monkeypatch):
    from bonnet.cli import main

    _installed(monkeypatch)
    path = _write_bridge_config(tmp_path)
    with open(path, "a") as f:
        f.write(
            '[[bridges.venue]]\ntype = "nostr"\nvenue = "nostr@relay.test"\n'
            'url = "wss://relay.test"\n[[bridges.venue.binding]]\nboard = "~nostr"\n'
        )
    with pytest.raises(SystemExit) as e:
        main(["server", "--config", path])
    assert e.value.code == 1
    err = capsys.readouterr().err
    assert "error: nostr@relay.test: no bridge adapter for venue type 'nostr'" in err
    assert main(["bridge", "rebuild-index", "--config", path]) == 1
    assert "no bridge adapter" in capsys.readouterr().err


def test_cli_bridge_usage(capsys):
    from bonnet.cli import main

    assert main(["bridge"]) == 2
    assert main(["bridge", "bogus"]) == 2
    assert main(["bridge", "run"]) == 2  # bridges run inside `bonnet server`


async def test_local_publisher_from_bridge_server_marks_runtime(h):
    pub = LocalPublisher.for_server(h.server)
    assert pub.context_for(h.runtime.daemon.public_key).via_bridge_runtime


async def test_bridges_run_on_an_acl_that_never_names_them(tmp_path):
    """No operator rule for the bridge: its facts are signed with the server's own key."""
    from bonnet.app.server import BonnetServer
    from tests.bridge_fakes import shipped_rules

    rules = shipped_rules() + [
        {"effect": "allow", "match": {"registered": True}, "actions": ["write"],
         "commands": ["PUBLISH_RECORD"], "kinds": ["bonnet.article"], "boards": ["~*"]},
    ]  # fmt: skip
    board = FakeFlatboard()
    board.post("hello", created=NOW - 600)
    rt_cfg = runtime_config(tmp_path, [venue_config()])
    server = BonnetServer(make_config(tmp_path, ORIGIN, rt_cfg, rules=rules))
    runtime = BridgeRuntime(server, adapter_factory=board.adapter, clock=Clock())
    try:
        await runtime.setup()
        venue = runtime.venues[0]
        assert await runtime.ingest_binding(venue, venue.config.bindings[0]) == 1
        # The server key may do anything, so the runtime's own guard is
        # what keeps it to bridge kinds: no routes, rules or controls.
        from bonnet.bridges.local_publish import KindRefused

        route = _register_intent(runtime.daemon, "x")
        route.kind = "bonnet.route.announce"
        with pytest.raises(KindRefused):
            runtime.publisher.build_frame(runtime.daemon, route)
    finally:
        await runtime.close()
        server.close()


async def test_crash_between_mirror_and_observation_is_recovered(h, monkeypatch):
    """The mirror landed, the observation didn't: the next poll re-observes."""
    mid = h.board.post("hello", created=NOW - 600)
    real_observe = h.runtime._observe

    async def crash(*args, **kwargs):
        raise RuntimeError("process died")

    monkeypatch.setattr(h.runtime, "_observe", crash)
    with pytest.raises(RuntimeError):
        await h.poll()
    assert str(mid) in h.mirrors()
    assert h.records(model.KIND_BRIDGE_OBSERVATION) == []

    monkeypatch.setattr(h.runtime, "_observe", real_observe)
    await h.poll()
    (obs,) = h.records(model.KIND_BRIDGE_OBSERVATION)
    assert obs.target_event_id == h.mirrors()[str(mid)].event_id
    assert len(h.records(KIND_ARTICLE)) == 1
