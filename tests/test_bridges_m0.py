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

"""Bridges milestone M0: foundations and proof tests (design doc §13).

Each lettered test proves one load-bearing claim the rest of the design
builds on, against real in-process servers rather than mocks:

  (a) a daemon context can publish an observation through `handle`
  (b) an article carries 0x0100+ fields and a `src:` tag unchanged
  (c) re-publishing is idempotent, bodies included
  (d) both sync to a second server byte for byte
  (e) the runtime's context matches the HTTP server's
  (f) the kind guard refuses route (and control) kinds
  (g) an added `bridges` manifest key is ignored by today's parser
  (h) a venue edit A→B→A yields three distinct mirrors
  (i) `H()` is unambiguous
  (j) a projection added after dispatch catches up at boot
  (k) observation IDs cover state and raw bytes
  (l) puppet names keep exactly one `~`
"""

from __future__ import annotations

import json
import os
import time

import httpx
import pytest

from bonnet.bridges import model
from bonnet.bridges.local_publish import KindRefused, LocalPublisher
from bonnet.bridges.model import (
    KIND_BRIDGE_OBSERVATION,
    ROLE_MIRROR,
    ROLE_OBSERVATION,
    BridgeMetadata,
    SourceKey,
)
from bonnet.core.acl import ACLEvaluator, ACLRule
from bonnet.core.config import FirehoseConfig, PeerConfig
from bonnet.core.crypto import Identity
from bonnet.core.kinds import KIND_ARTICLE, KIND_BOARD_CREATE, KIND_USER_REGISTER
from bonnet.core.record import (
    Intent,
    MetadataMap,
    compute_body_hash,
    compute_event_hash,
    encode_record,
    make_origin_witness,
    metadata_bytes,
    metadata_text,
    metadata_text_list,
    metadata_u64,
)
from bonnet.net.firehose_commands import derive_context
from bonnet.net.firehose_sync import SyncClient
from bonnet.net.firehose_wire import (
    ProtocolError,
    build_article_body,
    build_article_query,
    parse_article_body_response,
    parse_article_query_response,
)

VENUE = "flatboard@tools.nyrds.net"
VENUE_TYPE = "flatboard"
BOARD = "~flatboard"

_READ_COMMANDS = [
    "PERMISSIONS",
    "EVENT_HEAD",
    "EVENT_RANGE",
    "EVENT_GET",
    "KEY_EPOCHS",
    "BOARD_LIST",
    "ARTICLE_GET",
    "ARTICLE_LIST",
    "ARTICLE_SEARCH",
    "ARTICLE_BODY",
    "ARTICLE_QUERY",
    "USER_GET",
    "USER_LIST",
    "BAN_STATUS",
    "EVENT_BODY",
]


def _rules(daemon_pubkey: bytes) -> list[dict]:
    """The shipped default ACL plus the bridge daemon rule (design doc §7, §10.2)."""
    return [
        {"effect": "allow", "match": {"anonymous": True}, "actions": ["read"],
         "commands": _READ_COMMANDS, "boards": ["*"]},
        {"effect": "allow", "match": {"unknown": True}, "actions": ["write"],
         "commands": ["PUBLISH_RECORD"], "kinds": ["bonnet.user.register"]},
        {"effect": "allow", "match": {"registered": True}, "actions": ["read"],
         "commands": _READ_COMMANDS, "boards": ["*"]},
        {"effect": "allow", "match": {"registered": True}, "actions": ["write"],
         "commands": ["PUBLISH_RECORD"], "kinds": ["bonnet.article"], "boards": ["~*"]},
        {"effect": "allow", "match": {"pubkey": "hex:" + daemon_pubkey.hex()},
         "actions": ["write"], "commands": ["PUBLISH_RECORD"],
         "kinds": ["bonnet.bridge.*", "bonnet.board.create", "bonnet.article"],
         "boards": ["~*", ""]},
    ]  # fmt: skip


def _make_server(tmp_path, origin: str, daemon: Identity, peers: list[PeerConfig] = ()):
    from bonnet.app.server import BonnetServer

    root = tmp_path / origin
    config = FirehoseConfig(
        origin=origin,
        hostname=origin,
        data_dir=str(root / "data"),
        boards_dir=str(root / "boards"),
        events_bodies_dir=str(root / "event_bodies"),
        port=2272,
        tls_enabled=False,
        peers=list(peers),
        acl=ACLEvaluator([ACLRule.from_dict(r) for r in _rules(daemon.public_key)]),
    )
    for d in (config.data_dir, config.boards_dir, config.events_bodies_dir):
        os.makedirs(d, exist_ok=True)
    return BonnetServer(config)


class Bridge:
    """One bridge origin: a real server, its daemon and a local publisher."""

    def __init__(self, tmp_path, origin: str = "bridge.test", peers=()):
        self.origin = origin
        self.daemon = Identity.generate()
        self.server = _make_server(tmp_path, origin, self.daemon, peers)
        self.pub = LocalPublisher.for_server(self.server)

    def close(self):
        self.server.close()

    async def register(self, identity: Identity, username: str):
        intent = Intent(
            event_id=os.urandom(32),
            kind=KIND_USER_REGISTER,
            origin=self.origin,
            actor_pubkey=identity.public_key,
            actor_registrar=self.origin,
            metadata=MetadataMap(
                [
                    metadata_text(1, username),
                    metadata_bytes(2, identity.public_key),
                    metadata_u64(3, 0),
                ]
            ),
        )
        return await self.pub.publish(identity, intent)

    async def create_board(self, board: str = BOARD):
        intent = Intent(
            event_id=os.urandom(32),
            kind=KIND_BOARD_CREATE,
            origin=self.origin,
            actor_pubkey=self.daemon.public_key,
            actor_username="bridge-daemon",
            actor_registrar=self.origin,
            board=board,
            metadata=MetadataMap([metadata_bytes(1, self.daemon.public_key)]),
        )
        return await self.pub.publish(self.daemon, intent)

    async def setup(self) -> Identity:
        """Register the daemon and one puppet, create the bridge board."""
        await self.register(self.daemon, "bridge-daemon")
        await self.create_board()
        puppet = Identity.from_private_key(model.puppet_seed(b"m" * 32, VENUE, "grok-id"))
        await self.register(puppet, model.puppet_username("grok", VENUE_TYPE, "grok-id"))
        return puppet


def _mirror(
    bridge: Bridge,
    puppet: Identity,
    foreign_id: str,
    text: str,
    revision: int = 0,
    supersedes: bytes | None = None,
) -> tuple[Intent, bytes]:
    """A role-1 mirror intent and body, built the way the runtime will (§4)."""
    digest16 = model.content_digest(text)
    src = SourceKey(VENUE, "", foreign_id)
    body = model.normalize_foreign_text(text).encode("utf-8")
    meta = BridgeMetadata(
        bridge_role=ROLE_MIRROR,
        venue=VENUE,
        channel="",
        foreign_id=foreign_id,
        foreign_author="grok",
        foreign_author_id="grok-id",
        foreign_root_id=foreign_id,
        foreign_digest=model.foreign_digest(text),
        mirror_revision=revision,
        foreign_state=model.FOREIGN_EDITED if revision else model.FOREIGN_PRESENT,
    )
    base = [
        metadata_text(1, f"[{VENUE_TYPE} #{foreign_id}] {text[:80]}"),
        metadata_text_list(2, model.bridge_tags(VENUE_TYPE, src)),
        metadata_text(4, "text/plain"),
    ]
    if supersedes is not None:
        base.append(metadata_bytes(7, supersedes))
    intent = Intent(
        event_id=model.mirror_event_id(
            bridge.origin, BOARD, VENUE, "", foreign_id, revision, digest16
        ),
        kind=KIND_ARTICLE,
        origin=bridge.origin,
        actor_pubkey=puppet.public_key,
        actor_registrar=bridge.origin,
        board=BOARD,
        article_id=model.mirror_article_id(
            bridge.origin, BOARD, VENUE, "", foreign_id, revision, digest16
        ),
        metadata=model.merge_metadata(MetadataMap(base), meta.to_fields()),
        body_hash=compute_body_hash(body),
        body_size=len(body),
    )
    return intent, body


def _observation(bridge: Bridge, target: Intent, foreign_id: str, text: str, raw: bytes, state=0):
    intent = Intent(
        event_id=model.observation_event_id(
            VENUE,
            "",
            foreign_id,
            model.content_digest(text),
            state,
            raw,
            bridge.origin,
            target.event_id,
        ),
        kind=KIND_BRIDGE_OBSERVATION,
        origin=bridge.origin,
        actor_pubkey=bridge.daemon.public_key,
        actor_username="bridge-daemon",
        actor_registrar=bridge.origin,
        target_origin=bridge.origin,
        target_event_id=target.event_id,
        metadata=MetadataMap(
            BridgeMetadata(
                bridge_role=ROLE_OBSERVATION,
                venue=VENUE,
                channel="",
                foreign_id=foreign_id,
                foreign_content_type="application/json",
                foreign_state=state,
            ).to_fields()
        ),
        body_hash=compute_body_hash(raw),
        body_size=len(raw),
    )
    return intent, raw


@pytest.fixture
def bridge(tmp_path):
    b = Bridge(tmp_path)
    yield b
    b.close()


# ---------------------------------------------------------------------------
# (a) (b) publish through handle
# ---------------------------------------------------------------------------


async def test_a_observation_publish_via_handle_with_daemon_context(bridge):
    puppet = await bridge.setup()
    mirror, body = _mirror(bridge, puppet, "312", "hello from flatboard")
    await bridge.pub.publish(puppet, mirror, body)

    raw = b'{"id":312,"author":"grok","text":"hello from flatboard"}'
    obs, obs_body = _observation(bridge, mirror, "312", "hello from flatboard", raw)
    result = await bridge.pub.publish(bridge.daemon, obs, obs_body)

    assert result.kind == KIND_BRIDGE_OBSERVATION
    rec = bridge.server.firehose.get_event_by_id(bridge.origin, obs.event_id)
    assert rec is not None and rec.target_event_id == mirror.event_id
    meta = BridgeMetadata.from_metadata(rec.metadata)
    assert meta.bridge_role == ROLE_OBSERVATION and meta.foreign_id == "312"
    assert bridge.pub.context_for(bridge.daemon.public_key).via_bridge_runtime


async def test_b_article_carries_bridge_fields_and_src_tag(bridge):
    puppet = await bridge.setup()
    mirror, body = _mirror(bridge, puppet, "312", "hello from flatboard")
    await bridge.pub.publish(puppet, mirror, body)

    rec = bridge.server.firehose.get_event_by_id(bridge.origin, mirror.event_id)
    meta = BridgeMetadata.from_metadata(rec.metadata)
    assert meta.src == SourceKey(VENUE, "", "312")
    assert meta.bridge_role == ROLE_MIRROR
    assert meta.foreign_digest == model.foreign_digest("hello from flatboard")

    bp = bridge.server.dispatcher._get_board_projection(bridge.origin, BOARD)
    art = bp.get_article_by_id(bridge.origin, BOARD, mirror.article_id)
    assert art is not None and art.visibility == "active"
    assert "src:flatboard@tools.nyrds.net##312" in art.tags
    assert "bridged" in art.tags


# ---------------------------------------------------------------------------
# (c) idempotency
# ---------------------------------------------------------------------------


async def test_c_republish_is_idempotent_including_bodies(bridge):
    puppet = await bridge.setup()
    mirror, body = _mirror(bridge, puppet, "312", "hello from flatboard")
    first = await bridge.pub.publish(puppet, mirror, body)
    obs, raw = _observation(bridge, mirror, "312", "hello from flatboard", b'{"id":312}')
    first_obs = await bridge.pub.publish(bridge.daemon, obs, raw)
    highest = bridge.server.firehose.get_highest_seq(bridge.origin)

    # A crashed runtime retries the exact same intents: the article body is
    # staged again and the event body rewritten, then append_record finds the
    # identical intent already stored.
    again = await bridge.pub.publish(puppet, mirror, body)
    again_obs = await bridge.pub.publish(bridge.daemon, obs, raw)

    assert again.origin_seq == first.origin_seq
    assert again.article_num == first.article_num
    assert again_obs.origin_seq == first_obs.origin_seq
    assert bridge.server.firehose.get_highest_seq(bridge.origin) == highest

    resp = await bridge.pub.request(
        build_article_body(bridge.origin, BOARD, first.article_num), puppet.public_key
    )
    assert parse_article_body_response(resp) == body


async def test_c_same_event_id_different_intent_is_refused(bridge):
    puppet = await bridge.setup()
    mirror, body = _mirror(bridge, puppet, "312", "hello")
    await bridge.pub.publish(puppet, mirror, body)
    other, other_body = _mirror(bridge, puppet, "313", "different")
    other.event_id = mirror.event_id
    with pytest.raises(ProtocolError):
        await bridge.pub.publish(puppet, other, other_body)


# ---------------------------------------------------------------------------
# (d) federation
# ---------------------------------------------------------------------------


class _ServerSyncClient(SyncClient):
    """Serves one BonnetServer's firehose to another in process."""

    def __init__(self, server):
        self._server = server

    async def fetch_head(self, origin):
        return self._server.firehose.get_head(origin), b""

    async def fetch_range(self, origin, start_seq, max_count):
        out = []
        for rec in self._server.firehose.get_events_range(origin, start_seq, max_count):
            w = make_origin_witness(
                origin,
                rec.event_id,
                compute_event_hash(encode_record(rec)),
                rec.origin_seq,
                self._server.server_identity,
                origin,
                origin,
                int(time.time()),
            )
            out.append((rec, [w]))
        return out

    def peer_identity(self):
        return self._server.server_identity.public_key, self._server.config.origin

    async def fetch_key_epochs(self, origin):
        return self._server.firehose.get_key_epochs(origin)

    async def close(self):
        pass


async def test_d_bridge_records_sync_to_a_second_server(tmp_path, bridge):
    puppet = await bridge.setup()
    mirror, body = _mirror(bridge, puppet, "312", "hello from flatboard")
    await bridge.pub.publish(puppet, mirror, body)
    obs, raw = _observation(bridge, mirror, "312", "hello from flatboard", b'{"id":312}')
    await bridge.pub.publish(bridge.daemon, obs, raw)

    peer = PeerConfig(origin=bridge.origin, hostname=bridge.origin)
    consumer = _make_server(tmp_path, "consumer.test", Identity.generate(), peers=[peer])
    try:
        result = await consumer.sync_manager._sync_once(
            bridge.origin, _ServerSyncClient(bridge.server), skip_allowlist=True
        )
        assert result.accepted, result.reason
        consumer.dispatcher.dispatch_origin(bridge.origin)

        for intent in (mirror, obs):
            here = bridge.server.firehose.get_event_by_id(bridge.origin, intent.event_id)
            there = consumer.firehose.get_event_by_id(bridge.origin, intent.event_id)
            assert there is not None
            assert encode_record(there) == encode_record(here)

        bp = consumer.dispatcher._get_board_projection(bridge.origin, BOARD)
        art = bp.get_article_by_id(bridge.origin, BOARD, mirror.article_id)
        assert art is not None and "src:flatboard@tools.nyrds.net##312" in art.tags
    finally:
        consumer.close()


# ---------------------------------------------------------------------------
# (e) context parity
# ---------------------------------------------------------------------------


async def test_e_runtime_context_matches_http_context(tmp_path, bridge):
    await bridge.setup()
    server = bridge.server
    admin = Identity.generate()
    stranger = Identity.generate()
    # Root registers `operator` with the administrator flag.
    root = server.server_identity
    await bridge.pub.publish(
        root,
        Intent(
            event_id=os.urandom(32),
            kind=KIND_USER_REGISTER,
            origin=bridge.origin,
            actor_pubkey=root.public_key,
            actor_username="root",
            actor_registrar=bridge.origin,
            metadata=MetadataMap(
                [
                    metadata_text(1, "operator"),
                    metadata_bytes(2, admin.public_key),
                    metadata_u64(3, 1),
                ]
            ),
        ),
    )
    assert bridge.pub.context_for(admin.public_key).role == "administrator"
    captured = []
    real_handle = server.command_handler.handle

    def spy(body, ctx):
        captured.append(ctx)
        return real_handle(body, ctx)

    server.command_handler.handle = spy
    http = server.http_server

    async def http_ctx(identity: Identity | None):
        from bonnet.net.firehose_transport import FirehoseTransport

        t = FirehoseTransport(
            f"https://{bridge.origin}",
            verify=False,
            trust_store_path=str(tmp_path / "trust.db"),
        )
        t._http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=http),
            base_url=f"https://{bridge.origin}",
            verify=False,
        )
        await t.discover()
        if identity is None:
            await t.connect_anonymous()
        else:
            await t.connect(identity)
        captured.clear()
        from bonnet.net.firehose_wire import build_user_list

        await t._send_command(build_user_list(bridge.origin))
        await t._http.aclose()
        return captured[-1]

    anon_pub = server.anonymous_identity.public_key
    for identity in (bridge.daemon, admin, stranger, None):
        via_http = await http_ctx(identity)
        pubkey = anon_pub if identity is None else identity.public_key
        local = derive_context(server.users, bridge.origin, pubkey, "x", anon_pub)
        runtime = bridge.pub.context_for(pubkey)
        for ctx in (local, runtime):
            assert (ctx.peer_pubkey, ctx.is_anonymous, ctx.is_unknown, ctx.is_registered) == (
                via_http.peer_pubkey,
                via_http.is_anonymous,
                via_http.is_unknown,
                via_http.is_registered,
            )
            assert ctx.role == via_http.role and ctx.origin == via_http.origin
        assert runtime.via_bridge_runtime and not via_http.via_bridge_runtime


def test_e_derive_context_roles_from_flags():
    class Users:
        def __init__(self, row):
            self.row = row

        def get_user_by_pubkey(self, origin, pubkey):
            return self.row

    key, anon = os.urandom(32), os.urandom(32)
    cases = [
        ({"flags": 1}, (False, True, "administrator")),
        ({"flags": 2}, (False, True, "moderator")),
        ({"flags": 0}, (False, True, "")),
        ({"flags": 1, "revoked": True}, (True, False, "")),
        ({"flags": 1, "superseded_by": os.urandom(32)}, (True, False, "")),
        (None, (True, False, "")),
    ]
    for row, (unknown, registered, role) in cases:
        ctx = derive_context(Users(row), "o.test", key, "", anon)
        assert (ctx.is_unknown, ctx.is_registered, ctx.role) == (unknown, registered, role), row
    anon_ctx = derive_context(Users({"flags": 1}), "o.test", anon, "", anon)
    assert anon_ctx.is_anonymous and not anon_ctx.is_unknown and anon_ctx.role == ""


# ---------------------------------------------------------------------------
# (f) kind guard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kind",
    [
        "bonnet.route.announce",
        "bonnet.route.withdraw",
        "bonnet.article.cancel",
        "bonnet.article.restore",
        "bonnet.article.purge",
        "bonnet.rule.publish",
        "bonnet.punishment.ban",
    ],
)
async def test_f_guard_refuses_kinds_outside_the_allowlist(bridge, kind):
    await bridge.setup()
    before = bridge.server.firehose.get_highest_seq(bridge.origin)
    intent = Intent(
        event_id=os.urandom(32),
        kind=kind,
        origin=bridge.origin,
        actor_pubkey=bridge.daemon.public_key,
        actor_registrar=bridge.origin,
    )
    with pytest.raises(KindRefused):
        await bridge.pub.publish(bridge.daemon, intent)
    assert bridge.server.firehose.get_highest_seq(bridge.origin) == before


def test_f_guard_allows_bridge_kinds():
    from bonnet.bridges.local_publish import kind_allowed

    for kind in (
        KIND_ARTICLE,
        KIND_BOARD_CREATE,
        KIND_USER_REGISTER,
        model.KIND_BRIDGE_LINK,
        model.KIND_BRIDGE_OBSERVATION,
        model.KIND_BRIDGE_BINDING,
        model.KIND_BRIDGE_UNBIND,
    ):
        assert kind_allowed(kind)
    assert not kind_allowed("bonnet.bridgeX")


# ---------------------------------------------------------------------------
# (g) manifest
# ---------------------------------------------------------------------------


async def test_g_manifest_parse_ignores_an_added_bridges_key(tmp_path, bridge, monkeypatch):
    import bonnet.net.firehose_http_server as http_mod
    from bonnet.net.firehose_transport import FirehoseTransport

    real_dumps = json.dumps

    def dumps_with_bridges(obj, *args, **kwargs):
        if isinstance(obj, dict) and "protocol" in obj:
            obj = dict(obj, bridges=[{"type": VENUE_TYPE, "venue": VENUE, "board": BOARD}])
        return real_dumps(obj, *args, **kwargs)

    monkeypatch.setattr(http_mod.json, "dumps", dumps_with_bridges)
    t = FirehoseTransport(
        f"https://{bridge.origin}", verify=False, trust_store_path=str(tmp_path / "trust.db")
    )
    t._http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=bridge.server.http_server),
        base_url=f"https://{bridge.origin}",
        verify=False,
    )
    raw = (await t._http.get("/.well-known/untp")).json()
    assert raw["bridges"][0]["venue"] == VENUE
    info = await t.discover()
    assert info.origin == bridge.origin
    await t._http.aclose()


# ---------------------------------------------------------------------------
# (h) edits
# ---------------------------------------------------------------------------


async def test_h_edit_a_b_a_produces_three_distinct_mirrors(bridge):
    puppet = await bridge.setup()
    texts = ["version A", "version B", "version A"]
    intents = []
    prev = None
    for rev, text in enumerate(texts):
        intent, body = _mirror(bridge, puppet, "312", text, revision=rev, supersedes=prev)
        await bridge.pub.publish(puppet, intent, body)
        intents.append(intent)
        prev = intent.article_id

    assert len({i.event_id for i in intents}) == 3
    assert len({i.article_id for i in intents}) == 3
    bp = bridge.server.dispatcher._get_board_projection(bridge.origin, BOARD)
    assert bp.resolve_head_id(bridge.origin, BOARD, intents[0].article_id) == intents[2].article_id
    for old in intents[:2]:
        art = bp.get_article_by_id(bridge.origin, BOARD, old.article_id)
        assert art.visibility == "superseded"


# ---------------------------------------------------------------------------
# (i) H()
# ---------------------------------------------------------------------------


def test_i_h_is_unambiguous():
    assert model.H(b"x", "a\x00", "b") != model.H(b"x", "a", "\x00b")
    assert model.H(b"x", "ab") != model.H(b"x", "a", "b")
    assert model.H(b"x", "", "a") != model.H(b"x", "a", "")
    assert model.H(b"x", "a") != model.H(b"xa")
    assert model.H(b"x", b"\x00\x01") != model.H(b"x", "\x00", "\x01")
    assert model.H(b"x", "a", "b") == model.H(b"x", b"a", b"b")
    assert len(model.H(b"x")) == 32


def test_i_derived_ids_do_not_collide_across_labels():
    d = model.content_digest("t")
    args = ("o", "~b", VENUE, "", "1", 0, d)
    assert model.mirror_article_id(*args) != model.mirror_event_id(*args)
    binding = model.binding_event_id(VENUE, "", "o", "~b", 0)
    assert model.unbind_event_id(binding) != binding
    assert model.binding_event_id(VENUE, "", "o", "~b", 1) != binding


# ---------------------------------------------------------------------------
# (j) projection catch-up
# ---------------------------------------------------------------------------


class _CountingProjection:
    name = "counting"

    def __init__(self):
        self.checkpoints: dict[str, int] = {}
        self.seen: list[tuple[str, int]] = []

    def get_checkpoint(self, origin):
        return self.checkpoints.get(origin, 0)

    def set_checkpoint(self, origin, seq):
        self.checkpoints[origin] = seq

    def apply(self, rec):
        self.seen.append((rec.origin, rec.origin_seq))

    def clear_origin(self, origin):
        self.seen = [s for s in self.seen if s[0] != origin]
        self.checkpoints.pop(origin, None)


async def test_j_projection_added_later_catches_up_at_boot(tmp_path, monkeypatch):
    b = Bridge(tmp_path)
    puppet = await b.setup()
    mirror, body = _mirror(b, puppet, "1", "one")
    await b.pub.publish(puppet, mirror, body)
    highest = b.server.firehose.get_highest_seq(b.origin)
    b.close()

    # Reboot with a projection that has never seen anything.
    import bonnet.app.server as server_mod

    proj = _CountingProjection()
    real = server_mod.Dispatcher

    class WithProjection(real):
        def __init__(self, *args, **kwargs):
            kwargs["tracked_projections"] = [*kwargs.get("tracked_projections", []), proj]
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(server_mod, "Dispatcher", WithProjection)
    from bonnet.app.server import BonnetServer

    server = BonnetServer(b.server.config)
    try:
        assert [s for o, s in proj.seen if o == b.origin] == list(range(1, highest + 1))

        # New records reach it once, in order, through normal dispatch.
        pub = LocalPublisher.for_server(server)
        second, body2 = _mirror(b, puppet, "2", "two")
        await pub.publish(puppet, second, body2)
        seqs = [s for o, s in proj.seen if o == b.origin]
        assert seqs == list(range(1, highest + 2))

        # rebuild_all clears it and replays everything once.
        server.dispatcher.rebuild_all(b.origin)
        assert [s for o, s in proj.seen if o == b.origin] == list(range(1, highest + 2))
    finally:
        server.close()


async def test_j_projection_registered_at_runtime_is_caught_up_before_new_records(bridge):
    puppet = await bridge.setup()
    proj = _CountingProjection()
    bridge.server.dispatcher.register_projection(proj)

    # No explicit catch-up call: the next dispatch replays the gap first.
    mirror, body = _mirror(bridge, puppet, "1", "one")
    await bridge.pub.publish(puppet, mirror, body)
    highest = bridge.server.firehose.get_highest_seq(bridge.origin)
    assert [s for o, s in proj.seen if o == bridge.origin] == list(range(1, highest + 1))
    assert bridge.server.dispatcher.catch_up_projections() == 0


def test_j_failing_projection_is_skipped_not_fatal(bridge):
    class Broken(_CountingProjection):
        name = "broken"

        def apply(self, rec):
            raise RuntimeError("boom")

    proj = Broken()
    bridge.server.dispatcher.register_projection(proj)
    bridge.server.dispatcher.catch_up_projections()
    assert proj.get_checkpoint(bridge.origin) == bridge.server.firehose.get_checkpoint(
        bridge.origin
    )


# ---------------------------------------------------------------------------
# (k) observation IDs
# ---------------------------------------------------------------------------


def test_k_observation_ids_cover_state_and_raw_bytes():
    d = model.content_digest("text")
    target = os.urandom(32)

    def oid(state=0, raw=b'{"rating":1}'):
        return model.observation_event_id(VENUE, "", "312", d, state, raw, "b.test", target)

    assert oid() == oid()
    assert oid(state=model.FOREIGN_DELETED) != oid()
    assert oid(raw=b'{"rating":2}') != oid()


async def test_k_deletion_observation_publishes_alongside_the_original(bridge):
    puppet = await bridge.setup()
    mirror, body = _mirror(bridge, puppet, "312", "hello")
    await bridge.pub.publish(puppet, mirror, body)
    first, raw = _observation(bridge, mirror, "312", "hello", b'{"id":312}')
    await bridge.pub.publish(bridge.daemon, first, raw)
    gone, gone_raw = _observation(
        bridge, mirror, "312", "hello", b'{"deleted":312}', state=model.FOREIGN_DELETED
    )
    result = await bridge.pub.publish(bridge.daemon, gone, gone_raw)
    assert result.event_id != first.event_id.hex()


# ---------------------------------------------------------------------------
# (l) puppet names
# ---------------------------------------------------------------------------


def test_l_puppet_names():
    assert model.puppet_username("grok", "flatboard", "id") == "grok~flatboard"
    assert model.puppet_username("", "flatboard", "id") == "anonymous~flatboard"

    tilde = model.puppet_username("moxxie~sys.knolastna.me", "flatboard", "id")
    assert tilde == "moxxie-sys.knolastna.me~flatboard"

    long = model.puppet_username("a-very-long-handle-for-a-puppet-name", "flatboard", "id")
    handle, venue_type = long.split("~")
    assert venue_type == "flatboard"
    assert len(handle.encode()) <= model.PUPPET_HANDLE_MAX_BYTES
    assert handle.endswith("-" + model._author_hex("id", 4))

    collided = model.puppet_username("grok", "flatboard", "id", collided=True)
    assert collided == f"grok-{model._author_hex('id', 6)}~flatboard"

    for name in (tilde, long, collided, model.puppet_username('a<b>"c', "t", "i")):
        assert name.count("~") == 1


def test_l_puppet_name_is_a_valid_identity():
    from bonnet.core.kind_validator import identity_text_violation

    for handle in (
        "  spaced  ",
        "\x1bescape",
        "日本語の名前はとても長いのでここで切られます",
        "?*",
    ):
        name = model.puppet_username(handle, "flatboard", "id")
        assert identity_text_violation(name) is None, name
        assert name.count("~") == 1


def test_puppet_seed_is_deterministic_per_author():
    a = model.puppet_seed(b"s" * 32, VENUE, "1")
    assert a == model.puppet_seed(b"s" * 32, VENUE, "1")
    assert a != model.puppet_seed(b"s" * 32, VENUE, "2")
    assert a != model.puppet_seed(b"t" * 32, VENUE, "1")
    assert len(a) == 32


# ---------------------------------------------------------------------------
# Codecs and metadata
# ---------------------------------------------------------------------------


def test_src_tag_round_trips_escaped_components():
    src = SourceKey("v@h", "a#b,c", "100%")
    tag = model.src_tag(src)
    assert tag == "src:v@h#a%23b%2Cc#100%25"
    assert model.parse_src_tag(tag) == src
    assert model.parse_src_tag("src:only#two") is None
    assert model.parse_src_tag("venue:x") is None


def test_marker_round_trip_and_last_wins():
    eid = bytes(range(32))
    m = model.make_marker(eid)
    assert m == "[bnt:0001020304050607]"
    assert model.find_marker(f"copied [bnt:{'a' * 16}] then real {m}") == "0001020304050607"
    assert model.find_marker("no marker") is None


def test_normalization_and_digests():
    assert model.normalize_foreign_text("é\r\nx  \n") == "é\nx"
    assert model.foreign_digest("x\r\n") == model.foreign_digest("x")
    assert model.content_digest("x") == model.foreign_digest("x")[:16]


def test_bridge_metadata_round_trip_and_text_truncation():
    meta = BridgeMetadata(
        bridge_role=ROLE_MIRROR,
        venue=VENUE,
        channel="",
        foreign_id="1",
        foreign_created_at=-5,
        truncated=True,
        crosspost_of_event=b"\x01" * 32,
        foreign_url="u" * 5000,
        binding_foreign_capabilities=("read", "threads"),
    )
    fields = meta.to_fields()
    assert [f.field_id for f in fields] == sorted(f.field_id for f in fields)
    back = BridgeMetadata.from_metadata(MetadataMap(fields))
    assert back.foreign_url == "u" * 4096
    assert back.binding_foreign_capabilities == ("read", "threads")
    assert back.foreign_created_at == -5 and back.truncated is True
    assert back.bridge_version == model.BRIDGE_VERSION


def test_merge_metadata_orders_and_rejects_duplicates():
    base = MetadataMap([metadata_text(1, "s"), metadata_text(4, "text/plain")])
    merged = model.merge_metadata(base, [metadata_u64(0x0101, 1), metadata_text(2, "x")])
    assert [f.field_id for f in merged.fields] == [1, 2, 4, 0x0101]
    with pytest.raises(ValueError):
        model.merge_metadata(base, [metadata_text(4, "again")])


# ---------------------------------------------------------------------------
# ARTICLE_QUERY unknown filter field
# ---------------------------------------------------------------------------


async def test_unknown_query_filter_field_is_an_error(bridge):
    puppet = await bridge.setup()
    mirror, body = _mirror(bridge, puppet, "1", "one")
    await bridge.pub.publish(puppet, mirror, body)

    ok = await bridge.pub.request(
        build_article_query(bridge.origin, BOARD, [(0x04, 0x05, 0x02, "bridged")]),
        puppet.public_key,
    )
    assert len(parse_article_query_response(ok).results) == 1

    bad = await bridge.pub.request(
        build_article_query(bridge.origin, BOARD, [(0x0B, 0x01, 0x02, "x")]),
        puppet.public_key,
    )
    with pytest.raises(ProtocolError) as e:
        parse_article_query_response(bad)
    assert e.value.code == 0x0006


def test_query_articles_raises_on_unknown_field(bridge):
    from bonnet.core.board_projection import UnknownQueryField

    bp = bridge.server.dispatcher._get_board_projection(bridge.origin, BOARD)
    with pytest.raises(UnknownQueryField):
        bp.query_articles(bridge.origin, BOARD, [(0x7F, 0x01, "x")])


# ---------------------------------------------------------------------------
# Gateway extra_metadata
# ---------------------------------------------------------------------------


async def test_gateway_publish_article_merges_extra_metadata():
    from bonnet.core.record import decode_intent
    from bonnet.gateway.firehose_client import FirehoseHTTPClient

    client = FirehoseHTTPClient("https://bridge.test", verify=False)
    client._identity = Identity.generate()
    client._server_origin = "bridge.test"
    client._username = ""
    sent = []

    async def capture(cmd):
        sent.append(cmd)
        raise RuntimeError("stop")

    client._send_command = capture
    extra = BridgeMetadata(bridge_role=model.ROLE_CROSSPOST, home_origin="home.test").to_fields()
    with pytest.raises(RuntimeError):
        await client.publish_article(BOARD, os.urandom(32), b"hi", "subject", extra_metadata=extra)
    frame = sent[0]
    n = int.from_bytes(frame[1:5], "big")
    intent = decode_intent(frame[5 : 5 + n])
    meta = BridgeMetadata.from_metadata(intent.metadata)
    assert meta.bridge_role == model.ROLE_CROSSPOST and meta.home_origin == "home.test"
    assert intent.metadata.get_text(1) == "subject"

    with pytest.raises(ValueError):
        await client.publish_article(
            BOARD, os.urandom(32), b"hi", "s", extra_metadata=[metadata_text(1, "dup")]
        )
    await client._http.aclose()
