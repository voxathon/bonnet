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

"""Bridges milestone M4, part 2: relay egress and echo handling (design doc §11.3, §11.1).

B1 relays native articles from its bridge board to the fake flatboard under
one relay account and links them (role 3). B1 reads the relay's post back as
an echo and only observes it; B2, which syncs B1, mirrors it pointing at
B1's article; a home server recognizing both shows one copy, B1's, even
when it prefers B2.
"""

from __future__ import annotations

import os

import pytest

from bonnet.bridges import model
from bonnet.bridges.adapter import ForeignAccount, VenueAuthError, VenueError
from bonnet.bridges.config import BridgesEntry
from bonnet.bridges.model import BridgeMetadata, SourceKey
from bonnet.bridges.runtime import BridgeRuntime
from bonnet.core.config import PeerConfig
from bonnet.core.crypto import Identity
from bonnet.core.kinds import KIND_ARTICLE, KIND_USER_REGISTER
from bonnet.core.record import (
    Intent,
    MetadataMap,
    compute_body_hash,
    metadata_bytes,
    metadata_text,
    metadata_u64,
)
from bonnet.net.firehose_wire import build_article_list, parse_article_list_response
from tests.bridge_fakes import (
    FLATBOARD_VENUE,
    FakeFlatboard,
    make_config,
    publish_as,
    read,
    runtime_config,
    sync_from,
    venue_config,
)

B1 = "bridge-one.test"
B2 = "bridge-two.test"
HOME = "home.test"
BOARD = "~flatboard"
NOW = 1_900_000_000  # well past any real created_at, so articles are old enough
RELAY_USER = "bridge_relay"


class _Clock:
    def __init__(self):
        self.t = NOW

    def __call__(self):
        return self.t


class Side:
    def __init__(self, tmp_path, origin, venue, board: FakeFlatboard, peers=()):
        from bonnet.app.server import BonnetServer

        self.origin = origin
        rt = runtime_config(tmp_path / origin, [venue])
        self.server = BonnetServer(make_config(tmp_path, origin, rt, peers=list(peers)))
        self.clock = _Clock()
        self.runtime = BridgeRuntime(self.server, adapter_factory=board.adapter, clock=self.clock)

    @property
    def venue(self):
        return self.runtime.venues[0]

    @property
    def binding(self):
        return self.venue.config.bindings[0]

    async def ingest(self):
        return await self.runtime.ingest_binding(self.venue, self.binding)

    async def relay(self):
        return await self.runtime.relay_binding(self.venue, self.binding)

    async def close(self):
        await self.runtime.close()
        self.server.close()


class World:
    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.board = FakeFlatboard()
        self.board.accounts[RELAY_USER] = "s3cret"
        token = tmp_path / "relay.token"
        token.write_text("s3cret\n")
        v1 = venue_config(relay_egress=True)
        v1.relay_user = RELAY_USER
        v1.relay_token_file = str(token)
        self.b1 = Side(tmp_path, B1, v1, self.board)
        self.b2 = Side(
            tmp_path, B2, venue_config(), self.board, peers=[PeerConfig(origin=B1, hostname=B1)]
        )
        self.operator = Identity.generate()

    async def start(self, set_floor: bool = True):
        await self.b1.runtime.setup()
        await self.b2.runtime.setup()
        root = self.b1.server.server_identity
        await publish_as(
            self.b1.server,
            root,
            Intent(
                event_id=os.urandom(32),
                kind=KIND_USER_REGISTER,
                origin=B1,
                actor_pubkey=root.public_key,
                actor_username="root",
                actor_registrar=B1,
                metadata=MetadataMap(
                    [
                        metadata_text(1, "operator"),
                        metadata_bytes(2, self.operator.public_key),
                        metadata_u64(3, 0),
                    ]
                ),
            ),
        )
        if set_floor:
            await self.b1.relay()  # sets the floor: nothing before this is relayed

    async def native(self, text: str, reply_to: bytes | None = None) -> Intent:
        body = text.encode()
        fields = [metadata_text(1, text[:40]), metadata_text(4, "text/plain")]
        if reply_to is not None:
            fields += [metadata_bytes(5, reply_to), metadata_bytes(6, reply_to)]
        intent = Intent(
            event_id=os.urandom(32),
            kind=KIND_ARTICLE,
            origin=B1,
            actor_pubkey=self.operator.public_key,
            actor_username="operator",
            actor_registrar=B1,
            board=BOARD,
            article_id=os.urandom(32),
            metadata=MetadataMap(fields),
            body_hash=compute_body_hash(body),
            body_size=len(body),
        )
        await publish_as(self.b1.server, self.operator, intent, body)
        return intent

    def relay_posts(self):
        return [m for m in self.board.messages.values() if m["author"] == RELAY_USER]

    async def close(self):
        await self.b1.close()
        await self.b2.close()


@pytest.fixture
async def w(tmp_path):
    world = World(tmp_path)
    await world.start()
    yield world
    await world.close()


def _records(server, origin, kind):
    return [r for r in server.firehose.get_events_range(origin, 1, 100000) if r.kind == kind]


# ---------------------------------------------------------------------------
# Relay
# ---------------------------------------------------------------------------


async def test_relay_posts_with_attribution_and_marker_then_links(w):
    art = await w.native("hello venue")
    assert await w.b1.relay() == 1

    (msg,) = w.relay_posts()
    assert msg["text"] == f"operator@{B1}: hello venue\n{model.make_marker(art.event_id, B1)}"
    assert w.board.request_ids == {art.event_id.hex()[:32]: msg["id"]}

    (link,) = _records(w.b1.server, B1, model.KIND_BRIDGE_LINK)
    meta = BridgeMetadata.from_metadata(link.metadata)
    assert meta.bridge_role == model.ROLE_RELAY_LINK and meta.foreign_id == str(msg["id"])
    assert link.target_article_id == art.article_id
    assert link.event_id == model.link_event_id(
        B1, BOARD, art.article_id, FLATBOARD_VENUE, "", str(msg["id"])
    )
    copy = w.b1.server.bridges.copy_by_article(B1, BOARD, art.article_id)
    assert copy.role == model.ROLE_RELAY_LINK and copy.event_id == art.event_id

    assert await w.b1.relay() == 0  # done once


async def test_articles_before_relay_was_enabled_are_never_relayed(tmp_path):
    world = World(tmp_path)
    await world.start(set_floor=False)
    try:
        # Posted before the first relay tick: the backlog stays home.
        await world.native("old news")
        await world.b1.relay()
        await world.b1.relay()
        assert world.relay_posts() == []
    finally:
        await world.close()


async def test_bridge_authored_articles_are_not_relayed(w):
    w.board.post("from the venue", created=0)
    await w.b1.ingest()  # a puppet mirror lands on the board
    assert await w.b1.relay() == 0
    assert w.relay_posts() == []


async def test_reply_to_a_mirror_goes_out_as_a_venue_reply(w):
    parent_id = w.board.post("venue thread", created=0)
    await w.b1.ingest()
    mirror = next(
        r
        for r in _records(w.b1.server, B1, KIND_ARTICLE)
        if BridgeMetadata.from_metadata(r.metadata).foreign_id == str(parent_id)
    )
    await w.native("replying from bonnet", reply_to=mirror.article_id)
    await w.b1.relay()
    (msg,) = w.relay_posts()
    assert msg["reply_to"] == parent_id
    (link,) = _records(w.b1.server, B1, model.KIND_BRIDGE_LINK)
    assert BridgeMetadata.from_metadata(link.metadata).foreign_root_id == str(parent_id)


async def test_a_venue_reply_to_a_relayed_article_threads_under_it(w):
    art = await w.native("hello venue")
    await w.b1.relay()
    (msg,) = w.relay_posts()
    await w.b1.ingest()  # the echo: observed, not mirrored
    w.board.post("welcome", author="hermes", reply_to=int(msg["id"]), created=0)
    await w.b1.ingest()
    reply = next(
        r
        for r in _records(w.b1.server, B1, KIND_ARTICLE)
        if BridgeMetadata.from_metadata(r.metadata).foreign_author == "hermes"
    )
    assert reply.metadata.get_bytes(5) == art.article_id  # root
    assert reply.metadata.get_bytes(6) == art.article_id  # reply_to


async def test_crash_after_posting_reposts_idempotently(w, monkeypatch):
    art = await w.native("hello")
    real_publish = w.b1.runtime.publisher.publish
    calls = {"n": 0}

    async def crash_on_link(identity, intent, body=b""):
        if intent.kind == model.KIND_BRIDGE_LINK and calls["n"] == 0:
            calls["n"] += 1
            raise VenueError("process died")  # after the venue post, before the link
        return await real_publish(identity, intent, body)

    monkeypatch.setattr(w.b1.runtime.publisher, "publish", crash_on_link)
    await w.b1.relay()
    assert len(w.relay_posts()) == 1
    assert _records(w.b1.server, B1, model.KIND_BRIDGE_LINK) == []

    await w.b1.relay()
    assert len(w.relay_posts()) == 1  # request_id: the same venue post
    (link,) = _records(w.b1.server, B1, model.KIND_BRIDGE_LINK)
    assert link.target_article_id == art.article_id


async def test_bad_credentials_stop_relaying_without_retries(w):
    w.board.accounts[RELAY_USER] = "rotated"
    await w.native("one")
    await w.native("two")
    await w.b1.relay()
    await w.b1.relay()
    assert w.board.auth_failures == 1
    assert BOARD in w.b1.runtime._relay_stopped


async def test_gives_up_after_five_failures(w):
    art = await w.native("unlucky")
    w.board.fail_posts = 10
    for _ in range(7):
        await w.b1.relay()
    assert w.b1.runtime.index.relay_state(BOARD, art.article_id) == (5, False)
    assert w.board.fail_posts == 5
    assert w.relay_posts() == []


async def test_a_rate_limit_pauses_relay_without_counting_a_failure(w):
    art = await w.native("patient")
    w.board.rate_limit_posts = 3
    for _ in range(3):
        await w.b1.relay()
    assert w.b1.runtime.index.relay_state(BOARD, art.article_id) is None
    await w.b1.relay()
    (post,) = w.relay_posts()
    assert "patient" in post["text"]


def _not_idempotent(w):
    adapter = w.b1.venue.adapter
    adapter.capabilities = adapter.capabilities - {"idempotent_post"}


async def test_an_uncertain_relay_is_retried_onto_the_same_post(w):
    art = await w.native("once")
    w.board.lose_post_responses = 1
    await w.b1.relay()
    assert w.b1.runtime.index.relay_state(BOARD, art.article_id) == (1, False)
    await w.b1.relay()
    (post,) = w.relay_posts()  # the same key: flatboard handed back the same post
    assert w.b1.runtime.index.relay_state(BOARD, art.article_id) == (1, True)


async def test_an_uncertain_relay_on_a_non_idempotent_venue_is_never_retried(w):
    _not_idempotent(w)
    art = await w.native("maybe")
    w.board.lose_post_responses = 1
    for _ in range(3):
        await w.b1.relay()
    assert len(w.relay_posts()) == 1
    assert w.b1.runtime.index.relay_state(BOARD, art.article_id) == (0, True)


async def test_a_refused_relay_on_a_non_idempotent_venue_is_retried(w):
    _not_idempotent(w)
    art = await w.native("refused once")
    w.board.refuse_posts = 1
    await w.b1.relay()
    assert w.relay_posts() == []
    assert w.b1.runtime.index.relay_state(BOARD, art.article_id) == (1, False)
    await w.b1.relay()
    assert len(w.relay_posts()) == 1


async def test_no_account_means_no_relay(tmp_path):
    board = FakeFlatboard()
    side = Side(tmp_path, B1, venue_config(relay_egress=True), board)
    try:
        await side.runtime.setup()
        assert await side.relay() == 0
    finally:
        await side.close()


# ---------------------------------------------------------------------------
# Echoes (§11.1 steps 3-4)
# ---------------------------------------------------------------------------


async def test_the_relaying_bridge_observes_its_echo_and_does_not_mirror_it(w):
    art = await w.native("hello")
    await w.b1.relay()
    await w.b1.ingest()
    mirrors = [
        r
        for r in _records(w.b1.server, B1, KIND_ARTICLE)
        if BridgeMetadata.from_metadata(r.metadata).bridge_role == model.ROLE_MIRROR
    ]
    assert mirrors == []
    (obs,) = _records(w.b1.server, B1, model.KIND_BRIDGE_OBSERVATION)
    assert obs.target_event_id == art.event_id


async def test_another_bridge_mirrors_the_echo_pointing_at_the_original(w):
    art = await w.native("hello")
    await w.b1.relay()
    await sync_from(w.b2.server, w.b1.server)
    await w.b2.ingest()
    (mirror,) = [
        r
        for r in _records(w.b2.server, B2, KIND_ARTICLE)
        if BridgeMetadata.from_metadata(r.metadata).bridge_role == model.ROLE_MIRROR
    ]
    meta = BridgeMetadata.from_metadata(mirror.metadata)
    assert (meta.crosspost_of_origin, meta.crosspost_of_event) == (B1, art.event_id)


async def test_consumers_show_the_relayed_original_even_preferring_the_other_bridge(w):
    from bonnet.app.server import BonnetServer

    await w.native("hello")
    await w.b1.relay()
    await sync_from(w.b2.server, w.b1.server)
    await w.b2.ingest()
    home = BonnetServer(
        make_config(
            w.tmp_path,
            HOME,
            peers=[PeerConfig(origin=B1, hostname=B1), PeerConfig(origin=B2, hostname=B2)],
            bridges=[BridgesEntry("flatboard", FLATBOARD_VENUE, [B2, B1])],
        )
    )
    try:
        await sync_from(home, w.b1.server)
        await sync_from(home, w.b2.server)
        resp = await read(home, build_article_list("", BOARD, 0, 100))
        rows = parse_article_list_response(resp, aggregate=True).results
        assert [(r.origin, r.subject) for r in rows] == [(B1, "hello")]
    finally:
        home.close()


async def test_a_copied_marker_is_mirrored_as_an_ordinary_post(w):
    art = await w.native("hello")
    await w.b1.relay()
    copied = w.board.post(f"look: {model.make_marker(art.event_id, B1)}", author="troll", created=0)
    await w.b1.ingest()
    mirrors = {
        BridgeMetadata.from_metadata(r.metadata).foreign_id: BridgeMetadata.from_metadata(
            r.metadata
        )
        for r in _records(w.b1.server, B1, KIND_ARTICLE)
        if BridgeMetadata.from_metadata(r.metadata).bridge_role == model.ROLE_MIRROR
    }
    assert set(mirrors) == {str(copied)}
    assert mirrors[str(copied)].crosspost_of_origin is None


async def test_bridges_db_groups_the_link_with_the_venue_post(w):
    art = await w.native("hello")
    await w.b1.relay()
    (msg,) = w.relay_posts()
    copies = w.b1.server.bridges.copies_of(SourceKey(FLATBOARD_VENUE, "", str(msg["id"])))
    assert [(c.origin, c.event_id, c.role) for c in copies] == [
        (B1, art.event_id, model.ROLE_RELAY_LINK)
    ]


# ---------------------------------------------------------------------------
# Adapter write side
# ---------------------------------------------------------------------------


async def test_render_outbound_keeps_the_marker_within_the_cap():
    board = FakeFlatboard()
    adapter = board.adapter(venue_config())
    marker = model.make_marker(os.urandom(32), B1)
    try:
        text = adapter.render_outbound("x" * 5000, marker, "someone@b.test")
        assert len(text.encode()) <= 2048 and text.endswith(marker)
        assert text.startswith("someone@b.test: ")
    finally:
        await adapter.close()


async def test_post_errors_never_leak_the_token():
    board = FakeFlatboard()
    board.offline = True
    adapter = board.adapter(venue_config())
    account = ForeignAccount("u", "TOPSECRET")
    try:
        with pytest.raises(VenueError) as e:
            await adapter.post(account, "", "hi", None, "k")
        assert "TOPSECRET" not in str(e.value) and "TOPSECRET" not in repr(account)
        board.offline = False
        with pytest.raises(VenueAuthError) as e:
            await adapter.post(account, "", "hi", None, "k")
        assert "TOPSECRET" not in str(e.value)
    finally:
        await adapter.close()
