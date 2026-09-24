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

"""Bridges milestone M4, part 3: edge egress through the gateway (design doc §11.2).

The gateway's crosspost tool, end to end: a user of home.test posts on the
bridge board of bridge.test with their home key. The gateway posts to the
fake flatboard as the user first, then publishes the signed original on the
bridge, which admits the key by asking home.test. The bridge's runtime then
reads the venue post back as the echo and only observes it.
"""

from __future__ import annotations

import asyncio
import os

import httpx
import pytest

pytest.importorskip("fastmcp")

from bonnet.bridges import model
from bonnet.bridges.admission import AdmissionClient
from bonnet.bridges.config import AdmissionConfig
from bonnet.bridges.model import BridgeMetadata
from bonnet.bridges.runtime import BridgeRuntime
from bonnet.core.crypto import Identity
from bonnet.core.kinds import KIND_ARTICLE, KIND_USER_REGISTER
from bonnet.core.record import Intent, MetadataMap, metadata_bytes, metadata_text, metadata_u64
from bonnet.gateway import bridge_tools
from bonnet.gateway.firehose_client import FirehoseHTTPClient
from bonnet.gateway.outbox import Outbox
from bonnet.net.firehose_transport import FirehoseClientError
from tests.bridge_fakes import (
    FLATBOARD_VENUE,
    FakeFlatboard,
    asgi_transport_factory,
    make_config,
    publish_as,
    runtime_config,
    shipped_rules,
    venue_config,
)

B = "bridge.test"
HOME = "home.test"
HOME_URL = f"https://{HOME}"
B_URL = f"https://{B}"
BOARD = "~flatboard"
NOW = 1_900_000_000
VENUE_USER = "moxxie_fb"


class _Clock:
    def __call__(self):
        return NOW


class World:
    def __init__(self, tmp_path, monkeypatch):
        from bonnet.app.server import BonnetServer

        self.tmp_path = tmp_path
        self.board = FakeFlatboard()
        self.board.accounts[VENUE_USER] = "venue-token"
        self.home = BonnetServer(make_config(tmp_path, HOME, rules=shipped_rules()))
        rt = runtime_config(tmp_path / B, [venue_config()])
        self.bridge = BonnetServer(
            make_config(tmp_path, B, rt, bridge_admission=AdmissionConfig(enabled=True))
        )
        self.bridge.command_handler._admission._client = AdmissionClient(
            asgi_transport_factory({HOME_URL: self.home}, str(tmp_path / "adm-trust.db"))
        )
        self.runtime = BridgeRuntime(
            self.bridge, adapter_factory=self.board.adapter, clock=_Clock()
        )
        self.user = Identity.generate()
        self.fail_send = 0

        token = tmp_path / "venue.token"
        token.write_text("venue-token")
        accounts = tmp_path / "bridge_accounts.toml"
        accounts.write_text(
            f'[[account]]\nvenue = "{FLATBOARD_VENUE}"\ntype = "flatboard"\n'
            f'url = "https://flatboard.test"\nuser = "{VENUE_USER}"\ntoken_file = "{token}"\n'
        )
        monkeypatch.setenv("BONNET_BRIDGE_ACCOUNTS", str(accounts))
        monkeypatch.setattr(bridge_tools, "_home", lambda auth: (self.user, HOME, HOME_URL))
        monkeypatch.setattr(bridge_tools, "_client_for", self._client)
        monkeypatch.setattr(
            bridge_tools, "_adapter_for", lambda spec: self.board.adapter(venue_config())
        )
        # Post spacing on a fake clock: waits are recorded, never slept.
        self.now = 0.0
        self.slept: list[float] = []

        async def sleep(seconds):
            self.slept.append(seconds)
            self.now += seconds

        monkeypatch.setattr(bridge_tools, "_gates", {})
        monkeypatch.setattr(bridge_tools, "_clock", lambda: self.now)
        monkeypatch.setattr(bridge_tools, "_sleep", sleep)

    def _client(self, url: str) -> FirehoseHTTPClient:
        servers = {B_URL: self.bridge, HOME_URL: self.home}
        client = FirehoseHTTPClient(
            url, verify=False, trust_store_path=str(self.tmp_path / "gw.db")
        )
        client._http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=servers[url].http_server), base_url=url
        )
        if url == B_URL:
            world = self
            real = client._send_command

            async def send(frame):
                if frame[0] == 0x01 and world.fail_send:  # PUBLISH_RECORD
                    world.fail_send -= 1
                    raise FirehoseClientError("bridge unreachable")
                return await real(frame)

            client._send_command = send
        return client

    async def start(self):
        self.bridge.loop = asyncio.get_running_loop()
        await self.runtime.setup()
        self.bridge.command_handler.live_bridge_venues.add(FLATBOARD_VENUE)
        await publish_as(
            self.home,
            self.user,
            Intent(
                event_id=os.urandom(32),
                kind=KIND_USER_REGISTER,
                origin=HOME,
                actor_pubkey=self.user.public_key,
                actor_registrar=HOME,
                metadata=MetadataMap(
                    [
                        metadata_text(1, "moxxie"),
                        metadata_bytes(2, self.user.public_key),
                        metadata_u64(3, 0),
                    ]
                ),
            ),
        )

    async def crosspost(self, body="hello from bonnet", **kw):
        return await bridge_tools.crosspost(B, BOARD, body, bridge_url=B_URL, **kw)

    def articles(self):
        return [
            r for r in self.bridge.firehose.get_events_range(B, 1, 100000) if r.kind == KIND_ARTICLE
        ]

    def venue_posts(self):
        return [m for m in self.board.messages.values() if m["author"] == VENUE_USER]

    async def close(self):
        await self.runtime.close()
        self.bridge.close()
        self.home.close()


@pytest.fixture
async def w(tmp_path, monkeypatch):
    world = World(tmp_path, monkeypatch)
    await world.start()
    yield world
    await world.close()


def _outbox():
    from bonnet.gateway import paths

    return Outbox(os.path.join(paths.tenant_dir(), "outbox.db"))


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


async def test_crosspost_posts_to_the_venue_then_publishes_the_original(w):
    result = await w.crosspost()
    assert result["egress"] == "posted" and result["published"] is True

    (msg,) = w.venue_posts()
    (art,) = w.articles()
    meta = BridgeMetadata.from_metadata(art.metadata)
    assert meta.bridge_role == model.ROLE_CROSSPOST
    assert meta.foreign_id == str(msg["id"]) == result["foreign_id"]
    assert meta.home_origin == HOME and meta.home_url == HOME_URL
    assert msg["text"] == f"hello from bonnet\n{model.make_marker(art.event_id)}"
    assert w.board.request_ids == {art.event_id.hex()[:32]: msg["id"]}
    assert art.actor_pubkey == w.user.public_key and art.actor_username == ""

    user = w.bridge.users.get_user_by_pubkey(B, w.user.public_key)
    assert user["username"] == "moxxie"


async def test_the_runtime_observes_the_echo_instead_of_mirroring_it(w):
    await w.crosspost()
    (art,) = w.articles()
    venue = w.runtime.venues[0]
    await w.runtime.ingest_binding(venue, venue.config.bindings[0])
    assert len(w.articles()) == 1  # no mirror
    (obs,) = [
        r
        for r in w.bridge.firehose.get_events_range(B, 1, 100000)
        if r.kind == model.KIND_BRIDGE_OBSERVATION
    ]
    assert obs.target_event_id == art.event_id
    # The author is now known to crosspost: their next posts get the longer grace.
    assert w.runtime.index.is_crossposter(FLATBOARD_VENUE, VENUE_USER)


async def test_replies_thread_on_the_venue_and_the_bridge(w):
    parent = w.board.post("a venue thread", created=0)
    venue = w.runtime.venues[0]
    await w.runtime.ingest_binding(venue, venue.config.bindings[0])
    (mirror,) = w.articles()
    await w.crosspost("my reply", reply_to_foreign_id=str(parent))
    (msg,) = w.venue_posts()
    assert msg["reply_to"] == parent
    reply = next(a for a in w.articles() if a.event_id != mirror.event_id)
    assert reply.metadata.get_bytes(6) == mirror.article_id


# ---------------------------------------------------------------------------
# Failure paths
# ---------------------------------------------------------------------------


async def test_without_a_venue_account_the_post_stays_native(w, monkeypatch):
    monkeypatch.setenv("BONNET_BRIDGE_ACCOUNTS", str(w.tmp_path / "none.toml"))
    result = await w.crosspost()
    assert result["egress"] == "none" and result["published"] is True
    assert w.venue_posts() == []
    (art,) = w.articles()
    meta = BridgeMetadata.from_metadata(art.metadata)
    assert meta.bridge_role is None and meta.home_origin == HOME


async def test_a_venue_failure_publishes_natively_and_reports(w):
    w.board.fail_posts = 1
    result = await w.crosspost()
    assert result["egress"] == "failed" and "500" in result["venue_error"]
    assert result["published"] is True
    (art,) = w.articles()
    assert BridgeMetadata.from_metadata(art.metadata).bridge_role is None


async def test_a_refused_publish_is_recorded_and_the_venue_post_stays(w):
    w.user = Identity.generate()  # never registered at home.test
    result = await w.crosspost()
    assert result["published"] is False and "not registered at home" in result["refused"]
    assert len(w.venue_posts()) == 1
    assert w.articles() == []
    (entry,) = _outbox().by_state("refused")
    assert entry.bridge_origin == B


async def test_an_unreachable_bridge_queues_and_flush_sends_the_same_frame(w):
    w.fail_send = 1
    result = await w.crosspost()
    assert result["published"] is False and result["queued"] is True
    (queued,) = _outbox().by_state("ready")
    flushed = await bridge_tools.flush_outbox()
    assert flushed["entries"][0]["published"] is True
    (art,) = w.articles()
    assert art.event_id == queued.event_id
    assert len(w.venue_posts()) == 1


async def test_a_crash_before_the_final_frame_reposts_idempotently(w, monkeypatch):
    real_final = bridge_tools._final_frame

    def crash(*args, **kwargs):
        raise RuntimeError("gateway died after the venue post")

    monkeypatch.setattr(bridge_tools, "_final_frame", crash)
    with pytest.raises(RuntimeError):
        await w.crosspost()
    assert len(w.venue_posts()) == 1
    assert len(_outbox().by_state("pending")) == 1

    monkeypatch.setattr(bridge_tools, "_final_frame", real_final)
    flushed = await bridge_tools.flush_outbox()
    assert flushed["entries"][0]["reposted"] is True
    assert len(w.venue_posts()) == 1  # same request_id: the same venue post
    (art,) = w.articles()
    assert BridgeMetadata.from_metadata(art.metadata).foreign_id == str(w.venue_posts()[0]["id"])


async def test_a_pending_frame_on_a_non_idempotent_venue_is_dropped(w, monkeypatch):
    monkeypatch.setattr(
        bridge_tools, "_final_frame", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x"))
    )
    with pytest.raises(RuntimeError):
        await w.crosspost()

    def plain_adapter(spec):
        adapter = w.board.adapter(venue_config())
        adapter.capabilities = frozenset({"read", "write"})
        return adapter

    monkeypatch.setattr(bridge_tools, "_adapter_for", plain_adapter)
    flushed = await bridge_tools.flush_outbox()
    assert flushed["entries"] == [{"event_id": flushed["entries"][0]["event_id"], "dropped": True}]
    assert len(w.venue_posts()) == 1


async def test_posts_are_spaced_per_account_across_calls(w):
    await w.crosspost("one")
    await w.crosspost("two")
    assert w.slept == [15.0]
    assert len(w.venue_posts()) == 2


async def test_a_short_rate_limit_is_waited_out_and_retried(w):
    w.board.rate_limit_posts = 1
    result = await w.crosspost()
    assert result["egress"] == "posted" and result["published"] is True
    assert w.slept == [15.0]
    assert len(w.venue_posts()) == 1


async def test_a_long_rate_limit_is_reported_and_the_post_stays_native(w):
    w.board.rate_limit_posts = 1
    w.board.retry_after = 3600
    result = await w.crosspost()
    assert result["egress"] == "failed" and "rate limited" in result["venue_error"]
    assert result["published"] is True and w.venue_posts() == []
    assert w.slept == []
    # The next post waits out the venue's retry-after first.
    await w.crosspost("later")
    assert w.slept == [3600.0]


async def test_rejected_credentials_are_never_sent_again(w):
    w.board.accounts[VENUE_USER] = "a-new-token"
    first = await w.crosspost("one")
    assert first["egress"] == "failed" and first["published"] is True
    assert w.board.auth_failures == 1

    second = await w.crosspost("two")
    assert second["egress"] == "failed" and "not sending them again" in second["venue_error"]
    assert w.board.auth_failures == 1  # the venue never saw the token again

    (w.tmp_path / "venue.token").write_text("a-new-token")
    third = await w.crosspost("three")
    assert third["egress"] == "posted"
    assert [m["text"].split("\n")[0] for m in w.venue_posts()] == ["three"]
    assert bridge_tools._read_auth_failures() == {}


async def test_flush_carries_on_past_an_entry_the_venue_refuses(w, monkeypatch):
    # Entry 1: pending (the gateway died after the venue post).
    real_final = bridge_tools._final_frame
    monkeypatch.setattr(
        bridge_tools, "_final_frame", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x"))
    )
    with pytest.raises(RuntimeError):
        await w.crosspost("pending one")
    monkeypatch.setattr(bridge_tools, "_final_frame", real_final)
    # Entry 2: ready (the bridge was unreachable).
    w.fail_send = 1
    await w.crosspost("ready one")

    w.board.rate_limit_posts = 1
    w.board.retry_after = 3600
    flushed = await bridge_tools.flush_outbox()
    by_state = {e.get("state", "sent"): e for e in flushed["entries"]}
    assert "rate limited" in by_state["pending"]["error"]
    assert by_state["sent"]["published"] is True
    (pending,) = _outbox().by_state("pending")
    assert _outbox().by_state("ready") == []
    assert pending.venue_text.startswith("pending one")


async def test_crosspost_refuses_a_board_that_is_not_a_live_bridge(w):
    with pytest.raises(ValueError, match="not a live bridge board"):
        await bridge_tools.crosspost(B, "~nope", "hi", bridge_url=B_URL)


# ---------------------------------------------------------------------------
# list_bridges and corroborate
# ---------------------------------------------------------------------------


async def test_list_bridges_reads_the_manifest(w):
    (entry,) = await bridge_tools.list_bridges(url=B_URL)
    assert entry["venue"] == FLATBOARD_VENUE and entry["board"] == BOARD and entry["local"]


async def test_corroborate_finds_the_copies(w, monkeypatch):
    from bonnet.gateway import tools

    w.board.post("corroborate me", created=0)
    venue = w.runtime.venues[0]
    await w.runtime.ingest_binding(venue, venue.config.bindings[0])
    (mirror,) = w.articles()
    monkeypatch.setattr(tools, "_make_client", lambda url=None, verify=None: w._client(B_URL))
    result = await bridge_tools.corroborate(mirror.article_id.hex(), board=BOARD, origin=B)
    assert result["bridged"] is True
    assert result["recognized_origins"] == [B]
    assert [c["event_id"] for c in result["copies"]] == [mirror.event_id.hex()]


def test_accounts_file_is_validated(tmp_path, monkeypatch):
    bad = tmp_path / "a.toml"
    bad.write_text('[[account]]\nvenue = "v@h"\n')
    monkeypatch.setenv("BONNET_BRIDGE_ACCOUNTS", str(bad))
    with pytest.raises(ValueError, match="unusable"):
        bridge_tools.load_accounts()
    monkeypatch.setenv("BONNET_BRIDGE_ACCOUNTS", str(tmp_path / "missing.toml"))
    assert bridge_tools.load_accounts() == {}
