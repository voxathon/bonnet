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

"""Bridges milestone M4, part 1: admission of crossposters' home keys (design doc §6).

A real home origin and a real bridge origin. The bridge's admission client
dials the home in process, so first contact, rechecks, rotation at home,
bans, unreachable homes, name collisions and the concurrency guards all run
against the actual USER_GET the home serves.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from bonnet.bridges import model
from bonnet.bridges.admission import AdmissionClient, AdmissionRefused, base_name
from bonnet.bridges.config import AdmissionConfig, parse_bridge_admission
from bonnet.bridges.model import BridgeMetadata
from bonnet.core.crypto import Identity
from bonnet.core.kinds import KIND_ARTICLE, KIND_USER_KEY_ROTATE, KIND_USER_REGISTER
from bonnet.core.record import (
    Intent,
    MetadataMap,
    compute_body_hash,
    metadata_bytes,
    metadata_text,
    metadata_u64,
    sign_key_rotation_proof,
)
from bonnet.net.firehose_wire import ProtocolError
from tests.bridge_fakes import (
    asgi_transport_factory,
    make_config,
    publish_as,
    runtime_config,
    shipped_rules,
    venue_config,
)

B = "bridge.test"
HOME = "home.test"
HOME_URL = "https://home.test"
BOARD = "~flatboard"
NOW = 1_800_000_000

HOME_RULES = shipped_rules() + [
    {"effect": "allow", "match": {"registered": True}, "actions": ["write"],
     "commands": ["PUBLISH_RECORD"],
     "kinds": ["bonnet.article", "bonnet.board.create", "bonnet.user.key.rotate"],
     "boards": ["*"]},
]  # fmt: skip


class Clock:
    def __init__(self):
        self.t = float(NOW)

    def __call__(self):
        return self.t


def _register(origin: str, identity: Identity, name: str) -> Intent:
    return Intent(
        event_id=os.urandom(32),
        kind=KIND_USER_REGISTER,
        origin=origin,
        actor_pubkey=identity.public_key,
        actor_registrar=origin,
        metadata=MetadataMap(
            [metadata_text(1, name), metadata_bytes(2, identity.public_key), metadata_u64(3, 0)]
        ),
    )


class World:
    def __init__(self, tmp_path, **admission):
        from bonnet.app.server import BonnetServer

        self.tmp_path = tmp_path
        self.homes: dict[str, object] = {}
        self.home = self.add_home(HOME)
        rt = runtime_config(tmp_path / B, [venue_config()])
        config = make_config(
            tmp_path, B, rt, bridge_admission=AdmissionConfig(enabled=True, **admission)
        )
        self.bridge = BonnetServer(config)
        self.admission = self.bridge.command_handler._admission
        self.clock = Clock()
        self.admission._clock = self.clock
        self.urls = {f"https://{o}": s for o, s in self.homes.items()}
        self.admission._client = AdmissionClient(
            asgi_transport_factory(self.urls, str(tmp_path / "admission-trust.db"))
        )

    def add_home(self, origin: str):
        from bonnet.app.server import BonnetServer

        server = BonnetServer(make_config(self.tmp_path, origin, rules=HOME_RULES))
        self.homes[origin] = server
        if hasattr(self, "urls"):
            self.urls[f"https://{origin}"] = server
        return server

    async def start(self):
        from bonnet.bridges.runtime import BridgeRuntime

        self.bridge.loop = asyncio.get_running_loop()
        rt = BridgeRuntime(self.bridge)
        await rt.bindings.ensure_daemon()
        await rt.bindings.ensure_board(BOARD)
        await rt.close()

    async def user(self, name: str, home=None) -> Identity:
        home = home or self.home
        identity = Identity.generate()
        await publish_as(home, identity, _register(home.config.origin, identity, name))
        return identity

    def crosspost(
        self, identity: Identity, text: str = "hi", home_origin=HOME, home_url=HOME_URL, **meta
    ):
        body = text.encode()
        fields = BridgeMetadata(
            bridge_role=model.ROLE_CROSSPOST,
            venue="flatboard@flatboard.test",
            channel="",
            home_origin=home_origin,
            home_url=home_url,
            **meta,
        ).to_fields()
        base = MetadataMap([metadata_text(1, text), metadata_text(4, "text/plain")])
        return Intent(
            event_id=os.urandom(32),
            kind=KIND_ARTICLE,
            origin=B,
            actor_pubkey=identity.public_key,
            actor_registrar=B,
            board=BOARD,
            article_id=os.urandom(32),
            metadata=model.merge_metadata(base, fields),
            body_hash=compute_body_hash(body),
            body_size=len(body),
        ), body

    async def post(self, identity: Identity, **kw):
        intent, body = self.crosspost(identity, **kw)
        return await publish_as(self.bridge, identity, intent, body)

    def name_on_bridge(self, identity: Identity) -> str | None:
        user = self.bridge.users.get_user_by_pubkey(B, identity.public_key)
        return None if user is None or user.get("revoked") else user["username"]

    async def rotate_at_home(self, old: Identity, name: str) -> Identity:
        new = Identity.generate()
        proof = sign_key_rotation_proof(new, HOME, old.public_key, new.public_key)
        await publish_as(
            self.home,
            old,
            Intent(
                event_id=os.urandom(32),
                kind=KIND_USER_KEY_ROTATE,
                origin=HOME,
                actor_pubkey=old.public_key,
                actor_username=name,
                actor_registrar=HOME,
                metadata=MetadataMap([metadata_bytes(1, new.public_key), metadata_bytes(2, proof)]),
            ),
        )
        return new

    def close(self):
        self.bridge.close()
        for s in self.homes.values():
            s.close()


@pytest.fixture
async def w(tmp_path):
    world = World(tmp_path)
    await world.start()
    yield world
    world.close()


async def _refused(coro, text: str):
    with pytest.raises(ProtocolError) as e:
        await coro
    assert e.value.code == 0x0004, e.value
    assert text in str(e.value), e.value


# ---------------------------------------------------------------------------
# First contact (§6.2)
# ---------------------------------------------------------------------------


async def test_first_contact_admits_and_publishes(w):
    moxxie = await w.user("moxxie")
    result = await w.post(moxxie)
    assert result.kind == KIND_ARTICLE
    assert w.name_on_bridge(moxxie) == "moxxie"

    admission = w.bridge.bridges.admission(B, moxxie.public_key)
    assert admission["home_origin"] == HOME and admission["home_url"] == HOME_URL
    assert admission["home_username"] == "moxxie" and admission["active"]

    reg = w.bridge.firehose.get_event_by_id(B, admission["reg_event_id"])
    assert reg.actor_pubkey == w.bridge.server_identity.public_key
    assert BridgeMetadata.from_metadata(reg.metadata).home_origin == HOME


async def test_later_writes_need_the_pinned_home(w):
    moxxie = await w.user("moxxie")
    await w.post(moxxie)
    await w.post(moxxie)
    await _refused(w.post(moxxie, home_origin="elsewhere.test"), "does not match")
    await _refused(w.post(moxxie, home_url="https://other.url"), "does not match")


async def test_unknown_at_home_is_refused(w):
    stranger = Identity.generate()
    await _refused(w.post(stranger), "not registered at home")
    assert w.name_on_bridge(stranger) is None


async def test_home_cannot_be_the_bridge_itself(w):
    user = Identity.generate()
    await _refused(w.post(user, home_origin=B, home_url=f"https://{B}"), "register here first")


async def test_home_url_serving_another_origin_is_refused(w):
    user = await w.user("moxxie")
    w.add_home("impostor.test")
    await _refused(w.post(user, home_url="https://impostor.test"), "unreachable")


async def test_without_home_fields_an_unknown_key_gets_the_normal_refusal(w):
    user = await w.user("moxxie")
    intent, body = w.crosspost(user)
    intent.metadata = MetadataMap([metadata_text(1, "x"), metadata_text(4, "text/plain")])
    with pytest.raises(ProtocolError) as e:
        await publish_as(w.bridge, user, intent, body)
    assert "Not permitted" in str(e.value)


# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------


async def test_same_username_from_another_home_gets_a_suffix(w):
    other_home = w.add_home("other.test")
    first = await w.user("moxxie")
    second = await w.user("moxxie", home=other_home)
    await w.post(first)
    await w.post(second, home_origin="other.test", home_url="https://other.test")
    import hashlib

    expected = "moxxie-" + hashlib.sha256(b"other.test").hexdigest()[:4]
    assert w.name_on_bridge(second) == expected


def test_base_name_sanitizes():
    assert base_name("mox~xie") == "mox-xie"
    assert base_name("  ") == "user"
    assert base_name("a<b>") == "ab"


# ---------------------------------------------------------------------------
# Rechecks and staleness (§6.3)
# ---------------------------------------------------------------------------


async def test_home_rotation_is_caught_on_the_next_recheck(w):
    k1 = await w.user("moxxie")
    await w.post(k1)
    await w.rotate_at_home(k1, "moxxie")
    await w.post(k1)  # still within recheck_seconds: the cached check stands
    w.clock.t += 301
    await _refused(w.post(k1), "rotated at home")


async def test_unreachable_home_fails_open_until_stale(w):
    k = await w.user("moxxie")
    await w.post(k)
    del w.urls[HOME_URL]
    w.admission._client._transports.clear()
    w.clock.t += 301
    await w.post(k)  # unreachable, but the last good check is recent
    w.clock.t += 86400
    await _refused(w.post(k), "home origin unreachable")


# ---------------------------------------------------------------------------
# Rotation at home (§6.4)
# ---------------------------------------------------------------------------


async def test_successor_key_takes_over_the_name(w):
    k1 = await w.user("moxxie")
    await w.post(k1)
    k2 = await w.rotate_at_home(k1, "moxxie")
    await w.post(k2)
    assert w.name_on_bridge(k2) == "moxxie"
    assert w.name_on_bridge(k1) is None
    assert w.bridge.bridges.admission(B, k1.public_key)["active"] is False


async def test_a_key_that_is_not_the_successor_is_refused(w):
    """The name was revoked at home and re-registered by someone else."""
    from bonnet.core.kinds import KIND_USER_REVOKE

    k1 = await w.user("moxxie")
    await w.post(k1)
    root = w.home.server_identity
    reg = w.home.users.get_user_by_pubkey(HOME, k1.public_key)
    reg_event = next(
        r.event_id
        for r in w.home.firehose.get_events_range(HOME, 1, 1000)
        if r.kind == KIND_USER_REGISTER and r.metadata.get_bytes(2) == k1.public_key
    )
    assert reg is not None
    await publish_as(
        w.home,
        root,
        Intent(
            event_id=os.urandom(32),
            kind=KIND_USER_REVOKE,
            origin=HOME,
            actor_pubkey=root.public_key,
            actor_username="root",
            actor_registrar=HOME,
            target_origin=HOME,
            target_event_id=reg_event,
            metadata=MetadataMap([metadata_bytes(1, k1.public_key)]),
        ),
    )
    squatter = await w.user("moxxie")  # the freed name, a different person
    await _refused(w.post(squatter), "does not succeed")
    assert w.name_on_bridge(k1) == "moxxie"


async def test_successor_of_a_banned_key_is_refused(w, monkeypatch):
    k1 = await w.user("moxxie")
    await w.post(k1)
    monkeypatch.setattr(w.admission, "_banned", lambda pubkey: pubkey == k1.public_key)
    k2 = await w.rotate_at_home(k1, "moxxie")
    await _refused(w.post(k2), "banned here")
    assert w.name_on_bridge(k1) == "moxxie"


async def test_chain_walk_is_capped(w):
    w.admission._config.max_chain_hops = 1
    k1 = await w.user("moxxie")
    await w.post(k1)
    k2 = await w.rotate_at_home(k1, "moxxie")
    k3 = await w.rotate_at_home(k2, "moxxie")
    await _refused(w.post(k3), "chain too long")


# ---------------------------------------------------------------------------
# Running admission I/O (§6.6)
# ---------------------------------------------------------------------------


async def test_busy_admission_refuses(w):
    k = await w.user("moxxie")
    assert w.admission._slots.acquire(blocking=False)
    for _ in range(7):
        w.admission._slots.acquire(blocking=False)
    try:
        await _refused(w.post(k), "busy")
    finally:
        for _ in range(8):
            w.admission._slots.release()


async def test_admission_refuses_on_the_loop_thread(w):
    k = await w.user("moxxie")
    with pytest.raises(AdmissionRefused, match="event loop thread"):
        w.admission._ask(HOME, HOME_URL, k.public_key)


async def test_slow_home_times_out(w, monkeypatch):
    k = await w.user("moxxie")
    w.admission._config.timeout_seconds = 0.05

    async def slow(*args):
        await asyncio.sleep(1)

    monkeypatch.setattr(w.admission._client, "lookup", slow)
    await _refused(w.post(k), "did not answer in time")


async def test_no_loop_means_refused(w):
    k = await w.user("moxxie")
    w.bridge.loop = None
    await _refused(w.post(k), "no server loop")


# ---------------------------------------------------------------------------
# Config and capability
# ---------------------------------------------------------------------------


def test_admission_config_parses():
    cfg, unknown = parse_bridge_admission({"enabled": True, "timeout_seconds": 2, "odd": 1})
    assert cfg.enabled and cfg.timeout_seconds == 2 and unknown == ["bridge_admission.odd"]
    with pytest.raises(ValueError):
        parse_bridge_admission({"max_chain_hops": 0})


async def test_capability_advertised_only_when_enabled(w, tmp_path):
    assert "bonnet.bridge.admission" in w.bridge.http_server._capabilities()
    assert "bonnet.bridge.admission" not in w.home.http_server._capabilities()
