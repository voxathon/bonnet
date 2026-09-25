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

"""Test harness for bridges: bridge-origin servers and their config.

`FakeFlatboard` ships with its adapter (bonnet.bridges.adapters.flatboard.fake)
and is re-exported here for the runtime tests.
"""

from __future__ import annotations

import os

import httpx

from bonnet.bridges.adapters.flatboard.fake import FakeFlatboard, _NoLimit  # noqa: F401
from bonnet.bridges.config import BindingConfig, BridgeRuntimeConfig, VenueConfig
from bonnet.core.acl import ACLEvaluator, ACLRule
from bonnet.core.config import FirehoseConfig

FLATBOARD_URL = "https://flatboard.test"
FLATBOARD_VENUE = "flatboard@flatboard.test"

READ_COMMANDS = [
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


def venue_config(board: str = "~flatboard", **binding) -> VenueConfig:
    return VenueConfig(
        type="flatboard",
        venue=FLATBOARD_VENUE,
        url=FLATBOARD_URL,
        poll_interval_seconds=1,
        bindings=[BindingConfig(board=board, **binding)],
    )


def runtime_config(tmp_path, venues: list[VenueConfig], **kw) -> BridgeRuntimeConfig:
    """`tmp_path` is unused: the index and puppet secret live in the server's data_dir."""
    return BridgeRuntimeConfig(venues=venues, **kw)


def shipped_rules() -> list[dict]:
    return [
        {"effect": "allow", "match": {"anonymous": True}, "actions": ["read"],
         "commands": READ_COMMANDS, "boards": ["*"]},
        {"effect": "allow", "match": {"unknown": True}, "actions": ["read"],
         "commands": ["PERMISSIONS"]},
        {"effect": "allow", "match": {"unknown": True}, "actions": ["write"],
         "commands": ["PUBLISH_RECORD"], "kinds": ["bonnet.user.register"]},
        {"effect": "allow", "match": {"registered": True}, "actions": ["read"],
         "commands": READ_COMMANDS, "boards": ["*"]},
    ]  # fmt: skip


def bridge_rules() -> list[dict]:
    """§10.2: shipped reads and registration, and articles on `~*`.

    The server's own key, which signs bridge facts, is always its own admin.
    """
    return shipped_rules() + [
        {"effect": "allow", "match": {"registered": True}, "actions": ["write"],
         "commands": ["PUBLISH_RECORD"], "kinds": ["bonnet.article"], "boards": ["~*"]},
    ]  # fmt: skip


def make_config(
    tmp_path,
    origin: str,
    bridge_runtime: BridgeRuntimeConfig | None = None,
    rules: list[dict] | None = None,
    **kw,
) -> FirehoseConfig:
    root = tmp_path / origin
    if rules is None:
        if bridge_runtime is not None:
            rules = bridge_rules()
        else:
            rules = shipped_rules() + [
                {"effect": "allow", "match": {"registered": True}, "actions": ["write"],
                 "commands": ["PUBLISH_RECORD"],
                 "kinds": ["bonnet.article", "bonnet.board.create"], "boards": ["*"]},
            ]  # fmt: skip
    config = FirehoseConfig(
        origin=origin,
        hostname=origin,
        data_dir=str(root / "data"),
        boards_dir=str(root / "boards"),
        events_bodies_dir=str(root / "event_bodies"),
        port=2272,
        tls_enabled=False,
        acl=ACLEvaluator([ACLRule.from_dict(r) for r in rules]),
        bridge_runtime=bridge_runtime,
        **kw,
    )
    for d in (config.data_dir, config.boards_dir, config.events_bodies_dir):
        os.makedirs(d, exist_ok=True)
    return config


class ServerSyncClient:
    """Serves one BonnetServer's firehose to another in process (a SyncClient)."""

    def __init__(self, server):
        self._server = server

    async def fetch_head(self, origin):
        return self._server.firehose.get_head(origin), b""

    async def fetch_range(self, origin, start_seq, max_count):
        import time

        from bonnet.core.record import compute_event_hash, encode_record, make_origin_witness

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


async def sync_from(consumer, source) -> None:
    """Pull `source`'s whole log into `consumer` and dispatch it."""
    origin = source.config.origin
    result = await consumer.sync_manager._sync_once(
        origin, ServerSyncClient(source), skip_allowlist=True
    )
    assert result.accepted or result.reason == "already up to date", result.reason
    consumer.dispatcher.dispatch_origin(origin)


async def read(server, frame: bytes) -> bytes:
    """Run a read frame through `server` as its anonymous principal."""
    import asyncio

    from bonnet.net.firehose_commands import derive_context

    anon = server.anonymous_identity.public_key
    ctx = derive_context(server.users, server.config.origin, anon, "test", anon)
    return await asyncio.to_thread(server.command_handler.handle, frame, ctx)


async def publish_as(server, identity, intent, body: bytes = b""):
    """Publish with the context an HTTP request signed by `identity` would get."""
    import asyncio

    from bonnet.core.record import encode_intent, sign_intent
    from bonnet.net.firehose_commands import derive_context
    from bonnet.net.firehose_wire import build_publish_record, parse_publish_response

    frame = build_publish_record(intent, sign_intent(identity, encode_intent(intent)), body)
    ctx = derive_context(
        server.users,
        server.config.origin,
        identity.public_key,
        "test",
        server.anonymous_identity.public_key,
    )
    resp = await asyncio.to_thread(server.command_handler.handle, frame, ctx)
    return parse_publish_response(resp)


def asgi_transport_factory(servers_by_url: dict, trust_store_path: str):
    """An admission transport factory that dials in-process servers by URL."""

    from bonnet.bridges.admission import HomeUnreachable
    from bonnet.net.firehose_transport import FirehoseTransport

    def make(url: str):
        server = servers_by_url.get(url)
        if server is None:
            raise HomeUnreachable(f"no such home {url}")
        t = FirehoseTransport(url, verify=False, trust_store_path=trust_store_path)
        t._http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=server.http_server), base_url=url
        )
        return t

    return make
