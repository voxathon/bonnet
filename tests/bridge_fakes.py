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

"""Test harness for bridges: a fake flatboard and bridge-origin servers.

`FakeFlatboard` serves the endpoints the design doc lists in §12 through an
`httpx.MockTransport`: newest-first pages of 50 with `since`, single
messages, and a FIFO whose evicted ids 404 with an `evicted` hint.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

import httpx

from bonnet.bridges.adapters.flatboard import PAGE_SIZE, FlatboardAdapter
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


@dataclass
class FakeFlatboard:
    """An in-memory flatboard. Tests add, evict and break messages directly."""

    messages: dict[int, dict] = field(default_factory=dict)
    first_id: int = 1
    next_id: int = 1
    offline: bool = False
    requests: list[str] = field(default_factory=list)
    accounts: dict[str, str] = field(default_factory=dict)  # user -> token
    request_ids: dict[str, int] = field(default_factory=dict)
    auth_failures: int = 0
    fail_posts: int = 0  # the next N posts answer HTTP 500
    rate_limit_posts: int = 0  # the next N posts answer HTTP 429
    refuse_posts: int = 0  # the next N posts answer HTTP 400
    lose_post_responses: int = 0  # the next N posts land, then answer HTTP 502
    retry_after: int = 15

    def post(self, text: str, author: str = "grok", reply_to: int = 0, created: int = 0) -> int:
        mid = self.next_id
        self.next_id += 1
        self.messages[mid] = {
            "id": mid,
            "author": author,
            "rating": 0,
            "author_rating": 0,
            "created": created,
            "reply_to": reply_to or None,
            "text": text,
        }
        return mid

    def evict_below(self, first_id: int) -> None:
        self.first_id = first_id
        for mid in [m for m in self.messages if m < first_id]:
            del self.messages[mid]

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(str(request.url))
        if self.offline:
            raise httpx.ConnectError("flatboard is down", request=request)
        path = request.url.path
        if path == "/board/post":
            return self._handle_post(request.url.params)
        if path.startswith("/board/page/") and path.endswith(".json"):
            page = int(path[len("/board/page/") : -len(".json")])
            since = int(request.url.params.get("since", "0") or 0)
            ids = sorted((m for m in self.messages if m > since), reverse=True)
            chunk = ids[(page - 1) * PAGE_SIZE : page * PAGE_SIZE]
            body = {
                "page": page,
                "pages": max(1, -(-len(ids) // PAGE_SIZE)),
                "total": len(self.messages),
                "first_id": self.first_id,
                "last_id": self.next_id - 1,
                "you": None,
                "msgs": [self.messages[i] for i in chunk],
            }
            return httpx.Response(200, json=body)
        if path.startswith("/board/msg/") and path.endswith(".json"):
            mid = int(path[len("/board/msg/") : -len(".json")])
            if mid not in self.messages:
                return httpx.Response(404, json={"evicted": mid < self.first_id})
            return httpx.Response(
                200,
                content=json.dumps(self.messages[mid]).encode(),
                headers={"content-type": "application/json"},
            )
        return httpx.Response(404)

    def _handle_post(self, params) -> httpx.Response:
        user, token = params.get("user", ""), params.get("token", "")
        if self.accounts.get(user) != token:
            self.auth_failures += 1
            return httpx.Response(401, json={"error": "auth_failed"})
        if self.fail_posts:
            self.fail_posts -= 1
            return httpx.Response(500, text="boom")
        if self.rate_limit_posts:
            self.rate_limit_posts -= 1
            return httpx.Response(
                429,
                json={"error": "rate_limited", "retry_after": self.retry_after},
                headers={"retry-after": str(self.retry_after)},
            )
        if self.refuse_posts:
            self.refuse_posts -= 1
            return httpx.Response(400, json={"error": "bad_request"})
        rid = params.get("request_id", "")
        if rid and rid in self.request_ids:
            return httpx.Response(
                200, json={"ok": True, "id": self.request_ids[rid], "replay": True}
            )
        reply_to = int(params.get("reply_to", "0") or 0)
        mid = self.post(params.get("text", ""), author=user, reply_to=reply_to)
        if rid:
            self.request_ids[rid] = mid
        if self.lose_post_responses:
            self.lose_post_responses -= 1
            return httpx.Response(502, text="bad gateway")
        return httpx.Response(200, json={"ok": True, "id": mid})

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self._handle))

    def adapter(self, venue: VenueConfig) -> FlatboardAdapter:
        return FlatboardAdapter(
            venue, http=self.client(), limiter=_NoLimit(), post_limiter=_NoLimit()
        )


class _NoLimit:
    async def wait(self) -> None:
        return None


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
    import httpx

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
