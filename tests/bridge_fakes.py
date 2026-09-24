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
from bonnet.bridges.config import (
    BindingConfig,
    BridgeRuntimeConfig,
    VenueConfig,
    load_daemon_identity,
)
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

    def post(self, text: str, author: str = "grok", reply_to: int = 0, created: int = 0) -> int:
        mid = self.next_id
        self.next_id += 1
        self.messages[mid] = {
            "id": mid,
            "author": author,
            "rating": 0,
            "author_rating": 0,
            "created": created,
            "reply_to": reply_to,
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
        if path.startswith("/board/page/") and path.endswith(".json"):
            page = int(path[len("/board/page/") : -len(".json")])
            since = int(request.url.params.get("since", "0") or 0)
            ids = sorted((m for m in self.messages if m > since), reverse=True)
            chunk = ids[(page - 1) * PAGE_SIZE : page * PAGE_SIZE]
            body = {"first_id": self.first_id, "messages": [self.messages[i] for i in chunk]}
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

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self._handle))

    def adapter(self, venue: VenueConfig) -> FlatboardAdapter:
        return FlatboardAdapter(venue, http=self.client(), limiter=_NoLimit())


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
    keys = tmp_path / "bridge-keys"
    return BridgeRuntimeConfig(
        daemon_key=str(keys / "daemon.key"),
        master_secret=str(keys / "master.secret"),
        state_dir=str(tmp_path / "bridge-state"),
        venues=venues,
        **kw,
    )


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


def bridge_rules(daemon_pubkey: bytes) -> list[dict]:
    """§10.2: shipped reads and registration, articles on `~*`, the daemon rule."""
    return shipped_rules() + [
        {"effect": "allow", "match": {"registered": True}, "actions": ["write"],
         "commands": ["PUBLISH_RECORD"], "kinds": ["bonnet.article"], "boards": ["~*"]},
        {"effect": "allow", "match": {"pubkey": "hex:" + daemon_pubkey.hex()},
         "actions": ["write"], "commands": ["PUBLISH_RECORD"],
         "kinds": ["bonnet.bridge.*", "bonnet.board.create", "bonnet.article"],
         "boards": ["~*", ""]},
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
            rules = bridge_rules(load_daemon_identity(bridge_runtime).public_key)
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
