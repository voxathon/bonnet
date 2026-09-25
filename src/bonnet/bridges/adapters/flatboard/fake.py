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


"""An in-memory flatboard, for tests: this adapter's `VenueFake`.

Serves the endpoints the adapter uses (design doc §12) through an
`httpx.MockTransport`: newest-first pages of 50 with `since`, single
messages, a FIFO whose evicted ids 404 with an `evicted` hint, and
`/board/post` with accounts, `request_id` replays and injectable failures.
Tests add, evict and break messages directly; the conformance suite
(`bonnet.bridges.conformance`) drives it through the `VenueFake` methods.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import httpx

from bonnet.bridges.adapter import ForeignAccount
from bonnet.bridges.adapters.flatboard.adapter import PAGE_SIZE, FlatboardAdapter
from bonnet.bridges.venue import VenueConfig


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

    # -- VenueFake (bonnet.bridges.conformance) ---------------------------

    def venue_config(self) -> VenueConfig:
        return VenueConfig(type="flatboard", venue="flatboard@flatboard.test",
                           url="https://flatboard.test")  # fmt: skip

    def native_post(self, text: str, author: str = "alice", reply_to: str | None = None) -> str:
        return str(self.post(text, author=author, reply_to=int(reply_to or 0)))

    def remove(self, foreign_id: str) -> None:
        # The FIFO evicts from the oldest end; an id gone from the middle
        # reads as unknown, which is Gone all the same.
        self.messages.pop(int(foreign_id), None)

    def good_account(self) -> ForeignAccount:
        self.accounts["tester"] = "good-token"
        return ForeignAccount("tester", "good-token")

    def bad_account(self) -> ForeignAccount:
        return ForeignAccount("tester", "wrong-token")

    def rate_limit_next_post(self) -> None:
        self.rate_limit_posts += 1

    def venue_posts(self) -> list[str]:
        return [str(i) for i in sorted(self.messages)]

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self._handle))

    def adapter(self, venue: VenueConfig) -> FlatboardAdapter:
        return FlatboardAdapter(
            venue, http=self.client(), limiter=_NoLimit(), post_limiter=_NoLimit()
        )


class _NoLimit:
    async def wait(self) -> None:
        return None
