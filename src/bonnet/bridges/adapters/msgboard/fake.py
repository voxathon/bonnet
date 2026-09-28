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


"""An in-memory msgboard.dev, for tests: this adapter's `VenueFake`.

Serves the read endpoints the adapter uses through an `httpx.MockTransport`
in the venue's shapes (`fixtures/`): `/all` and `/messages` answer with the
newest `limit` matches, oldest first, and only `/messages` takes `before=`;
`/threads` lists by latest activity; an unknown thread is a 404. Posting
opens threads and adds messages with no account, with injectable failures.
Ids come from one counter, and `skip_ids` burns some the way private
channels do.

The answers to posts were never captured from the venue (see README.md):
they carry the stored thread or message, as the venue's API description
says, and the adapter reads either shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from bonnet.bridges.adapter import ForeignAccount
from bonnet.bridges.adapters.msgboard.adapter import (
    PAGE_SIZE,
    MsgboardAdapter,
    foreign_id,
    split_foreign_id,
)
from bonnet.bridges.venue import VenueConfig

_EPOCH = "2026-09-28T00:00:00Z"


@dataclass
class FakeMsgboard:
    """An in-memory msgboard. Tests add, remove and skip messages directly."""

    messages: dict[int, dict] = field(default_factory=dict)
    threads: dict[str, dict] = field(default_factory=dict)
    next_id: int = 1
    offline: bool = False
    requests: list[str] = field(default_factory=list)
    fail_posts: int = 0  # the next N posts answer HTTP 500
    rate_limit_posts: int = 0  # the next N posts answer HTTP 429
    lose_post_responses: int = 0  # the next N posts land, then answer HTTP 502
    retry_after: int = 5

    def open_thread(self, thread: str, title: str = "") -> str:
        self.threads.setdefault(thread, {"title": title or thread, "created_at": _EPOCH})
        return thread

    def post(self, thread: str, content: str, name: str | None = "grok", **extra) -> int:
        self.open_thread(thread)
        mid = self.next_id
        self.next_id += 1
        msg = {"id": mid, "thread": thread, "name": name, "content": content,
               "created_at": _EPOCH}  # fmt: skip
        if extra:
            msg["extra"] = extra
        self.messages[mid] = msg
        return mid

    def skip_ids(self, n: int) -> None:
        """Ids spent where no public read sees them (private channels)."""
        self.next_id += n

    def _thread_info(self, thread: str) -> dict:
        ids = [i for i, m in self.messages.items() if m["thread"] == thread]
        last = self.messages[max(ids)]["created_at"] if ids else _EPOCH
        return {
            "id": thread,
            "title": self.threads[thread]["title"],
            "listed": True,
            "created_at": self.threads[thread]["created_at"],
            "last_message_at": last,
            "message_count": len(ids),
            "url": f"https://msgboard.test/messages?thread={thread}",
        }

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(str(request.url))
        if self.offline:
            raise httpx.ConnectError("msgboard is down", request=request)
        if request.method == "POST":
            return self._handle_post(request)
        params = request.url.params
        limit = min(int(params.get("limit", "20")), PAGE_SIZE)
        since = int(params.get("since", "0") or 0)
        before = int(params["before"]) if params.get("before") else None
        path = request.url.path
        if path == "/all":
            ids = sorted(i for i in self.messages if i > since)[-limit:]
            return httpx.Response(
                200,
                json={
                    "messages": [self.messages[i] for i in ids],
                    "count": len(ids),
                    "limit": limit,
                    "poll": f"https://msgboard.test/all?since={max(ids, default=since)}&wait=25",
                },
            )
        if path == "/messages":
            thread = params.get("thread", "")
            if thread not in self.threads:
                return httpx.Response(404, json={"error": "No such thread.", "usage": "..."})
            ids = sorted(
                i
                for i, m in self.messages.items()
                if m["thread"] == thread and i > since and (before is None or i < before)
            )
            total = sum(1 for m in self.messages.values() if m["thread"] == thread)
            ids = ids[-limit:]
            return httpx.Response(
                200,
                json={
                    "thread": self._thread_info(thread),
                    "messages": [self.messages[i] for i in ids],
                    "count": len(ids),
                    "total": total,
                    "limit": limit,
                    "poll": f"https://msgboard.test/messages?thread={thread}&wait=25",
                },
            )
        if path == "/threads":
            infos = [self._thread_info(t) for t in self.threads]
            infos.sort(key=lambda t: max(
                (i for i, m in self.messages.items() if m["thread"] == t["id"]), default=0
            ), reverse=True)  # fmt: skip
            return httpx.Response(
                200,
                json={
                    "threads": infos[:limit],
                    "count": len(infos[:limit]),
                    "total": len(infos),
                    "limit": limit,
                },
            )
        return httpx.Response(404, json={"error": "No such endpoint.", "usage": "..."})

    def _handle_post(self, request: httpx.Request) -> httpx.Response:
        form = dict(httpx.QueryParams(request.content.decode()))
        if self.fail_posts:
            self.fail_posts -= 1
            return httpx.Response(500, text="boom")
        if self.rate_limit_posts:
            self.rate_limit_posts -= 1
            return httpx.Response(
                429, json={"error": "slow down"}, headers={"retry-after": str(self.retry_after)}
            )
        name = form.get("name") or None
        if request.url.path == "/threads":
            thread = self.open_thread(f"{0x5EED + len(self.threads):012x}", form.get("title", ""))
            return httpx.Response(200, json=self._thread_info(thread))
        if request.url.path == "/messages":
            thread = form.get("thread", "")
            if thread not in self.threads:
                return httpx.Response(404, json={"error": "No such thread.", "usage": "..."})
            mid = self.post(thread, form.get("content", ""), name=name)
            if self.lose_post_responses:
                self.lose_post_responses -= 1
                return httpx.Response(502, text="bad gateway")
            return httpx.Response(
                200,
                json={
                    **self.messages[mid],
                    "poll": f"https://msgboard.test/messages?thread={thread}&since={mid}&wait=25",
                },
            )
        return httpx.Response(404, json={"error": "No such endpoint.", "usage": "..."})

    # -- VenueFake (bonnet.bridges.conformance) ---------------------------

    def venue_config(self) -> VenueConfig:
        return VenueConfig(type="msgboard", venue="msgboard@msgboard.test",
                           url="https://msgboard.test")  # fmt: skip

    def native_post(self, text: str, author: str = "alice", reply_to: str | None = None) -> str:
        if reply_to:
            split = split_foreign_id(reply_to)
            assert split is not None
            thread = split[0]
        else:
            thread = self.open_thread(f"{len(self.threads) + 1:012x}")
        return foreign_id(thread, self.post(thread, text, name=author))

    def remove(self, foreign_id: str) -> None:
        split = split_foreign_id(foreign_id)
        if split is not None:
            self.messages.pop(split[1], None)

    def good_account(self) -> ForeignAccount:
        return ForeignAccount("tester", "")

    def rate_limit_next_post(self) -> None:
        self.rate_limit_posts += 1

    def venue_posts(self) -> list[str]:
        return [foreign_id(m["thread"], i) for i, m in sorted(self.messages.items())]

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self._handle))

    def adapter(self, venue: VenueConfig) -> MsgboardAdapter:
        return MsgboardAdapter(venue, http=self.client(), limiter=_NoLimit())


class _NoLimit:
    async def wait(self) -> None:
        return None
