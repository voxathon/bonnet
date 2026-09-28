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

"""msgboard.dev adapter: public threads of flat messages, read-only.

Everything on msgboard is a thread; message ids are one counter across the
whole board, so they order posts everywhere. Every listing answers with the
*newest* `limit` messages (at most 100) that match, oldest first within the
answer: `since=` doesn't page forward, it only drops what's older. Reading
further back takes `before=`, which only a single thread has.

API reference: `/llms.txt` and `/openapi.json` on the venue. A message is
`{id, thread, name, content, created_at}`, plus `extra` when its poster
sent fields of their own.

There is no endpoint for one message, so a foreign id carries its thread:
`<thread>/<id>`. A thread's first message is its root, and every later one
replies to it.
"""

from __future__ import annotations

import json
from datetime import datetime
from urllib.parse import urlencode

import httpx

from bonnet.bridges.adapter import ForeignPost, Gone, RateLimits, ReadLimiter, VenueError
from bonnet.bridges.venue import VenueConfig

# The venue's ceiling on `limit=`, everywhere.
PAGE_SIZE = 100
# Pages walked back through a thread per poll once a cursor exists.
MAX_CATCHUP_PAGES = 20
# Pages walked back to find a thread's first message before giving up on it.
MAX_ROOT_PAGES = 20


def _parse_created(value) -> int | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def _id(value) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value > 0 else None


def _usable(m) -> bool:
    return (
        isinstance(m, dict)
        and _id(m.get("id")) is not None
        and isinstance(m.get("thread"), str)
        and bool(m["thread"])
    )


def foreign_id(thread: str, message_id: int) -> str:
    return f"{thread}/{message_id}"


def split_foreign_id(value: str) -> tuple[str, int] | None:
    """`(thread, message id)` from `<thread>/<id>`, or None. Thread names are
    the venue's to choose, so only the part after the last `/` is the id."""
    thread, sep, n = value.rpartition("/")
    if not sep or not thread or not n.isdigit() or int(n) <= 0:
        return None
    return thread, int(n)


def _canonical(msg: dict) -> bytes:
    return json.dumps(msg, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


class _NoSuchThread(Exception):
    pass


class MsgboardAdapter:
    protocol = 1
    type = "msgboard"
    # Messages never change and nothing lists deletions. Posting needs no
    # account at all, so there is nothing for "write" to authenticate:
    # read-only until the bridge has a model for anonymous venues.
    capabilities = frozenset({"read", "threads"})
    # The venue publishes no read limit; this stays well clear of trouble.
    limits = RateLimits(reads_per_minute=60)
    options: frozenset[str] = frozenset()

    def __init__(
        self,
        venue: VenueConfig,
        http: httpx.AsyncClient | None = None,
        limiter=None,
    ):
        self.venue = venue.venue
        self._base = venue.url.rstrip("/")
        self._backfill_pages = venue.backfill_pages
        self._http = http or httpx.AsyncClient(timeout=30.0)
        self._owns_http = http is None
        self._limiter = limiter or ReadLimiter(self.limits.reads_per_minute)
        # thread -> the foreign id of its first message. Never changes.
        self._roots: dict[str, str] = {}

    async def close(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    # -- requests ---------------------------------------------------------

    async def _get(self, path: str, params: dict) -> dict:
        await self._limiter.wait()
        url = f"{self._base}{path}"
        try:
            resp = await self._http.get(url, params={**params, "format": "json"})
        except httpx.HTTPError as e:
            raise VenueError(f"msgboard {url}: {e or type(e).__name__}") from e
        if resp.status_code == 404 and "thread" in params:
            raise _NoSuchThread(params["thread"])
        if resp.status_code != 200:
            raise VenueError(f"msgboard {path}: HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as e:
            raise VenueError(f"msgboard {path}: bad JSON: {e}") from e
        if not isinstance(data, dict):
            raise VenueError(f"msgboard {path}: unexpected body")
        return data

    async def _messages(self, path: str, params: dict) -> list[dict]:
        data = await self._get(path, params)
        messages = data.get("messages")
        if not isinstance(messages, list):
            raise VenueError(f"msgboard {path}: no message list")
        return [m for m in messages if _usable(m)]

    async def _thread_back(
        self, thread: str, after: int, before: int | None, max_pages: int
    ) -> dict[int, dict]:
        """Messages of `thread` with ids in (after, before), walking back from
        `before` (the newest if None). A walk that reaches the thread's first
        message notes it as the thread's root."""
        found: dict[int, dict] = {}
        for _ in range(max_pages):
            params: dict = {"thread": thread, "limit": PAGE_SIZE}
            if before is not None:
                params["before"] = before
            page = await self._messages("/messages", params)
            ids = [m["id"] for m in page]
            found.update((m["id"], m) for m in page if m["id"] > after)
            if len(page) < PAGE_SIZE:
                lowest = min(ids, default=before)
                if lowest is not None:
                    self._roots.setdefault(thread, foreign_id(thread, lowest))
                break
            if min(ids) <= after:
                break
            before = min(ids)
        return found

    async def _root(self, thread: str) -> str | None:
        """The foreign id of `thread`'s first message, or None if it can't be
        found (the thread is gone, or longer than the walk allows)."""
        if thread not in self._roots:
            try:
                await self._thread_back(thread, 0, None, MAX_ROOT_PAGES)
            except _NoSuchThread:
                return None
        return self._roots.get(thread)

    async def _board_since(self, since: int | None) -> dict[int, dict]:
        """New messages across every public thread.

        `/all` gives only the newest page after `since`. When that page is
        full there may be a gap behind it, which each recently active thread
        fills with `before=`. `/threads` lists the 100 most recently active,
        so a gap spread over more threads than that loses the rest.
        """
        params: dict = {"limit": PAGE_SIZE}
        if since is not None:
            params["since"] = since
        page = await self._messages("/all", params)
        found = {m["id"]: m for m in page}
        if since is None or len(page) < PAGE_SIZE:
            return found
        oldest = min(found)
        listing = await self._get("/threads", {"limit": PAGE_SIZE})
        threads = listing.get("threads")
        for t in threads if isinstance(threads, list) else []:
            thread = t.get("id") if isinstance(t, dict) else None
            if not isinstance(thread, str) or not thread:
                continue
            try:
                more = await self._thread_back(thread, since, oldest, MAX_CATCHUP_PAGES)
            except _NoSuchThread:
                continue
            found.update(more)
        return found

    async def _posts(self, channel: str, messages: list[dict]) -> list[ForeignPost]:
        roots = {t: await self._root(t) for t in dict.fromkeys(m["thread"] for m in messages)}
        return [self._post(channel, m, roots[m["thread"]]) for m in messages]

    def _post(self, channel: str, msg: dict, root: str | None) -> ForeignPost:
        thread, n = msg["thread"], msg["id"]
        fid = foreign_id(thread, n)
        name = msg.get("name")
        name = name if isinstance(name, str) else ""
        text = msg.get("content")
        # A thread's later messages reply to its first. With the first out of
        # reach, the post stands alone rather than guess.
        reply_to = root if root is not None and root != fid else None
        return ForeignPost(
            venue=self.venue,
            channel=channel,
            foreign_id=fid,
            author_handle=name,
            # No accounts: a name is whatever the poster typed.
            author_id=name,
            created_at=_parse_created(msg.get("created_at")),
            reply_to=reply_to,
            root_id=root,
            text=text if isinstance(text, str) else "",
            raw=_canonical(msg),
            raw_content_type="application/json",
            url=f"{self._base}/messages?"
            + urlencode({"thread": thread, "before": n + 1, "limit": 1}),
        )

    async def poll(self, channel: str, cursor: str | None) -> list[ForeignPost]:
        """The channel is a thread id, or "" for every public thread."""
        since = int(cursor) if cursor and cursor.isdigit() else None
        if channel:
            max_pages = MAX_CATCHUP_PAGES if since is not None else self._backfill_pages
            try:
                found = await self._thread_back(channel, since or 0, None, max_pages)
            except _NoSuchThread:
                raise VenueError(f"msgboard has no thread {channel!r}") from None
        else:
            found = await self._board_since(since)
        return await self._posts(channel, [found[i] for i in sorted(found)])

    def cursor_after(self, post: ForeignPost) -> str:
        split = split_foreign_id(post.foreign_id)
        assert split is not None
        return str(split[1])

    def cursor_from_ids(self, foreign_ids: list[str]) -> str | None:
        ids = [s[1] for i in foreign_ids if (s := split_foreign_id(i)) is not None]
        return str(max(ids)) if ids else None

    async def fetch(self, channel: str, foreign_id: str) -> ForeignPost | Gone:
        split = split_foreign_id(foreign_id)
        if split is None:
            return Gone(foreign_id, "unknown")
        thread, n = split
        try:
            page = await self._messages(
                "/messages", {"thread": thread, "before": n + 1, "limit": 1}
            )
        except _NoSuchThread:
            return Gone(foreign_id, "unknown")
        msg = next((m for m in page if m["id"] == n and m["thread"] == thread), None)
        if msg is None:
            return Gone(foreign_id, "unknown")
        return self._post(channel, msg, await self._root(thread))
