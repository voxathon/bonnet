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

"""msgboard.dev adapter: public threads of flat messages, no accounts.

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

Posting takes no account: a name is whatever the poster sends, so the
adapter posts under the account's `user` and ignores its token. A post with
no `reply_to` on the whole-board channel opens a thread of its own.
"""

from __future__ import annotations

import json
from datetime import datetime
from urllib.parse import urlencode

import httpx

from bonnet.bridges.adapter import (
    ForeignAccount,
    ForeignPost,
    Gone,
    RateLimits,
    ReadLimiter,
    VenueError,
    VenueRateLimited,
    VenueUncertain,
)
from bonnet.bridges.model import normalize_foreign_text, truncate_utf8
from bonnet.bridges.venue import VenueConfig

# The venue's ceiling on `limit=`, everywhere.
PAGE_SIZE = 100
# Pages walked back through a thread per poll once a cursor exists.
MAX_CATCHUP_PAGES = 20
# Pages walked back to find a thread's first message before giving up on it.
MAX_ROOT_PAGES = 20
# `content` is capped at 8192 characters; bytes keep the cut exact.
MAX_TEXT_BYTES = 8192
MAX_TITLE_CHARS = 200
MAX_NAME_CHARS = 64


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
    # Messages never change and nothing lists deletions. "write" without
    # "signup": posting takes no account, so there is none to get or link.
    capabilities = frozenset({"read", "threads", "write"})
    # The venue publishes no limits; these stay well clear of trouble.
    limits = RateLimits(reads_per_minute=60, posts_min_interval_seconds=5.0)
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

    # -- write ------------------------------------------------------------

    def max_text_bytes(self) -> int:
        return MAX_TEXT_BYTES

    def render_outbound(self, text: str, marker: str, attribution: str | None) -> str:
        head = f"{attribution}: " if attribution else ""
        tail = f"\n{marker}"
        budget = MAX_TEXT_BYTES - len((head + tail).encode("utf-8"))
        body = truncate_utf8(normalize_foreign_text(text), max(budget, 0)).rstrip()
        return f"{head}{body}{tail}"

    async def _send(self, path: str, form: dict, uncertain: bool) -> dict:
        """POST `form`. With `uncertain`, a failure that doesn't say whether
        the venue took it raises VenueUncertain; else VenueError."""
        await self._limiter.wait()
        fail = VenueUncertain if uncertain else VenueError
        try:
            resp = await self._http.post(f"{self._base}{path}", data={**form, "format": "json"})
        except httpx.HTTPError as e:
            raise fail(f"msgboard {path}: {type(e).__name__}") from None
        if resp.status_code == 429:
            try:
                retry_after: float | None = float(resp.headers.get("retry-after", ""))
            except ValueError:
                retry_after = None
            raise VenueRateLimited(f"msgboard {path}: rate limited", retry_after)
        if resp.status_code >= 500:
            raise fail(f"msgboard {path}: HTTP {resp.status_code}")
        if resp.status_code != 200:
            raise VenueError(f"msgboard {path}: HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError:
            raise fail(f"msgboard {path}: bad JSON") from None
        if not isinstance(data, dict):
            raise fail(f"msgboard {path}: unexpected body")
        return data

    async def _open_thread(self, title: str, name: str) -> str:
        form = {"title": title[:MAX_TITLE_CHARS] or "untitled"}
        if name:
            form["name"] = name
        data = await self._send("/threads", form, uncertain=False)
        # The thread comes back on its own or under "thread".
        thread = data.get("thread") if isinstance(data.get("thread"), dict) else data
        tid = thread.get("id") if isinstance(thread, dict) else None
        if not isinstance(tid, str) or not tid:
            raise VenueError("msgboard /threads: no thread id in the answer")
        return tid

    async def post(
        self,
        account: ForeignAccount,
        channel: str,
        text: str,
        reply_to: str | None,
        idempotency_key: str,
    ) -> ForeignPost:
        """Post under `account.user` (its token means nothing here): into
        `reply_to`'s thread, else the channel's, else a new thread named after
        the text's first line."""
        name = account.user[:MAX_NAME_CHARS]
        split = split_foreign_id(reply_to) if reply_to else None
        thread = split[0] if split is not None else channel
        if not thread:
            thread = await self._open_thread(text.split("\n", 1)[0].strip(), name)
        form = {"thread": thread, "content": text}
        if name:
            form["name"] = name
        data = await self._send("/messages", form, uncertain=True)
        # The stored message comes back on its own or under "message".
        msg = data.get("message") if isinstance(data.get("message"), dict) else data
        n = _id(msg.get("id")) if isinstance(msg, dict) else None
        if n is None:
            raise VenueUncertain("msgboard /messages: no message id in the answer")
        # The post is made: reading it back is a nicety, and must never turn
        # a post the venue took into an error.
        try:
            fetched = await self.fetch(channel, foreign_id(thread, n))
        except VenueError:
            fetched = None
        if isinstance(fetched, ForeignPost):
            return fetched
        stored = {"id": n, "thread": thread, "name": name or None, "content": text}
        return self._post(channel, stored, self._roots.get(thread))
