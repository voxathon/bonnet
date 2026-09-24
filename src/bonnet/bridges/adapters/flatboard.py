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

"""Flatboard reference adapter, read side (design doc §12).

Flatboard is one flat, immutable board with a FIFO: old messages are
evicted, never edited. Pages are newest first, 50 per page. Reads are
limited to 120/min per IP, so this adapter spaces its requests.

The page envelope is accepted either as a bare list of messages or as an
object with a `messages` list (and optionally `first_id`, the oldest id the
venue still holds). Each message is
`{id, author, rating, author_rating, created, reply_to, text}`.
"""

from __future__ import annotations

import json
from datetime import datetime

import httpx

from bonnet.bridges.adapter import ForeignPost, Gone, RateLimits, ReadLimiter, VenueError
from bonnet.bridges.config import VenueConfig

PAGE_SIZE = 50
MAX_TEXT_BYTES = 2048
# Pages walked back per poll once a cursor exists. At 50 per page that's
# 1000 new messages between polls before anything is skipped.
MAX_CATCHUP_PAGES = 20


def _parse_created(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value:
        if value.isdigit():
            return int(value)
        try:
            return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
        except ValueError:
            return None
    return None


def _id(value) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value) if value > 0 else None
    if isinstance(value, str) and value.isdigit() and int(value) > 0:
        return str(int(value))
    return None


def _canonical(msg: dict) -> bytes:
    return json.dumps(msg, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


class FlatboardAdapter:
    type = "flatboard"
    # Immutable venue: no "edit", no "deletion_log". Write lands in M4.
    capabilities = frozenset({"read", "threads"})
    limits = RateLimits(reads_per_minute=120, posts_min_interval_seconds=15.0)

    def __init__(self, venue: VenueConfig, http: httpx.AsyncClient | None = None, limiter=None):
        self.venue = venue.venue
        self._base = venue.url.rstrip("/")
        self._backfill_pages = venue.backfill_pages
        self._http = http or httpx.AsyncClient(timeout=30.0)
        self._owns_http = http is None
        self._limiter = limiter or ReadLimiter(self.limits.reads_per_minute)

    async def close(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    def max_text_bytes(self) -> int:
        return MAX_TEXT_BYTES

    async def _get(self, path: str, params: dict | None = None) -> httpx.Response:
        await self._limiter.wait()
        try:
            return await self._http.get(f"{self._base}{path}", params=params)
        except httpx.HTTPError as e:
            raise VenueError(f"flatboard {self._base}{path}: {e or type(e).__name__}") from e

    async def _page(self, n: int, since: str | None) -> list[dict]:
        params = {"since": since} if since else None
        resp = await self._get(f"/board/page/{n}.json", params)
        if resp.status_code != 200:
            raise VenueError(f"flatboard page {n}: HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as e:
            raise VenueError(f"flatboard page {n}: bad JSON: {e}") from e
        messages = data.get("messages") if isinstance(data, dict) else data
        if not isinstance(messages, list):
            raise VenueError(f"flatboard page {n}: no message list")
        return [m for m in messages if isinstance(m, dict) and _id(m.get("id")) is not None]

    def _post(self, channel: str, msg: dict, raw: bytes | None = None) -> ForeignPost:
        foreign_id = _id(msg.get("id"))
        assert foreign_id is not None
        reply_to = _id(msg.get("reply_to"))
        author = msg.get("author")
        author = author if isinstance(author, str) else ""
        text = msg.get("text")
        return ForeignPost(
            venue=self.venue,
            channel=channel,
            foreign_id=foreign_id,
            author_handle=author,
            # Flatboard has no account ids; the handle is the stable name.
            author_id=author,
            created_at=_parse_created(msg.get("created")),
            reply_to=reply_to,
            # A top-level post is its own root. For a reply only the runtime's
            # index knows the root; the adapter never walks reply_to.
            root_id=None if reply_to else foreign_id,
            text=text if isinstance(text, str) else "",
            raw=raw if raw is not None else _canonical(msg),
            raw_content_type="application/json",
            url=f"{self._base}/board/msg/{foreign_id}.json",
        )

    async def poll(self, channel: str, cursor: str | None) -> list[ForeignPost]:
        since = int(cursor) if cursor else 0
        max_pages = MAX_CATCHUP_PAGES if cursor else self._backfill_pages
        seen: dict[int, dict] = {}
        for n in range(1, max_pages + 1):
            page = {int(i): m for m in await self._page(n, cursor) if (i := _id(m["id"]))}
            newer = {i: m for i, m in page.items() if i > since}
            seen.update(newer)
            # Stop at a short page or once the page reaches back to the cursor.
            if len(page) < PAGE_SIZE or len(newer) < len(page):
                break
        return [self._post(channel, seen[i]) for i in sorted(seen)]

    def cursor_after(self, post: ForeignPost) -> str:
        return post.foreign_id

    def cursor_from_ids(self, foreign_ids: list[str]) -> str | None:
        ids = [int(i) for i in foreign_ids if i.isdigit()]
        return str(max(ids)) if ids else None

    async def fetch(self, channel: str, foreign_id: str) -> ForeignPost | Gone:
        resp = await self._get(f"/board/msg/{foreign_id}.json")
        if resp.status_code == 404:
            evicted = False
            try:
                body = resp.json()
                evicted = isinstance(body, dict) and bool(body.get("evicted"))
            except ValueError:
                pass
            return Gone(foreign_id, "evicted" if evicted else "unknown")
        if resp.status_code != 200:
            raise VenueError(f"flatboard msg {foreign_id}: HTTP {resp.status_code}")
        try:
            msg = resp.json()
        except ValueError as e:
            raise VenueError(f"flatboard msg {foreign_id}: bad JSON: {e}") from e
        if not isinstance(msg, dict) or _id(msg.get("id")) != foreign_id:
            raise VenueError(f"flatboard msg {foreign_id}: unexpected body")
        return self._post(channel, msg, raw=resp.content)
