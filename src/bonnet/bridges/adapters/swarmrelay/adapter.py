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

"""SwarmRelay adapter, read-only (OpenAgentForum and other SwarmRelay hubs).

A hub holds named channels of signed envelopes that are never edited or
deleted. Each envelope the hub stores gets an unsigned, per-channel
`storedSeq` in arrival order; that is this adapter's foreign id and cursor,
since `GET /v1/channels/<c>/messages?after=<seq>` pages forward from it and
`?after=<seq - 1>&limit=1` reads one envelope back exactly.

Replies name their parent by envelope `id` (`payload.inReplyTo`, inside the
signed payload), not by `storedSeq`, so a parent is translated: from the
same poll, from what this adapter has already seen, or else from the hub's
Markdown permalink, which states the parent's relay position. That page is
only a hint: the position is confirmed against the JSON record before use.

API reference: `/agent.md` and `/llms-full.txt` on the hub. See README.md.
"""

from __future__ import annotations

import json
import re
from collections import OrderedDict
from urllib.parse import quote

import httpx

from bonnet.bridges.adapter import ForeignPost, Gone, RateLimits, ReadLimiter, VenueError
from bonnet.bridges.venue import VenueConfig

PAGE_SIZE = 200  # the hub's maximum `limit`
# Pages walked forward per poll once a cursor exists: 2000 new envelopes
# between polls before the rest waits for the next one.
MAX_CATCHUP_PAGES = 10
# The binding channel "" (the conformance suite's) means the hub's default.
DEFAULT_CHANNEL = "general"
# The hub blocks default client signatures at its edge and asks for a
# descriptive one.
USER_AGENT = "bonnet-bridge/swarmrelay (+https://github.com/voxathon/bonnet)"
# Envelope id -> storedSeq translations kept per adapter.
MAX_KNOWN_IDS = 50_000
ENCRYPTED_TEXT = "[encrypted SwarmRelay envelope]"

_URN = "urn:uuid:"
_POSITION = re.compile(r"Unsigned relay position: (\d+)\.")
_SOURCE_JSON = re.compile(r"/messages\?after=(\d+)&limit=1\b")


def _seq(value) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def _id_key(envelope_id: str) -> str:
    """Envelope ids appear both bare and as `urn:uuid:` URNs, and replies
    don't always use the form their parent was stored under."""
    return envelope_id.strip().lower().removeprefix(_URN)


def _id_forms(envelope_id: str) -> list[str]:
    """The stored id `envelope_id` may be under: as given, then the other form."""
    bare = envelope_id.strip().removeprefix(_URN)
    other = bare if envelope_id.strip().startswith(_URN) else _URN + bare
    return [envelope_id.strip(), other]


def _canonical(envelope: dict) -> bytes:
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _text(envelope: dict) -> str:
    if envelope.get("encrypted") is True:
        return ENCRYPTED_TEXT
    payload = envelope.get("payload")
    message = payload.get("message") if isinstance(payload, dict) else None
    if isinstance(message, str):
        return message
    # Not every payload carries a `message` string (a structured message,
    # an `insight`, or none at all): show the payload itself.
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)


def _handle(envelope: dict, sender: str) -> str:
    """The name the author signed into this envelope, else its key id.

    Self-chosen and unchecked: the identity is `sender`, the key fingerprint.
    """
    payload = envelope.get("payload")
    if isinstance(payload, dict):
        for key in ("name", "origin"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return sender


def _retry_after(resp: httpx.Response) -> float | None:
    try:
        seconds = float(resp.headers.get("retry-after", ""))
    except ValueError:
        return None
    return seconds if seconds >= 0 else None


class SwarmRelayAdapter:
    protocol = 1
    type = "swarmrelay"
    # Read-only for now: posting takes an Ed25519-signed envelope per author
    # (see README.md). Envelopes are never edited or deleted: no "edit", no
    # "deletion_log".
    capabilities = frozenset({"read", "threads"})
    # The hub publishes no read limit; it asks clients to respect 429/503.
    limits = RateLimits(reads_per_minute=60)
    options: frozenset[str] = frozenset()

    def __init__(self, venue: VenueConfig, http: httpx.AsyncClient | None = None, limiter=None):
        self.venue = venue.venue
        self._base = venue.url.rstrip("/")
        self._backfill_pages = venue.backfill_pages
        self._http = http or httpx.AsyncClient(timeout=30.0)
        self._owns_http = http is None
        self._limiter = limiter or ReadLimiter(self.limits.reads_per_minute)
        # (channel, id key) -> storedSeq, or None for a parent the hub
        # doesn't have in that channel.
        self._known: OrderedDict[tuple[str, str], int | None] = OrderedDict()
        self._checked_channels: set[str] = set()

    async def close(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    # -- HTTP -------------------------------------------------------------

    async def _get(self, path: str, params: dict | None = None) -> httpx.Response:
        await self._limiter.wait()
        try:
            resp = await self._http.get(
                f"{self._base}{path}", params=params, headers={"user-agent": USER_AGENT}
            )
        except httpx.HTTPError as e:
            raise VenueError(f"swarmrelay {self._base}{path}: {e or type(e).__name__}") from e
        if resp.status_code in (429, 503):
            retry = _retry_after(resp)
            defer = getattr(self._limiter, "defer", None)
            if retry is not None and defer is not None:
                defer(retry)
            raise VenueError(f"swarmrelay {path}: HTTP {resp.status_code}")
        return resp

    @staticmethod
    def _slug(channel: str) -> str:
        return channel or DEFAULT_CHANNEL

    def _path(self, channel: str) -> str:
        return f"/v1/channels/{quote(self._slug(channel), safe='')}"

    async def _check_channel(self, channel: str) -> None:
        """Refuse a channel the hub doesn't have: its message list would just
        come back empty forever, and a typo would never show."""
        if channel in self._checked_channels:
            return
        resp = await self._get(self._path(channel))
        if resp.status_code == 404:
            try:
                body = resp.json()
            except ValueError:
                body = None
            if isinstance(body, dict) and body.get("error") == "Channel not found":
                raise VenueError(f"swarmrelay: no channel {self._slug(channel)!r} on {self._base}")
        # Anything else (a hub without the route, say) proves nothing either
        # way; don't ask again.
        self._checked_channels.add(channel)

    async def _messages(self, channel: str, after: int | None, limit: int) -> list[dict]:
        params: dict = {"limit": limit}
        if after is not None:
            params["after"] = after
        resp = await self._get(f"{self._path(channel)}/messages", params)
        where = f"swarmrelay #{self._slug(channel)}"
        if resp.status_code != 200:
            raise VenueError(f"{where}: HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as e:
            raise VenueError(f"{where}: bad JSON: {e}") from e
        messages = data.get("messages") if isinstance(data, dict) else None
        if not isinstance(messages, list):
            raise VenueError(f"{where}: no message list")
        out = [
            m
            for m in messages
            if isinstance(m, dict)
            and _seq(m.get("storedSeq")) is not None
            and isinstance(m.get("id"), str)
            and m["id"].strip()
        ]
        for m in out:
            self._remember(channel, m["id"], m["storedSeq"])
        return out

    async def _envelope(self, channel: str, seq: int) -> dict | None:
        """The envelope stored at `seq`, or None if the hub doesn't serve one."""
        for m in await self._messages(channel, seq - 1, 1):
            if m["storedSeq"] == seq:
                return m
        return None

    # -- reply translation ------------------------------------------------

    def _remember(self, channel: str, envelope_id: str, seq: int | None) -> None:
        key = (channel, _id_key(envelope_id))
        self._known[key] = seq
        self._known.move_to_end(key)
        while len(self._known) > MAX_KNOWN_IDS:
            self._known.popitem(last=False)

    async def _parent_seq(self, channel: str, envelope_id: str) -> int | None:
        key = (channel, _id_key(envelope_id))
        if key in self._known:
            self._known.move_to_end(key)
            return self._known[key]
        seq = None
        for form in _id_forms(envelope_id):
            resp = await self._get(
                f"/channels/{quote(self._slug(channel), safe='')}"
                f"/messages/{quote(form, safe='')}/index.md"
            )
            if resp.status_code == 404:
                continue
            if resp.status_code != 200:
                raise VenueError(f"swarmrelay parent lookup: HTTP {resp.status_code}")
            hint = _POSITION.search(resp.text)
            if hint:
                candidate = int(hint.group(1))
            elif source := _SOURCE_JSON.search(resp.text):
                candidate = int(source.group(1)) + 1
            else:
                break
            # The page is a rendering, not the record: confirm it.
            envelope = await self._envelope(channel, candidate) if candidate > 0 else None
            if envelope is not None and _id_key(envelope["id"]) == key[1]:
                seq = candidate
            break
        self._remember(channel, envelope_id, seq)
        return seq

    # -- posts ------------------------------------------------------------

    def _post(self, channel: str, envelope: dict, reply_to: int | None) -> ForeignPost:
        seq = envelope["storedSeq"]
        foreign_id = str(seq)
        sender = envelope.get("sender")
        sender = sender if isinstance(sender, str) else ""
        timestamp = envelope.get("timestamp")
        created = (
            timestamp // 1000
            if isinstance(timestamp, int) and not isinstance(timestamp, bool) and timestamp > 0
            else None
        )
        return ForeignPost(
            venue=self.venue,
            channel=channel,
            foreign_id=foreign_id,
            author_handle=_handle(envelope, sender),
            author_id=sender,
            created_at=created,
            reply_to=str(reply_to) if reply_to else None,
            # A top-level post is its own root; for a reply the runtime's
            # index knows the root.
            root_id=None if reply_to else foreign_id,
            text=_text(envelope),
            raw=_canonical(envelope),
            raw_content_type="application/json",
            url=(
                f"{self._base}/channels/{quote(self._slug(channel), safe='')}"
                f"/messages/{quote(envelope['id'], safe='')}/"
            ),
        )

    async def _posts(self, channel: str, envelopes: list[dict]) -> list[ForeignPost]:
        out = []
        for m in envelopes:
            payload = m.get("payload")
            # Only the signed `inReplyTo` threads; the top-level `replyToId`
            # is unsigned and the hub itself doesn't treat it as a link.
            ref = payload.get("inReplyTo") if isinstance(payload, dict) else None
            parent = None
            if isinstance(ref, str) and ref.strip():
                parent = await self._parent_seq(channel, ref)
                if parent is not None and parent >= m["storedSeq"]:
                    parent = None  # a parent can't arrive after its reply
            out.append(self._post(channel, m, parent))
        return out

    async def _walk(
        self, channel: str, after: int, pages: int, until: int | None = None
    ) -> list[dict]:
        """Envelopes after `after`, oldest first: up to `pages` pages, or
        until reaching `until`."""
        out: list[dict] = []
        for _ in range(pages):
            page = [
                m for m in await self._messages(channel, after, PAGE_SIZE) if m["storedSeq"] > after
            ]
            out += page
            if len(page) < PAGE_SIZE:
                break
            after = max(m["storedSeq"] for m in page)
            if until is not None and after >= until:
                break
        return out

    async def poll(self, channel: str, cursor: str | None) -> list[ForeignPost]:
        await self._check_channel(channel)
        if cursor:
            envelopes = await self._walk(channel, int(cursor), MAX_CATCHUP_PAGES)
        else:
            # No cursor: the newest page (the hub serves it oldest first),
            # and with `backfill_pages`, as many pages before it.
            envelopes = await self._messages(channel, None, PAGE_SIZE)
            if self._backfill_pages > 1 and len(envelopes) == PAGE_SIZE:
                first = min(m["storedSeq"] for m in envelopes)
                start = max(0, first - 1 - PAGE_SIZE * (self._backfill_pages - 1))
                older = await self._walk(channel, start, self._backfill_pages - 1, until=first)
                envelopes = older + envelopes
        by_seq = {m["storedSeq"]: m for m in envelopes}
        return await self._posts(channel, [by_seq[s] for s in sorted(by_seq)])

    def cursor_after(self, post: ForeignPost) -> str:
        return post.foreign_id

    def cursor_from_ids(self, foreign_ids: list[str]) -> str | None:
        ids = [int(i) for i in foreign_ids if i.isdigit()]
        return str(max(ids)) if ids else None

    async def fetch(self, channel: str, foreign_id: str) -> ForeignPost | Gone:
        if not foreign_id.isdigit() or int(foreign_id) <= 0:
            return Gone(foreign_id, "unknown")
        envelope = await self._envelope(channel, int(foreign_id))
        if envelope is None:
            # Envelopes are never deleted, but a hub may stop serving one.
            return Gone(foreign_id, "unknown")
        return (await self._posts(channel, [envelope]))[0]
