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

"""The venue adapter interface (design doc §5.3).

An adapter turns one foreign venue into `ForeignPost`s. It never walks a
venue's reply chain: a reply's `root_id` is the venue's stated root if it
has one, otherwise None, and the runtime fills it from its own index.

Adapters register under the entry point group `bonnet.bridges.adapters`,
keyed by venue type. Built-ins are also listed in `BUILTIN_ADAPTERS`, so
they load even from a source tree that was never installed.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from importlib import metadata
from typing import Literal, Protocol

from bonnet.bridges.config import VenueConfig

ENTRY_POINT_GROUP = "bonnet.bridges.adapters"

BUILTIN_ADAPTERS = {
    "flatboard": "bonnet.bridges.adapters.flatboard:FlatboardAdapter",
}


@dataclass(frozen=True)
class ForeignPost:
    venue: str
    channel: str
    foreign_id: str
    author_handle: str
    author_id: str
    created_at: int | None
    reply_to: str | None
    root_id: str | None
    text: str
    raw: bytes
    raw_content_type: str
    url: str | None


@dataclass(frozen=True)
class Gone:
    foreign_id: str
    reason: Literal["deleted", "evicted", "unknown"]


@dataclass(frozen=True)
class RateLimits:
    reads_per_minute: int = 60
    posts_min_interval_seconds: float = 0.0


@dataclass(frozen=True)
class Deletion:
    """One entry of a venue's explicit deletion log (capability `deletion_log`)."""

    foreign_id: str
    raw: bytes
    raw_content_type: str = "application/json"


class VenueError(Exception):
    """The venue failed in a way worth backing off from."""


class VenueAuthError(VenueError):
    """The venue rejected an account's credentials. Never retry: venues lock
    out whole IPs after repeated bad tokens."""


@dataclass(frozen=True)
class ForeignAccount:
    """An account at a venue: the relay's, or a user's own (edge egress)."""

    user: str
    token: str = field(repr=False)


class VenueAdapter(Protocol):
    type: str
    venue: str
    capabilities: frozenset[str]
    limits: RateLimits

    async def poll(self, channel: str, cursor: str | None) -> list[ForeignPost]:
        """Posts newer than `cursor`, oldest first."""
        ...

    def cursor_after(self, post: ForeignPost) -> str:
        """The cursor that resumes polling just after `post`."""
        ...

    def cursor_from_ids(self, foreign_ids: list[str]) -> str | None:
        """The cursor after the newest of `foreign_ids` (index rebuild)."""
        ...

    async def fetch(self, channel: str, foreign_id: str) -> ForeignPost | Gone: ...

    async def post(
        self,
        account: ForeignAccount,
        channel: str,
        text: str,
        reply_to: str | None,
        idempotency_key: str,
    ) -> ForeignPost:
        """Post as `account`. Retrying with the same key must not post twice
        on venues with `idempotent_post`. Raises VenueAuthError on bad credentials."""
        ...

    def render_outbound(self, text: str, marker: str, attribution: str | None) -> str:
        """The venue text: attribution, body cut to fit, and the marker last."""
        ...

    def max_text_bytes(self) -> int: ...

    # Only on adapters with the `deletion_log` capability:
    #   async def deletions(self, channel, cursor) -> tuple[list[Deletion], str | None]
    # Entries after `cursor`, oldest first, and the cursor to resume from.
    # Venues with `edit` are swept with fetch(): a changed text is an edit.

    async def close(self) -> None: ...


class ReadLimiter:
    """Spaces requests to stay under `reads_per_minute`, per adapter."""

    def __init__(self, reads_per_minute: int, clock=time.monotonic, sleep=asyncio.sleep):
        self._interval = 60.0 / reads_per_minute if reads_per_minute > 0 else 0.0
        self._clock = clock
        self._sleep = sleep
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            now = self._clock()
            if now < self._next:
                await self._sleep(self._next - now)
                now = self._next
            self._next = now + self._interval


def load_adapter_class(venue_type: str) -> type:
    """The adapter class for `venue_type`, from entry points or the built-ins."""
    target = None
    for ep in metadata.entry_points(group=ENTRY_POINT_GROUP):
        if ep.name == venue_type:
            return ep.load()
    target = BUILTIN_ADAPTERS.get(venue_type)
    if target is None:
        raise ValueError(f"no bridge adapter for venue type {venue_type!r}")
    module_name, _, attr = target.partition(":")
    module = __import__(module_name, fromlist=[attr])
    return getattr(module, attr)


def build_adapter(venue: VenueConfig, **kwargs) -> VenueAdapter:
    return load_adapter_class(venue.type)(venue, **kwargs)
