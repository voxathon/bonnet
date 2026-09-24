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
keyed by venue type. Built-ins are listed in `BUILTIN_ADAPTERS` and always
win over entry points: an adapter runs next to the master secret and the
relay tokens, so installing a package must never swap out one the operator
already runs. A type no built-in covers must be claimed by exactly one
installed package.
"""

from __future__ import annotations

import asyncio
import importlib
import time
from dataclasses import dataclass, field
from importlib import metadata
from typing import Literal, Protocol

from bonnet.bridges.config import VenueConfig
from bonnet.core.logging import log_msg

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


class AdapterNotFound(ValueError):
    """No adapter, or more than one, is installed for a venue type."""


def _claims(venue_type: str) -> list[metadata.EntryPoint]:
    """Entry points claiming `venue_type`, one per distinct target."""
    out: dict[str, metadata.EntryPoint] = {}
    for ep in metadata.entry_points(group=ENTRY_POINT_GROUP):
        if ep.name == venue_type:
            out.setdefault(ep.value, ep)
    return list(out.values())


def load_adapter_class(venue_type: str) -> type:
    """The adapter class for `venue_type`: the built-in, else the one
    installed package that claims it."""
    builtin = BUILTIN_ADAPTERS.get(venue_type)
    if builtin is not None:
        for ep in _claims(venue_type):
            if ep.value != builtin:
                log_msg(
                    f"BRIDGE: ignoring {ep.value} for venue type {venue_type!r}: "
                    "built-in adapters can't be replaced"
                )
        module_name, _, attr = builtin.partition(":")
        return getattr(importlib.import_module(module_name), attr)
    claims = _claims(venue_type)
    if not claims:
        known = sorted({*BUILTIN_ADAPTERS, *adapter_types()})
        raise AdapterNotFound(
            f"no bridge adapter for venue type {venue_type!r}: install the package "
            "that provides it into the same environment as bonnet "
            f"(e.g. `uvx --with <package> bonnet`); installed types: {', '.join(known)}"
        )
    if len(claims) > 1:
        raise AdapterNotFound(
            f"venue type {venue_type!r} is claimed by more than one installed package "
            f"({', '.join(sorted(ep.value for ep in claims))}): uninstall all but one"
        )
    return claims[0].load()


def adapter_types() -> set[str]:
    """Venue types installed packages claim, built-ins not included."""
    return {ep.name for ep in metadata.entry_points(group=ENTRY_POINT_GROUP)}


def missing_adapters(venues: list[VenueConfig]) -> list[str]:
    """One error per venue whose adapter can't be loaded; empty if all can."""
    errors = []
    for venue in venues:
        try:
            load_adapter_class(venue.type)
        except AdapterNotFound as e:
            errors.append(f"{venue.venue}: {e}")
        except (ImportError, AttributeError) as e:
            errors.append(f"{venue.venue}: the adapter for {venue.type!r} failed to load: {e!r}")
    return errors


def build_adapter(venue: VenueConfig, **kwargs) -> VenueAdapter:
    return load_adapter_class(venue.type)(venue, **kwargs)
