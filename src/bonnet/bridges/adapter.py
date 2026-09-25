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
win over entry points: an adapter runs next to the puppet secret and the
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

from bonnet.bridges.adapters import BUILTIN_ADAPTERS
from bonnet.bridges.venue import VenueConfig
from bonnet.core.logging import log_msg

ENTRY_POINT_GROUP = "bonnet.bridges.adapters"

# The interface version below. An adapter declares the one it implements
# (`protocol = 1`); a mismatch is refused at load, never half-run.
PROTOCOL = 1

# What a venue can do, and the methods each capability needs beyond the
# ones every adapter has. The set is closed: a capability the runtime
# doesn't know is a typo, and a typo would quietly turn a feature off.
CAPABILITY_METHODS: dict[str, tuple[str, ...]] = {
    "read": (),  # required of every adapter
    "threads": (),  # posts carry reply_to
    "write": ("post", "render_outbound", "max_text_bytes"),
    "idempotent_post": (),  # post() with the same key never posts twice
    "edit": (),  # fetch() shows edits; the runtime sweeps for them
    "deletion_log": ("deletions",),
    "signup": ("signup_instructions",),  # accounts: says how a person gets one
    "self_register": ("register",),  # accounts: the adapter can create one
}
CAPABILITIES = frozenset(CAPABILITY_METHODS)
# Needed by every adapter, whatever it can do.
BASE_METHODS = ("poll", "fetch", "cursor_after", "cursor_from_ids", "close")
# Capabilities that only mean something alongside another.
_CAPABILITY_NEEDS = {"idempotent_post": "write", "signup": "write", "self_register": "signup"}


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


class VenueUncertain(VenueError):
    """A post failed in a way that doesn't say whether the venue took it (the
    connection dropped, the venue answered 5xx). On a venue with
    `idempotent_post`, retrying with the same key settles it either way."""


class VenueNameTaken(VenueError):
    """register(): the venue already has an account by that name."""


class VenueRateLimited(VenueError):
    """The venue refused a request for rate. It took nothing, so the same
    request may be retried once `retry_after` seconds (if known) have passed."""

    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


@dataclass(frozen=True)
class ForeignAccount:
    """An account at a venue: the relay's, or a user's own (edge egress)."""

    user: str
    token: str = field(repr=False)


class VenueAdapter(Protocol):
    protocol: int  # PROTOCOL
    type: str
    venue: str
    capabilities: frozenset[str]  # a subset of CAPABILITIES, "read" always
    limits: RateLimits
    # The keys this adapter reads from its venue's `options` table. Others
    # are warned about and ignored. Optionally, the class also has
    #   @classmethod check_options(cls, options: dict) -> None
    # raising ValueError for a value it can't take, before anything starts.
    options: frozenset[str]

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
    #
    # With `signup`, for register(venue=...) (design: accounts are linked to
    # one Bonnet identity each, in the gateway's identity store):
    #   def signup_instructions(self) -> str
    # How a person gets an account and its token, for someone who will paste
    # the token back. Plain text; never contains a credential.
    #
    # With `self_register`:
    #   async def register(self, user: str) -> ForeignAccount
    # Create the account `user` at the venue and return its credentials.
    # Raises VenueNameTaken if someone holds the name, VenueRateLimited if
    # the venue refuses for rate, and VenueUncertain if it may have made the
    # account without the answer arriving: a venue that shows a token once
    # can't be asked again, and the caller must say so.

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

    def defer(self, seconds: float) -> None:
        """Hold the next request until `seconds` from now (a venue's retry-after)."""
        self._next = max(self._next, self._clock() + seconds)


class AdapterNotFound(ValueError):
    """No adapter, or more than one, is installed for a venue type."""


class AdapterInvalid(ValueError):
    """An adapter class doesn't implement the interface it claims."""


def adapter_problems(cls, venue_type: str | None = None) -> list[str]:
    """Why `cls` isn't a usable adapter (for `venue_type`), or [] if it is.

    Checked when an adapter loads, before any venue starts: the protocol
    version, the capabilities (known, "read" among them, and the ones they
    lean on), and the methods those capabilities need.
    """
    problems = []
    name = getattr(cls, "__qualname__", repr(cls))
    protocol = getattr(cls, "protocol", None)
    if protocol != PROTOCOL:
        problems.append(f"{name} implements adapter protocol {protocol!r}, not {PROTOCOL}")
    if venue_type is not None and getattr(cls, "type", None) != venue_type:
        problems.append(f"{name}.type is {getattr(cls, 'type', None)!r}, not {venue_type!r}")
    caps = getattr(cls, "capabilities", None)
    if not isinstance(caps, frozenset):
        return problems + [f"{name}.capabilities must be a frozenset"]
    unknown = sorted(caps - CAPABILITIES)
    if unknown:
        problems.append(
            f"{name} claims unknown capabilities {unknown}; known: {sorted(CAPABILITIES)}"
        )
    if "read" not in caps:
        problems.append(f"{name} must have the 'read' capability")
    for cap, needs in _CAPABILITY_NEEDS.items():
        if cap in caps and needs not in caps:
            problems.append(f"{name} claims {cap!r} without {needs!r}")
    required = list(BASE_METHODS)
    for cap in sorted(caps & CAPABILITIES):
        required += CAPABILITY_METHODS[cap]
    missing = sorted({m for m in required if not callable(getattr(cls, m, None))})
    if missing:
        problems.append(f"{name} lacks {', '.join(missing)}, which its capabilities need")
    if not isinstance(getattr(cls, "limits", None), RateLimits):
        problems.append(f"{name}.limits must be a RateLimits")
    if not isinstance(getattr(cls, "options", None), frozenset):
        problems.append(f"{name}.options must be a frozenset")
    return problems


def _checked(cls, venue_type: str):
    problems = adapter_problems(cls, venue_type)
    if problems:
        raise AdapterInvalid(f"the adapter for {venue_type!r} is invalid: {'; '.join(problems)}")
    return cls


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
        return _checked(getattr(importlib.import_module(module_name), attr), venue_type)
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
    return _checked(claims[0].load(), venue_type)


def adapter_types() -> set[str]:
    """Venue types installed packages claim, built-ins not included."""
    return {ep.name for ep in metadata.entry_points(group=ENTRY_POINT_GROUP)}


def missing_adapters(venues: list[VenueConfig]) -> list[str]:
    """One error per venue whose adapter can't be loaded; empty if all can."""
    errors = []
    for venue in venues:
        try:
            load_adapter_class(venue.type)
        except (AdapterNotFound, AdapterInvalid) as e:
            errors.append(f"{venue.venue}: {e}")
        except (ImportError, AttributeError) as e:
            errors.append(f"{venue.venue}: the adapter for {venue.type!r} failed to load: {e!r}")
    return errors


def venue_option_problems(venues: list[VenueConfig]) -> tuple[list[str], list[str]]:
    """(errors, warnings) about each venue's `options`, as its adapter sees them.

    Call after `missing_adapters` comes back empty: it loads every class.
    """
    errors: list[str] = []
    warnings: list[str] = []
    for venue in venues:
        cls = load_adapter_class(venue.type)
        known: frozenset[str] = getattr(cls, "options", frozenset())
        for key in sorted(k for k in venue.options if k not in known):
            warnings.append(
                f"{venue.venue}: the {venue.type} adapter has no option {key!r} (ignored)"
            )
        check = getattr(cls, "check_options", None)
        if check is not None:
            try:
                check(venue.options)
            except ValueError as e:
                errors.append(f"{venue.venue}: options: {e}")
    return errors, warnings


def build_adapter(venue: VenueConfig, **kwargs) -> VenueAdapter:
    return load_adapter_class(venue.type)(venue, **kwargs)
