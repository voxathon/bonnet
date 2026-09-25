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

"""A venue as config names it: what adapters are built from.

The one module of bridge config an adapter may import (with
`bonnet.bridges.adapter`): it knows nothing of the server.
"""

from __future__ import annotations

from dataclasses import dataclass, field

DEFAULT_MAX_BODY_BYTES = 262144


@dataclass
class BindingConfig:
    """One (venue, channel) ↔ bridge board binding (§8)."""

    board: str
    channel: str = ""
    ingest: bool = True
    relay_egress: bool = False
    edge_egress_default: bool = True
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES


@dataclass
class VenueConfig:
    type: str
    venue: str
    url: str
    poll_interval_seconds: int = 60
    backfill_pages: int = 1
    # Edit/deletion sweeps, for venues that support either (design doc §11.4).
    sweep_interval_seconds: int = 600
    sweep_window: int = 50
    relay_user: str = ""
    relay_token_file: str = ""
    # Adapter-specific flags, as TOML gave them ([bridges.venue.options]).
    options: dict = field(default_factory=dict)
    bindings: list[BindingConfig] = field(default_factory=list)


def check_venue(venue_type: str, venue: str, where: str) -> None:
    """A venue is named `<type>@<host>`, after the type it runs as.

    Code that only has the venue name (the outbox, the discovery manifest,
    peers adopting a bridge) reads the type back from it, so the two must
    agree.
    """
    prefix, at, host = venue.partition("@")
    if not at or not prefix or not host:
        raise ValueError(f"{where}.venue must look like '<type>@<host>', got {venue!r}")
    if prefix != venue_type:
        raise ValueError(f"{where}.venue {venue!r} must start with its type, '{venue_type}@'")


def venue_type_of(venue: str) -> str:
    """The type a venue name carries (see `check_venue`)."""
    return venue.partition("@")[0]
