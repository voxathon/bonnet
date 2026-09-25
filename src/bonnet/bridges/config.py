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

"""Bridge configuration, as `config.toml` carries it, and the puppet secret.

  [bridges]      this origin's own bridges (design doc §10.2): tunables,
                 and a `[[bridges.venue]]` per foreign venue. Any origin may
                 carry one; the server runs its venues in-process
  [admission]    admitting other origins' users as crossposters (§6)
  [[recognize]]  other origins recognized as bridges for a venue (§10.1)

Each `[[bridges.venue]]` may carry a `[bridges.venue.options]` table of
flags for its adapter alone; the adapter declares and checks them
(`adapter.venue_option_problems`). Bridge facts are signed with the server's
own key; puppet keys derive from `puppet_secret` in the data directory.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from bonnet.bridges.venue import (  # noqa: F401 (re-exported: config's own types)
    DEFAULT_MAX_BODY_BYTES,
    BindingConfig,
    VenueConfig,
    check_venue,
    venue_type_of,
)

_RUNTIME_KEYS = {
    "grace_seconds",
    "linked_grace_seconds",
    "marker_timeout_seconds",
    "resolve_markers",
    "venue",
}
_VENUE_KEYS = {
    "type",
    "venue",
    "url",
    "poll_interval_seconds",
    "backfill_pages",
    "sweep_interval_seconds",
    "sweep_window",
    "relay_user",
    "relay_token_file",
    "options",
    "binding",
}
_BINDING_KEYS = {
    "channel",
    "board",
    "ingest",
    "relay_egress",
    "edge_egress_default",
    "max_body_bytes",
}


@dataclass
class BridgeRuntimeConfig:
    """`[bridges]`: the venues this origin bridges itself."""

    grace_seconds: int = 120
    linked_grace_seconds: int = 600
    marker_timeout_seconds: int = 3600
    # Dial the origin an addressed marker names to fetch its original
    # (bridges.remote). Venue text names the host, so it's opt-in.
    resolve_markers: bool = False
    venues: list[VenueConfig] = field(default_factory=list)

    @property
    def venue_types(self) -> frozenset[str]:
        return frozenset(v.type for v in self.venues)


def _int(table: dict, key: str, where: str, default: int, minimum: int = 0) -> int:
    value = table.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"{where}.{key} must be an integer >= {minimum}, got {value!r}")
    return value


def _bool(table: dict, key: str, where: str, default: bool) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise ValueError(f"{where}.{key} must be a boolean, got {value!r}")
    return value


def _str(table: dict, key: str, where: str, default: str | None = None) -> str:
    value = table.get(key, default)
    if value is None:
        raise ValueError(f"{where}.{key} is required")
    if not isinstance(value, str):
        raise ValueError(f"{where}.{key} must be a string, got {value!r}")
    return value


def parse_options(table: dict, where: str) -> dict:
    """A venue's `options` table, as given: its adapter checks it."""
    options = table.get("options", {})
    if not isinstance(options, dict):
        raise ValueError(f"{where}.options must be a table")
    return dict(options)


def parse_bridge_runtime(table: dict) -> tuple[BridgeRuntimeConfig, list[str]]:
    """Parse `[bridges]`. Returns the config and any unrecognized keys."""
    if not isinstance(table, dict):
        raise ValueError("[bridges] must be a table")
    unknown = [f"bridges.{k}" for k in table if k not in _RUNTIME_KEYS]
    where = "bridges"
    cfg = BridgeRuntimeConfig(
        grace_seconds=_int(table, "grace_seconds", where, 120),
        linked_grace_seconds=_int(table, "linked_grace_seconds", where, 600),
        marker_timeout_seconds=_int(table, "marker_timeout_seconds", where, 3600),
        resolve_markers=_bool(table, "resolve_markers", where, False),
    )

    venues = table.get("venue", [])
    if not isinstance(venues, list):
        raise ValueError("[[bridges.venue]] must be an array of tables")
    boards: set[str] = set()
    for i, v in enumerate(venues):
        vw = f"bridges.venue[{i}]"
        if not isinstance(v, dict):
            raise ValueError(f"{vw} must be a table")
        unknown.extend(f"{vw}.{k}" for k in v if k not in _VENUE_KEYS)
        venue = VenueConfig(
            type=_str(v, "type", vw),
            venue=_str(v, "venue", vw),
            url=_str(v, "url", vw).rstrip("/"),
            poll_interval_seconds=_int(v, "poll_interval_seconds", vw, 60, minimum=1),
            backfill_pages=_int(v, "backfill_pages", vw, 1, minimum=1),
            sweep_interval_seconds=_int(v, "sweep_interval_seconds", vw, 600, minimum=1),
            sweep_window=_int(v, "sweep_window", vw, 50),
            relay_user=_str(v, "relay_user", vw, ""),
            relay_token_file=_str(v, "relay_token_file", vw, ""),
            options=parse_options(v, vw),
        )
        if not venue.type or "~" in venue.type or "." in venue.type:
            raise ValueError(f"{vw}.type must be non-empty with no '~' or '.'")
        check_venue(venue.type, venue.venue, vw)
        bindings = v.get("binding", [])
        if not isinstance(bindings, list) or not bindings:
            raise ValueError(f"{vw} needs at least one [[...binding]]")
        for j, b in enumerate(bindings):
            bw = f"{vw}.binding[{j}]"
            if not isinstance(b, dict):
                raise ValueError(f"{bw} must be a table")
            unknown.extend(f"{bw}.{k}" for k in b if k not in _BINDING_KEYS)
            binding = BindingConfig(
                board=_str(b, "board", bw),
                channel=_str(b, "channel", bw, ""),
                ingest=_bool(b, "ingest", bw, True),
                relay_egress=_bool(b, "relay_egress", bw, False),
                edge_egress_default=_bool(b, "edge_egress_default", bw, True),
                max_body_bytes=_int(b, "max_body_bytes", bw, DEFAULT_MAX_BODY_BYTES, minimum=1),
            )
            if not binding.board.startswith(f"~{venue.type}"):
                raise ValueError(
                    f"{bw}.board must be '~{venue.type}' or '~{venue.type}.<channel>', "
                    f"got {binding.board!r}"
                )
            if binding.board in boards:
                raise ValueError(f"board {binding.board!r} is bound twice")
            boards.add(binding.board)
            venue.bindings.append(binding)
        cfg.venues.append(venue)
    return cfg, unknown


# ---------------------------------------------------------------------------
# [[recognize]]: which bridge origins a homeserver recognizes (§10.1)
# ---------------------------------------------------------------------------

_BRIDGES_KEYS = {"type", "venue", "origins"}


@dataclass
class BridgesEntry:
    """Recognized bridge origins for one venue, in canonical preference order."""

    type: str
    venue: str
    origins: list[str]


def parse_bridges(tables, normalize_origin) -> tuple[list[BridgesEntry], list[str]]:
    """Parse `[[recognize]]`. Returns the entries and any unrecognized keys."""
    if not isinstance(tables, list):
        raise ValueError("[[recognize]] must be an array of tables")
    entries: list[BridgesEntry] = []
    unknown: list[str] = []
    venues: set[str] = set()
    for i, t in enumerate(tables):
        where = f"recognize[{i}]"
        if not isinstance(t, dict):
            raise ValueError(f"{where} must be a table")
        unknown.extend(f"{where}.{k}" for k in t if k not in _BRIDGES_KEYS)
        origins = t.get("origins")
        if (
            not isinstance(origins, list)
            or not origins
            or not all(isinstance(o, str) and o for o in origins)
        ):
            raise ValueError(f"{where}.origins must be a non-empty list of origin names")
        normalized = [normalize_origin(o) for o in origins]
        if len(set(normalized)) != len(normalized):
            raise ValueError(f"{where}.origins lists an origin twice")
        entry = BridgesEntry(
            type=_str(t, "type", where), venue=_str(t, "venue", where), origins=normalized
        )
        check_venue(entry.type, entry.venue, where)
        if entry.venue in venues:
            raise ValueError(f"venue {entry.venue!r} appears in [[recognize]] twice")
        venues.add(entry.venue)
        entries.append(entry)
    return entries, unknown


def recognized_bridges(config) -> dict[str, list[str]]:
    """Venue -> recognized bridge origins, best first.

    `[[recognize]]` order, plus this origin itself for each venue its own
    runtime runs: first, unless `[[recognize]]` places it explicitly.
    """
    out = {e.venue: list(e.origins) for e in getattr(config, "bridges", [])}
    runtime = getattr(config, "bridge_runtime", None)
    if runtime is not None:
        for venue in runtime.venues:
            order = out.setdefault(venue.venue, [])
            if config.origin not in order:
                order.insert(0, config.origin)
    return out


def venue_types(config) -> dict[str, str]:
    """Venue -> type, from `[[recognize]]` and this origin's own runtime."""
    out = {e.venue: e.type for e in getattr(config, "bridges", [])}
    runtime = getattr(config, "bridge_runtime", None)
    if runtime is not None:
        out.update({v.venue: v.type for v in runtime.venues})
    return out


# ---------------------------------------------------------------------------
# The puppet secret
# ---------------------------------------------------------------------------


def load_puppet_secret(path: str) -> bytes:
    """The secret puppet keys derive from, generated on first use.

    Server state, not config: it lives in the data directory next to the
    server's identity, and unlike that identity it never rotates. Losing it
    orphans every puppet: new keys would be derived, and the old puppets'
    names stay held by keys nobody can sign with any more. Back it up.
    """
    if os.path.exists(path):
        with open(path, "rb") as f:
            data = f.read()
        if len(data) != 32:
            raise ValueError(f"{path}: expected 32 bytes, found {len(data)}")
        return data
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    data = os.urandom(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return data


# ---------------------------------------------------------------------------
# [admission]: admitting crossposters' home keys (§6)
# ---------------------------------------------------------------------------

_ADMISSION_KEYS = {
    "enabled",
    "recheck_seconds",
    "timeout_seconds",
    "max_staleness_seconds",
    "max_chain_hops",
    "max_concurrent_checks",
    "allow_private_dial",
    "verify_tls",
}


@dataclass
class AdmissionConfig:
    enabled: bool = False
    recheck_seconds: int = 300
    timeout_seconds: int = 5
    max_staleness_seconds: int = 86400
    max_chain_hops: int = 64
    max_concurrent_checks: int = 8
    allow_private_dial: bool = False
    verify_tls: bool = True


def parse_bridge_admission(table) -> tuple[AdmissionConfig, list[str]]:
    if not isinstance(table, dict):
        raise ValueError("[admission] must be a table")
    where = "admission"
    cfg = AdmissionConfig(
        enabled=_bool(table, "enabled", where, False),
        recheck_seconds=_int(table, "recheck_seconds", where, 300),
        timeout_seconds=_int(table, "timeout_seconds", where, 5, minimum=1),
        max_staleness_seconds=_int(table, "max_staleness_seconds", where, 86400),
        max_chain_hops=_int(table, "max_chain_hops", where, 64, minimum=1),
        max_concurrent_checks=_int(table, "max_concurrent_checks", where, 8, minimum=1),
        allow_private_dial=_bool(table, "allow_private_dial", where, False),
        verify_tls=_bool(table, "verify_tls", where, True),
    )
    return cfg, [f"{where}.{k}" for k in table if k not in _ADMISSION_KEYS]
