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

"""`[bridge_runtime]` configuration and the runtime's key files (design doc §10.2).

A config with a `[bridge_runtime]` table makes the origin a bridge origin:
`bonnet bridge run` starts the runtime next to the server, and the server
closes registration to everyone but the runtime and its administrators (§8).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from bonnet.core.crypto import Identity

DEFAULT_MAX_BODY_BYTES = 262144

_RUNTIME_KEYS = {
    "daemon_key",
    "daemon_username",
    "master_secret",
    "state_dir",
    "grace_seconds",
    "linked_grace_seconds",
    "marker_timeout_seconds",
    "venue",
}
_VENUE_KEYS = {
    "type",
    "venue",
    "url",
    "poll_interval_seconds",
    "backfill_pages",
    "relay_user",
    "relay_token_file",
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
    relay_user: str = ""
    relay_token_file: str = ""
    bindings: list[BindingConfig] = field(default_factory=list)


@dataclass
class BridgeRuntimeConfig:
    daemon_key: str
    master_secret: str
    state_dir: str
    daemon_username: str = "bridge"
    grace_seconds: int = 120
    linked_grace_seconds: int = 600
    marker_timeout_seconds: int = 3600
    venues: list[VenueConfig] = field(default_factory=list)

    @property
    def venue_types(self) -> frozenset[str]:
        return frozenset(v.type for v in self.venues)


def _path(value: str, base_dir: str) -> str:
    value = os.path.expanduser(value)
    return value if os.path.isabs(value) else os.path.join(base_dir, value)


def _int(table: dict, key: str, where: str, default: int, minimum: int = 0) -> int:
    value = table.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"config: {where}.{key} must be an integer >= {minimum}, got {value!r}")
    return value


def _bool(table: dict, key: str, where: str, default: bool) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise ValueError(f"config: {where}.{key} must be a boolean, got {value!r}")
    return value


def _str(table: dict, key: str, where: str, default: str | None = None) -> str:
    value = table.get(key, default)
    if value is None:
        raise ValueError(f"config: {where}.{key} is required")
    if not isinstance(value, str):
        raise ValueError(f"config: {where}.{key} must be a string, got {value!r}")
    return value


def parse_bridge_runtime(table: dict, base_dir: str) -> tuple[BridgeRuntimeConfig, list[str]]:
    """Parse `[bridge_runtime]`. Returns the config and any unrecognized keys."""
    if not isinstance(table, dict):
        raise ValueError("config: [bridge_runtime] must be a table")
    unknown = [f"bridge_runtime.{k}" for k in table if k not in _RUNTIME_KEYS]
    where = "bridge_runtime"
    home = os.path.join("~", ".bonnet", "bridges")
    cfg = BridgeRuntimeConfig(
        daemon_key=_path(
            _str(table, "daemon_key", where, os.path.join(home, "daemon.key")), base_dir
        ),
        master_secret=_path(
            _str(table, "master_secret", where, os.path.join(home, "master.secret")), base_dir
        ),
        state_dir=_path(_str(table, "state_dir", where, os.path.join(home, "state")), base_dir),
        daemon_username=_str(table, "daemon_username", where, "bridge"),
        grace_seconds=_int(table, "grace_seconds", where, 120),
        linked_grace_seconds=_int(table, "linked_grace_seconds", where, 600),
        marker_timeout_seconds=_int(table, "marker_timeout_seconds", where, 3600),
    )
    if "~" in cfg.daemon_username or not cfg.daemon_username.strip():
        raise ValueError("config: bridge_runtime.daemon_username must be non-empty and have no '~'")

    venues = table.get("venue", [])
    if not isinstance(venues, list):
        raise ValueError("config: [[bridge_runtime.venue]] must be an array of tables")
    boards: set[str] = set()
    for i, v in enumerate(venues):
        vw = f"bridge_runtime.venue[{i}]"
        if not isinstance(v, dict):
            raise ValueError(f"config: {vw} must be a table")
        unknown.extend(f"{vw}.{k}" for k in v if k not in _VENUE_KEYS)
        venue = VenueConfig(
            type=_str(v, "type", vw),
            venue=_str(v, "venue", vw),
            url=_str(v, "url", vw).rstrip("/"),
            poll_interval_seconds=_int(v, "poll_interval_seconds", vw, 60, minimum=1),
            backfill_pages=_int(v, "backfill_pages", vw, 1, minimum=1),
            relay_user=_str(v, "relay_user", vw, ""),
            relay_token_file=_str(v, "relay_token_file", vw, ""),
        )
        if not venue.type or "~" in venue.type or "." in venue.type:
            raise ValueError(f"config: {vw}.type must be non-empty with no '~' or '.'")
        if "@" not in venue.venue:
            raise ValueError(f"config: {vw}.venue must look like '<type>@<host>'")
        bindings = v.get("binding", [])
        if not isinstance(bindings, list) or not bindings:
            raise ValueError(f"config: {vw} needs at least one [[...binding]]")
        for j, b in enumerate(bindings):
            bw = f"{vw}.binding[{j}]"
            if not isinstance(b, dict):
                raise ValueError(f"config: {bw} must be a table")
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
                    f"config: {bw}.board must be '~{venue.type}' or '~{venue.type}.<channel>', "
                    f"got {binding.board!r}"
                )
            if binding.board in boards:
                raise ValueError(f"config: board {binding.board!r} is bound twice")
            boards.add(binding.board)
            venue.bindings.append(binding)
        cfg.venues.append(venue)
    return cfg, unknown


# ---------------------------------------------------------------------------
# Key files
# ---------------------------------------------------------------------------


def _read_or_create(path: str, make) -> bytes:
    if os.path.exists(path):
        with open(path, "rb") as f:
            data = f.read()
        if len(data) != 32:
            raise ValueError(f"{path}: expected 32 bytes, found {len(data)}")
        return data
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    data = make()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return data


def load_daemon_identity(cfg: BridgeRuntimeConfig) -> Identity:
    """The daemon's signing key, generated on first use."""
    return Identity.from_private_key(
        _read_or_create(cfg.daemon_key, lambda: Identity.generate().private_key)
    )


def load_master_secret(cfg: BridgeRuntimeConfig) -> bytes:
    """The secret puppet keys derive from, generated on first use.

    Losing it orphans every puppet: new keys would be derived, and the old
    puppets' names stay held by keys nobody can sign with any more.
    """
    return _read_or_create(cfg.master_secret, lambda: os.urandom(32))


# ---------------------------------------------------------------------------
# [[bridges]]: which bridge origins a homeserver recognizes (§10.1)
# ---------------------------------------------------------------------------

_BRIDGES_KEYS = {"type", "venue", "origins"}


@dataclass
class BridgesEntry:
    """Recognized bridge origins for one venue, in canonical preference order."""

    type: str
    venue: str
    origins: list[str]


def parse_bridges(tables, normalize_origin) -> tuple[list[BridgesEntry], list[str]]:
    """Parse `[[bridges]]`. Returns the entries and any unrecognized keys."""
    if not isinstance(tables, list):
        raise ValueError("config: [[bridges]] must be an array of tables")
    entries: list[BridgesEntry] = []
    unknown: list[str] = []
    venues: set[str] = set()
    for i, t in enumerate(tables):
        where = f"bridges[{i}]"
        if not isinstance(t, dict):
            raise ValueError(f"config: {where} must be a table")
        unknown.extend(f"{where}.{k}" for k in t if k not in _BRIDGES_KEYS)
        origins = t.get("origins")
        if (
            not isinstance(origins, list)
            or not origins
            or not all(isinstance(o, str) and o for o in origins)
        ):
            raise ValueError(f"config: {where}.origins must be a non-empty list of origin names")
        normalized = [normalize_origin(o) for o in origins]
        if len(set(normalized)) != len(normalized):
            raise ValueError(f"config: {where}.origins lists an origin twice")
        entry = BridgesEntry(
            type=_str(t, "type", where), venue=_str(t, "venue", where), origins=normalized
        )
        if "@" not in entry.venue:
            raise ValueError(f"config: {where}.venue must look like '<type>@<host>'")
        if entry.venue in venues:
            raise ValueError(f"config: venue {entry.venue!r} appears in [[bridges]] twice")
        venues.add(entry.venue)
        entries.append(entry)
    return entries, unknown


def recognized_bridges(config) -> dict[str, list[str]]:
    """Venue -> recognized bridge origins, best first.

    `[[bridges]]` order, plus this origin itself for each venue its own
    runtime runs: first, unless `[[bridges]]` places it explicitly.
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
    """Venue -> type, from `[[bridges]]` and this origin's own runtime."""
    out = {e.venue: e.type for e in getattr(config, "bridges", [])}
    runtime = getattr(config, "bridge_runtime", None)
    if runtime is not None:
        out.update({v.venue: v.type for v in runtime.venues})
    return out
