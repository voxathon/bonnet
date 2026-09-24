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

"""`bridges.toml`: bridge configuration, and the runtime's key files.

Bridges have their own file, next to the server's `config.toml`:

  [runtime]      makes this origin a bridge origin (design doc §10.2):
                 `bonnet bridge run` starts the runtime next to the server,
                 and the server closes registration to everyone but the
                 runtime and its administrators (§8)
  [[recognize]]  which bridge origins this homeserver recognizes (§10.1)
  [admission]    admitting crossposters' home keys (§6)

A missing file means no bridges. Each `[[runtime.venue]]` may carry an
`[runtime.venue.options]` table of flags for its adapter alone; the adapter
declares and checks them (`adapter.venue_option_problems`).
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field

from bonnet.core.crypto import Identity

DEFAULT_MAX_BODY_BYTES = 262144

BRIDGES_FILE = "bridges.toml"
_FILE_KEYS = {"runtime", "recognize", "admission"}

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
    # Adapter-specific flags, as TOML gave them ([runtime.venue.options]).
    options: dict = field(default_factory=dict)
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


def parse_options(table: dict, where: str) -> dict:
    """A venue's `options` table, as given: its adapter checks it."""
    options = table.get("options", {})
    if not isinstance(options, dict):
        raise ValueError(f"{where}.options must be a table")
    return dict(options)


def parse_bridge_runtime(table: dict, base_dir: str) -> tuple[BridgeRuntimeConfig, list[str]]:
    """Parse `[runtime]`. Returns the config and any unrecognized keys."""
    if not isinstance(table, dict):
        raise ValueError("[runtime] must be a table")
    unknown = [f"runtime.{k}" for k in table if k not in _RUNTIME_KEYS]
    where = "runtime"
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
        raise ValueError("runtime.daemon_username must be non-empty and have no '~'")

    venues = table.get("venue", [])
    if not isinstance(venues, list):
        raise ValueError("[[runtime.venue]] must be an array of tables")
    boards: set[str] = set()
    for i, v in enumerate(venues):
        vw = f"runtime.venue[{i}]"
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


# ---------------------------------------------------------------------------
# The file
# ---------------------------------------------------------------------------


class BridgesConfigError(ValueError):
    """`bridges.toml` is unreadable or invalid. Carries the file's path."""

    def __init__(self, path: str, message: str):
        super().__init__(f"{path}: {message}")
        self.path = path


@dataclass
class BridgesFile:
    runtime: BridgeRuntimeConfig | None = None
    recognize: list[BridgesEntry] = field(default_factory=list)
    admission: AdmissionConfig | None = None
    unknown_keys: list[str] = field(default_factory=list)


def bridges_path(config_path: str) -> str:
    """The `bridges.toml` that goes with the server config at `config_path`."""
    return os.path.join(os.path.dirname(os.path.abspath(config_path)), BRIDGES_FILE)


def load_bridges_file(path: str, normalize_origin) -> BridgesFile:
    """Parse the bridges file at `path`; a missing file is no bridges.

    Unknown keys come back prefixed with the file name, the way the
    server's includes report theirs.
    """
    if not os.path.exists(path):
        return BridgesFile()
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise BridgesConfigError(path, f"could not parse: {e}") from e
    except OSError as e:
        raise BridgesConfigError(path, f"could not read: {e}") from e
    out = BridgesFile()
    unknown = [k for k in data if k not in _FILE_KEYS]
    try:
        if "runtime" in data:
            out.runtime, more = parse_bridge_runtime(
                data["runtime"], os.path.dirname(os.path.abspath(path))
            )
            unknown.extend(more)
        if "recognize" in data:
            out.recognize, more = parse_bridges(data["recognize"], normalize_origin)
            unknown.extend(more)
        if "admission" in data:
            out.admission, more = parse_bridge_admission(data["admission"])
            unknown.extend(more)
    except ValueError as e:
        raise BridgesConfigError(path, str(e)) from e
    out.unknown_keys = [f"{BRIDGES_FILE}:{k}" for k in unknown]
    return out
