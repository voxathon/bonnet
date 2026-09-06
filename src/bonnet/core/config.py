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

"""Firehose protocol configuration loader.

Parses TOML config into a FirehoseConfig object with ACL rules, origin
settings, data paths, and operational parameters.
"""

from __future__ import annotations

import glob
import os
import re
import socket
import tomllib
from dataclasses import dataclass

from bonnet.core.acl import ACLEvaluator
from bonnet.core.record import normalize_origin


@dataclass
class WitnessConfig:
    """Provenance retention policy for relay witnesses (global).

    Forensics-first defaults: retain everything, first verified statement
    wins (immutable observation), unbounded storage, wire reads truncated
    deterministically. Operators who care about disk opt into a cap via
    max_per_event. Per-peer overrides deliberately not supported.
    """

    retain_upstream: bool = True
    max_per_event: int = 0  # 0 = unbounded; otherwise >= 2 (origin + self)
    update_policy: str = "first"  # "first" | "last"
    wire_max: int = 32  # 1..MAX_WITNESS_SET frame ceiling


@dataclass
class PeerConfig:
    """Configuration for a firehose federation peer.

    The import_* flags control which punishment types are applied locally
    when they arrive from this peer. Records are always stored and
    relayed regardless; the flags only govern enforcement. Default is
    opt-in: a peer confers no moderation authority until each type is
    explicitly turned on.
    """

    origin: str
    hostname: str
    port: int = 2272
    scheme: str = "https"
    verify_tls: bool = False
    allow_private: bool = False
    import_warnings: bool = False
    import_temp_bans: bool = False
    import_permabans: bool = False

    def imported_punishment_types(self) -> set[str]:
        """Return the locally enforced punishment type names for this peer."""
        types = set()
        if self.import_warnings:
            types.add("warning")
        if self.import_temp_bans:
            types.add("ban")
        if self.import_permabans:
            types.add("permaban")
        return types


def _normalize_origin(origin: str) -> str:
    """Config's origin normalization, shared with the wire's lookup keys."""
    return normalize_origin(origin)


# ASCII hostname (RFC 1123 labels) or dotted-quad IPv4. `origin` is a
# federation identity, not just a display string — an unvalidated value
# becomes this server's permanent identity, so garbage (embedded whitespace,
# a "scheme://" fragment, non-ASCII that isn't punycode-encoded) needs to be
# caught here rather than silently accepted and served.
_HOSTNAME_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9-]{0,62})?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62})?)*$"
)


def _validate_hostname_like(field: str, value: str) -> None:
    if not _HOSTNAME_RE.match(value):
        raise ValueError(
            f"config: {field} {value!r} is not a valid hostname (use punycode for "
            "non-ASCII names, and no scheme/path/whitespace)"
        )


def _as_bool(table: dict, key: str, section: str, default: bool) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise ValueError(f"config: {section}.{key} must be a boolean, got {value!r}")
    return value


_TOP_LEVEL_KEYS = {"server", "limits", "search", "tls", "sync", "acl", "include", "witnesses"}

_INCLUDE_ALLOWED_TOP_KEYS = {"acl", "sync"}

_SECTION_KEYS = {
    "server": {
        "origin",
        "hostname",
        "data_dir",
        "boards_dir",
        "events_bodies_dir",
        "port",
        "admin_pubkey",
        "admin_pubkey_file",
        "signature_lifetime_seconds",
        "clock_skew_seconds",
        "host",
    },
    "limits": {
        "max_request_size",
        "max_article_body_size",
        "rate_limit_requests",
        "rate_limit_window",
    },
    "search": {
        "max_count",
        "timeout_seconds",
        "result_limit",
        "rg_path",
    },
    "tls": {
        "enabled",
        "cert_path",
        "key_path",
        "ca_bundle",
    },
    "sync": {
        "interval_seconds",
        "peers",
    },
    "witnesses": {
        "retain_upstream",
        "max_per_event",
        "update_policy",
        "wire_max",
    },
}

_PEER_KEYS = {
    "origin",
    "hostname",
    "port",
    "scheme",
    "verify_tls",
    "allow_private",
    "import_warnings",
    "import_temp_bans",
    "import_permabans",
}


def _find_unknown_keys(data: dict) -> list[str]:
    """Return dotted paths of recognized-section keys the loader ignores."""
    unknown = []
    for key in data:
        if key not in _TOP_LEVEL_KEYS:
            unknown.append(key)
    for section_name in ("server", "limits", "search", "tls", "sync", "witnesses"):
        table = data.get(section_name)
        if not isinstance(table, dict):
            continue
        for key in table:
            if key not in _SECTION_KEYS[section_name]:
                unknown.append(f"{section_name}.{key}")
    for i, peer in enumerate(data.get("sync", {}).get("peers", [])):
        if not isinstance(peer, dict):
            continue
        for key in peer:
            if key not in _PEER_KEYS:
                unknown.append(f"sync.peers[{i}].{key}")
    return unknown


def _resolve_admin_pubkey(server: dict) -> str:
    """Resolve server.admin_pubkey, inline or via admin_pubkey_file.

    admin_pubkey_file lets the key live outside the config file itself - a
    secrets-mounted file, a path injected by an orchestrator - rather than
    committed inline. Exactly one of the two may be set.
    """
    inline = server.get("admin_pubkey", "")
    file_path = server.get("admin_pubkey_file", "")

    if inline and file_path:
        raise ValueError(
            "config: server.admin_pubkey and server.admin_pubkey_file are "
            "mutually exclusive — set only one"
        )
    if not file_path:
        return inline

    try:
        with open(file_path, encoding="utf-8") as f:
            pubkey_hex = f.read().strip()
    except OSError as exc:
        raise ValueError(
            f"config: could not read server.admin_pubkey_file '{file_path}': {exc}"
        ) from exc

    if not pubkey_hex:
        raise ValueError(f"config: server.admin_pubkey_file '{file_path}' is empty")

    return pubkey_hex


def _load_include_file(inc_path: str) -> dict:
    """Load one conf.d-style include file.

    Include files may only contribute [[acl]] rules and [sync] peers —
    anything else raises rather than being silently dropped, and a nested
    'include' key raises rather than being silently ignored.
    """
    if not os.path.exists(inc_path):
        raise FileNotFoundError(f"config: included file not found: {inc_path}")

    with open(inc_path, "rb") as f:
        inc_data = tomllib.load(f)

    if "include" in inc_data:
        raise ValueError(f"config: included file '{inc_path}' must not itself use 'include'")

    for key in inc_data:
        if key not in _INCLUDE_ALLOWED_TOP_KEYS:
            raise ValueError(
                f"config: included file '{inc_path}' has unsupported top-level key "
                f"'{key}' — include files may only contain [[acl]] and [sync] (peers only)"
            )

    sync_table = inc_data.get("sync")
    if sync_table is not None and (
        not isinstance(sync_table, dict) or set(sync_table.keys()) - {"peers"}
    ):
        raise ValueError(f"config: included file '{inc_path}' [sync] may only contain 'peers'")

    return inc_data


def _resolve_includes(data: dict, base_dir: str) -> tuple[list, list, list]:
    """Expand top-level 'include' glob patterns into merged acl/peer tables.

    Returns (acl_tables, peer_tables, included) with the main file's own
    [[acl]] / [[sync.peers]] entries first, followed by each matched include
    file's entries in sorted-path order. `included` is a list of
    (path, parsed_toml) pairs, kept around so callers don't have to
    re-parse each include file for unknown-key reporting.
    """
    acl_tables = list(data.get("acl", []))
    peer_tables = list(data.get("sync", {}).get("peers", []))
    included: list[tuple[str, dict]] = []

    patterns = data.get("include", [])
    if not isinstance(patterns, list):
        raise ValueError("config: 'include' must be a list of glob patterns")

    for pattern in patterns:
        full_pattern = pattern if os.path.isabs(pattern) else os.path.join(base_dir, pattern)
        matches = sorted(glob.glob(full_pattern))
        if not matches:
            raise ValueError(f"config: include pattern '{pattern}' matched no files")
        for inc_path in matches:
            inc_data = _load_include_file(inc_path)
            acl_tables.extend(inc_data.get("acl", []))
            peer_tables.extend(inc_data.get("sync", {}).get("peers", []))
            included.append((inc_path, inc_data))

    return acl_tables, peer_tables, included


class FirehoseConfig:
    """Configuration for a Bonnet server."""

    def __init__(
        self,
        origin: str = "localhost",
        hostname: str = "",
        data_dir: str = "./data",
        boards_dir: str = "./boards",
        events_bodies_dir: str = "./event_bodies",
        port: int = 2272,
        tls_enabled: bool = False,
        tls_cert_path: str = "",
        tls_key_path: str = "",
        tls_ca_bundle: bool | str = True,
        max_request_size: int = 10 * 1024 * 1024,
        max_article_body_size: int = 1024 * 1024,
        rate_limit_requests: int = 100,
        rate_limit_window: int = 1,
        signature_lifetime_seconds: int = 300,
        clock_skew_seconds: int = 300,
        search_max_count: int = 1000,
        search_timeout_seconds: int = 10,
        search_result_limit: int = 100,
        rg_path: str = "",
        sync_interval_seconds: int = 300,
        peers: list = None,
        acl: ACLEvaluator = None,
        admin_pubkey_hex: str = "",
        host: str = "127.0.0.1",
        unknown_keys: list = None,
        witness: WitnessConfig = None,
    ):
        self.origin = _normalize_origin(origin)
        self.hostname = hostname or self.origin
        self.data_dir = data_dir
        self.boards_dir = boards_dir
        self.events_bodies_dir = events_bodies_dir
        self.port = port
        self.tls_enabled = tls_enabled
        self.tls_cert_path = tls_cert_path
        self.tls_key_path = tls_key_path
        self.tls_ca_bundle = tls_ca_bundle
        self.max_request_size = max_request_size
        self.max_article_body_size = max_article_body_size
        self.rate_limit_requests = rate_limit_requests
        self.rate_limit_window = rate_limit_window
        self.signature_lifetime_seconds = signature_lifetime_seconds
        self.clock_skew_seconds = clock_skew_seconds
        self.search_max_count = search_max_count
        self.search_timeout_seconds = search_timeout_seconds
        self.search_result_limit = search_result_limit
        self.rg_path = rg_path
        self.sync_interval_seconds = sync_interval_seconds
        self.peers = peers or []
        self.acl = acl or ACLEvaluator([])
        self.admin_pubkey_hex = admin_pubkey_hex
        self.host = host
        self.unknown_keys = list(unknown_keys or [])
        self.witness = witness or WitnessConfig()

    def validate(self) -> None:
        """Raise ValueError if configuration is invalid."""
        if not self.origin:
            raise ValueError("config: origin must not be empty")
        _validate_hostname_like("origin", self.origin)
        if self.hostname:
            _validate_hostname_like("hostname", self.hostname)
        if not isinstance(self.port, int) or isinstance(self.port, bool):
            raise ValueError(f"config: port must be an integer, got {self.port!r}")
        if not (1 <= self.port <= 65535):
            raise ValueError(f"config: port {self.port} out of range [1, 65535]")
        try:
            socket.getaddrinfo(self.host, None)
        except socket.gaierror as exc:
            raise ValueError(f"config: host {self.host!r} does not resolve: {exc}") from exc
        if self.max_request_size <= 0:
            raise ValueError(
                f"config: max_request_size must be positive, got {self.max_request_size}"
            )
        if self.max_article_body_size <= 0:
            raise ValueError(
                f"config: max_article_body_size must be positive, got {self.max_article_body_size}"
            )
        if self.rate_limit_requests <= 0:
            raise ValueError(
                f"config: rate_limit_requests must be positive, got {self.rate_limit_requests}"
            )
        if self.rate_limit_window <= 0:
            raise ValueError(
                f"config: rate_limit_window must be positive, got {self.rate_limit_window}"
            )
        # No upper cap on signature_lifetime_seconds / clock_skew_seconds:
        # a permissive node only weakens itself (receiver-side verification
        # contains the blast radius). Defaults ship Kerberos-style 300/300;
        # operators who need more accept a wider replay window explicitly.
        # Non-positive values are still rejected below via _positive checks.
        if self.signature_lifetime_seconds <= 0:
            raise ValueError(
                f"config: signature_lifetime_seconds must be positive, got {self.signature_lifetime_seconds}"
            )
        if self.clock_skew_seconds < 0:
            raise ValueError(
                f"config: clock_skew_seconds must not be negative, got {self.clock_skew_seconds}"
            )
        if (
            self.search_max_count <= 0
            or self.search_timeout_seconds <= 0
            or self.search_result_limit <= 0
        ):
            raise ValueError("config: search limits must be positive")
        if self.sync_interval_seconds <= 0:
            raise ValueError(
                f"config: sync_interval_seconds must be positive, got {self.sync_interval_seconds}"
            )
        if self.tls_enabled:
            if self.tls_cert_path and not os.path.exists(self.tls_cert_path):
                raise ValueError(f"config: TLS cert_path does not exist: {self.tls_cert_path}")
            if self.tls_key_path and not os.path.exists(self.tls_key_path):
                raise ValueError(f"config: TLS key_path does not exist: {self.tls_key_path}")
        seen_origins = set()
        for peer in self.peers:
            if not peer.origin:
                raise ValueError("config: peer origin must not be empty")
            _validate_hostname_like(f"peer '{peer.origin}' origin", peer.origin)
            if peer.hostname:
                _validate_hostname_like(f"peer '{peer.origin}' hostname", peer.hostname)
            normalized_origin = _normalize_origin(peer.origin)
            if normalized_origin in seen_origins:
                raise ValueError(f"config: duplicate peer origin '{peer.origin}'")
            seen_origins.add(normalized_origin)
            if not isinstance(peer.port, int) or isinstance(peer.port, bool):
                raise ValueError(
                    f"config: peer '{peer.origin}' port must be an integer, got {peer.port!r}"
                )
            if not (1 <= peer.port <= 65535):
                raise ValueError(f"config: peer '{peer.origin}' port {peer.port} out of range")
            if peer.scheme not in ("http", "https"):
                raise ValueError(
                    f"config: peer '{peer.origin}' scheme must be 'http' or 'https', "
                    f"got {peer.scheme!r}"
                )
            for flag in ("import_warnings", "import_temp_bans", "import_permabans"):
                value = getattr(peer, flag)
                if not isinstance(value, bool):
                    raise ValueError(f"config: peer '{peer.origin}' {flag} must be a boolean")
        if self.witness.update_policy not in ("first", "last"):
            raise ValueError(
                f"config: witnesses.update_policy must be 'first' or 'last', "
                f"got {self.witness.update_policy!r}"
            )
        if not isinstance(self.witness.max_per_event, int) or isinstance(
            self.witness.max_per_event, bool
        ):
            raise ValueError(
                f"config: witnesses.max_per_event must be an integer, "
                f"got {self.witness.max_per_event!r}"
            )
        if self.witness.max_per_event < 0 or self.witness.max_per_event == 1:
            raise ValueError(
                "config: witnesses.max_per_event must be 0 (unbounded) or >= 2 "
                f"(origin + self), got {self.witness.max_per_event}"
            )
        if not isinstance(self.witness.wire_max, int) or isinstance(self.witness.wire_max, bool):
            raise ValueError(
                f"config: witnesses.wire_max must be an integer, got {self.witness.wire_max!r}"
            )
        if not 1 <= self.witness.wire_max <= 32:
            raise ValueError(
                f"config: witnesses.wire_max must be in [1, 32], got {self.witness.wire_max}"
            )

    @property
    def identity_path(self) -> str:
        return os.path.join(self.data_dir, "identity")

    @property
    def events_db_path(self) -> str:
        return os.path.join(self.data_dir, "events.db")

    @property
    def nav_db_path(self) -> str:
        return os.path.join(self.data_dir, "nav.db")

    @property
    def users_db_path(self) -> str:
        return os.path.join(self.data_dir, "users.db")

    @property
    def policy_db_path(self) -> str:
        return os.path.join(self.data_dir, "policy.db")

    @property
    def replay_db_path(self) -> str:
        return os.path.join(self.data_dir, "replay.db")

    @property
    def http_host(self) -> str:
        return self.host

    @staticmethod
    def load(path: str) -> FirehoseConfig:
        if not os.path.exists(path):
            raise FileNotFoundError(f"config file not found: {path}")
        if os.path.isdir(path):
            raise IsADirectoryError(f"config path is a directory, not a file: {path}")

        with open(path, "rb") as f:
            data = tomllib.load(f)

        base_dir = os.path.dirname(os.path.abspath(path))
        acl_tables, peer_tables, included = _resolve_includes(data, base_dir)

        unknown_keys = _find_unknown_keys(data)
        for inc_path, inc_data in included:
            rel = os.path.relpath(inc_path, base_dir)
            unknown_keys.extend(f"{rel}:{k}" for k in _find_unknown_keys(inc_data))

        server = data.get("server", {})
        limits = data.get("limits", {})
        search = data.get("search", {})
        tls = data.get("tls", {})
        sync = data.get("sync", {})
        witnesses = data.get("witnesses", {})
        if not isinstance(witnesses, dict):
            raise ValueError("config: [witnesses] must be a table")

        # BONNET_SERVER_HOME (or the per-user default, see core.home) only
        # supplies a *default* for storage paths left unset in config.toml —
        # an explicit config.toml value always wins, so a stray environment
        # variable can't silently relocate a deliberately configured server's
        # data.
        #
        # The fallback below is `base_dir` (this config file's own
        # directory), not `resolve_home()`'s globally-remembered pointer.
        # `resolve_home()`'s pointer file is process-wide per OS user, keyed
        # by nothing this specific `--config PATH` chose — two concurrent
        # `bonnet server` instances started with distinct `--config` paths
        # but no `--dir`/`BONNET_SERVER_HOME` would otherwise silently share
        # (and race on) whichever instance's `--dir`/`--init` last wrote that
        # pointer. An explicit env var override still wins, matching the
        # comment above; `--dir`/`--init` continue to work unchanged, since
        # they set `args.config` to `<dir>/config.toml`, making `base_dir`
        # equal to the directory they named.
        env_server_home = os.environ.get("BONNET_SERVER_HOME")
        server_home = os.path.expanduser(env_server_home) if env_server_home else base_dir

        def _storage_default(subdir: str) -> str:
            return os.path.join(server_home, subdir)

        origin = server.get("origin", "localhost")
        hostname = server.get("hostname", "")
        data_dir = server.get("data_dir") or _storage_default("data")
        boards_dir = server.get("boards_dir") or _storage_default("boards")
        events_bodies_dir = server.get("events_bodies_dir") or _storage_default("event_bodies")
        port = server.get("port", 2272)
        admin_pubkey_hex = _resolve_admin_pubkey(server)

        acl = ACLEvaluator.from_toml({"acl": acl_tables})

        if admin_pubkey_hex:
            # Ensure admin_pubkey_hex actually grants admin, regardless of
            # whether other [[acl]] rules are already configured — it used
            # to only take effect when the [[acl]] table was completely
            # empty, so the moment an operator kept even one of the sample
            # config's default rules (the documented first-run flow: keep
            # the three defaults, uncomment admin_pubkey), the configured
            # key silently got nothing, with no error anywhere.
            from bonnet.core.acl import default_rules_for_admin

            admin_pubkey_bytes = bytes.fromhex(admin_pubkey_hex)
            has_configured_admin = any(
                r.matcher.pubkey == admin_pubkey_bytes and r.effect == "allow" for r in acl._rules
            )
            if not has_configured_admin:
                acl.add_rule(default_rules_for_admin(admin_pubkey_hex)[0])

        return FirehoseConfig(
            origin=origin,
            hostname=hostname,
            data_dir=data_dir,
            boards_dir=boards_dir,
            events_bodies_dir=events_bodies_dir,
            port=port,
            tls_enabled=_as_bool(tls, "enabled", "tls", False),
            tls_cert_path=tls.get("cert_path", ""),
            tls_key_path=tls.get("key_path", ""),
            tls_ca_bundle=tls.get("ca_bundle", True),
            max_request_size=limits.get("max_request_size", 10 * 1024 * 1024),
            max_article_body_size=limits.get("max_article_body_size", 1024 * 1024),
            rate_limit_requests=limits.get("rate_limit_requests", 100),
            rate_limit_window=limits.get("rate_limit_window", 1),
            signature_lifetime_seconds=server.get("signature_lifetime_seconds", 300),
            clock_skew_seconds=server.get("clock_skew_seconds", 300),
            search_max_count=search.get("max_count", 1000),
            search_timeout_seconds=search.get("timeout_seconds", 10),
            search_result_limit=search.get("result_limit", 100),
            rg_path=search.get("rg_path", ""),
            sync_interval_seconds=sync.get("interval_seconds", 300),
            peers=[
                PeerConfig(
                    origin=p.get("origin", ""),
                    hostname=p.get("hostname", ""),
                    port=p.get("port", 2272),
                    scheme=p.get("scheme", "https"),
                    verify_tls=p.get("verify_tls", False),
                    allow_private=_as_bool(p, "allow_private", "sync.peers", False),
                    import_warnings=_as_bool(p, "import_warnings", "sync.peers", False),
                    import_temp_bans=_as_bool(p, "import_temp_bans", "sync.peers", False),
                    import_permabans=_as_bool(p, "import_permabans", "sync.peers", False),
                )
                for p in peer_tables
            ],
            acl=acl,
            admin_pubkey_hex=admin_pubkey_hex,
            host=server.get("host", "127.0.0.1"),
            unknown_keys=unknown_keys,
            witness=WitnessConfig(
                retain_upstream=_as_bool(witnesses, "retain_upstream", "witnesses", True),
                max_per_event=witnesses.get("max_per_event", 0),
                update_policy=witnesses.get("update_policy", "first"),
                wire_max=witnesses.get("wire_max", 32),
            ),
        )

    @staticmethod
    def create_default_config(
        path: str,
        force: bool = False,
        tls_paths: tuple[str, str] | None = None,
        port: int = 2272,
    ) -> FirehoseConfig:
        """Write a sample config file and return the default config.

        Raises FileExistsError if the path already exists unless force is
        true. Existing operator configuration must never be silently
        overwritten by a sample-generation flag.

        tls_paths, if given, is a (cert_path, key_path) pair to write into
        the sample's [tls] section with tls.enabled = true, for callers that
        generated a certificate alongside the config (see --self-signed).
        """
        if os.path.exists(path) and not force:
            raise FileExistsError(f"config file already exists: {path} (use --force to overwrite)")
        config = FirehoseConfig(
            acl=ACLEvaluator([]),
            port=port,
            tls_enabled=tls_paths is not None,
            tls_cert_path=tls_paths[0] if tls_paths else "",
            tls_key_path=tls_paths[1] if tls_paths else "",
        )
        config._write_default(path, tls_paths=tls_paths, port=port)
        return config

    @staticmethod
    def _write_default(
        path: str, tls_paths: tuple[str, str] | None = None, port: int = 2272
    ) -> None:
        if tls_paths:
            cert_path, key_path = tls_paths
            tls_section = f"""[tls]
enabled = true
cert_path = "{cert_path}"
key_path = "{key_path}"
# ca_bundle = true"""
        else:
            tls_section = """[tls]
enabled = false
# cert_path = "./certs/bonnet.crt"
# key_path = "./certs/bonnet.key"
# ca_bundle = true"""

        default_content = f"""# Bonnet server configuration sample.
# Operator documentation: OPERATOR_GUIDE.md

# Split a growing [[acl]] or [[sync.peers]] list into separate files with
# conf.d-style includes. Glob patterns are resolved relative to this file;
# each match may only contain [[acl]] and/or [sync] (peers only) — nothing
# else, and no further 'include' of its own. Must appear before any [table]
# header (a TOML requirement, not a Bonnet one) — this comment block is the
# only place in this file it's legal to add it.
# include = ["acl.d/*.toml", "peers.d/*.toml"]

[server]
origin = "localhost"
hostname = ""
# Storage paths. Default to data, boards, event_bodies under this server's
# home directory ($BONNET_SERVER_HOME if set, else the OS per-user data dir —
# see `bonnet server -h`). Uncomment to pin an explicit path regardless.
# data_dir = "./data"
# boards_dir = "./boards"
# events_bodies_dir = "./event_bodies"
port = {port}
# Bind address: 127.0.0.1 for local-only, 0.0.0.0 for all interfaces.
# Change this deliberately once you're ready to accept remote connections.
host = "127.0.0.1"
# admin_pubkey = "<hex-encoded Ed25519 public key for full access>"
# See OPERATOR_GUIDE.md "Becoming your own server's admin" for how to get one.
# Or point at a file instead of inlining the key (a secrets mount, a path an
# orchestrator injects) — set exactly one of the two:
# admin_pubkey_file = "/run/secrets/bonnet_admin_pubkey"

[limits]
max_request_size = 10485760
max_article_body_size = 1048576
rate_limit_requests = 100
rate_limit_window = 1

[search]
# Full-text search shells out to ripgrep. Install rg and put it on PATH,
# or point rg_path at the binary; without it ARTICLE_SEARCH returns 503.
max_count = 1000
timeout_seconds = 10
result_limit = 100

{tls_section}

[witnesses]
# Provenance retention for relay witnesses (global; no per-peer overrides).
# retain_upstream = true keeps each peer's chain so it survives that peer
# going offline; false stores only our own + the origin witness.
# max_per_event = 0 keeps everything (~300B per witness: events x relays);
# set N >= 2 to keep the origin witness + our own + the newest N-2 upstream
# (oldest upstream evicted first, never the origin/own entries).
# update_policy = "first" makes a relay's first verified statement about an
# event immutable (forensics default); "last" keeps the current replace-on-
# re-sign behavior. wire_max truncates reads deterministically
# (own, origin, newest) without touching storage; must be in [1, 32].
retain_upstream = true
max_per_event = 0
update_policy = "first"
wire_max = 32

[sync]
interval_seconds = 300

# Firehose federation peers. Each entry starts a background sync loop.
# The origin is the peer's Bonnet origin string; hostname/port is the dial address.
# scheme selects how the peer is dialed ("https", the default, or "http" for
# a peer running with TLS disabled entirely). verify_tls only matters when
# scheme is "https": set it false for self-signed certs (common on LAN).
# allow_private permits dialing loopback/private/link-local addresses (e.g.
# 127.0.0.1 or 10.0.0.15) - refused by default as an SSRF guard, so set this
# to true for local testing or a real LAN-only federation deployment.
# import_warnings, import_temp_bans, and import_permabans control which
# punishment types this peer's moderation actions are enforced with locally.
# Records are always stored and relayed regardless; these flags only govern
# whether you trust the peer's authority. Default is opt-in (all false).
#
# [[sync.peers]]
# origin = "10.0.0.15"
# hostname = "10.0.0.15"
# port = 2272
# scheme = "https"
# verify_tls = false
# allow_private = true
# import_warnings = true
# import_temp_bans = true
# import_permabans = false

# ACL rules: explicit deny-wins, conjunctive dimensions.
# Supported matchers: pubkey, role, origin, anonymous, unknown, registered, wildcard.
# Selector lists: commands, kinds, boards, objects. Omit = not granted. "*" = all.
#
# Out of the box (the four active rules below): anyone can read every
# board, anyone can self-register a username (bonnet.user.register), and
# any registered user can publish articles, create boards, and succeed
# their own signing key (bonnet.user.key.rotate). Note that
# the matchers are mutually exclusive — a registered principal is not also
# `anonymous`, so reads have to be granted to each class that needs them
# rather than once to `anonymous`. Moderation
# and admin access still need explicit rules. This lets the documented
# first-run flow (run bonnet gateway, call connect then
# register, then publish_article / create_board) work without any editing;
# the server's own identity is always its own admin regardless of
# what's below (see OPERATOR_GUIDE.md "Becoming your own server's admin").
# Tighten or remove any of these once you're ready to lock the server down.

[[acl]]
effect = "allow"
match.anonymous = true
actions = ["read"]
commands = ["PERMISSIONS", "EVENT_HEAD", "EVENT_RANGE", "EVENT_GET", "KEY_EPOCHS", "BOARD_LIST", "ARTICLE_GET", "ARTICLE_LIST", "ARTICLE_SEARCH", "ARTICLE_BODY", "USER_GET", "USER_LIST", "BAN_STATUS", "EVENT_BODY"]
boards = ["*"]

[[acl]]
effect = "allow"
match.unknown = true
actions = ["read"]
commands = ["PERMISSIONS"]

[[acl]]
effect = "allow"
match.unknown = true
actions = ["write"]
commands = ["PUBLISH_RECORD"]
kinds = ["bonnet.user.register"]

[[acl]]
effect = "allow"
match.registered = true
actions = ["read"]
commands = ["PERMISSIONS", "EVENT_HEAD", "EVENT_RANGE", "EVENT_GET", "KEY_EPOCHS", "BOARD_LIST", "ARTICLE_GET", "ARTICLE_LIST", "ARTICLE_SEARCH", "ARTICLE_BODY", "USER_GET", "USER_LIST", "BAN_STATUS", "EVENT_BODY"]
boards = ["*"]

[[acl]]
effect = "allow"
match.registered = true
actions = ["write"]
commands = ["PUBLISH_RECORD"]
kinds = ["bonnet.article", "bonnet.board.create", "bonnet.report", "bonnet.user.key.rotate", "bonnet.punishment.ack"]
boards = ["*"]

# To grant a specific key full access (read/write, every command/kind/board):
#
# [[acl]]
# effect = "allow"
# match.pubkey = "hex:<64 hex chars>"
# actions = ["read", "write"]
# commands = ["*"]
# kinds = ["*"]
# boards = ["*"]
# objects = ["*"]
"""
        config_dir = os.path.dirname(path)
        if config_dir:
            os.makedirs(config_dir, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(default_content)
