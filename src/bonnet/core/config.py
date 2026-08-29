"""Firehose protocol configuration loader.

Parses TOML config into a FirehoseConfig object with ACL rules, origin
settings, data paths, and operational parameters.
"""

from __future__ import annotations

import glob
import os
import tomllib
from dataclasses import dataclass

from bonnet.core.acl import ACLEvaluator


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
    verify_tls: bool = False
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
    if not origin:
        return ""
    return origin.strip().lower().rstrip(".")


def _as_bool(table: dict, key: str, section: str, default: bool) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise ValueError(f"config: {section}.{key} must be a boolean, got {value!r}")
    return value


_TOP_LEVEL_KEYS = {"server", "limits", "search", "tls", "sync", "acl", "include"}

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
}

_PEER_KEYS = {
    "origin",
    "hostname",
    "port",
    "verify_tls",
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
    for section_name in ("server", "limits", "search", "tls", "sync"):
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
        signature_lifetime_seconds: int = 60,
        clock_skew_seconds: int = 30,
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

    def validate(self) -> None:
        """Raise ValueError if configuration is invalid."""
        if not self.origin:
            raise ValueError("config: origin must not be empty")
        if not (1 <= self.port <= 65535):
            raise ValueError(f"config: port {self.port} out of range [1, 65535]")
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
        if self.signature_lifetime_seconds > 60:
            raise ValueError(
                f"config: signature_lifetime_seconds must not exceed 60, got {self.signature_lifetime_seconds}"
            )
        if self.clock_skew_seconds > 30:
            raise ValueError(
                f"config: clock_skew_seconds must not exceed 30, got {self.clock_skew_seconds}"
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
            normalized_origin = _normalize_origin(peer.origin)
            if normalized_origin in seen_origins:
                raise ValueError(f"config: duplicate peer origin '{peer.origin}'")
            seen_origins.add(normalized_origin)
            if not (1 <= peer.port <= 65535):
                raise ValueError(f"config: peer '{peer.origin}' port {peer.port} out of range")
            for flag in ("import_warnings", "import_temp_bans", "import_permabans"):
                value = getattr(peer, flag)
                if not isinstance(value, bool):
                    raise ValueError(f"config: peer '{peer.origin}' {flag} must be a boolean")

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

        # BONNET_HOME only supplies a *default* for storage paths left unset
        # in config.toml — an explicit config.toml value always wins, so a
        # stray environment variable can't silently relocate a deliberately
        # configured server's data.
        bonnet_home = os.environ.get("BONNET_HOME")

        def _storage_default(subdir: str, fallback: str) -> str:
            return os.path.join(bonnet_home, subdir) if bonnet_home else fallback

        origin = server.get("origin", "localhost")
        hostname = server.get("hostname", "")
        data_dir = server.get("data_dir") or _storage_default("data", "./data")
        boards_dir = server.get("boards_dir") or _storage_default("boards", "./boards")
        events_bodies_dir = server.get("events_bodies_dir") or _storage_default(
            "event_bodies", "./event_bodies"
        )
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
            tls_enabled=tls.get("enabled", False),
            tls_cert_path=tls.get("cert_path", ""),
            tls_key_path=tls.get("key_path", ""),
            tls_ca_bundle=tls.get("ca_bundle", True),
            max_request_size=limits.get("max_request_size", 10 * 1024 * 1024),
            max_article_body_size=limits.get("max_article_body_size", 1024 * 1024),
            rate_limit_requests=limits.get("rate_limit_requests", 100),
            rate_limit_window=limits.get("rate_limit_window", 1),
            signature_lifetime_seconds=server.get("signature_lifetime_seconds", 60),
            clock_skew_seconds=server.get("clock_skew_seconds", 30),
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
                    verify_tls=p.get("verify_tls", False),
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
        )

    @staticmethod
    def create_default_config(
        path: str, force: bool = False, tls_paths: tuple[str, str] | None = None
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
            tls_enabled=tls_paths is not None,
            tls_cert_path=tls_paths[0] if tls_paths else "",
            tls_key_path=tls_paths[1] if tls_paths else "",
        )
        config._write_default(path, tls_paths=tls_paths)
        return config

    @staticmethod
    def _write_default(path: str, tls_paths: tuple[str, str] | None = None) -> None:
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
# Storage paths. Default to ./data, ./boards, ./event_bodies (relative to
# the server's working directory) unless BONNET_HOME is set, in which case
# they default to $BONNET_HOME/data, $BONNET_HOME/boards,
# $BONNET_HOME/event_bodies. Uncomment to pin an explicit path regardless
# of BONNET_HOME or working directory.
# data_dir = "./data"
# boards_dir = "./boards"
# events_bodies_dir = "./event_bodies"
port = 2272
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

[sync]
interval_seconds = 300

# Firehose federation peers. Each entry starts a background sync loop.
# The origin is the peer's Bonnet origin string; hostname/port is the dial address.
# verify_tls should be false for self-signed certs (common on LAN).
# import_warnings, import_temp_bans, and import_permabans control which
# punishment types this peer's moderation actions are enforced with locally.
# Records are always stored and relayed regardless; these flags only govern
# whether you trust the peer's authority. Default is opt-in (all false).
#
# [[sync.peers]]
# origin = "10.0.0.15"
# hostname = "10.0.0.15"
# port = 2272
# verify_tls = false
# import_warnings = true
# import_temp_bans = true
# import_permabans = false

# ACL rules: explicit deny-wins, conjunctive dimensions.
# Supported matchers: pubkey, role, origin, anonymous, unknown, registered, wildcard.
# Selector lists: commands, kinds, boards, objects. Omit = not granted. "*" = all.
#
# Out of the box (the four active rules below): anyone can read every
# board, anyone can self-register a username (bonnet.user.register), and
# any registered user can publish articles and create boards. Note that
# the matchers are mutually exclusive — a registered principal is not also
# `anonymous`, so reads have to be granted to each class that needs them
# rather than once to `anonymous`. Moderation
# and admin access still need explicit rules. This lets the documented
# first-run flow (install the client extra, run bonnet-mcp, call
# register_user, then publish_article / create_board) work without any
# editing; the server's own identity is always its own admin regardless of
# what's below (see OPERATOR_GUIDE.md "Becoming your own server's admin").
# Tighten or remove any of these once you're ready to lock the server down.

[[acl]]
effect = "allow"
match.anonymous = true
actions = ["read"]
commands = ["EVENT_HEAD", "EVENT_RANGE", "EVENT_GET", "KEY_EPOCHS", "BOARD_LIST", "ARTICLE_GET", "ARTICLE_LIST", "ARTICLE_SEARCH", "ARTICLE_BODY", "USER_GET", "USER_LIST", "BAN_STATUS", "EVENT_BODY"]
boards = ["*"]

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
commands = ["EVENT_HEAD", "EVENT_RANGE", "EVENT_GET", "KEY_EPOCHS", "BOARD_LIST", "ARTICLE_GET", "ARTICLE_LIST", "ARTICLE_SEARCH", "ARTICLE_BODY", "USER_GET", "USER_LIST", "BAN_STATUS", "EVENT_BODY"]
boards = ["*"]

[[acl]]
effect = "allow"
match.registered = true
actions = ["write"]
commands = ["PUBLISH_RECORD"]
kinds = ["bonnet.article", "bonnet.board.create"]
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
