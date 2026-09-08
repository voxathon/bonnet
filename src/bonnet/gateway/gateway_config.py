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

"""The gateway's own TOML config — `gateway.toml`, http mode only.

Stdio needs none of this: there's no host/port/TLS to configure and no reason
to touch a file for a process an agent host launches over its own pipes. This
exists purely so an http deployment's settings survive a restart without
having to re-type them as flags every time, mirroring `core.config`'s
CLI-flag-overrides-file precedence (see `app/main.py`'s `--host`/`config.host`).

Absent entirely by default — `bonnet gateway --http` with no `gateway.toml`
behaves exactly as it always has, resolving flags then $MCP_* env vars then
built-in defaults. This file only ever narrows that further, never widens it:
a caller cannot see a setting here that CLI/env didn't already allow.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field

#: Keys recognized under the [gateway] table. Anything else warns and is
#: ignored (warn-and-ignore, mirroring the server's unknown_keys handling).
KNOWN_KEYS = frozenset(
    {
        "transport",
        "host",
        "port",
        "tls_cert",
        "tls_key",
        "gating",
        "path",
        "url",
        "log_level",
        "log_keep_files",
    }
)

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")

_SAMPLE = """\
# Bonnet gateway configuration sample (http mode only).
# Stdio needs no file: there is no host/port/TLS to configure for a process
# an agent host launches over its own pipes. This file exists so an http
# deployment's settings survive a restart without re-typing flags every time.
# Precedence: CLI flags > $MCP_* / $BONNET_URL env vars > this file > built-ins.
# Everything below is commented, so a fresh `--init` file behaves exactly
# like no file at all. Uncomment deliberately.
#
# [gateway]
# # stdio | http | sse (sse is legacy, prefer http)
# # transport = "http"
# # http bind address: 127.0.0.1 for local-only, 0.0.0.0 to expose.
# # Exposing holds every tenant's signing keys beyond this machine: set
# # tls_cert/tls_key and restrict access first.
# # host = "127.0.0.1"
# # http port
# # port = 8080
# # http endpoint path (e.g. "/", "/mcp" or "/blah").
# # Must not be /health or /.well-known/untp (the gateway's own routes).
# # path = "/mcp"
# # Default upstream board server (fills $BONNET_URL when the environment
# # does not set it; env still wins). Just scheme+host+port, no path/query.
# # url = "https://bbs.example:2272"
# # TLS certificate/key for the gateway itself (reuse the board server's
# # certs, or terminate TLS at a reverse proxy and leave these unset).
# # tls_cert = "/path/to/bonnet.crt"
# # tls_key = "/path/to/bonnet.key"
# # Show every tool regardless of state (debug only; default is gated).
# # gating = true
# # File verbosity: DEBUG | INFO | WARNING | ERROR (env BONNET_LOG_LEVEL
# # wins over this file). Pruning keeps the newest N boot files.
# # log_level = "DEBUG"
# # log_keep_files = 20
"""


@dataclass
class GatewayConfig:
    transport: str | None = None
    host: str | None = None
    port: int | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    gating: bool | None = None
    path: str | None = None
    url: str | None = None
    log_level: str | None = None
    log_keep_files: int | None = None
    unknown_keys: list[str] = field(default_factory=list)


def load(path: str) -> GatewayConfig | None:
    """The parsed `gateway.toml` at `path`, or None if it doesn't exist.

    Malformed TOML is not swallowed — a config an operator meant to be read
    should fail loudly rather than silently fall back to defaults.
    """
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        return None

    table = data.get("gateway", {})
    if not isinstance(table, dict):
        raise ValueError("config: [gateway] must be a table")
    unknown = sorted(k for k in table if k not in KNOWN_KEYS)
    return GatewayConfig(
        transport=table.get("transport"),
        host=table.get("host"),
        port=table.get("port"),
        tls_cert=table.get("tls_cert") or None,
        tls_key=table.get("tls_key") or None,
        gating=table.get("gating"),
        path=table.get("path") or None,
        url=table.get("url") or None,
        log_level=table.get("log_level"),
        log_keep_files=table.get("log_keep_files"),
        unknown_keys=unknown,
    )


def create_default_config(path: str, force: bool = False) -> None:
    """Write a commented sample gateway.toml.

    Everything is commented, so a fresh file behaves exactly like no file.
    Raises FileExistsError unless force; never silently overwrites.
    """
    if os.path.exists(path) and not force:
        raise FileExistsError(f"config file already exists: {path} (use --force to overwrite)")
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(_SAMPLE)


def validate(cfg: GatewayConfig) -> None:
    """Raise ValueError on any invalid [gateway] value."""
    if cfg.transport is not None and cfg.transport not in ("stdio", "http", "sse"):
        raise ValueError(
            f"config: gateway.transport must be stdio, http or sse, got {cfg.transport!r}"
        )
    if cfg.host is not None and (not isinstance(cfg.host, str) or not cfg.host.strip()):
        raise ValueError(f"config: gateway.host must be a non-empty string, got {cfg.host!r}")
    if cfg.port is not None:
        if not isinstance(cfg.port, int) or isinstance(cfg.port, bool):
            raise ValueError(f"config: gateway.port must be an integer, got {cfg.port!r}")
        if not 1 <= cfg.port <= 65535:
            raise ValueError(f"config: gateway.port must be 1-65535, got {cfg.port!r}")
    for key in ("tls_cert", "tls_key"):
        value = getattr(cfg, key)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise ValueError(f"config: gateway.{key} must be a non-empty string, got {value!r}")
    if cfg.gating is not None and not isinstance(cfg.gating, bool):
        raise ValueError(f"config: gateway.gating must be true or false, got {cfg.gating!r}")
    if cfg.path is not None:
        _validate_path(cfg.path)
    if cfg.url is not None:
        _validate_url(cfg.url)
    if cfg.log_level is not None:
        if not isinstance(cfg.log_level, str) or cfg.log_level.upper() not in LOG_LEVELS:
            raise ValueError(
                f"config: gateway.log_level must be one of "
                f"{', '.join(LOG_LEVELS)}, got {cfg.log_level!r}"
            )
    if cfg.log_keep_files is not None:
        if (
            not isinstance(cfg.log_keep_files, int)
            or isinstance(cfg.log_keep_files, bool)
            or cfg.log_keep_files < 1
        ):
            raise ValueError(
                f"config: gateway.log_keep_files must be an integer >= 1, "
                f"got {cfg.log_keep_files!r}"
            )


def _validate_path(raw: object) -> None:
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"config: gateway.path must be a non-empty string, got {raw!r}")
    path = raw.strip()
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    if path in ("/health", "/.well-known/untp"):
        raise ValueError(
            f"config: gateway.path {raw!r} collides with the gateway's own route; "
            "pick another (e.g. '/', '/mcp' or '/blah')"
        )
    if any(c.isspace() for c in path):
        raise ValueError(f"config: gateway.path must not contain whitespace, got {raw!r}")


def _validate_url(raw: object) -> None:
    from urllib.parse import urlsplit

    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"config: gateway.url must be a non-empty string, got {raw!r}")
    parsed = urlsplit(raw.strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"config: gateway.url must be e.g. https://bbs.example:2272, got {raw!r}")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError(
            f"config: gateway.url takes just scheme+host+port, got {raw!r} "
            "(with no path, query or fragment)"
        )
