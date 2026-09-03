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

import tomllib
from dataclasses import dataclass


@dataclass
class GatewayConfig:
    transport: str | None = None
    host: str | None = None
    port: int | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    gating: bool | None = None


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
    return GatewayConfig(
        transport=table.get("transport"),
        host=table.get("host"),
        port=table.get("port"),
        tls_cert=table.get("tls_cert") or None,
        tls_key=table.get("tls_key") or None,
        gating=table.get("gating"),
    )
