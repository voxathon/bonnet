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

"""Per-user default directories for the `server`, `bridge` and `gateway` subcommands.

Both currently hand-rolled their own "env var, else default" resolution
independently (`gateway/paths.py`, `core/config.py`) with different defaults —
one per-user, one CWD-relative. This unifies the algorithm; each component
still gets its own env var and its own subdirectory, since a server's config/
ACL/peers and a gateway's tenants/registry are different things that happen to
share a resolution rule, not one directory two subcommands compete over.

Resolution order, per component:

1. The component's own env var (`BONNET_SERVER_HOME` / `BONNET_BRIDGE_HOME` /
   `BONNET_GATEWAY_HOME`), if set — an explicit operator override for *this*
   run, always honored. `--dir` sets it for its own process and nothing else.
2. The pointer file `set_home` last wrote for that component, if any. Only
   `--set-default-dir` writes it: a plain `--dir` used to, which let one
   instance's `--dir` silently redirect every later bare run on the account.
3. `platformdirs.user_data_dir("bonnet", appauthor=False)/<component>`.

A bridge origin is a server too, but never shares a home with one: it has
its own component, env var and config file name (`bridge.toml`, as the
gateway has `gateway.toml`), and each refuses a home holding the other's
config file (`home_conflict`).

Pointer files live at a fixed, non-relocatable bootstrap location —
`platformdirs.user_config_dir`, not the data dir being pointed to — so
resolving "where do I look for the pointer" never depends on the answer the
pointer itself supplies.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import platformdirs


@dataclass(frozen=True)
class HomeKind:
    """One kind of server home: its component name, env var and config file."""

    component: str
    env_var: str
    config_name: str


SERVER = HomeKind("server", "BONNET_SERVER_HOME", "config.toml")
BRIDGE = HomeKind("bridge", "BONNET_BRIDGE_HOME", "bridge.toml")
_SERVER_KINDS = (SERVER, BRIDGE)


def kind_for_config(path: str) -> HomeKind:
    """The kind a server config file belongs to, read from its name."""
    return BRIDGE if os.path.basename(path) == BRIDGE.config_name else SERVER


def home_conflict(kind: HomeKind, config_path: str, home: str | None = None) -> str | None:
    """Why `kind` must not run with this config and home, or None if it may.

    A bridge's config file must be named `bridge.toml` and a server's must
    not (`kind_for_config` reads the kind back from the name). Neither the
    config's directory nor `home` may hold another kind's config file: that
    directory belongs to a different server, and sharing it shares its data.
    """
    if kind_for_config(config_path) is not kind:
        return (
            f"{config_path} can't be a {kind.component}'s config: "
            f"a bridge's is named {BRIDGE.config_name}, and only a bridge's is"
        )
    dirs = {os.path.dirname(os.path.abspath(config_path))}
    if home:
        dirs.add(os.path.abspath(home))
    for d in sorted(dirs):
        for other in _SERVER_KINDS:
            if other is kind:
                continue
            found = os.path.join(d, other.config_name)
            if os.path.exists(found):
                return (
                    f"{d} holds {other.config_name}, so it is a {other.component}'s home; "
                    f"give this {kind.component} its own (--dir or ${kind.env_var})"
                )
    return None


def _pointer_path(component: str) -> str:
    config_dir = platformdirs.user_config_dir("bonnet", appauthor=False)
    return os.path.join(config_dir, f"{component}.dir")


def resolve_home(component: str, env_var: str) -> str:
    """Where `component` ("server", "bridge" or "gateway") keeps its durable state.

    Never creates anything — callers create the directory (or don't) as their
    own concern; this only decides the path.
    """
    override = os.environ.get(env_var)
    if override:
        return os.path.expanduser(override)

    pointer = _pointer_path(component)
    try:
        with open(pointer, encoding="utf-8") as f:
            remembered = f.read().strip()
    except OSError:
        remembered = ""
    if remembered:
        return os.path.expanduser(remembered)

    return os.path.join(platformdirs.user_data_dir("bonnet", appauthor=False), component)


def set_home(component: str, path: str) -> None:
    """Remember `path` as `component`'s home for future runs (`--set-default-dir`).

    Written to the pointer file, not the process environment: a child process
    cannot set an environment variable that survives into the shell that
    launched it, so persisting the choice has to happen on disk.
    """
    pointer = _pointer_path(component)
    os.makedirs(os.path.dirname(pointer), exist_ok=True)
    with open(pointer, "w", encoding="utf-8") as f:
        f.write(os.path.abspath(path))
