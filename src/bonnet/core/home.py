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

"""Per-user default directories for the `server` and `gateway` subcommands.

Both currently hand-rolled their own "env var, else default" resolution
independently (`gateway/paths.py`, `core/config.py`) with different defaults —
one per-user, one CWD-relative. This unifies the algorithm; each component
still gets its own env var and its own subdirectory, since a server's config/
ACL/peers and a gateway's tenants/registry are different things that happen to
share a resolution rule, not one directory two subcommands compete over.

Resolution order, per component:

1. The component's own env var (`BONNET_SERVER_HOME` / `BONNET_GATEWAY_HOME`),
   if set — an explicit operator override for *this* run, always honored.
2. The pointer file `set_home` last wrote for that component, if any — what
   makes `--dir` persist across runs without touching the invoking shell's
   environment, which a child process cannot do.
3. `platformdirs.user_data_dir("bonnet", appauthor=False)/<component>`.

Pointer files live at a fixed, non-relocatable bootstrap location —
`platformdirs.user_config_dir`, not the data dir being pointed to — so
resolving "where do I look for the pointer" never depends on the answer the
pointer itself supplies.
"""

from __future__ import annotations

import os

import platformdirs


def _pointer_path(component: str) -> str:
    config_dir = platformdirs.user_config_dir("bonnet", appauthor=False)
    return os.path.join(config_dir, f"{component}.dir")


def resolve_home(component: str, env_var: str) -> str:
    """Where `component` ("server" or "gateway") keeps its durable state.

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
    """Remember `path` as `component`'s home for future runs. What `--dir` calls.

    Written to the pointer file, not the process environment: a child process
    cannot set an environment variable that survives into the shell that
    launched it, so persisting the choice has to happen on disk.
    """
    pointer = _pointer_path(component)
    os.makedirs(os.path.dirname(pointer), exist_ok=True)
    with open(pointer, "w", encoding="utf-8") as f:
        f.write(os.path.abspath(path))
