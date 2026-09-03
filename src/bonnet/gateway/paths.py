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

"""Where the gateway keeps things, and which tenant's copy it means.

Distinct from configuration. Configuration is what an operator supplies
(a TOML file, environment variables, command-line flags); this resolves the
paths of state the gateway itself learns and must not forget between
processes — pinned origin keys, joined origins, identities.

Layout::

    <gateway dir>/                 BONNET_GATEWAY_HOME, else the per-user data dir
      gateway.toml                 http mode only
      registry.db                  tenants and their hashed API keys
      tenants/
        default/                   stdio's tenant, full capability
          identities.db
          origins.db
          trust.db
        anonymous/                 shared fallback for bad or missing auth
        <tenant-id>/

The per-user default (rather than anything CWD-relative) is deliberate and
predates tenancy: the gateway is launched by an agent host that chooses its
own working directory, so a relative path would silently become a fresh empty
store — and orphan the agent's existing keys — on the next launch from
somewhere else.

`current_tenant` lives here, at the bottom of the import graph, because
"which tenant" is exactly what turns a name into a path. `tenancy` re-exports
it and is what most callers should use; putting it there instead would cycle,
since `identity` and `origins` need it to resolve their own defaults.
"""

from __future__ import annotations

import contextvars
import os

from bonnet.core.home import resolve_home

#: The tenant a stdio gateway is, and the one a single-tenant deployment uses.
DEFAULT_TENANT = "default"

#: The shared tenant a request falls back to when its credential is missing or
#: not accepted. Read-only; its identity store is created like any other but
#: stays empty, because nothing that could write to it is reachable from this
#: tenant — see `tenancy.is_anonymous` and `gating.ANONYMOUS_FORBIDDEN`.
ANONYMOUS_TENANT = "anonymous"

#: Names an operator may not register, because they already mean something.
RESERVED_TENANTS = frozenset({DEFAULT_TENANT, ANONYMOUS_TENANT})

#: Which tenant the current request belongs to. A ContextVar, not a global,
#: for the same reason the identity and cursor state are: one http gateway
#: serves many callers concurrently and must not let one see another's stores.
current_tenant: contextvars.ContextVar[str] = contextvars.ContextVar(
    "tenant", default=DEFAULT_TENANT
)


def gateway_dir() -> str:
    """Directory holding all of this gateway's durable state."""
    return resolve_home("gateway", "BONNET_GATEWAY_HOME")


def registry_db_path() -> str:
    """Where tenants and their hashed API keys live.

    Gateway-level, not per-tenant: a credential has to be resolved *before*
    it is known which tenant's directory to open, so this cannot live inside
    one of them.
    """
    return os.path.join(gateway_dir(), "registry.db")


def config_path() -> str:
    """The gateway's own TOML config. Read in http mode only."""
    return os.path.join(gateway_dir(), "gateway.toml")


def tenant_dir(tenant: str | None = None) -> str:
    """Directory holding one tenant's state. Defaults to the current tenant.

    A tenant is a directory rather than a row or a filename prefix so that
    isolation is enforced by the filesystem: there is no query that can forget
    its WHERE clause, deleting a tenant is removing a tree, and backing one up
    is archiving a directory.
    """
    return os.path.join(gateway_dir(), "tenants", tenant or current_tenant.get())


def identities_db_path(tenant: str | None = None) -> str:
    """Where a tenant's signing identities live.

    $BONNET_IDENTITIES_DB overrides this for the default tenant only. It
    predates tenancy and names a single file; honouring it for every tenant
    would point them all at one identity store, which is precisely the
    isolation failure this module exists to prevent.
    """
    resolved = tenant or current_tenant.get()
    if resolved == DEFAULT_TENANT:
        override = os.environ.get("BONNET_IDENTITIES_DB")
        if override:
            return override
    return os.path.join(tenant_dir(resolved), "identities.db")


def origins_db_path(tenant: str | None = None) -> str:
    """Where a tenant's joined origins are recorded."""
    return os.path.join(tenant_dir(tenant), "origins.db")


def trust_db_path(tenant: str | None = None) -> str:
    """Where a tenant's pinned origin keys are persisted.

    Per tenant, not shared: a pin is a trust decision, and one tenant
    accepting a key must not silently commit another to it.
    """
    return os.path.join(tenant_dir(tenant), "trust.db")
