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

"""Which tenant a request belongs to, and that tenant's stores.

A tenant is an account on this gateway: it owns identities, joined origins and
pinned keys, and sees nothing of any other tenant's. Resolution happens once
per request in `AuthMiddleware`, which sets `current_tenant`; everything below
reads it rather than being handed a tenant id through every call.

**Stores are cached by resolved path, not by tenant id.** Two tenants never
share a path, so this is tenant-correct by construction — and it additionally
survives $BONNET_GATEWAY_HOME changing underneath the process, which a cache
keyed on the id alone would not. That case is not hypothetical: the test suite
relocates the gateway directory per test, and an id-keyed cache would hand
test B the store test A opened.

The anonymous tenant
--------------------
A request whose credential is missing or not accepted resolves here rather
than being refused. A non-200 on the MCP transport strands a lot of harnesses
in ways neither the agent nor its operator can diagnose; a session that works
but is visibly reduced is legible, and the reduction is reported through the
tool list (see `gating`).

This is the protocol's own model one layer up. `firehose_http_server` already
treats the anonymous key as a *principal* distinct from `unknown`, and the ACL
matches on it as a first-class case — "deliberately claiming no identity" is
not the same as "presenting a key I do not recognise".

An anonymous tenant may only ever read, always as the anonymous principal. It
holds no identities and cannot mint one, so nothing it does is attributable to
a key, and there is nothing for it to sign with.
"""

from __future__ import annotations

import contextvars

from bonnet.core.logging import log_msg
from bonnet.gateway.identity import IdentityStore
from bonnet.gateway.origins import OriginStore
from bonnet.gateway.paths import (
    ANONYMOUS_TENANT,
    DEFAULT_TENANT,
    RESERVED_TENANTS,
    current_tenant,
    identities_db_path,
    origins_db_path,
    registry_db_path,
    trust_db_path,
)
from bonnet.gateway.registry import Registry

__all__ = [
    "ANONYMOUS_TENANT",
    "DEFAULT_TENANT",
    "RESERVED_TENANTS",
    "AUTH_OK",
    "AUTH_ABSENT",
    "AUTH_REJECTED",
    "current_tenant",
    "current_auth_status",
    "is_anonymous",
    "identity_store",
    "origin_store",
    "tenant_trust_db_path",
    "resolve_key",
    "reset_store_cache",
    "reset_registry_cache",
]

#: A credential was presented and accepted (or none was needed, in stdio).
AUTH_OK = "ok"
#: No credential was presented at all.
AUTH_ABSENT = "absent"
#: A credential was presented and not accepted — unknown, revoked, or its
#: tenant is disabled.
AUTH_REJECTED = "rejected"

#: How this request's tenant was arrived at. Tracked separately from the
#: tenant id because the id alone cannot distinguish "nobody said who they
#: were" from "someone said, and was wrong" — and those want different
#: warnings, since only the second means something is misconfigured.
current_auth_status: contextvars.ContextVar[str] = contextvars.ContextVar(
    "auth_status", default=AUTH_OK
)


def is_anonymous() -> bool:
    """Whether this request is running as the anonymous tenant."""
    return current_tenant.get() == ANONYMOUS_TENANT


_identity_stores: dict[str, IdentityStore] = {}
_origin_stores: dict[str, OriginStore] = {}


def identity_store() -> IdentityStore:
    """The current tenant's signing identities."""
    path = identities_db_path()
    store = _identity_stores.get(path)
    if store is None:
        store = IdentityStore(path)
        _identity_stores[path] = store
    return store


def origin_store() -> OriginStore:
    """The current tenant's joined origins."""
    path = origins_db_path()
    store = _origin_stores.get(path)
    if store is None:
        store = OriginStore(path)
        _origin_stores[path] = store
    return store


def tenant_trust_db_path() -> str:
    """The current tenant's pinned origin keys."""
    return trust_db_path()


def reset_store_cache() -> None:
    """Drop every cached store, closing each one first.

    For tests and for tenant removal. Closing is not tidiness: a store left
    open on a directory that is about to be deleted holds a file handle, and
    on Windows that makes the removal fail outright rather than merely
    leaking.

    `IdentityStore` keeps its connection in a `threading.local`, so this
    closes the calling thread's handle and not any opened by others. That is
    enough for the CLI and the test suite, which are the callers that go on
    to delete the directory; a threaded server removing a tenant it has
    recently served may still need a restart before the files go away.
    """
    stores: list[IdentityStore | OriginStore] = [
        *_identity_stores.values(),
        *_origin_stores.values(),
    ]
    for store in stores:
        try:
            store.close()
        except Exception as e:
            # Best-effort, but never silent. A cross-thread close raises
            # ProgrammingError when check_same_thread is on, and swallowing
            # that leaves the handle open on a directory the caller is about
            # to delete — the exact failure this function exists to prevent,
            # with nothing to show for it.
            log_msg(f"TENANCY: closing {type(store).__name__} failed: {type(e).__name__}: {e}")
    _identity_stores.clear()
    _origin_stores.clear()


# --- credential resolution -------------------------------------------------
#
# The registry connection is kept for the life of the process, unlike the
# per-call opens in `tenants`: this runs on every request. Holding it is safe
# because SQLite reads see other processes' committed writes immediately, so a
# key revoked by the CLI stops resolving here without the server restarting.

_registries: dict[str, Registry] = {}


def _registry() -> Registry:
    path = registry_db_path()
    registry = _registries.get(path)
    if registry is None:
        registry = Registry(path)
        _registries[path] = registry
    return registry


def resolve_key(presented: str) -> str | None:
    """The tenant a presented API key names, or None if it names no usable one.

    None covers unknown, revoked, and belonging-to-a-disabled-tenant alike.
    Callers do not distinguish them: all three degrade to the anonymous
    tenant, and telling an unauthenticated caller which one it was would only
    help someone probing for valid key ids.
    """
    return _registry().resolve(presented)


def reset_registry_cache() -> None:
    """Drop the cached registry connection. For tests and tenant removal."""
    for registry in _registries.values():
        try:
            registry.close()
        except Exception as e:
            log_msg(f"TENANCY: closing Registry failed: {type(e).__name__}: {e}")
    _registries.clear()
