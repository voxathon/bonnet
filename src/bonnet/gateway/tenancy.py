"""Which tenant a request belongs to, and that tenant's stores.

A tenant is an account on this gateway: it owns identities, joined origins and
pinned keys, and sees nothing of any other tenant's. Resolution happens once
per request in `AuthMiddleware`, which sets `current_tenant`; everything below
reads it rather than being handed a tenant id through every call.

**Stores are cached by resolved path, not by tenant id.** Two tenants never
share a path, so this is tenant-correct by construction — and it additionally
survives $BONNET_GATEWAY_DIR changing underneath the process, which a cache
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

from bonnet.gateway.identity import IdentityStore
from bonnet.gateway.origins import OriginStore
from bonnet.gateway.paths import (
    ANONYMOUS_TENANT,
    DEFAULT_TENANT,
    RESERVED_TENANTS,
    current_tenant,
    identities_db_path,
    origins_db_path,
    trust_db_path,
)

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
    "reset_store_cache",
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
    """Drop every cached store, closing what can be closed.

    For tests and for tenant removal — a store held open on a directory that
    is about to be deleted keeps a file handle on Windows and makes the
    removal fail.
    """
    for store in _origin_stores.values():
        try:
            store.close()
        except Exception:
            pass
    _identity_stores.clear()
    _origin_stores.clear()
