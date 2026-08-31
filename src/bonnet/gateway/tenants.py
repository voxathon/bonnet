"""Tenant lifecycle: the programmatic path, and what the CLI wraps.

Deliberately not MCP tools. Every tool in this gateway is hidden until the
caller has what it needs and revealed once they do; an account-creation tool
would have to be visible to callers who have *nothing*, from a context the
gateway cannot attribute — an open registration endpoint reachable by anything
that can speak MCP. Account lifecycle belongs out of band, so it lives here and
is driven by an operator or a script.

Every function here opens the registry, does its work and closes it, rather
than holding one open: these run from a CLI process or an external script, not
inside the request path, and an open handle blocks removing a tenant on
Windows. Resolution is the exception and lives in `tenancy`, where it can keep
one connection for the life of the process — it runs on every request.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from bonnet.gateway import tenancy
from bonnet.gateway.paths import tenant_dir
from bonnet.gateway.registry import Registry, TenantError, validate_tenant_id

__all__ = [
    "TenantError",
    "add_tenant",
    "add_key",
    "revoke_key",
    "list_tenants",
    "list_keys",
    "set_enabled",
    "remove_tenant",
]


def add_tenant(tenant_id: str, note: str = "", db_path: str | None = None) -> str:
    """Create a tenant and return its first API key.

    The key is returned once and never recoverable — only its hash is stored.
    "Lost your key" is "issue another and revoke the old one", which is also
    why a tenant may hold several at a time.
    """
    validate_tenant_id(tenant_id)
    registry = Registry(db_path)
    try:
        registry.add_tenant(tenant_id, note)
        return registry.add_key(tenant_id, label="initial")
    finally:
        registry.close()


def add_key(tenant_id: str, label: str = "", db_path: str | None = None) -> str:
    """Mint an additional key for an existing tenant, and return it."""
    registry = Registry(db_path)
    try:
        return registry.add_key(tenant_id, label)
    finally:
        registry.close()


def revoke_key(key_id: str, db_path: str | None = None) -> None:
    """Revoke one key by id, leaving the tenant's other keys working."""
    registry = Registry(db_path)
    try:
        registry.revoke_key(key_id)
    finally:
        registry.close()


def list_tenants(db_path: str | None = None) -> list[dict]:
    registry = Registry(db_path)
    try:
        return registry.list_tenants()
    finally:
        registry.close()


def list_keys(tenant_id: str | None = None, db_path: str | None = None) -> list[dict]:
    registry = Registry(db_path)
    try:
        return registry.list_keys(tenant_id)
    finally:
        registry.close()


def set_enabled(tenant_id: str, enabled: bool, db_path: str | None = None) -> None:
    """Enable or disable a tenant without destroying anything it holds.

    A disabled tenant's keys stop resolving, so its requests degrade to the
    anonymous tenant like any other unusable credential.
    """
    registry = Registry(db_path)
    try:
        registry.set_enabled(tenant_id, enabled)
    finally:
        registry.close()


def remove_tenant(tenant_id: str, db_path: str | None = None) -> None:
    """Delete a tenant: its registry row, its keys, and its directory.

    Irreversible, and it destroys signing keys — a tenant's identities live
    only in its own directory, and nothing else holds a copy. The stores are
    dropped first because a cached open handle keeps the directory
    undeletable on Windows.
    """
    registry = Registry(db_path)
    try:
        registry.remove_tenant(tenant_id)
    finally:
        registry.close()

    tenancy.reset_store_cache()
    tenancy.reset_registry_cache()
    path = Path(tenant_dir(tenant_id))
    if path.exists():
        shutil.rmtree(path)
