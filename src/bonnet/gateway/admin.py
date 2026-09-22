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

"""HTTP tenant administration (`/admin/*`, http mode only).

The same operations the `bonnet gateway tenant ...` / `key ...` CLI wraps
(`gateway.tenants`), exposed over HTTP so a same-machine helper — e.g. a
closed-down shim on a companion web server — can provision tenants without
switching venvs or shelling out.

Deliberately not MCP tools: see `tenants` for why account lifecycle must not
be visible to callers who have nothing. And deliberately its own credential:
`@mcp.custom_route` handlers never pass through `AuthMiddleware` (see
`get_facade`), so this module authenticates itself against a dedicated admin
secret rather than tenant API keys.

Secret source (first one wins):
  1. $BONNET_GATEWAY_ADMIN_TOKEN (env wins, rotation without restart)
  2. [gateway] admin_token in gateway.toml
Unset entirely → every route 404s (disabled, undiscoverable).

Destructive operations are guarded by explicit confirmation, not by their
transport: `tenant remove --yes` on the CLI and the routes below are the
same `tenants` calls with the same consequences. Removal destroys the
tenant's signing-key directory, which nothing else holds — the delete
route requires `{"confirm": "<tenant_id>"}` echoing the path id rather
than a bare POST, and revoking a tenant's last live key (which locks it
out until an operator runs `key add`) requires `{"force": true}` instead
of the default 409 refusal.
"""

from __future__ import annotations

import functools
import os
import secrets

from starlette.requests import Request
from starlette.responses import JSONResponse

from bonnet.gateway import paths, tenants
from bonnet.gateway.registry import TenantError, validate_tenant_id
from bonnet.gateway.tools import mcp


def _counted(op: str):
    """Decorator counting one admin handler's hits by outcome."""

    def deco(fn):
        @functools.wraps(fn)
        async def wrapper(request: Request) -> JSONResponse:
            try:
                from bonnet.core import metrics
            except Exception:
                return await fn(request)
            try:
                resp = await fn(request)
            except Exception:
                try:
                    metrics.observe_http(f"admin_{op}", request.method, ok=False)
                except Exception:
                    pass
                raise
            try:
                metrics.observe_http(f"admin_{op}", request.method, ok=resp.status_code < 400)
            except Exception:
                pass
            return resp

        return wrapper

    return deco


#: Env var naming the admin bearer secret. Env wins over gateway.toml so a
#: rotation is a process-environment change, not a config-file edit.
ADMIN_TOKEN_ENV = "BONNET_GATEWAY_ADMIN_TOKEN"


def _expected_token() -> str:
    """The configured admin secret, or "" when admin HTTP is disabled."""
    env = (os.environ.get(ADMIN_TOKEN_ENV) or "").strip()
    if env:
        return env
    try:
        from bonnet.gateway import gateway_config

        cfg = gateway_config.load(paths.config_path())
    except Exception:
        return ""
    if cfg is not None and cfg.admin_token:
        return cfg.admin_token.strip()
    return ""


def _presented_token(request: Request) -> str:
    """Bearer token from the Authorization header. Header-only on purpose:
    a `?key=` spelling would land the secret in URLs, history and logs."""
    auth = request.headers.get("Authorization", "") or ""
    scheme, _, rest = auth.partition(" ")
    if scheme.lower() == "bearer":
        return rest.strip()
    return ""


def _no_store() -> dict[str, str]:
    return {"Cache-Control": "no-store, no-cache"}


def _forbidden(request: Request) -> JSONResponse | None:
    """None when authorized; otherwise the 404/403 to answer with.

    Unconfigured → 404 (indistinguishable from "no such route", so the
    surface is undiscoverable until an operator enables it). Configured but
    wrong/missing credential → 403.
    """
    expected = _expected_token()
    if not expected:
        return JSONResponse(
            {"ok": False, "error": "not found"}, status_code=404, headers=_no_store()
        )
    if not secrets.compare_digest(_presented_token(request), expected):
        return JSONResponse(
            {"ok": False, "error": "forbidden"}, status_code=403, headers=_no_store()
        )
    return None


async def _body(request: Request) -> dict:
    try:
        data = await request.json()
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


@mcp.custom_route("/admin/tenants", methods=["POST"])
@_counted("tenant_add")
async def admin_tenant_add(request: Request) -> JSONResponse:
    denied = _forbidden(request)
    if denied is not None:
        return denied
    data = await _body(request)
    tenant_id = data.get("tenant_id", "")
    note = data.get("note", "")
    if not isinstance(note, str):
        return JSONResponse(
            {"ok": False, "error": "note must be a string"}, status_code=400, headers=_no_store()
        )
    try:
        api_key = tenants.add_tenant(tenant_id, note)
    except TenantError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400, headers=_no_store())
    return JSONResponse(
        {"ok": True, "tenant_id": tenant_id, "api_key": api_key},
        status_code=201,
        headers=_no_store(),
    )


@mcp.custom_route("/admin/tenants", methods=["GET"])
@_counted("tenant_list")
async def admin_tenant_list(request: Request) -> JSONResponse:
    denied = _forbidden(request)
    if denied is not None:
        return denied
    return JSONResponse({"ok": True, "tenants": tenants.list_tenants()}, headers=_no_store())


@mcp.custom_route("/admin/tenants/{tenant_id}", methods=["GET"])
@_counted("tenant_get")
async def admin_tenant_get(request: Request) -> JSONResponse:
    denied = _forbidden(request)
    if denied is not None:
        return denied
    tenant_id = request.path_params.get("tenant_id", "")
    try:
        validate_tenant_id(tenant_id)
    except TenantError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400, headers=_no_store())
    row = tenants.get_tenant(tenant_id)
    if row is None:
        return JSONResponse(
            {"ok": False, "error": f"no such tenant {tenant_id!r}"},
            status_code=404,
            headers=_no_store(),
        )
    return JSONResponse({"ok": True, "tenant": row}, headers=_no_store())


def _set_enabled(request: Request, enabled: bool) -> JSONResponse:
    tenant_id = request.path_params.get("tenant_id", "")
    try:
        validate_tenant_id(tenant_id)
    except TenantError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400, headers=_no_store())
    try:
        tenants.set_enabled(tenant_id, enabled)
    except TenantError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=404, headers=_no_store())
    return JSONResponse(
        {"ok": True, "tenant_id": tenant_id, "enabled": enabled}, headers=_no_store()
    )


@mcp.custom_route("/admin/tenants/{tenant_id}/enable", methods=["POST"])
@_counted("tenant_enable")
async def admin_tenant_enable(request: Request) -> JSONResponse:
    denied = _forbidden(request)
    if denied is not None:
        return denied
    return _set_enabled(request, True)


@mcp.custom_route("/admin/tenants/{tenant_id}/disable", methods=["POST"])
@_counted("tenant_disable")
async def admin_tenant_disable(request: Request) -> JSONResponse:
    denied = _forbidden(request)
    if denied is not None:
        return denied
    return _set_enabled(request, False)


@mcp.custom_route("/admin/keys", methods=["POST"])
@_counted("key_add")
async def admin_key_add(request: Request) -> JSONResponse:
    denied = _forbidden(request)
    if denied is not None:
        return denied
    data = await _body(request)
    tenant_id = data.get("tenant_id", "")
    label = data.get("label", "")
    if not isinstance(label, str):
        return JSONResponse(
            {"ok": False, "error": "label must be a string"},
            status_code=400,
            headers=_no_store(),
        )
    try:
        api_key = tenants.add_key(tenant_id, label)
    except TenantError as e:
        status = 404 if "no such tenant" in str(e) else 400
        return JSONResponse({"ok": False, "error": str(e)}, status_code=status, headers=_no_store())
    return JSONResponse(
        {"ok": True, "tenant_id": tenant_id, "api_key": api_key},
        status_code=201,
        headers=_no_store(),
    )


@mcp.custom_route("/admin/keys", methods=["GET"])
@_counted("key_list")
async def admin_key_list(request: Request) -> JSONResponse:
    denied = _forbidden(request)
    if denied is not None:
        return denied
    tenant_id = request.query_params.get("tenant_id") or None
    try:
        rows = tenants.list_keys(tenant_id)
    except TenantError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=404, headers=_no_store())
    return JSONResponse({"ok": True, "keys": rows}, headers=_no_store())


@mcp.custom_route("/admin/tenants/{tenant_id}/delete", methods=["POST"])
@_counted("tenant_delete")
async def admin_tenant_delete(request: Request) -> JSONResponse:
    """Delete a tenant: its registry row, its keys, and its state directory.

    Irreversible, and it destroys signing keys — a tenant's identities live
    only in its own directory, and nothing else holds a copy. The body must
    echo the tenant id (`{"confirm": "<tenant_id>"}`); anything else is a
    400 and nothing happens. This is the HTTP spelling of
    `bonnet gateway tenant remove --yes`.
    """
    denied = _forbidden(request)
    if denied is not None:
        return denied
    tenant_id = request.path_params.get("tenant_id", "")
    try:
        validate_tenant_id(tenant_id)
    except TenantError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400, headers=_no_store())
    data = await _body(request)
    if data.get("confirm") != tenant_id:
        return JSONResponse(
            {
                "ok": False,
                "error": (
                    f"refusing to delete {tenant_id!r} without "
                    f'{{"confirm": "{tenant_id}"}}: this deletes its signing '
                    "keys, and nothing else holds a copy"
                ),
            },
            status_code=400,
            headers=_no_store(),
        )
    try:
        tenants.remove_tenant(tenant_id)
    except TenantError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=404, headers=_no_store())
    return JSONResponse({"ok": True, "tenant_id": tenant_id, "deleted": True}, headers=_no_store())


@mcp.custom_route("/admin/keys/{key_id}/revoke", methods=["POST"])
@_counted("key_revoke")
async def admin_key_revoke(request: Request) -> JSONResponse:
    """Revoke one key, unless it is the tenant's last live one.

    Revoking the last live key locks the tenant out until an operator runs
    `key add` — so that case refuses with 409 unless the body carries
    `{"force": true}`, the HTTP spelling of the CLI's `--yes` guard
    (`server._run_admin`).
    """
    denied = _forbidden(request)
    if denied is not None:
        return denied
    key_id = request.path_params.get("key_id", "")
    data = await _body(request)
    force = data.get("force") is True
    all_keys = tenants.list_keys()
    target = next((k for k in all_keys if k["key_id"] == key_id), None)
    if target is None or target.get("revoked_at") is not None:
        return JSONResponse(
            {"ok": False, "error": f"no live key with id {key_id!r}"},
            status_code=404,
            headers=_no_store(),
        )
    other_live = [
        k
        for k in all_keys
        if k["tenant_id"] == target["tenant_id"]
        and k["key_id"] != key_id
        and k.get("revoked_at") is None
    ]
    if not other_live and not force:
        return JSONResponse(
            {
                "ok": False,
                "error": (
                    f"refusing to revoke {key_id}: it is the last live key for "
                    f"tenant {target['tenant_id']!r} — pass "
                    '{"force": true} or run `bonnet gateway key revoke --yes` '
                    "on the gateway host"
                ),
            },
            status_code=409,
            headers=_no_store(),
        )
    try:
        tenants.revoke_key(key_id)
    except TenantError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=404, headers=_no_store())
    return JSONResponse({"ok": True, "key_id": key_id, "revoked": True}, headers=_no_store())
