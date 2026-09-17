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

Destructive operations are CLI-only by design and have no route here:
  - tenant removal destroys signing-key directories nothing else holds
    (use `bonnet gateway tenant remove --yes`)
  - revoking a tenant's last live key locks it out until an operator runs
    `key add` (the revoke route refuses with 409 instead)
"""

from __future__ import annotations

import os
import secrets

from starlette.requests import Request
from starlette.responses import JSONResponse

from bonnet.gateway import paths, tenants
from bonnet.gateway.registry import TenantError, validate_tenant_id
from bonnet.gateway.tools import mcp

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
async def admin_tenant_list(request: Request) -> JSONResponse:
    denied = _forbidden(request)
    if denied is not None:
        return denied
    return JSONResponse({"ok": True, "tenants": tenants.list_tenants()}, headers=_no_store())


@mcp.custom_route("/admin/tenants/{tenant_id}", methods=["GET"])
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
async def admin_tenant_enable(request: Request) -> JSONResponse:
    denied = _forbidden(request)
    if denied is not None:
        return denied
    return _set_enabled(request, True)


@mcp.custom_route("/admin/tenants/{tenant_id}/disable", methods=["POST"])
async def admin_tenant_disable(request: Request) -> JSONResponse:
    denied = _forbidden(request)
    if denied is not None:
        return denied
    return _set_enabled(request, False)


@mcp.custom_route("/admin/keys", methods=["POST"])
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


@mcp.custom_route("/admin/keys/{key_id}/revoke", methods=["POST"])
async def admin_key_revoke(request: Request) -> JSONResponse:
    """Revoke one key, unless it is the tenant's last live one.

    The CLI's `--yes` guard (`server._run_admin`) exists because revoking
    the last live key locks the tenant out until an operator runs `key add`
    over SSH. Over HTTP there is no operator to confirm, so refuse with 409
    and point at the CLI instead.
    """
    denied = _forbidden(request)
    if denied is not None:
        return denied
    key_id = request.path_params.get("key_id", "")
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
    if not other_live:
        return JSONResponse(
            {
                "ok": False,
                "error": (
                    f"refusing to revoke {key_id}: it is the last live key for "
                    f"tenant {target['tenant_id']!r} — run "
                    "`bonnet gateway key revoke --yes` on the gateway host"
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
