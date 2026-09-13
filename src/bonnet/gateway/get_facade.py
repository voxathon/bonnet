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

"""Braindead GET facade: full tool-calls for agents that cannot do POST.

A lobotomite agent can only fetch a URL — no headers, no JSON-RPC envelope,
no `initialize` handshake, no SSE. So this exposes every MCP tool as:

    GET /call/<tool>?<arg>=<value>&key=bnt_<id>_<secret>
    → 200 {"ok": true, "result": ...} | {"ok": false, "error": "..."}

`GET /call` lists tools with per-tool usage. No body, no headers required,
no session handshake. One URL per action, pasteable into a browser.

Design (see spike notes in the plan thread):

- Parallel `custom_route`s, not a transport change: `POST /mcp/` is
  untouched, and plain `GET /mcp/` still means SSE subscribe. The MCP
  `Route` is registered first (FastMCP appends custom routes last), so
  these coexist purely by living on a different path.
- Dispatch is `mcp.call_tool(name, args)` with `run_middleware=True` (the
  default): Auth, Session-lock and Gating all run. Auth resolves the
  tenant from the request's headers — so when the credential arrived as
  `?key=`, the facade injects it as an `Authorization: Bearer` header
  into a patched request scope and enters FastMCP's `set_http_request`
  around the call. No SDK privates are patched; the inner Auth path is
  the exact same code `POST` requests go through.
- Session persistence is facade-owned: `call_tool` creates a `Context`
  with no session, so FastMCP's session load/save degrades to no-ops
  (best-effort by design) and the facade restores/saves its own
  `session.snapshot()` keyed by `(tenant, ?session= label)` in memory.
  Anonymous callers are stateless (no restore/save) so one shared
  fallback key can't leak cursor position across callers.
- Query-auth (`?key=`) is accepted **only here**, never on `/mcp/`.
  Header credentials always win over query ones. OIDC JWTs stay
  header-only. `?key=` must be the full `bnt_<id>_<secret>`; a bare key
  id never resolves.

Gated off by default: `--allow-get-rpc` / `$MCP_ALLOW_GET_RPC` /
`gateway.toml [gateway] allow_get_rpc`. Disabled → 404 (the surface is
not advertised). `?key=` in URLs leaks into proxy/access logs — prefer
headers outside the lobotomite path, mint per-agent keys, and serve TLS
off-loopback.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse

from bonnet.gateway import session as session_store
from bonnet.gateway import tenancy
from bonnet.gateway.paths import ANONYMOUS_TENANT
from bonnet.gateway.tools import mcp

#: Set by `server.run()` from flag > env > toml. Tests may call
#: `set_enabled(True)` directly. Env is honored live so the facade can be
#: toggled without a restart in a pinch.
_enabled_override: bool | None = None

_ENV_TRUE = ("1", "true", "yes", "on")


def set_enabled(value: bool | None) -> None:
    """Pin the facade on/off (None clears the pin; env still applies)."""
    global _enabled_override
    _enabled_override = value


def is_enabled() -> bool:
    if _enabled_override is not None:
        return _enabled_override
    return os.environ.get("MCP_ALLOW_GET_RPC", "").lower() in _ENV_TRUE


#: Query keys consumed by the facade itself, never passed to tools.
RESERVED_PARAMS = frozenset({"key", "auth", "session"})

#: In-memory snapshots keyed by (tenant, session label). Process-local,
#: like FastMCP's default MemoryStore — a restart starts fresh and falls
#: back to the remembered origin, exactly like a brand-new MCP session.
_snapshots: dict[tuple[str, str], dict[str, Any]] = {}
_snapshot_locks: dict[tuple[str, str], asyncio.Lock] = {}


def _snapshot_lock(key: tuple[str, str]) -> asyncio.Lock:
    lock = _snapshot_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _snapshot_locks[key] = lock
    return lock


def _header_candidates(headers) -> list[str]:
    """API key candidates from headers only (mirrors server logic)."""
    candidates: list[str] = []
    auth = headers.get("Authorization", "") or ""
    scheme, _, rest = auth.partition(" ")
    if scheme.lower() == "bearer":
        token = rest.strip()
        if token:
            candidates.append(token)
    api_key = (headers.get("X-API-Key", "") or "").strip()
    if api_key:
        candidates.append(api_key)
    return candidates


def _apply_tenant(request: Request, query_key: str):
    """Resolve this facade request's tenant and set the request ContextVars.

    Mirrors `AuthMiddleware` (header credentials first, `?key=` last so
    headers win; OIDC JWTs header-only) because Auth has no `on_list_tools`
    hook — without this, `GET /call` would list tools for the `default`
    tenant no matter what credential was presented, while `GET /call/<tool>`
    (which runs `on_call_tool`) would resolve correctly. Setting it here
    keeps both paths consistent; the inner Auth pass during `call_tool`
    re-resolves deterministically to the same tenant over the patched
    request (see `_with_injected_key`).

    Returns (tenant, reset) where reset() restores the previous ContextVar
    values — call it in a `finally`, after the snapshot save.
    """
    from bonnet.gateway.server import AuthMiddleware  # lazy: server imports us
    from bonnet.gateway.tools import current_password, current_username

    header_candidates = _header_candidates(request.headers)
    query_candidate = (query_key or "").strip()
    candidates = list(header_candidates)
    if query_candidate and query_candidate not in candidates:
        candidates.append(query_candidate)

    tenant = None
    for candidate in candidates:
        if not candidate.startswith("bnt_"):
            continue
        try:
            tenant = tenancy.resolve_key(candidate)
        except Exception:
            tenant = None
        if tenant is not None:
            break
    if tenant is None:
        try:
            tenant = AuthMiddleware._resolve_oauth(header_candidates)
        except Exception:
            tenant = None

    applied: list[tuple[Any, Any]] = []
    if tenant is not None:
        applied.append((tenancy.current_tenant, tenancy.current_tenant.set(tenant)))
        applied.append((tenancy.current_auth_status, tenancy.current_auth_status.set(tenancy.AUTH_OK)))
    else:
        tenant = ANONYMOUS_TENANT
        applied.append((tenancy.current_tenant, tenancy.current_tenant.set(tenant)))
        applied.append(
            (
                tenancy.current_auth_status,
                tenancy.current_auth_status.set(
                    tenancy.AUTH_REJECTED if candidates else tenancy.AUTH_ABSENT
                ),
            )
        )
        applied.append((current_username, current_username.set(None)))
        applied.append((current_password, current_password.set("")))

    def reset() -> None:
        for var, token in reversed(applied):
            try:
                var.reset(token)
            except Exception:
                pass

    return tenant, reset


def _coerce_value(raw: str, prop: dict[str, Any] | None, name: str) -> Any:
    """Coerce one query-string value to a tool parameter.

    Everything off the wire is a string; the tool's JSON schema decides
    the target type. Raises ValueError with a lobotomite-legible message.
    """
    schema = prop or {}
    target = schema.get("type")
    if target is None:
        for branch in schema.get("anyOf", []) or []:
            if isinstance(branch, dict) and branch.get("type") not in (None, "null"):
                target = branch.get("type")
                break
    allows_null = target is None or any(
        isinstance(b, dict) and b.get("type") == "null" for b in schema.get("anyOf", []) or []
    )
    if raw == "" and allows_null and target != "string":
        return None
    if target in (None, "string"):
        return raw
    if target == "integer":
        try:
            return int(raw.strip(), 10)
        except ValueError:
            raise ValueError(f"bad arg {name!r}: expected int, got {raw!r}")
    if target == "number":
        try:
            return float(raw.strip())
        except ValueError:
            raise ValueError(f"bad arg {name!r}: expected number, got {raw!r}")
    if target == "boolean":
        lowered = raw.strip().lower()
        if lowered in ("true", "1", "yes", "on"):
            return True
        if lowered in ("false", "0", "no", "off"):
            return False
        raise ValueError(f"bad arg {name!r}: expected boolean, got {raw!r}")
    if target == "array":
        if raw.strip().startswith("["):
            try:
                parsed = json.loads(raw)
            except ValueError:
                raise ValueError(f"bad arg {name!r}: expected JSON array, got {raw!r}")
            if not isinstance(parsed, list):
                raise ValueError(f"bad arg {name!r}: expected JSON array, got {raw!r}")
            return parsed
        if raw == "":
            return []
        return [part for part in raw.split(",")]
    if target == "object":
        try:
            parsed = json.loads(raw)
        except ValueError:
            raise ValueError(f"bad arg {name!r}: expected JSON object, got {raw!r}")
        if not isinstance(parsed, dict):
            raise ValueError(f"bad arg {name!r}: expected JSON object, got {raw!r}")
        return parsed
    return raw


def _result_to_json(result: Any) -> Any:
    """Unwrap a FastMCP ToolResult into JSON-serializable data."""
    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict):
        return structured
    content = getattr(result, "content", None)
    if isinstance(content, list):
        texts = [getattr(block, "text", None) for block in content]
        texts = [t for t in texts if isinstance(t, str)]
        if len(texts) == 1:
            try:
                return json.loads(texts[0])
            except ValueError:
                return texts[0]
        if texts:
            return texts
    try:
        json.dumps(result)
        return result
    except (TypeError, ValueError):
        return str(result)


def _no_store_headers() -> dict[str, str]:
    return {"Cache-Control": "no-store, no-cache", "Vary": "Authorization"}


def _disabled() -> JSONResponse:
    return JSONResponse(
        {"ok": False, "error": "GET facade is disabled (see --allow-get-rpc)"},
        status_code=404,
        headers=_no_store_headers(),
    )


@mcp.custom_route("/call", methods=["GET"])
@mcp.custom_route("/call/", methods=["GET"])
async def call_list(request: Request) -> JSONResponse:
    """List tools with braindead usage strings."""
    if not is_enabled():
        return _disabled()
    query_key = request.query_params.get("key", "") or ""
    tenant, reset_tenant = _apply_tenant(request, query_key)
    try:
        patched_request = _with_injected_key(request, query_key)
        from fastmcp.server.http import set_http_request

        with set_http_request(patched_request):
            tools = await mcp.list_tools()
    finally:
        reset_tenant()
    entries = []
    for tool in tools:
        params = getattr(tool, "parameters", {}) or {}
        properties = params.get("properties", {}) or {}
        required = params.get("required", []) or []
        hint = "&".join(f"{name}=..." for name in required) if required else ""
        usage = f"/call/{tool.name}" + (f"?{hint}&key=..." if hint else "?key=...")
        entries.append(
            {
                "name": tool.name,
                "description": (getattr(tool, "description", "") or "")[:300],
                "usage": usage,
                "required": list(required),
                "optional": sorted(k for k in properties if k not in required),
            }
        )
    return JSONResponse({"ok": True, "tools": entries}, headers=_no_store_headers())


@mcp.custom_route("/call/{tool_name}", methods=["GET"])
async def call_tool_get(request: Request) -> JSONResponse:
    """Run one tool from query params: GET /call/<tool>?<arg>=<v>&key=..."""
    if not is_enabled():
        return _disabled()
    tool_name = request.path_params.get("tool_name", "") or ""
    params = request.query_params
    query_key = params.get("key", "") or ""
    query_auth = params.get("auth", "") or ""
    session_label = params.get("session", "") or "default"

    tool = await mcp.get_tool(tool_name)
    if tool is None:
        return JSONResponse(
            {"ok": False, "error": f"unknown tool {tool_name!r} (see GET /call)"},
            status_code=404,
            headers=_no_store_headers(),
        )
    schema = getattr(tool, "parameters", {}) or {}
    properties = schema.get("properties", {}) or {}

    args: dict[str, Any] = {}
    try:
        for key in params.keys():
            if key in RESERVED_PARAMS:
                continue
            values = params.getlist(key)
            raw = values[-1]
            args[key] = _coerce_value(raw, properties.get(key), key)
        if query_auth and "auth" in properties and "auth" not in args:
            args["auth"] = query_auth
    except ValueError as e:
        return JSONResponse(
            {"ok": False, "error": str(e)}, headers=_no_store_headers()
        )

    tenant, reset_tenant = _apply_tenant(request, query_key)
    anonymous = tenant == ANONYMOUS_TENANT
    snapshot_key = (tenant, session_label)
    if not anonymous:
        stored = _snapshots.get(snapshot_key)
        session_store.restore(stored)

    patched_request = _with_injected_key(request, query_key)
    from fastmcp.server.http import set_http_request

    lock = _snapshot_lock(snapshot_key) if not anonymous else None
    try:
        if lock is not None:
            await lock.acquire()
        with set_http_request(patched_request):
            result = await mcp.call_tool(tool_name, args)
    except Exception as e:
        from fastmcp.exceptions import NotFoundError

        if isinstance(e, NotFoundError):
            return JSONResponse(
                {"ok": False, "error": f"unknown tool {tool_name!r}"},
                status_code=404,
                headers=_no_store_headers(),
            )
        return JSONResponse(
            {"ok": False, "error": str(e) or type(e).__name__},
            headers=_no_store_headers(),
        )
    finally:
        if not anonymous:
            try:
                _snapshots[snapshot_key] = session_store.snapshot()
            except Exception:
                pass
        reset_tenant()
        if lock is not None:
            lock.release()
    return JSONResponse(
        {"ok": True, "result": _result_to_json(result)},
        headers=_no_store_headers(),
    )


def _with_injected_key(request: Request, query_key: str) -> Request:
    """The facade request, plus `?key=` as a Bearer header when needed.

    Inner AuthMiddleware only reads headers. If the caller already sent
    header credentials they win untouched; otherwise the query key is
    injected so the exact same Auth code resolves the tenant (bnt keys
    only — anything else in `?key=` is left for Auth to degrade to
    anonymous, same as a bad header).
    """
    if _header_candidates(request.headers):
        return request
    key = (query_key or "").strip()
    if not key:
        return request
    scope = dict(request.scope)
    headers = list(scope.get("headers", []))
    headers.append((b"authorization", f"Bearer {key}".encode("latin-1")))
    scope["headers"] = headers
    return Request(scope)
