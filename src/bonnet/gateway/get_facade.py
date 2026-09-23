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
  `session.snapshot()` keyed by `(tenant, ?session= label)` with a sliding
  TTL. A missing, blank, or literal-`"default"` label mints a fresh random
  one per call — there is no shared `default` cursor — and the minted label
  rides home in the response's `session` field (with `session_minted: true`)
  for the caller to adopt on later calls. Anonymous callers are stateless
  (no restore/save, no mint) so one shared fallback key can't leak cursor
  position across callers.
- Query-auth (`?key=`) is accepted **only here**, never on `/mcp/`.
  Header credentials always win over query ones. `?key=` must be the
  full `bnt_<id>_<secret>`; a bare key id never resolves.
- Every `GET /call/<tool>` response carries a tiny addendum — `session`,
  `tools_changed`, `visible_tools` (names only) — so a notification-blind
  GET-only caller knows when to re-fetch `GET /call` for usage strings.
- Burst dedup for writes: identical `GET /call/<write-tool>?<args>` URLs
  arriving within a few seconds of each other execute once; the later
  call gets the first call's `result` replayed (with a fresh addendum).
  GET-only harnesses retry by re-fetching the same URL, and every write
  tool mints fresh randomness (`article_id`, `event_id`) per call, so each
  retry would otherwise append a distinct duplicate record to the firehose.
  The dedup key is (tenant, requested session label, tool, canonical args)
  — requested, not minted, so same-URL retries coalesce even though each
  would mint its own label, and the replay echoes the executing call's
  session for the caller to adopt. The source IP is deliberately ignored,
  `?key=`/`?session=` never reach the tool args, and only `ok:true`
  results are cached. Reads are never deduped. Process-local memory, like
  `_snapshots` below; intentional duplicate content should be spaced past
  the window or sent via POST. See `DEDUP_TTL_SECONDS`.

Gated off by default: `--allow-get-rpc` / `$MCP_ALLOW_GET_RPC` /
`gateway.toml [gateway] allow_get_rpc`. Disabled → 404 (the surface is
not advertised). `?key=` in URLs leaks into proxy/access logs — prefer
headers outside the lobotomite path, mint per-agent keys, and serve TLS
off-loopback.
"""

from __future__ import annotations

import asyncio
import copy
import functools
import hashlib
import json
import os
import secrets
import time
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse

from bonnet.gateway import session as session_store
from bonnet.gateway import tenancy
from bonnet.gateway.paths import ANONYMOUS_TENANT
from bonnet.gateway.tools import mcp
from bonnet.net.firehose_transport import forwarded_for_ctx, forwarded_for_from_request


def _observe_http(route: str, ok: bool) -> None:
    """Best-effort facade hit counter. Never raises."""
    try:
        from bonnet.core import metrics

        metrics.observe_http(route, "GET", ok=ok)
    except Exception:
        pass


def _counted(route: str):
    """Decorator counting one facade handler's hits by outcome."""

    def deco(fn):
        @functools.wraps(fn)
        async def wrapper(request: Request):
            try:
                resp = await fn(request)
            except Exception:
                _observe_http(route, False)
                raise
            _observe_http(route, resp.status_code < 400)
            return resp

        return wrapper

    return deco


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
#: Entries carry a sliding expiry refreshed on every access: an idle label
#: dies on its own, so minting labels per caller needs no cap and no sweep.
#: Anonymous callers are stateless (no restore/save), so one shared
#: fallback key can't leak cursor position across callers.
_snapshots: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}
_snapshot_locks: dict[tuple[str, str], tuple[float, asyncio.Lock]] = {}

#: Sliding session TTL in seconds. Override with
#: $MCP_SESSION_TTL_SECONDS ("0" makes every call start fresh).
SESSION_TTL_SECONDS = 86400.0


def _session_ttl() -> float:
    """The live session TTL in seconds (env override, floor 0)."""
    raw = os.environ.get("MCP_SESSION_TTL_SECONDS", "")
    if not raw.strip():
        return SESSION_TTL_SECONDS
    try:
        return max(0.0, float(raw.strip()))
    except ValueError:
        return SESSION_TTL_SECONDS


def _snapshot_get(key: tuple[str, str]) -> dict[str, Any] | None:
    """A live snapshot for `key`, or None on miss/expiry (sweeps the entry)."""
    entry = _snapshots.get(key)
    if entry is None:
        return None
    expires, stored = entry
    if time.monotonic() >= expires:
        _snapshots.pop(key, None)
        _snapshot_locks.pop(key, None)
        return None
    _snapshots[key] = (time.monotonic() + _session_ttl(), stored)
    return stored


def _snapshot_put(key: tuple[str, str], snapshot: dict[str, Any]) -> None:
    """Remember a snapshot with a fresh sliding expiry (TTL 0 stores nothing)."""
    window = _session_ttl()
    if window <= 0:
        return
    _snapshots[key] = (time.monotonic() + window, snapshot)


def _snapshot_lock(key: tuple[str, str]) -> asyncio.Lock:
    now = time.monotonic()
    entry = _snapshot_locks.get(key)
    if entry is not None:
        expires, lock = entry
        if now < expires:
            _snapshot_locks[key] = (now + _session_ttl(), lock)
            return lock
    lock = asyncio.Lock()
    _snapshot_locks[key] = (now + _session_ttl(), lock)
    return lock


def reset_snapshot_state() -> None:
    """Drop session snapshots and locks (tests only)."""
    _snapshots.clear()
    _snapshot_locks.clear()


def _mint_label(tenant: str) -> str:
    """A fresh session label no live entry under `tenant` holds.

    Collision is already absurd (128-bit URL-safe randomness); the loop is
    belt-and-braces against a lingering live entry, and the fallback past
    it is more randomness rather than an error.
    """
    for _ in range(8):
        candidate = secrets.token_urlsafe(16)
        entry = _snapshots.get((tenant, candidate))
        if entry is None or time.monotonic() >= entry[0]:
            return candidate
    return secrets.token_urlsafe(24)


#: Burst-dedup window for write tools reached through this facade, in
#: seconds. A GET-only caller that hits the same write URL several times in
#: a row — retries from several IPs, prefetch replays, a double-pasted URL —
#: is one intention executed several times, and each execution would mint
#: fresh `article_id`/`event_id` randomness into a distinct firehose record.
#: Within this window the second and later identical calls replay the first
#: call's stored `result` instead of executing. Override with
#: $MCP_DEDUP_WINDOW_SECONDS ("0" disables); failures are never cached.
DEDUP_TTL_SECONDS = 5.0

#: Cap on cached burst-dedup entries. Lazy expiry on lookup plus an
#: opportunistic sweep on insert; same never-cleaned tolerance as
#: `session._locks` and `tools.auth_tokens` — one small entry per recent
#: write is cheap next to a 24h token TTL.
_DEDUP_MAX_ENTRIES = 1024

#: Tools whose GET-facade calls append records to the firehose (or otherwise
#: mutate durable gateway state, like `register` minting an identity). Reads
#: are deliberately absent: caching a read would serve stale board content.
WRITE_TOOL_NAMES = frozenset(
    {
        "register",
        "rotate_identity_key",
        "create_board",
        "close_board",
        "reopen_board",
        "purge_board",
        "publish_article",
        "supersede_article",
        "cancel_article",
        "restore_article",
        "purge_article",
        "pin_article",
        "unpin_article",
        "close_thread",
        "reopen_thread",
        "report",
        "punish_warn",
        "punish_ban",
        "punish_permaban",
        "punish_revoke",
        "acknowledge_punishment",
    }
)

#: Tools never served over GET, however the facade is configured. An exported
#: seed in a query string would land in URLs, history and proxy/access logs —
#: and a GET is prefetchable, turning one export into a replayable secret.
#: (Identity passwords via `?auth=` remain the caller's pre-existing risk;
#: prefer header keys outside the lobotomite path.)
FACADE_FORBIDDEN = frozenset({"export_identity"})

#: Recent successful write results keyed by dedup key (see `_dedup_key`):
#: key -> (expires_monotonic, (stored JSON-able result, executing session)).
#: The executing session rides along so a replay echoes the label whose
#: snapshot the first execution saved under — the retry adopts the cursor
#: that actually moved, not a fresh one that never ran.
_recent_writes: dict[tuple[str, str, str, str], tuple[float, tuple[Any, str]]] = {}
_dedup_locks: dict[tuple[str, str, str, str], asyncio.Lock] = {}

#: Miss sentinel for `_dedup_get`: a cached result may legitimately be
#: None, which must replay rather than re-execute.
_DEDUP_MISS: Any = object()


def _dedup_window() -> float:
    """The live burst-dedup window in seconds (env override, floor 0=off)."""
    raw = os.environ.get("MCP_DEDUP_WINDOW_SECONDS", "")
    if not raw.strip():
        return DEDUP_TTL_SECONDS
    try:
        return max(0.0, float(raw.strip()))
    except ValueError:
        return DEDUP_TTL_SECONDS


def _dedup_key(args: dict[str, Any]) -> str:
    """Fingerprint one write intention's arguments for burst dedup.

    Canonical JSON over the already-parsed `args` (which exclude the facade
    `RESERVED_PARAMS`), so `?subject=A&body=B` and `?body=B&subject=A` hash
    together, and `?key=` differences and the caller's source IP never split
    the key. The requested `?session=` DOES split the key — but one level up,
    as a tuple element, because the cursor scope differs per session; the
    requested label is used (missing/blank/`"default"` normalizes to `""`),
    never the minted one, so same-URL retries coalesce across mints.
    `?auth=` splits too, via `args` itself: different identities must never
    coalesce. Non-JSON-able arg values degrade to `repr` rather than
    breaking the call.
    """
    try:
        canonical = json.dumps(args, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        canonical = repr(sorted(args.items()))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _dedup_lock(key: tuple[str, str, str, str]) -> asyncio.Lock:
    lock = _dedup_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _dedup_locks[key] = lock
    return lock


def _dedup_get(key: tuple[str, str, str, str]) -> Any:
    """A live cached (result, session) pair for `key`, or `_DEDUP_MISS`.

    `None` is a legitimate cached result (a tool returning nothing), so the
    sentinel — not None — marks a miss. Returns a deep copy so callers
    cannot mutate the stored entry through the response they were handed.
    """
    entry = _recent_writes.get(key)
    if entry is None:
        return _DEDUP_MISS
    expires, stored = entry
    if time.monotonic() >= expires:
        _recent_writes.pop(key, None)
        return _DEDUP_MISS
    try:
        return copy.deepcopy(stored)
    except Exception:
        return stored


def _dedup_store(
    key: tuple[str, str, str, str], result: Any, session_label: str, window: float
) -> None:
    """Remember a successful write result plus its session for `window`."""
    if window <= 0:
        return
    if len(_recent_writes) >= _DEDUP_MAX_ENTRIES:
        now = time.monotonic()
        stale = [k for k, (exp, _) in _recent_writes.items() if exp <= now]
        for k in stale:
            _recent_writes.pop(k, None)
        while len(_recent_writes) >= _DEDUP_MAX_ENTRIES:
            _recent_writes.pop(next(iter(_recent_writes)))
    try:
        stored = copy.deepcopy(result)
    except Exception:
        stored = result
    _recent_writes[key] = (time.monotonic() + window, (stored, session_label))


def reset_dedup_state() -> None:
    """Drop burst-dedup entries and locks (tests only)."""
    _recent_writes.clear()
    _dedup_locks.clear()


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
    headers win) because Auth has no `on_list_tools`
    hook — without this, `GET /call` would list tools for the `default`
    tenant no matter what credential was presented, while `GET /call/<tool>`
    (which runs `on_call_tool`) would resolve correctly. Setting it here
    keeps both paths consistent; the inner Auth pass during `call_tool`
    re-resolves deterministically to the same tenant over the patched
    request (see `_with_injected_key`).

    Returns (tenant, reset) where reset() restores the previous ContextVar
    values — call it in a `finally`, after the snapshot save.
    """
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

    applied: list[tuple[Any, Any]] = []
    # Custom Starlette routes never pass through AuthMiddleware, so without
    # this the facade's gateway->server POSTs would export no X-Forwarded-For
    # and the origin would log/bucket every facade call under the gateway's
    # own IP. Same extraction rule as the middleware; the origin decides what
    # to trust via its trusted_forwarders list.
    applied.append((forwarded_for_ctx, forwarded_for_ctx.set(forwarded_for_from_request(request))))
    if tenant is not None:
        applied.append((tenancy.current_tenant, tenancy.current_tenant.set(tenant)))
        applied.append(
            (tenancy.current_auth_status, tenancy.current_auth_status.set(tenancy.AUTH_OK))
        )
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
        texts: list[str] = [
            t for t in (getattr(block, "text", None) for block in content) if isinstance(t, str)
        ]
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


async def _visible_tool_names() -> list[str]:
    """Names currently visible to this facade request, tenant-filtered.

    Must run inside `set_http_request(patched_request)` with the tenant
    ContextVars applied: Auth + Gating then filter exactly as `GET /call`
    does. Names only — usage strings stay at `GET /call`.
    """
    tools = await mcp.list_tools()
    return sorted(t.name for t in tools)


async def _try_visible_tool_names(patched_request: Request) -> list[str] | None:
    """Best-effort `_visible_tool_names`: None instead of ever raising.

    The addendum must never break the tool call it rides on; a listing
    failure degrades to `tools_changed: false` with whatever half is known.
    """
    try:
        from fastmcp.server.http import set_http_request

        with set_http_request(patched_request):
            return await _visible_tool_names()
    except Exception:
        return None


def _addendum(
    session_label: str, before: list[str] | None, after: list[str] | None, minted: bool = False
) -> dict[str, Any]:
    """The tiny visibility addendum for a `GET /call/<tool>` response.

    `session` is always echoed — it is how a caller that cannot keep local
    state learns which cursor it holds. `session_minted` marks a label the
    server minted for a missing/blank/`"default"` request: adopt the echo
    on later calls.
    """
    visible = after if after is not None else (before if before is not None else [])
    changed = before is not None and after is not None and before != after
    return {
        "session": session_label,
        "session_minted": minted,
        "tools_changed": changed,
        "visible_tools": visible,
    }


@mcp.custom_route("/call", methods=["GET"])
@mcp.custom_route("/call/", methods=["GET"])
@_counted("call_list")
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
        if tool.name in FACADE_FORBIDDEN:
            continue
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
@_counted("call_tool")
async def call_tool_get(request: Request) -> JSONResponse:
    """Run one tool from query params: GET /call/<tool>?<arg>=<v>&key=..."""
    if not is_enabled():
        return _disabled()
    tool_name = request.path_params.get("tool_name", "") or ""
    params = request.query_params
    query_key = params.get("key", "") or ""
    query_auth = params.get("auth", "") or ""
    raw_session = params.get("session", "") or ""
    # Requested label, normalized: missing/blank/`"default"` all mean "mint
    # me one" and share one dedup slot, so same-URL retries coalesce across
    # mints. An explicit anything-else is honored verbatim. (`"Default"` and
    # friends are literal labels, not the default.)
    requested_norm = "" if (raw_session.strip() == "" or raw_session == "default") else raw_session

    tool = await mcp.get_tool(tool_name)
    if tool is None:
        return JSONResponse(
            {"ok": False, "error": f"unknown tool {tool_name!r} (see GET /call)"},
            status_code=404,
            headers=_no_store_headers(),
        )
    if tool_name in FACADE_FORBIDDEN:
        return JSONResponse(
            {
                "ok": False,
                "error": (
                    f"{tool_name} is not served over GET: credentials and private keys "
                    "must not travel in URLs (history, proxy/access logs). Use POST /mcp/."
                ),
            },
            status_code=403,
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
        return JSONResponse({"ok": False, "error": str(e)}, headers=_no_store_headers())

    tenant, reset_tenant = _apply_tenant(request, query_key)
    anonymous = tenant == ANONYMOUS_TENANT
    if anonymous:
        # Stateless: no restore, no save, no mint — the label is echoed
        # untouched but holds nothing, so one shared fallback key can't
        # leak cursor position across callers.
        session_label = raw_session or "default"
        minted = False
    elif requested_norm:
        session_label = requested_norm
        minted = False
    else:
        # No shared `default` cursor: mint a fresh label holding this call's
        # position, echoed back for the caller to adopt.
        session_label = _mint_label(tenant)
        minted = True
    snapshot_key = (tenant, session_label)
    if not anonymous:
        session_store.restore(_snapshot_get(snapshot_key))

    patched_request = _with_injected_key(request, query_key)
    from fastmcp.server.http import set_http_request

    # Before-state for the addendum: after restore so the cursor is hydrated
    # (board-scoped PERMISSIONS answers for the right board), inside the
    # patched request so the tenant resolves as the inner Auth pass will.
    before = await _try_visible_tool_names(patched_request)

    # Burst dedup for writes (singleflight + short-TTL replay). Keyed per
    # (tenant, requested session label, tool, canonical args) so one caller's
    # retry burst coalesces while two callers sharing a tenant but doing
    # different things never collide — and, by the same token, two
    # genuinely different write intentions from one caller never merge.
    # Requested, not minted: same-URL retries share the "" slot across
    # mints, and the replay echoes the executing call's session so the
    # retry adopts the cursor that actually moved. Lock order is fixed
    # everywhere: dedup lock -> snapshot lock, never the reverse, so
    # concurrent bursts cannot deadlock against each other.
    dedup_window = _dedup_window()
    dedup_cacheable = tool_name in WRITE_TOOL_NAMES and not anonymous and dedup_window > 0
    dedup_key: tuple[str, str, str, str] | None = None
    dedup_lock: asyncio.Lock | None = None
    if dedup_cacheable:
        dedup_key = (tenant, requested_norm, tool_name, _dedup_key(args))
        dedup_lock = _dedup_lock(dedup_key)
        await dedup_lock.acquire()
        try:
            hit = _dedup_get(dedup_key)
        except Exception:
            hit = _DEDUP_MISS
        if hit is not _DEDUP_MISS:
            try:
                from bonnet.core.logging import log_info as _log_info

                _log_info("GET_FACADE dedup hit", tool=tool_name, tenant=tenant)
            except Exception:
                pass
            hit_result, hit_session = hit
            # Hydrate the executing call's cursor so the replayed addendum
            # reports visibility for the position that moved, not this
            # request's fresh one.
            session_store.restore(_snapshot_get((tenant, hit_session)))
            after_hit = await _try_visible_tool_names(patched_request)
            addendum = _addendum(
                hit_session, before, after_hit, minted=(hit_session != raw_session)
            )
            reset_tenant()
            dedup_lock.release()
            return JSONResponse(
                {"ok": True, "result": hit_result, **addendum},
                headers=_no_store_headers(),
            )

    lock = _snapshot_lock(snapshot_key) if not anonymous else None
    try:
        if lock is not None:
            await lock.acquire()
        with set_http_request(patched_request):
            result = await mcp.call_tool(tool_name, args)
            try:
                after = await _visible_tool_names()
            except Exception:
                after = None
            if dedup_cacheable and dedup_key is not None:
                try:
                    _dedup_store(dedup_key, _result_to_json(result), session_label, dedup_window)
                except Exception:
                    pass
    except Exception as e:
        from fastmcp.exceptions import NotFoundError

        after_err = await _try_visible_tool_names(patched_request)
        addendum = _addendum(session_label, before, after_err, minted=minted)
        if isinstance(e, NotFoundError):
            return JSONResponse(
                {"ok": False, "error": f"unknown tool {tool_name!r}", **addendum},
                status_code=404,
                headers=_no_store_headers(),
            )
        return JSONResponse(
            {"ok": False, "error": str(e) or type(e).__name__, **addendum},
            headers=_no_store_headers(),
        )
    finally:
        if not anonymous:
            try:
                _snapshot_put(snapshot_key, session_store.snapshot())
            except Exception:
                pass
        reset_tenant()
        if lock is not None:
            lock.release()
        if dedup_lock is not None:
            try:
                dedup_lock.release()
            except RuntimeError:
                pass
    return JSONResponse(
        {
            "ok": True,
            "result": _result_to_json(result),
            **_addendum(session_label, before, after, minted=minted),
        },
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
