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

"""Navigation state that survives from one request to the next.

The cursor, the active origin and the selected identity are all ContextVars,
which is right: one gateway process serves many callers at once and none of
them may see another's position. But a ContextVar only lives as long as the
context it was set in, and **ASGI gives every HTTP request a fresh copy of the
context.** Anything a tool sets is discarded the moment it returns.

In stdio that is invisible, because the whole session runs in one context. Over
HTTP it meant `open_board` reported success and the next call saw no open
board, and `disconnect` was undone by the following request re-adopting the
remembered origin from disk. Neither failed loudly; both just did nothing.

The fix is not to abandon ContextVars — every call site reads them
synchronously, and per-caller isolation is exactly what is wanted *within* a
request. It is to give them somewhere to live *between* requests, which MCP
already defines: a session. FastMCP exposes it as `Context.session_id`
(the `mcp-session-id` header over HTTP, a UUID cached on the session object
for stdio) with a session-scoped `get_state`/`set_state` store behind it.

So this module is a seam, not a mechanism: load the snapshot into the
ContextVars before the request runs, write it back after. Nothing downstream
changes, and stdio behaves exactly as before — there is one session, so the
round trip returns what it stored.

Two properties worth keeping in mind:

- **State is keyed by session *and* tenant.** FastMCP already prefixes by
  session; the tenant is added because one session presenting a different API
  key is a different account, and must not inherit the first one's position.
- **Origins and identities stay durable on disk** (see `origins`). This
  carries only what is genuinely per-session: where the caller currently is.
  A brand-new session restores nothing and falls back to the remembered
  origin, which is what makes a restarted client resume where it left off.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from fastmcp.server.middleware import Middleware, MiddlewareContext

from bonnet.core.logging import log_debug
from bonnet.gateway import tenancy

#: Stand-in identity for transports that don't hand back a stable
#: `ctx.session_id` — see `_session_key` below.
_PROCESS_SESSION_ID = str(uuid.uuid4())

#: One key per tenant, under FastMCP's own per-session prefix.
_STATE_KEY = "bonnet.navigation"


def _key() -> str:
    return f"{_STATE_KEY}:{tenancy.current_tenant.get()}"


def snapshot() -> dict[str, Any]:
    """The current navigation position, as JSON-serializable values.

    Everything here is a ContextVar that a tool may have set during this
    request. `origin_loaded` is included even though it looks internal: it is
    what distinguishes "no origin yet, go and adopt the remembered one" from
    "this session deliberately disconnected", and without it `disconnect`
    silently undoes itself on the next request.

    `manifest_url`/`manifest` carry the session's cached UNTP manifest (see
    `tools._manifest_cache_*`): the verified discovery document is plain
    str/int/list values, so it round-trips through the session store like
    the cursor does. A missing entry is simply a cache miss on the next
    request — never an error.
    """
    from bonnet.gateway import cursor, tools

    return {
        "origin_loaded": tools._origin_loaded.get(),
        "origin_url": tools.current_origin_url.get(),
        "origin": tools.current_origin.get(),
        "origin_verify": tools.current_origin_verify.get(),
        "username": tools.current_username.get(),
        "board": cursor.current_board.get(),
        "article_board": cursor.current_article_board.get(),
        "article_num": cursor.current_article_num.get(),
        "article_id": cursor.current_article_id.get(),
        "manifest_url": tools._cached_manifest_url.get(),
        "manifest": tools._cached_manifest.get(),
    }


def restore(state: dict[str, Any] | None) -> None:
    """Put a snapshot back into this request's ContextVars.

    A missing or empty snapshot is left alone rather than cleared: a session's
    first request has nothing stored, and blanking the ContextVars there would
    wipe state a caller established some other way (which is how the test
    suite drives the tools directly).
    """
    if not state:
        return

    from bonnet.gateway import cursor, tools

    tools._origin_loaded.set(bool(state.get("origin_loaded", False)))
    tools.current_origin_url.set(state.get("origin_url"))
    tools.current_origin.set(state.get("origin"))
    tools.current_origin_verify.set(state.get("origin_verify"))
    tools.current_username.set(state.get("username"))
    cursor.current_board.set(state.get("board"))
    cursor.current_article_board.set(state.get("article_board"))
    cursor.current_article_num.set(state.get("article_num"))
    cursor.current_article_id.set(state.get("article_id"))
    # Manifest cache: restore only a well-formed entry (URL + origin +
    # public key); anything else — older snapshots, corrupt state — is a
    # clean miss, and a miss just means the next call fetches fresh.
    manifest_url = state.get("manifest_url")
    manifest = state.get("manifest")
    if (
        isinstance(manifest_url, str)
        and manifest_url
        and isinstance(manifest, dict)
        and manifest.get("origin")
        and manifest.get("public_key")
    ):
        tools._cached_manifest_url.set(manifest_url)
        tools._cached_manifest.set(dict(manifest))


async def load(ctx) -> None:
    """Hydrate this request from the session store. Best-effort by design.

    A missing session, an unavailable store, or a snapshot written by an older
    version must degrade to "no stored position" rather than failing the
    request — the caller loses its cursor, which `where_am_i` will show, and
    not its ability to work.
    """
    if ctx is None:
        return
    try:
        restore(await ctx.get_state(_key()))
    except Exception as e:
        log_debug("SESSION load degrade", err=f"{type(e).__name__}")
        return


async def save(ctx) -> None:
    """Persist this request's position back to the session store."""
    if ctx is None:
        return
    try:
        await ctx.set_state(_key(), snapshot())
    except Exception as e:
        log_debug("SESSION save degrade", err=f"{type(e).__name__}")
        return


#: One lock per (session, tenant), guarding the load -> run tool -> save span
#: below. FastMCP's state store is a bare get/put with no compare-and-swap
#: (the default MemoryStore is an unguarded dict), and that span holds a
#: loaded snapshot across the whole tool body, including any await out to an
#: origin server. Two tool calls dispatched concurrently in the same session
#: would each load the same starting snapshot and the slower one to save
#: would silently overwrite the faster one's cursor movement. Never
#: cleaned up, same tolerance as `tools.auth_tokens` and `needs._cache` —
#: one lock per live session is cheap next to a 24h session TTL.
_locks: dict[tuple[str, str], asyncio.Lock] = {}

#: Spans currently inside load -> run tool -> save, per (session, tenant).
#: Incremented synchronously before the first await so asyncio cannot
#: preempt between the increment and the contention check: an overlapping
#: call always observes a count above 1, a strictly sequential one always
#: observes exactly 1. Same single-process boundary as `_locks` (and the
#: MemoryStore itself) — across `uvicorn --workers N` neither the lock nor
#: this counter sees the other process, and both degrade to last-writer-wins.
_inflight: dict[tuple[str, str], int] = {}

#: Keys that saw overlapping spans since their last quiescent moment. A
#: peak, not an instant: spans queue on the lock rather than overlapping in
#: execution, so checking the count only at save time would let the second
#: span re-save its article after the first cleared it. The flag is raised by
#: any newcomer arriving while another span is in flight and consumed only
#: when the count returns to zero — every span of a raced generation then
#: clears, and the session lands deterministically at `in_board` instead of
#: a coin-flip article.
_contended: set[tuple[str, str]] = set()


def reset_session_state() -> None:
    """Drop lock, in-flight and contention bookkeeping (tests only).

    Session snapshots in the FastMCP store are untouched — only this
    module's process-local guards. Lets contention flags from one test
    never leak into the next.
    """
    _locks.clear()
    _inflight.clear()
    _contended.clear()


def _session_key(ctx) -> str | None:
    """A per-caller identity stable across the calls in one session, or None.

    `ctx.session_id` is only actually stable across calls when there is a
    real HTTP request behind it (the `mcp-session-id` header). Off that path
    — stdio, in particular — some FastMCP versions mint a fresh UUID on
    every single call instead of the one-per-process id the rest of this
    module assumes (see the module docstring), which would make every call
    look like a new session. There is genuinely one connection per process
    for those transports, so `_PROCESS_SESSION_ID` is the correct stable
    identity there regardless of what `ctx.session_id` reports.
    """
    request_context = getattr(ctx, "request_context", None)
    if request_context is not None and getattr(request_context, "request", None) is not None:
        try:
            return ctx.session_id
        except Exception:
            return None
    return _PROCESS_SESSION_ID


def _inflight_key(ctx) -> tuple[str, str] | None:
    """The (session, tenant) key for contention tracking, or None.

    Same key `_lock_for` locks on, factored out so the two cannot drift:
    no key means no session-scoped state in play, and both the lock and the
    counter correctly do nothing.
    """
    if ctx is None:
        return None
    session_id = _session_key(ctx)
    if session_id is None:
        return None
    return (session_id, tenancy.current_tenant.get())


def _lock_for(ctx) -> asyncio.Lock | None:
    """The lock serializing load/save for this session and tenant, or None.

    None when there is no session to serialize against — ctx is unset (no
    request context). Matches load/save's own best-effort degrade: nothing
    here can race if there is no session-scoped state in play.
    """
    key = _inflight_key(ctx)
    if key is None:
        return None
    lock = _locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _locks[key] = lock
    return lock


class SessionStateMiddleware(Middleware):
    """Carry navigation state across requests within one MCP session.

    Registered between AuthMiddleware and GatingMiddleware: the state key
    needs the tenant the first one resolves, and gating reads the cursor this
    one restores — `_missing_for` consults board-scoped PERMISSIONS, so
    listing tools with an unhydrated cursor would answer for the wrong board.

    Only `on_call_tool` writes back. Listing tools and reading resources
    cannot move the cursor, so saving there would be a redundant round trip.
    """

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        ctx = context.fastmcp_context
        lock = _lock_for(ctx)
        key = _inflight_key(ctx)
        if lock is None or key is None:
            return await self._call(ctx, context, call_next)
        # Synchronous section — no await between the increment and the
        # contention check, so asyncio cannot interleave a second span
        # between them. A newcomer arriving while another span is in flight
        # raises the peak flag; strictly sequential spans always see 1.
        _inflight[key] = _inflight.get(key, 0) + 1
        if _inflight[key] > 1:
            _contended.add(key)
        try:
            async with lock:
                return await self._call(ctx, context, call_next, key=key)
        finally:
            remaining = _inflight.get(key, 1) - 1
            if remaining <= 0:
                _inflight.pop(key, None)
                _contended.discard(key)
            else:
                _inflight[key] = remaining

    async def _call(self, ctx, context: MiddlewareContext, call_next, key=None):
        await load(ctx)
        try:
            return await call_next(context)
        finally:
            # In a finally: a tool that raises part-way may still have moved
            # the cursor, and losing that would leave the session's idea of
            # where it is disagreeing with what the tool actually did.
            #
            # Contended generations clear back to the board before saving:
            # parallel cursor-moving calls would otherwise land on whichever
            # span happened to save last — a coin flip the next implicit
            # `target_article_id=` would silently inherit. Only the article
            # fields are suppressed; the board still saves last-writer-wins.
            if key is not None and key in _contended:
                try:
                    from bonnet.gateway import cursor

                    cursor.clear_article()
                except Exception as e:
                    log_debug("SESSION contention clear degrade", err=f"{type(e).__name__}")
            await save(ctx)

    async def on_list_tools(self, context: MiddlewareContext, call_next):
        await load(context.fastmcp_context)
        return await call_next(context)

    async def on_read_resource(self, context: MiddlewareContext, call_next):
        await load(context.fastmcp_context)
        return await call_next(context)
