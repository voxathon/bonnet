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

from typing import Any

from fastmcp.server.middleware import Middleware, MiddlewareContext

from bonnet.gateway import tenancy

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
    except Exception:
        return


async def save(ctx) -> None:
    """Persist this request's position back to the session store."""
    if ctx is None:
        return
    try:
        await ctx.set_state(_key(), snapshot())
    except Exception:
        return


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
        await load(ctx)
        try:
            return await call_next(context)
        finally:
            # In a finally: a tool that raises part-way may still have moved
            # the cursor (get_article sets it before any later failure), and
            # losing that would leave the session's idea of where it is
            # disagreeing with what the tool actually did.
            await save(ctx)

    async def on_list_tools(self, context: MiddlewareContext, call_next):
        await load(context.fastmcp_context)
        return await call_next(context)

    async def on_read_resource(self, context: MiddlewareContext, call_next):
        await load(context.fastmcp_context)
        return await call_next(context)
