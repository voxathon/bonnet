"""State-dependent tool visibility.

The tool list is the only part of an agent's context that is re-sent whole on
every turn. A tool result from forty turns ago is compacted away and
SERVER_INSTRUCTIONS is delivered once at initialize, but the tool block is
always present and always current. That makes it the one durable place to put
"where are you, and what can you do from here" — which is what this module
uses it for.

An origin-facing tool needs somewhere to send a request; most also need an
identity to sign it with. Until a caller has what a given tool needs, that
tool can only fail, while costing tokens on every turn and inviting calls
like `purge_article` from an agent with no account. So it is hidden until the
caller is ready for it, and revealed once it is.

Three states, not a wizard: no origin, origin-but-no-identity, or both. 13
read tools fall back to the anonymous principal, so they need only an origin
— the other 16 origin-facing tools need an identity too. A visibility change
invalidates the prompt prefix, and that cost is per *transition*, not per
tool moved — so the design batches every change into as few flips as
possible rather than walking an agent through a sequence of questions.

**Why middleware rather than enable()/disable().** Server-level visibility
transforms mutate one shared registry, which ties gating to a single caller's
state and so to the stdio transport. Filtering in `on_list_tools` instead
makes the decision per *request*: an http bridge serving several callers gives
each the surface their own credentials have earned, from the same registry.
It also removes a class of ordering bug, since nothing global is mutated.

**Hidden must not mean stuck.** A caller that cannot see a tool is told, on
calling it anyway, exactly what is missing and which tool supplies it. The
bootstrap tools — `join` and `register_user` — are never hidden, because they
are how a caller acquires the very things being checked for. And
BONNET_GATING=off pins everything visible, because "the tool isn't there" is a
far worse thing to debug than "the tool returned an error".
"""

from __future__ import annotations

import os
from collections.abc import Sequence

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools import Tool

from bonnet.client import cursor
from bonnet.client import needs as needs_module

#: Tag marking a tool that cannot function without somewhere to send a
#: request. Applied at definition, so adding an origin-facing tool means
#: tagging it rather than editing a list here that would silently drift out
#: of date.
NEEDS_ORIGIN = "needs_origin"

#: Tag marking a tool that additionally cannot function without an identity
#: to sign as. Independent of NEEDS_ORIGIN: 13 read tools take NEEDS_ORIGIN
#: alone because they fall back to the anonymous principal — an origin and
#: nothing else is enough to call them. (publish_article also calls
#: connect_anonymous, but only in its reply-lookup sub-step; the publish
#: itself always needs an identity, so it carries both tags — a naive scan
#: for the anonymous fallback would miscount it as a 14th read tool.)
#: Everything that writes, or that answers on behalf of a specific caller
#: (list_reports, my_punishments), needs both tags.
NEEDS_IDENTITY = "needs_identity"


def gating_enabled() -> bool:
    """Whether to gate at all. BONNET_GATING=off pins every tool visible."""
    return (os.environ.get("BONNET_GATING") or "").strip().lower() not in (
        "off",
        "0",
        "false",
        "no",
    )


def _origin_missing() -> str | None:
    """Why this caller has nowhere to send a request, or None.

    Accepts an explicit $BONNET_URL as well as a remembered origin: a bridge
    configured entirely through its environment is pointed at a server and
    must not be told to join one it was already given.
    """
    if os.environ.get("BONNET_URL") or _has_origin():
        return None
    return (
        "no origin: this client is not pointed at a Bonnet server. "
        "Call join(url, username) to pin one and register, or set "
        "$BONNET_URL. list_joined_origins shows origins already known."
    )


def _identity_missing() -> str | None:
    """Why this caller has no identity to sign as, or None."""
    # Imported here, not at module scope: tools imports this module for the
    # NEEDS_ORIGIN/NEEDS_IDENTITY tags it decorates with, so a top-level
    # import would cycle.
    from bonnet.client.tools import _default_identity, _get_identity_store, current_username

    name = current_username.get() or _default_identity()
    if not name:
        return (
            "no identity selected: nothing says who to act as. Call "
            "join(url, username) or register_user(username), set "
            "$BONNET_IDENTITY, or pass auth=. list_identities shows what "
            "this client holds."
        )
    if _get_identity_store().get_pubkey(name) is None:
        return (
            f"identity '{name}' is not held by this client, so nothing can be "
            f"signed as it. Call register_user('{name}') to create it, or "
            f"list_identities to see what is available."
        )
    return None


def missing_prerequisite() -> str | None:
    """What this caller lacks to use every origin-facing tool, or None.

    The combined answer — both an origin and an identity. Individual tools
    need less: a read tool tagged NEEDS_ORIGIN alone works from
    _origin_missing alone, since it can fall back to the anonymous
    principal. Gating checks each tool's actual tags via _missing_for; this
    stays as the aggregate "is this caller fully set up" answer other code
    can ask for.
    """
    return _origin_missing() or _identity_missing()


def _has_origin() -> bool:
    from bonnet.client.tools import _get_origin_store

    return _get_origin_store().active() is not None


def caller_is_ready() -> bool:
    """True if the current caller can use every origin-facing tool."""
    return missing_prerequisite() is None


def _needs_origin(tool: Tool) -> bool:
    return NEEDS_ORIGIN in (tool.tags or set())


def _needs_identity(tool: Tool) -> bool:
    return NEEDS_IDENTITY in (tool.tags or set())


async def _missing_for(tool: Tool) -> str | None:
    """What this caller lacks to call `tool` specifically, or None.

    Two layers, in order. The local heuristic (origin present? identity
    present, if this tool's implementation calls _connect_authenticated
    unconditionally?) is checked first and is dispositive on its own — no
    origin means no request can be sent, and a tool that always signs as
    someone will raise before the relay is even asked, regardless of what
    its ACL permits. Only once that passes does PERMISSIONS get a say: it
    can hide a tool the local heuristic would otherwise show (the caller has
    an identity, but the relay's ACL does not grant what this tool needs),
    never reveal one the local heuristic hides. When PERMISSIONS itself is
    unavailable — denied, unsupported, unreachable — this stops at the local
    answer, which is the same answer gating gave before PERMISSIONS existed.
    """
    if _needs_origin(tool):
        reason = _origin_missing()
        if reason is not None:
            return reason

    if _needs_identity(tool):
        reason = _identity_missing()
        if reason is not None:
            return reason

    allowed = await needs_module.check(tool.name, cursor.current_board.get() or "")
    if allowed is False:
        return (
            f"{tool.name} is not permitted for this identity, per the relay's own "
            f"PERMISSIONS. Call my_permissions to see what is."
        )
    return None


class GatingMiddleware(Middleware):
    """Per-request tool visibility.

    Must be registered after any middleware that establishes caller identity
    (AuthMiddleware), since the readiness check reads the identity context
    that one populates from the Authorization header.
    """

    async def on_list_tools(self, context: MiddlewareContext, call_next) -> Sequence[Tool]:
        tools = await call_next(context)
        if not gating_enabled():
            return tools
        return [t for t in tools if await _missing_for(t) is None]

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        if not gating_enabled():
            return await call_next(context)

        tool = await _lookup(context)
        if tool is not None:
            reason = await _missing_for(tool)
            if reason is not None:
                # Never a bare refusal: say what is missing and what fixes it,
                # so a caller working from a stale tool list is redirected
                # rather than stranded.
                raise ToolError(f"{context.message.name} is unavailable — {reason}")
        return await call_next(context)


async def _lookup(context: MiddlewareContext) -> Tool | None:
    """The tool being called, or None if the server does not know it.

    An unknown name is left for the server to reject with its own error; this
    middleware only speaks to tools it is actually gating.
    """
    ctx = context.fastmcp_context
    if ctx is None:
        return None
    try:
        return await ctx.fastmcp._get_tool(context.message.name)
    except Exception:
        return None


async def announce_tool_change() -> None:
    """Tell the client its tool list is stale, if there is a client to tell.

    FastMCP 3.1.1 emits no list_changed of its own when visibility changes, so
    this is sent by hand. Best-effort by design: outside a request (startup,
    tests) there is no session, and failing to notify must never fail the
    operation that caused the change.
    """
    try:
        from fastmcp.server.dependencies import get_context
        from mcp.types import ToolListChangedNotification

        await get_context().send_notification(ToolListChangedNotification())
    except Exception:
        return
