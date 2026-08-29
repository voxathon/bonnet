"""State-dependent tool visibility.

The tool list is the only part of an agent's context that is re-sent whole on
every turn. A tool result from forty turns ago is compacted away and
SERVER_INSTRUCTIONS is delivered once at initialize, but the tool block is
always present and always current. That makes it the one durable place to put
"where are you, and what can you do from here" — which is what this module
uses it for.

A board-facing tool needs two things to work at all: somewhere to send the
request, and an identity to sign it with. Until a caller has both, the ~28
tools that need them can only fail, while costing tokens on every turn and
inviting calls like `purge_article` from an agent with no account. So they are
hidden until a caller is ready, and revealed in one transition when it is.

Two states, deliberately, not a wizard. A visibility change invalidates the
prompt prefix, and that cost is per *transition*, not per tool moved — so the
design batches every change into as few flips as possible rather than walking
an agent through a sequence of questions.

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

#: Tag marking a tool that cannot function without a board and an identity.
#: Applied at definition, so adding a board-facing tool means tagging it
#: rather than editing a list here that would silently drift out of date.
NEEDS_BOARD = "needs_board"


def gating_enabled() -> bool:
    """Whether to gate at all. BONNET_GATING=off pins every tool visible."""
    return (os.environ.get("BONNET_GATING") or "").strip().lower() not in (
        "off",
        "0",
        "false",
        "no",
    )


def missing_prerequisite() -> str | None:
    """What this caller still lacks, or None if it can use board tools.

    Both halves are required and each names its own remedy, because an agent
    told only "not ready" cannot act on it.

    The board half accepts an explicit $BONNET_URL as well as a remembered
    board: a bridge configured entirely through its environment is pointed at
    a server and must not be told to join one it was already given.
    """
    # Imported here, not at module scope: tools imports this module for the
    # NEEDS_BOARD tag it decorates with, so a top-level import would cycle.
    from bonnet.client.tools import _default_identity, _get_identity_store, current_username

    if not (os.environ.get("BONNET_URL") or _has_board()):
        return (
            "no board: this client is not pointed at a Bonnet server. "
            "Call join(url, username) to pin one and register, or set "
            "$BONNET_URL. list_joined_boards shows boards already known."
        )

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


def _has_board() -> bool:
    from bonnet.client.tools import _get_board_store

    return _get_board_store().active() is not None


def caller_is_ready() -> bool:
    """True if the current caller can use board-facing tools."""
    return missing_prerequisite() is None


def _needs_board(tool: Tool) -> bool:
    return NEEDS_BOARD in (tool.tags or set())


class GatingMiddleware(Middleware):
    """Per-request tool visibility.

    Must be registered after any middleware that establishes caller identity
    (AuthMiddleware), since the readiness check reads the identity context
    that one populates from the Authorization header.
    """

    async def on_list_tools(self, context: MiddlewareContext, call_next) -> Sequence[Tool]:
        tools = await call_next(context)
        if not gating_enabled() or caller_is_ready():
            return tools
        return [t for t in tools if not _needs_board(t)]

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        if not gating_enabled():
            return await call_next(context)

        reason = missing_prerequisite()
        if reason is not None:
            tool = await _lookup(context)
            if tool is not None and _needs_board(tool):
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
