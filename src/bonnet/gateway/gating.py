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
bootstrap tools — `connect`, `register`, and `disconnect` — are never hidden,
because they are how a caller acquires (or steps back from) the very things
being checked for. And BONNET_GATING=off pins everything visible, because
"the tool isn't there" is a far worse thing to debug than "the tool returned
an error".

**The one exception, and why it is not one.** An anonymous tenant (see
`tenancy`) never sees `register` or `login`. That looks like a violation of
the rule above, and is its logical end: the rule exists so a caller is never
stranded from a transition it *could* make, and for that tenant `register` is
not a transition — no sequence of calls makes it succeed. Showing it would
advertise a dead end, which is the failure this module exists to prevent.
That session is also told so directly: `_auth_warning` prefixes every
description with what happened and whether the operator needs to hear about
it. Reduced capability is reported, never merely enacted.
"""

from __future__ import annotations

import os
from collections.abc import Sequence

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools import Tool

from bonnet.gateway import cursor, tenancy
from bonnet.gateway import needs as needs_module

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


#: Tools an anonymous tenant can never use, however the rest of its state
#: looks. They mint or unlock a local identity, and that tenant holds none and
#: may not acquire one.
#:
#: `connect`, `disconnect`, `switch_origin` and the navigation tools are
#: deliberately *not* here: they still work, and hiding them would strand a
#: caller with no way to move.
ANONYMOUS_FORBIDDEN = frozenset({"register", "login"})

_WARNING_ABSENT = """\
[!] This session is ANONYMOUS: read-only, no identity, nothing can be
published. No API key was presented. If you expected an account here, say so
to your operator rather than retrying — nothing you can do from this session
will change it.

"""

_WARNING_REJECTED = """\
[!] This session is ANONYMOUS: read-only, no identity, nothing can be
published. An API key WAS presented and was not accepted — it is unknown,
revoked, or its tenant is disabled. **Alert your operator.** This is a
configuration problem on their side; retrying will not fix it, and no
credential you can construct will either.

"""


def gating_enabled() -> bool:
    """Whether to gate at all. BONNET_GATING=off pins every tool visible."""
    return (os.environ.get("BONNET_GATING") or "").strip().lower() not in (
        "off",
        "0",
        "false",
        "no",
    )


def _anonymous_forbids(tool: Tool) -> str | None:
    """Why the anonymous tenant may not use `tool`, or None.

    Checked independently of `gating_enabled`, unlike everything else here.
    BONNET_GATING=off is a debugging aid for *visibility*; it must not hand a
    caller who presented no valid credential the ability to mint identities
    inside the shared anonymous tenant.
    """
    if tool.name in ANONYMOUS_FORBIDDEN and tenancy.is_anonymous():
        return (
            "this session is anonymous, and an anonymous session holds no "
            "identity and cannot create one. Reads work; publishing does not. "
            "If you expected an account, your operator needs to give this "
            "gateway a valid API key."
        )
    return None


def _auth_warning() -> str | None:
    """The banner to prefix onto every tool description, or None.

    The tool list is the only part of an agent's context re-sent whole on
    every turn, which is what a *persistent* condition needs: a one-shot error
    scrolls away, and SERVER_INSTRUCTIONS is delivered once at initialize —
    before a credential has necessarily been presented, let alone rejected.
    """
    if not tenancy.is_anonymous():
        return None
    if tenancy.current_auth_status.get() == tenancy.AUTH_REJECTED:
        return _WARNING_REJECTED
    return _WARNING_ABSENT


def _with_warning(tool: Tool, warning: str) -> Tool:
    """A copy of `tool` carrying `warning`. Never mutates the registry object,
    which is shared with every other tenant's list."""
    return tool.model_copy(update={"description": warning + (tool.description or "")})


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
        "Call connect(url) to pin one, or set $BONNET_URL. "
        "list_joined_origins shows origins already known."
    )


def _identity_missing(auth: str | None = None) -> str | None:
    """Why this caller has no identity to sign as, or None.

    `auth` is the call's own per-call identity override, checked ahead of
    the session's default the same way `_tools._connect_authenticated`
    already resolves it — a call naming `auth="alice"` must be judged on
    whether alice is a known identity, not on whatever identity the session
    otherwise defaults to.
    """
    # Imported here, not at module scope: tools imports this module for the
    # NEEDS_ORIGIN/NEEDS_IDENTITY tags it decorates with, so a top-level
    # import would cycle.
    from bonnet.gateway.tools import (
        _default_identity,
        _default_origin,
        _get_identity_store,
        current_username,
    )

    name = auth or current_username.get() or _default_identity()
    if not name:
        return (
            "no identity selected: nothing says who to act as. Call "
            "register(username) — after connect(url) — set $BONNET_IDENTITY, "
            "or pass auth=. list_identities shows what this client holds."
        )
    if _get_identity_store().get_pubkey(_default_origin() or "", name) is None:
        return (
            f"identity '{name}' is not held by this client for this origin, so "
            f"nothing can be signed as it. Call register('{name}') to create "
            f"it, or list_identities to see what is available."
        )
    return None


def _has_origin() -> bool:
    """Whether *this caller's context* currently has an active origin.

    Checked against the context's own state (after lazily adopting whatever
    was remembered on disk), not disk state directly — disk still remembers
    an origin after `disconnect()` (disconnect forgets nothing), but this
    caller's context no longer has one active, and gating must see that.
    """
    from bonnet.gateway.tools import _ensure_origin_loaded, current_origin_url

    _ensure_origin_loaded()
    return current_origin_url.get() is not None


def _needs_origin(tool: Tool) -> bool:
    return NEEDS_ORIGIN in (tool.tags or set())


def _needs_identity(tool: Tool) -> bool:
    return NEEDS_IDENTITY in (tool.tags or set())


async def _missing_for(tool: Tool, board: str | None = None, auth: str | None = None) -> str | None:
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

    `board` is the board this specific call will actually target, when the
    caller knows it (on_call_tool passes the call's own `board=` argument).
    It defaults to the cursor's board — the only thing on_list_tools has, since
    listing tools has no call arguments to read — which is also correct for a
    call that omits `board=` itself: every board-scoped tool falls back to the
    cursor the same way (see `cursor.resolve_board`). Without this, a call
    passing an explicit `board=` other than the open one would be checked
    against the wrong board's PERMISSIONS.

    `auth` is likewise the call's own `auth=` argument, when the caller
    passes one: gating must judge a call against the identity it will
    actually sign as, not the session default, the same way my_permissions
    already does.
    """
    if _needs_origin(tool):
        reason = _origin_missing()
        if reason is not None:
            return reason

    if _needs_identity(tool):
        reason = _identity_missing(auth)
        if reason is not None:
            return reason

    effective_board = board or cursor.current_board.get() or ""
    allowed = await needs_module.check(tool.name, effective_board, auth)
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
        if gating_enabled():
            tools = [
                t for t in tools if _anonymous_forbids(t) is None and await _missing_for(t) is None
            ]
        # Outside the gating check on purpose: BONNET_GATING=off suppresses
        # filtering, not the report that this session is degraded.
        warning = _auth_warning()
        if warning is not None:
            tools = [_with_warning(t, warning) for t in tools]
        return tools

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        tool = await _lookup(context)
        if tool is not None:
            reason = _anonymous_forbids(tool)
            if reason is None and gating_enabled():
                # The call's own board=, not the cursor's — a call naming a
                # different board must be checked against that board's
                # PERMISSIONS, not whatever board happens to be open. Empty
                # or absent falls through to the cursor inside _missing_for,
                # same as cursor.resolve_board's own fallback.
                arguments = context.message.arguments or {}
                reason = await _missing_for(
                    tool, arguments.get("board") or None, arguments.get("auth") or None
                )
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
