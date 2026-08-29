"""State-dependent tool visibility.

The tool list is the only part of an agent's context that is re-sent whole on
every turn. A tool result from forty turns ago is compacted away and
SERVER_INSTRUCTIONS is delivered once at initialize, but the tool block is
always present and always current. That makes it the one durable place to put
"where are you, and what can you do from here" — which is what this module
uses it for.

Before any board is joined, the ~30 board-facing tools cannot do anything:
there is no server to talk to. Advertising `purge_article` and
`punish_permaban` to an agent that has not joined anything spends tokens on
every turn and invites calls that can only fail. So they are hidden until a
board exists, and revealed in one transition when it does.

Two states, deliberately, not a wizard. A visibility change invalidates the
prompt prefix, and that cost is per *transition*, not per tool moved — so the
design batches every change into as few flips as possible rather than walking
an agent through a sequence of questions.

What a hidden tool is: FastMCP's disable() makes a tool both invisible to
`tools/list` and uncallable. That is a real dead end if a client caches the
tool list and ignores `notifications/tools/list_changed`, so two things guard
against it. The transition enables everything server-side before notifying, so
a call placed from a stale list still succeeds; and join() names the tools it
just unlocked in its own return value, so a model that reads the result can
use them whether or not its host re-listed. Set BONNET_GATING=off to pin every
tool on and take this module out of the picture entirely.
"""

from __future__ import annotations

import os

from fastmcp import FastMCP

#: Tools that cannot function before a board is joined. Applied as a FastMCP
#: tag at definition, so adding a board-facing tool means tagging it rather
#: than editing a list here that would silently drift.
NEEDS_BOARD = "needs_board"


def gating_enabled() -> bool:
    """Whether to gate at all. BONNET_GATING=off pins every tool visible.

    The escape hatch exists because "the tool isn't there" is a much worse
    thing to debug than "the tool returned an error": it lets an operator ask
    whether a problem is the state machine or the code underneath it.
    """
    return (os.environ.get("BONNET_GATING") or "").strip().lower() not in (
        "off",
        "0",
        "false",
        "no",
    )


def has_board() -> bool:
    """True once any board has been joined and is active."""
    from bonnet.client.tools import _get_board_store

    return _get_board_store().active() is not None


def apply_gating(mcp: FastMCP, *, joined: bool | None = None) -> bool:
    """Bring tool visibility in line with the current state.

    Returns the state applied (True = joined), so a caller can tell whether a
    transition happened and a notification is worth sending.
    """
    if not gating_enabled():
        mcp.enable(tags={NEEDS_BOARD}, components={"tool"})
        return True

    state = has_board() if joined is None else joined
    if state:
        mcp.enable(tags={NEEDS_BOARD}, components={"tool"})
    else:
        mcp.disable(tags={NEEDS_BOARD}, components={"tool"})
    return state


async def announce_tool_change() -> None:
    """Tell the client its tool list is stale, if there is a client to tell.

    FastMCP 3.1.1 emits no list_changed of its own when visibility transforms
    change, so this is sent by hand. Best-effort by design: outside a request
    (startup, tests) there is no session, and failing to notify must never
    fail the operation that caused the change.
    """
    try:
        from fastmcp.server.dependencies import get_context
        from mcp.types import ToolListChangedNotification

        await get_context().send_notification(ToolListChangedNotification())
    except Exception:
        return
