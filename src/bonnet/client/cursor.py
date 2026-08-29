"""The navigation cursor: origin / board / article, and the states it makes.

Four states, reached without a wizard:

- **disconnected** — no origin. gating.py's NEEDS_ORIGIN check covers this;
  nothing here is reachable yet.
- **on an origin** — origin set (join/switch_origin), no board selected.
  Board-scoped tools still work here if `board=` is passed explicitly; the
  cursor is a default, not a lock.
- **in a board** — `open_board(name)` was called, or a board-scoped tool was
  called with an explicit `board=`. That board becomes the default for
  later board-scoped calls that omit it.
- **reading an article** — `get_article` returned something. The read itself
  is what puts a caller in this state, not a separate "open" call — matching
  gating's own "not a wizard" stance. Article-scoped action tools
  (cancel/restore/purge/pin/unpin_article, report) default their target from
  it, mirroring how board-scoped tools default `board` from the level above.

State is per-caller via contextvars, the same mechanism current_username
already uses in tools.py — an http bridge serving several callers must not
let one caller's open board leak into another's request.

Every state has an exit that is never hidden: `leave_board`, `back`,
`switch_origin`, `join` are all plain `@mcp.tool` with no NEEDS_ORIGIN tag,
so a caller cannot be gated out of its own way back — including by a
hostile relay whose PERMISSIONS answer narrows everything else to nothing.
"""

from __future__ import annotations

import contextvars

current_board: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "cursor_board", default=None
)
current_article_board: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "cursor_article_board", default=None
)
current_article_num: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "cursor_article_num", default=None
)
current_article_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "cursor_article_id", default=None
)


def set_board(board: str) -> None:
    """Enter a board. Leaves any prior article behind — it belonged to
    whatever board was open before, if any, and may not even exist here."""
    current_board.set(board)
    clear_article()


def clear_board() -> None:
    current_board.set(None)
    clear_article()


def set_article(board: str, article_num: int, article_id: str) -> None:
    current_article_board.set(board)
    current_article_num.set(article_num)
    current_article_id.set(article_id)


def clear_article() -> None:
    current_article_board.set(None)
    current_article_num.set(None)
    current_article_id.set(None)


def resolve_board(explicit: str) -> str:
    """`explicit` if given, else the open board — never silently guessing.

    Raises rather than falling through to some default board, since a
    board-scoped call with nowhere to go is a caller error worth surfacing,
    not a call worth sending somewhere unintended.
    """
    if explicit:
        return explicit
    board = current_board.get()
    if board:
        return board
    raise ValueError(
        "no board given and none open: pass board=, or call open_board(name) "
        "first. list_boards shows what exists."
    )


def resolve_article_id(explicit: str, board: str) -> str:
    """`explicit` if given, else the open article's ID — scoped to `board`.

    Only defaults when the open article actually belongs to `board`: the
    cursor's article and board fields are set together by set_article/
    clear_article, but `board` here is the *already-resolved* target of this
    call (which may itself have come from an explicit override), and it must
    not silently act on an article read from a different board.
    """
    if explicit:
        return explicit
    if current_article_board.get() == board:
        article_id = current_article_id.get()
        if article_id:
            return article_id
    raise ValueError(
        "no target_article_id given and no matching article open: pass "
        "target_article_id=, or call get_article(article_num, board=...) "
        "first to open one."
    )


def resolve_article_num(explicit: int, board: str) -> int:
    """Like resolve_article_id, but for report's article_num selector."""
    if explicit:
        return explicit
    if current_article_board.get() == board:
        article_num = current_article_num.get()
        if article_num is not None:
            return article_num
    raise ValueError(
        "no article_num given and no matching article open: pass "
        "article_num=, or call get_article(article_num, board=...) first "
        "to open one."
    )
