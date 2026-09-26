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

"""Tool descriptions must fit the client-side cap on what an agent sees.

Some MCP clients cut a tool description off at a fixed length — Claude Code
at 2048 characters — and the cut drops the tail silently. What reaches the
agent is also longer than the docstring: gating prefixes the anonymous-session
warning onto every tool, and the cursor banner onto the board-scoped ones. So
each tool's budget is the cap minus whichever of those it can carry.

Per-parameter docs belong on the parameter (`Annotated[..., Field(description=
...)]`), where they travel in the input schema instead of the description.
"""

import contextvars

import pytest

pytest.importorskip("fastmcp")

from bonnet.gateway import cursor, gating, tools

CLIENT_DESCRIPTION_CAP = 2048

#: A board name of a realistic length for sizing the cursor banner. The
#: protocol allows up to MAX_BOARD (255), but budgeting for that would leave
#: the board-scoped tools almost nothing.
_BANNER_BOARD = "b" * 32

#: Tools still over budget, each with the length it may not grow past. They
#: need their prose restructured, not just their parameter docs moved; drop
#: an entry once its tool fits.
KNOWN_OVER_BUDGET = {
    "query_articles": 3788,
    "get_article": 3410,
    "connect": 3004,
    "get_event": 1888,
}


def _worst_cursor_banner() -> str:
    def render() -> str | None:
        cursor.current_board.set(_BANNER_BOARD + "x")
        cursor.current_article_board.set(_BANNER_BOARD)
        cursor.current_article_num.set(99999)
        cursor.current_article_id.set("f" * 64)
        return gating._cursor_banner()

    banner = contextvars.copy_context().run(render)
    assert banner is not None
    return banner


def _budget(name: str) -> int:
    headroom = max(len(gating._WARNING_ABSENT), len(gating._WARNING_REJECTED))
    if name in gating.CURSOR_CONTEXT_TOOLS:
        headroom += len(_worst_cursor_banner())
    return CLIENT_DESCRIPTION_CAP - headroom


async def _descriptions() -> dict[str, str]:
    return {t.name: t.description or "" for t in await tools.mcp._list_tools()}


async def test_tool_descriptions_fit_the_client_cap():
    over = {
        name: (len(desc), _budget(name))
        for name, desc in (await _descriptions()).items()
        if name not in KNOWN_OVER_BUDGET and len(desc) > _budget(name)
    }
    assert not over, (
        f"tool descriptions over budget (length, budget): {over}. Move parameter "
        f"docs into Field(description=...) and implementation notes into comments."
    )


@pytest.mark.parametrize("name", sorted(KNOWN_OVER_BUDGET))
async def test_known_over_budget_tools_only_shrink(name):
    desc = (await _descriptions())[name]
    assert len(desc) <= KNOWN_OVER_BUDGET[name], (
        f"{name} grew to {len(desc)} characters; it is already past the cap"
    )
    assert len(desc) > _budget(name), (
        f"{name} now fits its budget ({len(desc)} <= {_budget(name)}): "
        f"remove it from KNOWN_OVER_BUDGET"
    )
