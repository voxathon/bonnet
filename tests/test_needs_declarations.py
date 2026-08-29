"""Each origin-facing tool's Needs() declaration must match what it calls.

Needs is declarative by design (see client/needs.py's docstring) — gating
trusts the declaration rather than scraping tool bodies at runtime, because
an earlier pass tried exactly that scrape and got several kinds wrong. But a
declaration nobody checks against the implementation can drift silently the
next time a tool's body changes and its decorator is not updated to match.
This test is that check, done once, statically, here — not at gating time.

CLIENT_COMMANDS maps each FirehoseHTTPClient method name to the PERMISSIONS
command it issues; CLIENT_KINDS maps the publish-family methods to the record
kind they publish. Both are read off firehose_client.py directly (see the
comments), not guessed.
"""

import inspect
import re

import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("cryptography")
pytest.importorskip("fastmcp")

from bonnet.client import tools
from bonnet.client.needs import NEEDS

# client method -> PERMISSIONS command it issues (firehose_client.py).
CLIENT_COMMANDS = {
    "get_permissions": "PERMISSIONS",
    "get_user": "USER_GET",
    "list_users": "USER_LIST",
    "list_boards": "BOARD_LIST",
    "get_article": "ARTICLE_GET",
    "get_article_by_id": "ARTICLE_GET",
    "list_articles": "ARTICLE_LIST",
    "search_articles": "ARTICLE_SEARCH",
    "query_articles": "ARTICLE_QUERY",
    "get_article_body": "ARTICLE_BODY",
    "get_ban_status": "BAN_STATUS",
    "get_head": "EVENT_HEAD",
    "get_event_range": "EVENT_RANGE",
    "get_event": "EVENT_GET",
    "get_event_body": "EVENT_BODY",
    # trace_event dials each hop and issues its own EVENT_GET per hop
    # (firehose_client.py) — the caller sees one client.trace_event() call,
    # but what it needs granted on this origin is EVENT_GET.
    "trace_event": "EVENT_GET",
    "list_reports": "REPORT_LIST",
    "publish_article": "PUBLISH_RECORD",
    "publish_supersede": "PUBLISH_RECORD",
    "publish_board_create": "PUBLISH_RECORD",
    "publish_user_register": "PUBLISH_RECORD",
    "publish_cancel": "PUBLISH_RECORD",
    "publish_restore": "PUBLISH_RECORD",
    "publish_purge": "PUBLISH_RECORD",
    "publish_report": "PUBLISH_RECORD",
    "publish_pin": "PUBLISH_RECORD",
    "publish_unpin": "PUBLISH_RECORD",
    "publish_punishment_warn": "PUBLISH_RECORD",
    "publish_punishment_ban": "PUBLISH_RECORD",
    "publish_punishment_permaban": "PUBLISH_RECORD",
    "publish_punishment_revoke": "PUBLISH_RECORD",
    "publish_punishment_ack": "PUBLISH_RECORD",
}

# publish-family client method -> the record kind it publishes. Only methods
# with one fixed kind are listed; publish_supersede and publish_article share
# "bonnet.article" (supersede is the same kind with a metadata field set, not
# a distinct kind — see board_projection.py's supersede handling).
CLIENT_KINDS = {
    "publish_article": "bonnet.article",
    "publish_supersede": "bonnet.article",
    "publish_board_create": "bonnet.board.create",
    "publish_cancel": "bonnet.article.cancel",
    "publish_restore": "bonnet.article.restore",
    "publish_purge": "bonnet.article.purge",
    "publish_pin": "bonnet.article.pin",
    "publish_unpin": "bonnet.article.unpin",
    "publish_report": "bonnet.report",
    "publish_punishment_warn": "bonnet.punishment.warn",
    "publish_punishment_ban": "bonnet.punishment.ban",
    "publish_punishment_permaban": "bonnet.punishment.permaban",
    "publish_punishment_revoke": "bonnet.punishment.revoke",
    "publish_punishment_ack": "bonnet.punishment.ack",
}

# Tools whose implementation calls a client method only inside a try/except
# that swallows failure — an optional enhancement, not something the tool
# needs to work at all, so it is deliberately left out of Needs. Recorded
# here so the omission reads as a decision, not a gap the scrape missed.
OPTIONAL_CALLS = {
    "get_article": {"get_article_body"},  # remote-body fallback; failure is caught
}

# needs_module.<method> -> the PERMISSIONS command it issues on the caller's
# behalf (needs.py, not firehose_client.py). Only open_board calls into this
# module today, via refresh() -> _permissions_for() -> client.get_permissions().
NEEDS_MODULE_COMMANDS = {
    "refresh": "PERMISSIONS",
}

_CALL_RE = re.compile(r"\b(client|needs_module)\.(\w+)\(")


def _client_calls(tool_name: str) -> set[str]:
    fn = getattr(tools, tool_name)
    src = inspect.getsource(fn)
    optional = OPTIONAL_CALLS.get(tool_name, set())
    return {name for _prefix, name in _CALL_RE.findall(src) if name not in optional}


@pytest.mark.parametrize("tool_name", sorted(NEEDS))
def test_declared_commands_match_the_calls_the_tool_makes(tool_name):
    calls = _client_calls(tool_name)
    commands = {**CLIENT_COMMANDS, **NEEDS_MODULE_COMMANDS}
    expected_commands = {commands[c] for c in calls if c in commands}

    declared = NEEDS[tool_name]
    assert set(declared.commands) == expected_commands, (
        f"{tool_name} declares commands={sorted(declared.commands)} but its "
        f"body calls client methods implying {sorted(expected_commands)}"
    )


@pytest.mark.parametrize("tool_name", sorted(NEEDS))
def test_declared_kinds_match_the_calls_the_tool_makes(tool_name):
    calls = _client_calls(tool_name)
    expected_kinds = {CLIENT_KINDS[c] for c in calls if c in CLIENT_KINDS}

    declared = NEEDS[tool_name]
    assert set(declared.kinds) == expected_kinds, (
        f"{tool_name} declares kinds={sorted(declared.kinds)} but its body "
        f"calls client methods implying {sorted(expected_kinds)}"
    )


def test_every_origin_facing_tool_has_a_declaration():
    """A tool tagged NEEDS_ORIGIN with no Needs would silently fall all the
    way back to the coarse identity-only heuristic forever, never getting a
    real PERMISSIONS answer — this catches a tool added without one."""
    from bonnet.client.gating import NEEDS_ORIGIN

    async def _tools():
        return await tools.mcp._list_tools()

    import asyncio

    all_tools = asyncio.run(_tools())
    origin_facing = {t.name for t in all_tools if NEEDS_ORIGIN in (t.tags or set())}

    assert origin_facing == set(NEEDS)
