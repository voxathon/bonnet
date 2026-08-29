"""State-dependent tool visibility.

A fresh bridge advertises only what works before a board exists; joining one
reveals the rest in a single transition. The dead-end tests matter most: a
host that caches the tool list and ignores notifications must still end up
able to use what it gained.
"""

import httpx
import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("cryptography")
pytest.importorskip("fastmcp")

from fastmcp import Client

from bonnet.client import gating, tools
from bonnet.client.firehose_client import FirehoseHTTPClient
from bonnet.core.acl import ACLRule, PrincipalMatcher
from tests.test_firehose_http_server import ORIGIN, server_stack  # noqa: F401

pytestmark = pytest.mark.slow

UNGATED = {"login", "join", "list_joined_boards", "switch_board", "list_identities", "whoami"}


@pytest.fixture
def bridge(server_stack, tmp_path, monkeypatch):  # noqa: F811
    """A tools module wired to the in-process board, with state isolated."""
    monkeypatch.setenv("BONNET_CLIENT_DIR", str(tmp_path / "state"))
    monkeypatch.delenv("BONNET_IDENTITY", raising=False)
    monkeypatch.delenv("BONNET_URL", raising=False)
    monkeypatch.delenv("BONNET_GATING", raising=False)

    saved = (tools.identity_store, tools.board_store, tools.bonnet_url, tools.bonnet_verify)
    tools.identity_store = None
    tools.board_store = None
    tools._board_loaded = False

    server_stack["command_handler"]._acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(registered=True),
            actions=["read"],
            commands=["BOARD_LIST", "ARTICLE_LIST", "ARTICLE_GET", "EVENT_HEAD", "USER_GET"],
            boards=["*"],
        )
    )

    app = server_stack["server"]

    def make_client() -> FirehoseHTTPClient:
        client = FirehoseHTTPClient(tools.bonnet_url, verify=False)
        client._http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=tools.bonnet_url,
            timeout=30.0,
            verify=False,
        )
        return client

    monkeypatch.setattr(tools, "_make_client", make_client)

    yield server_stack

    gating.apply_gating(tools.mcp, joined=True)
    for store in (tools.identity_store, tools.board_store):
        if store is not None:
            store.close()
    tools.identity_store, tools.board_store, tools.bonnet_url, tools.bonnet_verify = saved
    tools._board_loaded = False
    tools.current_username.set(None)


async def _visible() -> set[str]:
    async with Client(tools.mcp) as c:
        return {t.name for t in await c.list_tools()}


async def test_unjoined_shows_only_what_can_work(bridge):
    """Before a board exists there is no server to talk to, so the ~28
    board-facing tools can only fail — and cost tokens every turn."""
    gating.apply_gating(tools.mcp)

    assert await _visible() == UNGATED


async def test_joining_reveals_the_rest(bridge):
    gating.apply_gating(tools.mcp)
    before = await _visible()

    await tools.join("https://bbs.test", "scout")

    after = await _visible()
    assert before < after
    assert {"publish_article", "list_articles", "get_article"} <= after


async def test_join_reports_what_it_unlocked(bridge):
    """The guard against a host that ignores list_changed: the names arrive in
    the result, so a model that reads it can call them regardless."""
    gating.apply_gating(tools.mcp)

    result = await tools.join("https://bbs.test", "scout")

    assert "publish_article" in result["tools_unlocked"]
    assert len(result["tools_unlocked"]) == 28


async def test_a_stale_tool_list_is_not_a_dead_end(bridge):
    """Tools are enabled before the notification goes out, so a call placed
    from a cached list still works."""
    gating.apply_gating(tools.mcp)
    await tools.join("https://bbs.test", "scout")

    async with Client(tools.mcp) as c:
        result = await c.call_tool("list_boards", {"origin": ORIGIN})

    assert result is not None


async def test_a_restarted_bridge_starts_joined(bridge):
    """State comes from the board store, not from having called join this
    session — the second process must not be sent back to the gate."""
    await tools.join("https://bbs.test", "scout")

    gating.apply_gating(tools.mcp)

    assert "publish_article" in await _visible()


async def test_gating_off_shows_everything(bridge, monkeypatch):
    monkeypatch.setenv("BONNET_GATING", "off")

    gating.apply_gating(tools.mcp)

    assert "publish_article" in await _visible()


async def test_the_escape_hatch_survives_a_disabled_start(bridge, monkeypatch):
    """Turning gating off must recover a bridge already sitting at the gate,
    which is the situation an operator reaches for it in."""
    gating.apply_gating(tools.mcp)
    assert "publish_article" not in await _visible()

    monkeypatch.setenv("BONNET_GATING", "off")
    gating.apply_gating(tools.mcp)

    assert "publish_article" in await _visible()


async def test_notification_is_best_effort_outside_a_request(bridge):
    """Called at startup or in tests there is no session; failing to notify
    must never fail the operation that caused the change."""
    await gating.announce_tool_change()
