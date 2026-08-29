"""State-dependent tool visibility.

A caller that has no origin or no usable identity is shown only the tools that
can work without them, and the rest appear in one transition once it does.

Gating is decided per request, not by mutating a shared registry, so two
callers of the same http bridge see different surfaces. The dead-end tests
matter most: a caller working from a stale tool list must be redirected, never
stranded.
"""

import httpx
import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("cryptography")
pytest.importorskip("fastmcp")

from fastmcp import Client

from bonnet.client import gating, tools
from bonnet.client.firehose_client import FirehoseHTTPClient
from bonnet.client.gating import GatingMiddleware
from bonnet.core.acl import ACLRule, PrincipalMatcher
from tests.test_firehose_http_server import ORIGIN, server_stack  # noqa: F401

pytestmark = pytest.mark.slow

UNGATED = {
    "login",
    "join",
    "register_user",
    "list_joined_origins",
    "switch_origin",
    "list_identities",
    "whoami",
}

# Tools tagged NEEDS_ORIGIN but not NEEDS_IDENTITY: they fall back to the
# anonymous principal, so an origin alone is enough — no identity required.
READ_ONLY = {
    "get_user",
    "list_users",
    "list_boards",
    "get_article",
    "list_articles",
    "search_articles",
    "query_articles",
    "ban_status",
    "event_head",
    "event_range",
    "get_event",
    "trace_event",
    "get_event_body",
    "my_permissions",
}


@pytest.fixture
def bridge(server_stack, tmp_path, monkeypatch):  # noqa: F811
    """A tools module wired to the in-process origin, with state isolated."""
    monkeypatch.setenv("BONNET_CLIENT_DIR", str(tmp_path / "state"))
    for var in ("BONNET_IDENTITY", "BONNET_URL", "BONNET_GATING"):
        monkeypatch.delenv(var, raising=False)

    saved = (tools.identity_store, tools.origin_store, tools.bonnet_url, tools.bonnet_verify)
    tools.identity_store = None
    tools.origin_store = None
    tools._origin_loaded = False

    if not any(isinstance(m, GatingMiddleware) for m in tools.mcp.middleware):
        tools.mcp.add_middleware(GatingMiddleware())

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

    for store in (tools.identity_store, tools.origin_store):
        if store is not None:
            store.close()
    tools.identity_store, tools.origin_store, tools.bonnet_url, tools.bonnet_verify = saved
    tools._origin_loaded = False
    tools.current_username.set(None)


async def _visible() -> set[str]:
    async with Client(tools.mcp) as c:
        return {t.name for t in await c.list_tools()}


# --- the two states -------------------------------------------------------


async def test_unready_shows_only_what_can_work(bridge):
    """Origin-facing tools need somewhere to send a request and an identity to
    sign it; with neither they can only fail, at a cost every turn."""
    assert await _visible() == UNGATED


async def test_joining_reveals_the_rest(bridge):
    before = await _visible()

    await tools.join("https://bbs.test", "scout")

    after = await _visible()
    assert before < after
    assert {"publish_article", "list_articles", "get_article"} <= after


async def test_join_reports_what_it_unlocked(bridge):
    """The guard against a host that ignores list_changed: the names arrive in
    the result, so a model that reads it can call them regardless."""
    result = await tools.join("https://bbs.test", "scout")

    assert "publish_article" in result["tools_unlocked"]
    assert len(result["tools_unlocked"]) == 30


async def test_a_restarted_bridge_starts_ready(bridge):
    """Readiness comes from stored state, not from having called join this
    session — a second process must not be sent back to the gate."""
    await tools.join("https://bbs.test", "scout")
    tools.current_username.set(None)

    assert "publish_article" in await _visible()


# --- configured entirely by environment -----------------------------------


async def test_env_configured_bridge_is_not_gated(bridge, monkeypatch):
    """The documented env-var flow: BONNET_URL plus an identity, never joined.
    Gating on a remembered origin alone would strand it behind a join it does
    not need."""
    tools._get_identity_store().register("scout")
    monkeypatch.setenv("BONNET_URL", "https://bbs.test")
    monkeypatch.setenv("BONNET_IDENTITY", "scout")

    assert "publish_article" in await _visible()


async def test_a_url_without_an_identity_is_still_gated(bridge, monkeypatch):
    """Write tools still need an identity — an origin with nothing to sign as
    cannot publish."""
    monkeypatch.setenv("BONNET_URL", "https://bbs.test")
    monkeypatch.setenv("BONNET_IDENTITY", "nonexistent")

    assert "publish_article" not in await _visible()


async def test_an_origin_alone_reveals_the_read_tools(bridge, monkeypatch):
    """The bug this replaces: a caller with an origin but no identity could see
    none of the 13 tools that only need an origin, because the old gate ANDed
    identity into every origin-facing tool regardless of whether the tool
    itself needed one. README promises read-only tools work without an
    account — this is that promise, checked."""
    monkeypatch.setenv("BONNET_URL", "https://bbs.test")

    visible = await _visible()
    assert READ_ONLY <= visible
    assert "publish_article" not in visible
    assert "create_board" not in visible


async def test_register_user_is_never_gated(bridge, monkeypatch):
    """It is how a caller acquires the identity the gate checks for, so
    hiding it would make the missing-identity state unrecoverable."""
    monkeypatch.setenv("BONNET_URL", "https://bbs.test")

    assert "register_user" in await _visible()


# --- per-caller, which is what makes http work ----------------------------


async def test_two_callers_see_different_surfaces(bridge):
    """The point of deciding per request: one shared registry, one bridge,
    two callers, two answers."""
    await tools.join("https://bbs.test", "scout")

    tools.current_username.set("scout")
    ready = await _visible()
    tools.current_username.set("stranger")
    unready = await _visible()

    assert "publish_article" in ready
    assert "publish_article" not in unready
    # "stranger" has an origin (joined by "scout") but no local identity of its
    # own, so it gets the read tools and nothing that writes or answers for a
    # specific caller.
    assert unready == UNGATED | READ_ONLY


# --- never stranded -------------------------------------------------------


async def test_calling_a_hidden_tool_explains_the_fix(bridge):
    """A caller working from a stale list gets redirected, not refused."""
    async with Client(tools.mcp) as c:
        with pytest.raises(Exception) as exc:
            await c.call_tool("publish_article", {"board": "b", "subject": "s", "content": "c"})

    assert "join" in str(exc.value)


async def test_a_stale_tool_list_still_works_once_ready(bridge):
    """Nothing is disabled server-side, so a call placed from a cached list
    succeeds the moment the caller is actually ready."""
    await tools.join("https://bbs.test", "scout")

    async with Client(tools.mcp) as c:
        assert await c.call_tool("list_boards", {"origin": ORIGIN}) is not None


async def test_unknown_tools_are_left_to_the_server(bridge):
    """The middleware speaks only for tools it gates; anything else keeps the
    server's own error."""
    async with Client(tools.mcp) as c:
        with pytest.raises(Exception) as exc:
            await c.call_tool("no_such_tool", {})

    assert "no_such_tool" in str(exc.value)


# --- escape hatch ---------------------------------------------------------


async def test_gating_off_shows_everything(bridge, monkeypatch):
    monkeypatch.setenv("BONNET_GATING", "off")

    assert "publish_article" in await _visible()


async def test_gating_off_also_lifts_the_call_block(bridge, monkeypatch):
    """The hatch has to cover both halves. Visible-but-uncallable would only
    half-answer the question an operator reaches for it to settle: this call
    is gated without the hatch (no origin, no identity) and goes through with
    it."""
    async with Client(tools.mcp) as c:
        with pytest.raises(Exception) as exc:
            await c.call_tool("list_boards", {"origin": ORIGIN})
    assert "unavailable" in str(exc.value)

    monkeypatch.setenv("BONNET_GATING", "off")

    async with Client(tools.mcp) as c:
        assert await c.call_tool("list_boards", {"origin": ORIGIN}) is not None


async def test_notification_is_best_effort_outside_a_request(bridge):
    """At startup or in tests there is no session; failing to notify must
    never fail the operation that caused the change."""
    await gating.announce_tool_change()
