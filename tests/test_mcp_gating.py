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

from bonnet.core.acl import ACLRule, PrincipalMatcher
from bonnet.gateway import cursor, gating, tenancy, tools
from bonnet.gateway.firehose_client import FirehoseHTTPClient
from bonnet.gateway.gating import GatingMiddleware
from tests.test_firehose_http_server import ORIGIN, server_stack  # noqa: F401

UNGATED = {
    "login",
    "connect",
    "disconnect",
    "register",
    # How a caller accepts the key connect asked it about — gating it behind
    # having an origin would be circular, since accepting is what produces one.
    "trust_origin_key",
    "list_joined_origins",
    "switch_origin",
    "list_identities",
    "whoami",
    "leave_board",
    "back",
    "where_am_i",
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
    "read_thread",
    "ban_status",
    "event_head",
    "event_range",
    "get_event",
    "trace_event",
    "get_event_body",
    "my_permissions",
    "open_board",
}


@pytest.fixture
def bridge(server_stack, tmp_path, monkeypatch):  # noqa: F811
    """A tools module wired to the in-process origin, with state isolated."""
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "state"))
    for var in ("BONNET_IDENTITY", "BONNET_URL", "BONNET_GATING"):
        monkeypatch.delenv(var, raising=False)

    tenancy.reset_store_cache()
    tools.current_origin_url.set(None)
    tools.current_origin_verify.set(None)
    tools.current_origin.set(None)
    tools._origin_loaded.set(False)

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
    # server_stack grants the anonymous principal every other read command but
    # not ARTICLE_QUERY — filling that gap so the PERMISSIONS-based gate sees
    # the full READ_ONLY set as actually permitted for anonymous, matching
    # what these tests assert.
    server_stack["command_handler"]._acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(anonymous=True),
            actions=["read"],
            commands=["ARTICLE_QUERY"],
            boards=["*"],
        )
    )

    app = server_stack["server"]

    def make_client(url: str | None = None, verify=None) -> FirehoseHTTPClient:
        target = url if url is not None else tools._current_url()
        client = FirehoseHTTPClient(target, verify=False)
        client._http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=target,
            timeout=30.0,
            verify=False,
        )
        return client

    monkeypatch.setattr(tools, "_make_client", make_client)

    yield server_stack

    tenancy.reset_store_cache()
    tools.current_origin_url.set(None)
    tools.current_origin_verify.set(None)
    tools.current_origin.set(None)
    tools._origin_loaded.set(False)
    tools.current_username.set(None)


async def _visible() -> set[str]:
    async with Client(tools.mcp) as c:
        return {t.name for t in await c.list_tools()}


async def _connect_and_register(username: str = "scout") -> dict:
    await tools.connect("https://bbs.test")
    return await tools.register(username)


# --- the three states ------------------------------------------------------


async def test_unready_shows_only_what_can_work(bridge):
    """Origin-facing tools need somewhere to send a request and an identity to
    sign it; with neither they can only fail, at a cost every turn."""
    assert await _visible() == UNGATED


async def test_connecting_reveals_the_read_tools(bridge):
    """connect alone establishes an origin but no identity, so only the tools
    that fall back to the anonymous principal appear."""
    before = await _visible()

    await tools.connect("https://bbs.test")

    after = await _visible()
    assert after == UNGATED | READ_ONLY
    assert "publish_article" not in after
    assert before < after


async def test_connect_reports_what_it_unlocked(bridge):
    result = await tools.connect("https://bbs.test")

    assert set(result["tools_unlocked"]) == READ_ONLY


async def test_registering_reveals_the_rest(bridge):
    await tools.connect("https://bbs.test")
    before = await _visible()

    await tools.register("scout")

    after = await _visible()
    assert before < after
    assert {"publish_article", "list_articles", "get_article"} <= after


async def test_register_reports_what_it_unlocked(bridge):
    """The guard against a host that ignores list_changed: the names arrive in
    the result, so a model that reads it can call them regardless."""
    await tools.connect("https://bbs.test")
    result = await tools.register("scout")

    assert "publish_article" in result["tools_unlocked"]
    assert READ_ONLY <= set(result["tools_unlocked"])


async def test_a_restarted_bridge_starts_ready(bridge):
    """Readiness comes from stored state, not from having called register this
    session — a second process must not be sent back to the gate."""
    await _connect_and_register("scout")
    tools.current_username.set(None)

    assert "publish_article" in await _visible()


# --- configured entirely by environment -----------------------------------


async def test_env_configured_bridge_is_not_gated(bridge, monkeypatch):
    """The documented env-var flow: BONNET_URL plus an identity, never
    connected. Gating on a remembered origin alone would strand it behind a
    connect it does not need.

    Identity lookups fall back to scoping by the configured URL itself here
    (see _default_origin) — a bridge wired up entirely through environment
    variables never calls connect(), so nothing ever learns the origin's own
    discovered identifier to scope by instead."""
    tools._get_identity_store().register("https://bbs.test", "scout")
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


async def test_open_board_is_hidden_with_no_origin(bridge):
    """The bug that motivated tagging open_board NEEDS_ORIGIN: calling it
    before connect/switch_origin used to silently "succeed" against whatever
    origin happened to default to, cursor left pointed at a board on an
    origin never actually reached. Gating it out makes that state
    unreachable instead of just quiet."""
    assert "open_board" not in await _visible()

    async with Client(tools.mcp) as c:
        with pytest.raises(Exception) as exc:
            await c.call_tool("open_board", {"board": "general"})
    assert "unavailable" in str(exc.value)
    assert cursor.current_board.get() is None


async def test_register_is_never_gated(bridge, monkeypatch):
    """It is how a caller acquires the identity the gate checks for, so
    hiding it would make the missing-identity state unrecoverable."""
    monkeypatch.setenv("BONNET_URL", "https://bbs.test")

    assert "register" in await _visible()


async def test_disconnect_is_never_gated(bridge):
    """Every state needs a way out that is not itself gated."""
    assert "disconnect" in await _visible()

    await _connect_and_register("scout")
    assert "disconnect" in await _visible()


async def test_disconnect_re_gates_origin_facing_tools(bridge):
    await _connect_and_register("scout")
    assert "publish_article" in await _visible()

    await tools.disconnect()

    assert await _visible() == UNGATED


# --- per-caller, which is what makes http work ----------------------------


async def test_two_callers_see_different_surfaces(bridge):
    """The point of deciding per request: one shared registry, one bridge,
    two callers, two answers."""
    await _connect_and_register("scout")

    tools.current_username.set("scout")
    ready = await _visible()
    tools.current_username.set("stranger")
    unready = await _visible()

    assert "publish_article" in ready
    assert "publish_article" not in unready
    # "stranger" has an origin (connected by "scout") but no local identity of
    # its own, so it gets the read tools and nothing that writes or answers
    # for a specific caller.
    assert unready == UNGATED | READ_ONLY


# --- never stranded -------------------------------------------------------


async def test_calling_a_hidden_tool_explains_the_fix(bridge):
    """A caller working from a stale list gets redirected, not refused."""
    async with Client(tools.mcp) as c:
        with pytest.raises(Exception) as exc:
            await c.call_tool("publish_article", {"board": "b", "subject": "s", "content": "c"})

    assert "connect" in str(exc.value)


async def test_a_stale_tool_list_still_works_once_ready(bridge):
    """Nothing is disabled server-side, so a call placed from a cached list
    succeeds the moment the caller is actually ready."""
    await _connect_and_register("scout")

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


# --- narrowed by the relay's actual PERMISSIONS ----------------------------


async def test_permissions_hides_a_tool_the_local_heuristic_would_show(bridge):
    """Having an identity is necessary but not sufficient. The local
    heuristic alone (origin + identity present) cannot distinguish a caller
    who may publish bonnet.article from one who may not — only the relay's
    own PERMISSIONS answer can, and it must be able to hide a tool the local
    heuristic would otherwise leave visible."""
    from bonnet.core.acl import ACLRule, PrincipalMatcher

    acl = bridge["command_handler"]._acl
    # Give "registered" a real PERMISSIONS answer (the fixture otherwise
    # never grants that command to registered, so this scenario would
    # silently fall back to the identity-only heuristic and prove nothing).
    acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(registered=True),
            actions=["read"],
            commands=["PERMISSIONS"],
            boards=["*"],
        )
    )

    await _connect_and_register("scout")
    tools.current_username.set("scout")

    # scout holds an identity, so the local heuristic alone would show
    # publish_article — but nothing here granted PUBLISH_RECORD to
    # "registered", so the relay's own PERMISSIONS answer says no.
    assert "publish_article" not in await _visible()


async def test_call_time_gate_checks_the_calls_own_board(bridge):
    """A call naming a board other than the open one must be checked against
    *that* board's PERMISSIONS, not whatever happens to be open.

    Board-scoped tools accept an explicit board= specifically so a caller can
    read (or act on) a different board without leaving the one it has open —
    open_board's docstring calls this "a default, not a lock". The on_call_tool
    gate has to honor that: if it fell back to the cursor's board here, a
    command granted on the open board but not on the named one would be let
    through the gate, only to be refused by the relay's own ACL a moment
    later — the exact case my_permissions exists to let a caller avoid."""
    from bonnet.core.acl import ACLRule, PrincipalMatcher

    acl = bridge["command_handler"]._acl
    acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(registered=True),
            actions=["read"],
            commands=["PERMISSIONS"],
            boards=["*"],
        )
    )
    # ARTICLE_SEARCH granted on "mine" only. ACLEvaluator requires a single
    # rule to cover every dimension of a check together — so this rule's own
    # boards=["mine"] is what keeps "other" out; it cannot be widened by the
    # bridge fixture's unrelated boards=["*"] rule for BOARD_LIST/ARTICLE_LIST
    # /etc, since that rule doesn't grant ARTICLE_SEARCH at all.
    acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(registered=True),
            actions=["read"],
            commands=["ARTICLE_SEARCH"],
            boards=["mine"],
        )
    )

    await _connect_and_register("scout")
    tools.current_username.set("scout")
    # open_board now confirms the board exists (regression for the
    # chaos-testing report's #1.1) - "mine" is only a name in an ACL rule
    # above, so it has to actually be created before it can be opened.
    acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(registered=True),
            actions=["write"],
            commands=["PUBLISH_RECORD"],
            kinds=["bonnet.board.create"],
            boards=["*"],
        )
    )
    await tools.create_board("mine")
    await tools.open_board("mine")

    async with Client(tools.mcp) as c:
        with pytest.raises(Exception) as exc:
            await c.call_tool("search_articles", {"query": "x", "board": "other"})

    # The gate's own message, not whatever the relay would have said — proof
    # the check ran against "other", where ARTICLE_SEARCH is not granted, and
    # not "mine", where it is.
    assert "per the relay's own PERMISSIONS" in str(exc.value)


async def test_call_time_gate_honors_the_calls_own_auth(bridge):
    """A call's own auth= must be judged on its own identity, not the
    session default — the same per-call identity model my_permissions(auth=)
    already implements. Before this was wired through, gating computed
    _identity_missing() off current_username alone, so a call naming a
    perfectly valid auth= was refused "no identity selected" whenever the
    session's own default happened to be unset."""
    from bonnet.core.acl import ACLRule, PrincipalMatcher

    acl = bridge["command_handler"]._acl
    acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(registered=True),
            actions=["write"],
            commands=["PUBLISH_RECORD"],
            kinds=["bonnet.board.create", "bonnet.article"],
            boards=["*"],
        )
    )

    await _connect_and_register("scout")
    await tools.create_board("general")
    # Simulate a caller relying entirely on auth=, not a session default.
    tools.current_username.set(None)

    async with Client(tools.mcp) as c:
        result = await c.call_tool(
            "publish_article",
            {"board": "general", "subject": "s", "content": "c", "auth": "scout"},
        )
    assert result is not None


async def test_notification_is_best_effort_outside_a_request(bridge):
    """At startup or in tests there is no session; failing to notify must
    never fail the operation that caused the change."""
    await gating.announce_tool_change()
