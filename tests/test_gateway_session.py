"""Navigation state across HTTP requests.

**These tests must run over a real HTTP transport.** The bug they cover is
invisible to an in-memory client: ASGI gives every HTTP request a fresh copy
of the context, so a ContextVar a tool sets is discarded when it returns,
while an in-memory session runs everything in one context and so never
notices. `open_board` reported success and the next call saw no open board;
`disconnect` was undone by the following request re-adopting the remembered
origin. Both failed silently.

A snapshot round-trips through FastMCP's session-scoped state store — see
`gateway.session`. Delete `SessionStateMiddleware` from the stack and every
test below fails.
"""

import asyncio
import socket
import threading

import httpx
import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("cryptography")
pytest.importorskip("fastmcp")

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from bonnet.core.acl import ACLRule, PrincipalMatcher
from bonnet.gateway import session as session_module
from bonnet.gateway import tenancy, tenants, tools
from bonnet.gateway.firehose_client import FirehoseHTTPClient
from bonnet.gateway.server import mcp
from tests.test_firehose_http_server import server_stack  # noqa: F401

#: Set by the http_gateway fixture, which picks the port at run time.
URL = ""


def _free_port() -> int:
    """Ask the OS for an unused port rather than hoping a fixed one is free.

    A hardcoded port collides under `pytest -n auto`: another worker, or a
    server still shutting down from an earlier run, holds it; uvicorn then
    calls sys.exit(1) inside its startup thread and every test in this module
    fails as an unhandled thread exception that names nothing useful.

    There is a small race between closing this socket and uvicorn binding it,
    which is unavoidable without handing uvicorn the socket itself — but it is
    a far smaller window than a port that is contended by construction.
    """
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def http_gateway():
    """The gateway on a real port. Module-scoped: uvicorn cannot rebind a
    port quickly, and each test opens its own MCP session anyway."""
    global URL
    port = _free_port()
    URL = f"http://127.0.0.1:{port}/mcp"
    threading.Thread(
        target=lambda: mcp.run(transport="http", host="127.0.0.1", port=port, show_banner=False),
        daemon=True,
    ).start()
    yield URL


@pytest.fixture
def gw(http_gateway, server_stack, tmp_path, monkeypatch):  # noqa: F811
    """A tenant on the http gateway, with tools routed at the in-process origin.

    The gateway runs in a thread of *this* process, so monkeypatching
    tools._make_client reaches it — the requests are real HTTP, the origin
    behind them is the real ASGI stack.
    """
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "gw"))
    for var in ("BONNET_IDENTITIES_DB", "BONNET_IDENTITY", "BONNET_URL", "BONNET_GATING"):
        monkeypatch.delenv(var, raising=False)
    tenancy.reset_store_cache()
    tenancy.reset_registry_cache()

    server_stack["command_handler"]._acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(registered=True),
            actions=["read"],
            commands=["BOARD_LIST", "ARTICLE_LIST", "ARTICLE_GET", "EVENT_HEAD", "USER_GET"],
            boards=["*"],
        )
    )
    server_stack["command_handler"]._acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(registered=True),
            actions=["write"],
            commands=["PUBLISH_RECORD"],
            kinds=["bonnet.board.create"],
            boards=["*"],
        )
    )
    app = server_stack["server"]

    def make_client(url: str | None = None, verify=None) -> FirehoseHTTPClient:
        target = url if url is not None else tools._current_url()
        if target != "https://bbs.test":
            raise httpx.ConnectError(f"no server at {target}")
        client = FirehoseHTTPClient(target, verify=False)
        client._http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=target,
            timeout=30.0,
            verify=False,
        )
        return client

    monkeypatch.setattr(tools, "_make_client", make_client)

    yield tenants.add_tenant("alice")

    tenancy.reset_store_cache()
    tenancy.reset_registry_cache()


def _client(key: str | None = None) -> Client:
    headers = {"X-API-Key": key} if key else {}
    return Client(StreamableHttpTransport(URL, headers=headers))


async def _ready(key: str) -> None:
    for _ in range(80):
        try:
            async with _client(key) as c:
                await c.list_tools()
            return
        except Exception:
            await asyncio.sleep(0.25)
    raise RuntimeError("gateway did not start")


async def _connected(c, username: str = "scout", board: str = "general"):
    """connect + register + create `board`, so board-scoped tools are
    reachable — open_board now confirms the board actually exists (regression
    for the chaos-testing report's #1.1), so these tests can no longer open a
    board nothing ever created.

    Usernames are first-writer-wins per origin, so two *different* tenants
    against this one server need distinct names. The second would otherwise be
    refused, which is the rule working rather than a wrinkle in it.
    """
    await c.call_tool("connect", {"url": "https://bbs.test", "verify_tls": False})
    await c.call_tool("register", {"username": username})
    await c.call_tool("create_board", {"name": board})


async def _where(c) -> dict:
    return (await c.call_tool("where_am_i", {})).data


async def test_an_open_board_survives_the_next_request(gw):
    """The original failure: open_board returned board='general' and the very
    next call in the same session reported None."""
    await _ready(gw)

    async with _client(gw) as c:
        await _connected(c)
        opened = await c.call_tool("open_board", {"board": "general"})
        assert opened.data["board"] == "general"

        after = await _where(c)

    assert after["board"] == "general"
    assert after["state"] == "in_board"


async def test_the_cursor_is_not_shared_between_sessions(gw):
    """Per-caller isolation is the reason the cursor is a ContextVar in the
    first place, and persisting it must not cost that."""
    await _ready(gw)

    async with _client(gw) as c:
        await _connected(c)
        await c.call_tool("open_board", {"board": "general"})

    async with _client(gw) as fresh:
        assert (await _where(fresh))["board"] is None


async def test_disconnect_is_not_undone_by_the_next_request(gw):
    """disconnect clears the active origin but forgets nothing on disk, so a
    later request would re-adopt the remembered origin and silently reconnect.
    `origin_loaded` is in the snapshot precisely to stop that."""
    await _ready(gw)

    async with _client(gw) as c:
        await _connected(c)
        await c.call_tool("open_board", {"board": "general"})
        await c.call_tool("disconnect", {})

        after = await _where(c)

    assert after["state"] == "disconnected"
    assert after["origin"] is None
    assert after["board"] is None


async def test_leaving_a_board_also_survives(gw):
    await _ready(gw)

    async with _client(gw) as c:
        await _connected(c)
        await c.call_tool("open_board", {"board": "general"})
        await c.call_tool("leave_board", {})

        assert (await _where(c))["board"] is None


async def test_two_tenants_in_one_process_keep_separate_cursors(gw):
    """The state key carries the tenant as well as the session: a different
    account must not inherit another's position, and concurrent sessions in
    one process must not blur together."""
    await _ready(gw)
    bob_key = tenants.add_tenant("bob")
    tenancy.reset_registry_cache()

    async with _client(gw) as alice:
        await _connected(alice)
        await alice.call_tool("open_board", {"board": "general"})

        async with _client(bob_key) as bob:
            await _connected(bob, username="bob-scout", board="lounge")
            await bob.call_tool("open_board", {"board": "lounge"})
            assert (await _where(bob))["board"] == "lounge"

        # alice's position is untouched by bob having moved elsewhere
        assert (await _where(alice))["board"] == "general"


async def test_an_anonymous_session_still_gets_a_cursor(gw):
    """Reduced capability is not no capability: reads are board-scoped too,
    so navigation has to work for a session that cannot publish."""
    await _ready(gw)

    # Anonymous cannot create a board itself; a throwaway registered session
    # creates "general" first so there is something for it to open.
    async with _client(gw) as setup:
        await _connected(setup)

    async with _client() as c:
        await c.call_tool("connect", {"url": "https://bbs.test", "verify_tls": False})
        opened = await c.call_tool("open_board", {"board": "general"})
        assert opened.data["board"] == "general"

        assert (await _where(c))["board"] == "general"


async def test_fresh_session_resolves_remembered_identity(gw):
    """A brand-new session for a tenant that already registered elsewhere
    must resolve that remembered identity without calling connect() first —
    regression for the chaos-testing report's fresh-session finding."""
    await _ready(gw)

    async with _client(gw) as c:
        await _connected(c, username="scout")

    async with _client(gw) as fresh:
        who = (await fresh.call_tool("whoami", {})).data
        assert "scout" in who

        ids = (await fresh.call_tool("list_identities", {})).data
        assert len(ids) == 1
        assert ids[0].username == "scout"
        assert ids[0].active is True

        joined = (await fresh.call_tool("list_joined_origins", {})).data
        assert len(joined) == 1
        assert joined[0].origin == "bbs.test"
        assert joined[0].active is True


async def test_whoami_after_disconnect_resolves_the_remembered_identity(gw):
    """disconnect() forgets nothing on disk, so whoami() right after it must
    still resolve the identity it just had — regression for the
    chaos-testing report's disconnect/whoami finding. Previously
    `_default_origin` fell back to the raw connection URL once `disconnect`
    cleared `current_origin`, while `_default_identity` kept resolving the
    origin store's remembered identity — the mismatch made a real, still-held
    identity look missing."""
    await _ready(gw)

    async with _client(gw) as c:
        await _connected(c, username="scout")
        await c.call_tool("disconnect", {})

        who = (await c.call_tool("whoami", {})).data
        assert "scout" in who


# --- concurrent calls in one session ----------------------------------------


async def test_concurrent_calls_in_one_session_are_serialized():
    """FastMCP's state store is a bare get/put with no compare-and-swap (the
    default MemoryStore backing it is an unguarded dict) — two tool calls
    dispatched concurrently in the same session would each load the same
    starting snapshot, and whichever finished and saved last would silently
    discard the other's cursor movement. SessionStateMiddleware's per-
    (session, tenant) lock closes that by serializing the whole
    load -> run tool -> save span.

    Proven directly rather than by inference: call A starts, opens the race
    window (a_running), then sleeps before saving — the classic lost-update
    gap. Call B is released into that gap. Without the lock, B's entire
    load -> run -> save fits inside it and finishes before A's save, so A's
    stale, already-loaded snapshot overwrites what B just committed. With the
    lock, B cannot even begin its load until A's save has completed, so the
    six events land in exactly one order with no interleaving possible."""
    from bonnet.gateway.session import SessionStateMiddleware

    events: list[str] = []
    gate = asyncio.Event()
    store: dict = {}

    class FakeCtx:
        session_id = "race-session"

        async def get_state(self, key):
            events.append("load")
            return store.get(key)

        async def set_state(self, key, value):
            events.append("save")
            store[key] = value

    class FakeContext:
        fastmcp_context = FakeCtx()

    async def slow_next(_context):
        events.append("a_running")
        gate.set()
        await asyncio.sleep(0.05)
        return "a"

    async def fast_next(_context):
        events.append("b_running")
        return "b"

    middleware = SessionStateMiddleware()

    async def run_a():
        await middleware.on_call_tool(FakeContext(), slow_next)

    async def run_b():
        await gate.wait()
        await middleware.on_call_tool(FakeContext(), fast_next)

    await asyncio.gather(run_a(), run_b())

    assert events == ["load", "a_running", "save", "load", "b_running", "save"]


# --- the snapshot itself ---------------------------------------------------


def test_restoring_nothing_leaves_the_context_alone(gw):
    """A session's first request has nothing stored. Blanking the ContextVars
    there would wipe state established another way — which is how the rest of
    the suite drives the tools directly."""
    from bonnet.gateway import cursor

    cursor.current_board.set("general")

    session_module.restore(None)
    session_module.restore({})

    assert cursor.current_board.get() == "general"


def test_a_snapshot_round_trips(gw):
    from bonnet.gateway import cursor

    cursor.current_board.set("general")
    cursor.set_article("general", 7, "ab" * 32)
    taken = session_module.snapshot()

    cursor.clear_board()
    assert cursor.current_board.get() is None

    session_module.restore(taken)

    assert cursor.current_board.get() == "general"
    assert cursor.current_article_num.get() == 7
    assert cursor.current_article_id.get() == "ab" * 32


def test_a_snapshot_is_json_serializable(gw):
    """It goes through FastMCP's state store, which serializes. A value that
    is not JSON-safe raises there, inside a best-effort except, and the cursor
    would silently stop persisting."""
    import json

    from bonnet.gateway import cursor

    cursor.current_board.set("general")
    cursor.set_article("general", 3, "cd" * 32)

    assert json.loads(json.dumps(session_module.snapshot()))
