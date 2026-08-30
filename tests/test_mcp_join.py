"""The cold start: connect(url) then register(username).

Exercised against the real ASGI server stack, so the registration record is
genuinely signed by a locally-minted key, evaluated by the real ACL, and
committed to the real firehose — not a mocked round trip.
"""

import httpx
import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("cryptography")
pytest.importorskip("fastmcp")

from bonnet.client import tools
from bonnet.client.firehose_client import FirehoseHTTPClient
from bonnet.core.acl import ACLRule, PrincipalMatcher
from tests.test_firehose_http_server import ORIGIN, server_stack  # noqa: F401

pytestmark = pytest.mark.slow


@pytest.fixture
def wired(server_stack, tmp_path, monkeypatch):  # noqa: F811
    """Route tools._make_client at the in-process server, on a temp store."""
    monkeypatch.setenv("BONNET_CLIENT_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("BONNET_IDENTITIES_DB", str(tmp_path / "identities.db"))
    monkeypatch.delenv("BONNET_IDENTITY", raising=False)
    monkeypatch.delenv("BONNET_URL", raising=False)

    saved = (tools.identity_store, tools.origin_store)
    tools.identity_store = None
    tools.origin_store = None
    tools.current_origin_url.set(None)
    tools.current_origin_verify.set(None)
    tools.current_origin.set(None)
    tools._origin_loaded.set(False)

    # Mirror the shipped default policy: matchers are mutually exclusive, so a
    # principal that has just registered stops being `unknown` and needs reads
    # granted to `registered` explicitly. Without this an agent can publish but
    # not read back, which is what config.example.toml now grants.
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

    def make_client(url: str | None = None, verify=None) -> FirehoseHTTPClient:
        target = url if url is not None else tools._current_url()
        client = FirehoseHTTPClient(target, verify=False)
        # Only https://bbs.test is served. Anything else must fail like an
        # unreachable host, or the routing here would mask a connect that
        # pointed the client somewhere it never actually reached.
        if target != "https://bbs.test":
            raise httpx.ConnectError(f"no server at {target}")
        client._http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=target,
            timeout=30.0,
            verify=False,
        )
        return client

    monkeypatch.setattr(tools, "_make_client", make_client)

    yield server_stack

    for store in (tools.identity_store, tools.origin_store):
        if store is not None:
            store.close()
    tools.identity_store, tools.origin_store = saved
    tools.current_origin_url.set(None)
    tools.current_origin_verify.set(None)
    tools.current_origin.set(None)
    tools._origin_loaded.set(False)
    tools.current_username.set(None)


async def _connect_and_register(username: str) -> dict:
    """The two-call cold start this fixture exercises throughout."""
    await tools.connect("https://bbs.test")
    return await tools.register(username)


async def test_connect_reports_the_origin_and_boards(wired):
    result = await tools.connect("https://bbs.test")

    assert result["origin"] == ORIGIN
    assert result["identities"] == []


async def test_register_registers_and_reports_the_board(wired):
    await tools.connect("https://bbs.test")
    result = await tools.register("scout")

    assert result["origin"] == ORIGIN
    assert result["username"] == "scout"
    assert len(result["public_key"]) == 64
    assert result["registered_seq"] > 0


async def test_register_actually_lands_a_registration_the_server_accepted(wired):
    """The point of register is a real registration, so assert against the
    server's own user projection rather than the returned summary."""
    await tools.connect("https://bbs.test")
    result = await tools.register("scout")

    user = wired["users"].get_user_by_pubkey(ORIGIN, bytes.fromhex(result["public_key"]))
    assert user is not None
    assert user["username"] == "scout"


async def test_register_mints_a_local_passwordless_identity(wired):
    await tools.connect("https://bbs.test")
    await tools.register("scout")

    store = tools._get_identity_store()
    assert store.is_wrapped(ORIGIN, "scout") is False
    assert store.is_registered(ORIGIN, "scout") is True


async def test_register_makes_the_identity_active_for_later_calls(wired):
    """After register, a tool call that omits auth must resolve to the
    registered identity — that is what makes it a cold start."""
    await tools.connect("https://bbs.test")
    await tools.register("scout")

    assert tools._resolve_auth(None) == ("scout", "")


async def test_connect_points_the_client_at_the_board(wired):
    await tools.connect("https://bbs.test")

    assert tools._current_url() == "https://bbs.test"


async def test_registering_twice_reuses_the_existing_keypair(wired):
    """A retry under the same name must not orphan the first key, or the
    agent silently loses the identity its earlier posts were signed with."""
    await tools.connect("https://bbs.test")
    first = await tools.register("scout")
    second = await tools.register("scout")

    assert first["public_key"] == second["public_key"]


async def test_registering_two_usernames_holds_two_identities_on_one_origin(wired):
    """The actual point of the per-origin schema: multiple identities on the
    same origin are independent keypairs, not one shared registration."""
    await tools.connect("https://bbs.test")
    scout = await tools.register("scout")
    mod = await tools.register("mod")

    assert scout["public_key"] != mod["public_key"]
    names = {i["username"] for i in await tools.list_identities()}
    assert names == {"scout", "mod"}


async def test_a_failed_connect_does_not_redirect_the_client(wired):
    """A half-applied connect would silently send every later tool call to an
    origin the agent never successfully reached."""
    await tools.connect("https://bbs.test")
    before = tools._current_url()

    with pytest.raises(Exception):
        await tools.connect("https://unreachable.invalid:2272")

    assert tools._current_url() == before


async def test_disconnect_returns_to_the_disconnected_state(wired):
    await tools.connect("https://bbs.test")
    await tools.register("scout")

    result = await tools.disconnect()

    assert result["state"] == "disconnected"
    where = await tools.where_am_i()
    assert where["state"] == "disconnected"
    assert where["identity"] is None


async def test_disconnect_forgets_nothing(wired):
    """disconnect exits the origin, it does not forget it — reconnecting or
    switching back should still find the origin and identity."""
    await tools.connect("https://bbs.test")
    await tools.register("scout")
    await tools.disconnect()

    origins = await tools.list_joined_origins()
    assert any(o["origin"] == ORIGIN for o in origins)

    await tools.connect("https://bbs.test")
    identities = await tools.list_identities()
    assert any(i["username"] == "scout" for i in identities)
