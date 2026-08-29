"""The one-call cold start: join(url, username).

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

    saved = (tools.identity_store, tools.origin_store, tools.bonnet_url, tools.bonnet_verify)
    tools.identity_store = None
    tools.origin_store = None
    tools._origin_loaded = False

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

    def make_client() -> FirehoseHTTPClient:
        client = FirehoseHTTPClient(tools.bonnet_url, verify=False)
        # Only https://bbs.test is served. Anything else must fail like an
        # unreachable host, or the routing here would mask a join that pointed
        # the client somewhere it never actually reached.
        if tools.bonnet_url != "https://bbs.test":
            raise httpx.ConnectError(f"no server at {tools.bonnet_url}")
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


async def test_join_registers_and_reports_the_board(wired):
    result = await tools.join("https://bbs.test", "scout")

    assert result["origin"] == ORIGIN
    assert result["username"] == "scout"
    assert len(result["public_key"]) == 64
    assert result["registered_seq"] > 0


async def test_join_actually_lands_a_registration_the_server_accepted(wired):
    """The point of join is a real registration, so assert against the
    server's own user projection rather than the returned summary."""
    result = await tools.join("https://bbs.test", "scout")

    user = wired["users"].get_user_by_pubkey(ORIGIN, bytes.fromhex(result["public_key"]))
    assert user is not None
    assert user["username"] == "scout"


async def test_join_mints_a_local_passwordless_identity(wired):
    await tools.join("https://bbs.test", "scout")

    store = tools._get_identity_store()
    assert store.is_wrapped("scout") is False
    assert store.is_registered("scout") is True


async def test_join_makes_the_identity_active_for_later_calls(wired):
    """After join, a tool call that omits auth must resolve to the joined
    identity — that is what makes it a one-call cold start."""
    await tools.join("https://bbs.test", "scout")

    assert tools._resolve_auth(None) == ("scout", "")


async def test_join_points_the_client_at_the_board(wired):
    await tools.join("https://bbs.test", "scout")

    assert tools.bonnet_url == "https://bbs.test"


async def test_rejoining_reuses_the_existing_keypair(wired):
    """A retry under the same name must not orphan the first key, or the
    agent silently loses the identity its earlier posts were signed with."""
    first = await tools.join("https://bbs.test", "scout")
    second = await tools.join("https://bbs.test", "scout")

    assert first["public_key"] == second["public_key"]


async def test_a_failed_join_does_not_redirect_the_client(wired):
    """A half-applied join would silently send every later tool call to an
    origin the agent never successfully joined."""
    await tools.join("https://bbs.test", "scout")
    before = tools.bonnet_url

    with pytest.raises(Exception):
        await tools.join("https://unreachable.invalid:2272", "scout2")

    assert tools.bonnet_url == before
