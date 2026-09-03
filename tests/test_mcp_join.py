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

from bonnet.core.acl import ACLRule, PrincipalMatcher
from bonnet.gateway import tenancy, tools
from bonnet.gateway.firehose_client import FirehoseHTTPClient
from tests.test_firehose_http_server import ORIGIN, server_stack  # noqa: F401


@pytest.fixture
def wired(server_stack, tmp_path, monkeypatch):  # noqa: F811
    """Route tools._make_client at the in-process server, on a temp store."""
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("BONNET_IDENTITIES_DB", str(tmp_path / "identities.db"))
    monkeypatch.delenv("BONNET_IDENTITY", raising=False)
    monkeypatch.delenv("BONNET_URL", raising=False)

    tenancy.reset_store_cache()
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

    tenancy.reset_store_cache()
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


@pytest.mark.parametrize("bad_url", ["", "   ", "\t\n"])
async def test_connect_rejects_blank_url(wired, bad_url):
    """An empty url used to be stored as-is and then treated as "unset" by
    _current_url()'s `or` fallback chain, silently connecting to the default
    origin instead of the one the caller (thought they) asked for. A
    whitespace-only url took a different, uglier path with the same root
    cause. Both must fail loudly instead of picking either default."""
    with pytest.raises(ValueError, match="requires a URL"):
        await tools.connect(bad_url)
    assert tools.current_origin_url.get() is None


async def test_register_registers_and_reports_the_board(wired):
    await tools.connect("https://bbs.test")
    result = await tools.register("scout")

    assert result["origin"] == ORIGIN
    assert result["username"] == "scout"
    assert len(result["public_key"]) == 64
    assert result["registered_seq"] > 0
    assert result["already_registered"] is False
    assert "message" not in result


async def test_duplicate_register_reports_already_registered_explicitly(wired):
    """Re-registering a (origin, username) this key already registered with
    is a safe no-op, not a failure - but `registered_seq: null` alone reads
    ambiguously, so the response also spells it out with a flag and a
    message rather than leaving the caller to infer success-but-no-op from a
    null sequence number."""
    await tools.connect("https://bbs.test")
    await tools.register("scout")

    result = await tools.register("scout")

    assert result["registered_seq"] is None
    assert result["already_registered"] is True
    assert "scout" in result["message"]
    assert "already registered" in result["message"]


async def test_register_collision_with_another_key_explains_the_fix(wired, tmp_path, monkeypatch):
    """Regression for the chaos-testing report's #2.5: when `username` is
    already held by a *different* key than this client's, the refusal used
    to reach the caller bare, with nothing saying the fix is picking another
    name. A second local identity store stands in for a different client
    holding the name first."""
    await tools.connect("https://bbs.test")
    await tools.register("scout")

    monkeypatch.setenv("BONNET_IDENTITIES_DB", str(tmp_path / "other-identities.db"))
    tenancy.reset_store_cache()

    with pytest.raises(ValueError, match="Pick a different username") as exc:
        await tools.register("scout")
    assert "scout" in str(exc.value)


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
    names = {i.username for i in await tools.list_identities()}
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
    assert any(o.origin == ORIGIN for o in origins)

    await tools.connect("https://bbs.test")
    identities = await tools.list_identities()
    assert any(i.username == "scout" for i in identities)
