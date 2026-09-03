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

"""Tenant authentication, and the anonymous session a bad key degrades to.

The rule these pin down: **bad auth never returns a non-200.** A failed
credential produces a working but reduced session, and the reduction is
reported through the tool list rather than an error — because a non-200 on the
MCP transport strands harnesses in ways neither the agent nor its operator can
diagnose, while a warning on every tool description is re-sent every turn.
"""

import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("cryptography")
pytest.importorskip("fastmcp")

from fastmcp import Client

from bonnet.gateway import gating, server, tenancy, tenants, tools
from bonnet.gateway.gating import GatingMiddleware


class FakeRequest:
    def __init__(self, headers: dict):
        self.headers = headers


@pytest.fixture
def gw(tmp_path, monkeypatch):
    """An http-mode gateway with one enabled tenant, "alice"."""
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "gw"))
    for var in ("BONNET_IDENTITIES_DB", "BONNET_IDENTITY", "BONNET_URL", "BONNET_GATING"):
        monkeypatch.delenv(var, raising=False)
    tenancy.reset_store_cache()
    tenancy.reset_registry_cache()

    key = tenants.add_tenant("alice", note="test")

    if not any(isinstance(m, GatingMiddleware) for m in tools.mcp.middleware):
        tools.mcp.add_middleware(GatingMiddleware())

    yield {"key": key}

    tenancy.current_tenant.set(tenancy.DEFAULT_TENANT)
    tenancy.current_auth_status.set(tenancy.AUTH_OK)
    tools.current_username.set(None)
    tenancy.reset_store_cache()
    tenancy.reset_registry_cache()


def _resolve(monkeypatch, headers: dict | None):
    """Run AuthMiddleware's resolution for `headers` (None = stdio)."""
    if headers is None:

        def boom():
            raise RuntimeError("no http request")

        monkeypatch.setattr(server, "get_http_request", boom)
    else:
        monkeypatch.setattr(server, "get_http_request", lambda: FakeRequest(headers))
    server.AuthMiddleware()._set_auth_context(None)
    return tenancy.current_tenant.get(), tenancy.current_auth_status.get()


# --- which header, and what it resolves to ---------------------------------


def test_bearer_and_x_api_key_are_equivalent(gw, monkeypatch):
    """Harnesses differ in which header they can set; the same key must work
    through either."""
    key = gw["key"]
    assert _resolve(monkeypatch, {"Authorization": f"Bearer {key}"}) == ("alice", tenancy.AUTH_OK)
    assert _resolve(monkeypatch, {"X-API-Key": key}) == ("alice", tenancy.AUTH_OK)


def test_garbage_bearer_falls_back_to_a_valid_x_api_key(gw, monkeypatch):
    """A harness that defensively sets both headers must not have a stale or
    garbage Bearer token silently shadow a working X-API-Key - only the tenant
    store knows which candidate (if either) actually resolves, so both must
    be tried rather than picking Bearer unconditionally."""
    key = gw["key"]
    assert _resolve(monkeypatch, {"Authorization": "Bearer garbage", "X-API-Key": key}) == (
        "alice",
        tenancy.AUTH_OK,
    )


def test_no_header_is_anonymous_absent(gw, monkeypatch):
    assert _resolve(monkeypatch, {}) == (tenancy.ANONYMOUS_TENANT, tenancy.AUTH_ABSENT)


def test_an_unknown_key_is_anonymous_rejected(gw, monkeypatch):
    """Distinct from absent: something was presented and did not work, which
    is a configuration problem worth telling the operator about."""
    assert _resolve(monkeypatch, {"X-API-Key": "bnt_00000000_nope"}) == (
        tenancy.ANONYMOUS_TENANT,
        tenancy.AUTH_REJECTED,
    )


def test_a_revoked_key_stops_resolving_but_its_siblings_do_not(gw, monkeypatch):
    """One key per consumer is the point: revoking a leaked one must not take
    the tenant's other consumers down with it."""
    first = gw["key"]
    second = tenants.add_key("alice", label="second")
    tenancy.reset_registry_cache()

    key_id = [k for k in tenants.list_keys("alice") if k["label"] == "initial"][0]["key_id"]
    tenants.revoke_key(key_id)
    tenancy.reset_registry_cache()

    assert _resolve(monkeypatch, {"X-API-Key": first})[0] == tenancy.ANONYMOUS_TENANT
    assert _resolve(monkeypatch, {"X-API-Key": second})[0] == "alice"


def test_a_disabled_tenants_key_degrades(gw, monkeypatch):
    tenants.set_enabled("alice", False)
    tenancy.reset_registry_cache()

    assert _resolve(monkeypatch, {"X-API-Key": gw["key"]}) == (
        tenancy.ANONYMOUS_TENANT,
        tenancy.AUTH_REJECTED,
    )


def test_stdio_has_no_header_and_stays_the_default_tenant(gw, monkeypatch):
    """Auth is an http-mode concept: a process the agent host launched over
    its own pipes has nothing to authenticate."""
    tenancy.current_tenant.set(tenancy.DEFAULT_TENANT)
    tenancy.current_auth_status.set(tenancy.AUTH_OK)

    assert _resolve(monkeypatch, None) == (tenancy.DEFAULT_TENANT, tenancy.AUTH_OK)


def test_http_never_falls_back_to_the_default_tenant(gw, monkeypatch):
    """`default` is stdio's full-capability tenant. An http request that
    failed to authenticate must land on `anonymous`, never on it."""
    for headers in ({}, {"X-API-Key": "garbage"}, {"Authorization": "Bearer garbage"}):
        tenant, _ = _resolve(monkeypatch, headers)
        assert tenant == tenancy.ANONYMOUS_TENANT


def test_an_anonymous_session_does_not_inherit_a_username(gw, monkeypatch):
    """contextvars are reused across requests in a served process; a session
    that signs as nobody must not pick up whoever ran before it."""
    tools.current_username.set("scout")

    _resolve(monkeypatch, {})

    assert tools.current_username.get() is None


# --- what the anonymous tenant sees ----------------------------------------


async def _visible() -> set[str]:
    async with Client(tools.mcp) as c:
        return {t.name for t in await c.list_tools()}


async def _descriptions() -> dict[str, str]:
    async with Client(tools.mcp) as c:
        return {t.name: (t.description or "") for t in await c.list_tools()}


def _as_anonymous(status: str = tenancy.AUTH_ABSENT):
    tenancy.current_tenant.set(tenancy.ANONYMOUS_TENANT)
    tenancy.current_auth_status.set(status)


async def test_register_and_login_are_hidden_not_offered(gw):
    """They mint or unlock an identity, and this tenant can never hold one.
    Showing them would advertise a dead end — the exact failure the gating
    design exists to avoid."""
    _as_anonymous()

    visible = await _visible()

    assert "register" not in visible
    assert "login" not in visible


async def test_the_way_out_is_never_hidden(gw):
    """Whatever else is withheld, a caller keeps the tools that let it move."""
    _as_anonymous()

    visible = await _visible()

    assert {"connect", "disconnect", "switch_origin", "where_am_i"} <= visible


async def test_calling_a_forbidden_tool_explains_rather_than_crashes(gw):
    _as_anonymous()

    async with Client(tools.mcp) as c:
        with pytest.raises(Exception) as exc:
            await c.call_tool("register", {"username": "scout"})

    assert "anonymous" in str(exc.value).lower()


async def test_the_restriction_survives_gating_being_off(gw, monkeypatch):
    """BONNET_GATING=off is a debugging aid for visibility. It must not hand a
    caller who presented no valid credential the ability to mint identities."""
    monkeypatch.setenv("BONNET_GATING", "off")
    _as_anonymous()

    async with Client(tools.mcp) as c:
        with pytest.raises(Exception):
            await c.call_tool("register", {"username": "scout"})


# --- the warning ------------------------------------------------------------


async def test_absent_and_rejected_read_differently(gw):
    """The two causes want different advice: one may be expected, the other
    means something is misconfigured and the agent should escalate."""
    _as_anonymous(tenancy.AUTH_ABSENT)
    absent = (await _descriptions())["connect"]

    _as_anonymous(tenancy.AUTH_REJECTED)
    rejected = (await _descriptions())["connect"]

    assert absent != rejected
    assert "no api key was presented" in absent.lower()
    assert "alert your operator" in rejected.lower()


async def test_every_tool_carries_the_warning(gw):
    """The tool list is re-sent whole every turn, so it is where a persistent
    condition belongs — an agent that compacted away the first response still
    sees this."""
    _as_anonymous()

    descriptions = await _descriptions()

    assert descriptions
    assert all(d.startswith("[!]") for d in descriptions.values())


async def test_an_authenticated_session_carries_no_warning(gw):
    tenancy.current_tenant.set("alice")
    tenancy.current_auth_status.set(tenancy.AUTH_OK)

    descriptions = await _descriptions()

    assert not any(d.startswith("[!]") for d in descriptions.values())


async def test_the_warning_does_not_leak_into_another_tenants_list(gw):
    """The banner is applied to a copy. Mutating the registry's own Tool
    objects would put it in front of every other tenant too."""
    _as_anonymous()
    await _descriptions()

    tenancy.current_tenant.set("alice")
    tenancy.current_auth_status.set(tenancy.AUTH_OK)

    assert not any(d.startswith("[!]") for d in (await _descriptions()).values())


async def test_the_warning_survives_gating_being_off(gw, monkeypatch):
    """Suppressing the filtering must not suppress the report that this
    session is degraded."""
    monkeypatch.setenv("BONNET_GATING", "off")
    _as_anonymous()

    descriptions = await _descriptions()

    assert all(d.startswith("[!]") for d in descriptions.values())
    # gating off pins everything visible, warning included
    assert "register" in descriptions


def test_presented_key_prefers_bearer_but_accepts_either():
    assert server.presented_key({"Authorization": "Bearer abc"}) == "abc"
    assert server.presented_key({"X-API-Key": "xyz"}) == "xyz"
    assert server.presented_key({"Authorization": "Bearer ", "X-API-Key": "xyz"}) == "xyz"
    assert server.presented_key({}) == ""


def test_presented_key_scheme_is_case_insensitive():
    """RFC 7235 makes the auth scheme token case-insensitive - lowercase
    'bearer' used to silently miss the exact-case check and fall through to
    X-API-Key (empty), degrading to anonymous with no signal that a
    credential was even presented."""
    assert server.presented_key({"Authorization": "bearer abc"}) == "abc"
    assert server.presented_key({"Authorization": "BEARER abc"}) == "abc"
    assert server.presented_key({"Authorization": "BeArEr abc"}) == "abc"


def test_presented_key_candidates_orders_bearer_before_x_api_key():
    assert server.presented_key_candidates({"Authorization": "Bearer abc", "X-API-Key": "xyz"}) == [
        "abc",
        "xyz",
    ]
    assert server.presented_key_candidates({"X-API-Key": "xyz"}) == ["xyz"]
    assert server.presented_key_candidates({"Authorization": "Bearer abc"}) == ["abc"]
    assert server.presented_key_candidates({"Authorization": "Bearer ", "X-API-Key": "xyz"}) == [
        "xyz"
    ]
    assert server.presented_key_candidates({}) == []


def test_gating_module_exposes_the_forbidden_set():
    """Named rather than inlined, so the restriction is greppable from the
    tools it applies to."""
    assert gating.ANONYMOUS_FORBIDDEN == {"register", "login"}
