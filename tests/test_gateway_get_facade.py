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

"""Always-tiny visibility addendum on `GET /call/<tool>`.

Drives `get_facade.call_tool_get` directly with Starlette Requests and
fake tools: the fakes simulate gating transitions (the before/after name
sets), so these tests cover the facade's diff + envelope logic rather
than the real gating middleware.
"""

import json
from urllib.parse import urlencode

import pytest

pytest.importorskip("fastmcp")

from starlette.requests import Request

from bonnet.gateway import get_facade, tenancy, tenants


class _FakeTool:
    def __init__(self, name, properties=None, required=None):
        self.name = name
        self.parameters = {
            "type": "object",
            "properties": properties or {},
            "required": required or [],
        }


@pytest.fixture
def facade_env(tmp_path, monkeypatch):
    """Isolated gateway home, facade enabled, fakes installed."""
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "gw"))
    for var in ("BONNET_IDENTITIES_DB", "BONNET_IDENTITY", "BONNET_URL", "BONNET_GATING"):
        monkeypatch.delenv(var, raising=False)
    tenancy.reset_store_cache()
    tenancy.reset_registry_cache()
    get_facade._snapshots.clear()
    get_facade.set_enabled(True)

    state = {"extra": False, "fail": False}
    calls = []

    async def fake_list_tools():
        names = ["connect", "where_am_i"]
        if state["extra"]:
            names.append("publish_article")
        return [_FakeTool(n) for n in names]

    async def fake_get_tool(name):
        schemas = {
            "connect": ({"url": {"type": "string"}}, ["url"]),
            "register": ({"username": {"type": "string"}}, ["username"]),
            "where_am_i": ({}, []),
            "with_int": ({"limit": {"type": "integer", "default": 50}}, []),
        }
        if name not in schemas:
            return None
        props, required = schemas[name]
        return _FakeTool(name, props, required)

    async def fake_call_tool(name, args):
        calls.append((name, args))
        if state["fail"]:
            raise ValueError("boom")
        if name == "register":
            state["extra"] = True
        return {"echo": args}

    monkeypatch.setattr(get_facade.mcp, "list_tools", fake_list_tools)
    monkeypatch.setattr(get_facade.mcp, "get_tool", fake_get_tool)
    monkeypatch.setattr(get_facade.mcp, "call_tool", fake_call_tool)

    yield state, calls

    get_facade.set_enabled(None)
    get_facade._snapshots.clear()
    tenancy.reset_store_cache()
    tenancy.reset_registry_cache()


def _request(tool_name, query):
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": f"/call/{tool_name}",
        "query_string": urlencode(query).encode(),
        "headers": [],
        "server": ("test", 80),
        "path_params": {"tool_name": tool_name},
    }
    return Request(scope)


def _body(resp):
    return json.loads(resp.body)


async def test_steady_state_addendum_is_present_and_unchanged(facade_env):
    _, _ = facade_env
    resp = await get_facade.call_tool_get(_request("where_am_i", {}))
    body = _body(resp)
    assert body["ok"] is True
    assert body["session"] == "default"
    assert body["tools_changed"] is False
    assert body["visible_tools"] == ["connect", "where_am_i"]


async def test_transition_flips_tools_changed(facade_env):
    _, _ = facade_env
    resp = await get_facade.call_tool_get(
        _request("register", {"username": "scout", "session": "s1"})
    )
    body = _body(resp)
    assert body["ok"] is True
    assert body["session"] == "s1"
    assert body["tools_changed"] is True
    assert body["visible_tools"] == ["connect", "publish_article", "where_am_i"]

    # Next call in the same session label: steady again.
    resp2 = await get_facade.call_tool_get(_request("where_am_i", {"session": "s1"}))
    body2 = _body(resp2)
    assert body2["tools_changed"] is False
    assert body2["visible_tools"] == body["visible_tools"]


async def test_tool_error_still_carries_addendum(facade_env):
    state, _ = facade_env
    state["fail"] = True
    resp = await get_facade.call_tool_get(_request("where_am_i", {}))
    body = _body(resp)
    assert body["ok"] is False
    assert body["error"] == "boom"
    assert body["session"] == "default"
    assert body["tools_changed"] is False
    assert body["visible_tools"] == ["connect", "where_am_i"]


async def test_coercion_failure_has_no_addendum(facade_env):
    _, _ = facade_env
    resp = await get_facade.call_tool_get(_request("with_int", {"limit": "fifty"}))
    body = _body(resp)
    assert body["ok"] is False
    assert "session" not in body
    assert "tools_changed" not in body
    assert "visible_tools" not in body


async def test_unknown_tool_has_no_addendum(facade_env):
    _, _ = facade_env
    resp = await get_facade.call_tool_get(_request("nope", {}))
    assert resp.status_code == 404
    body = _body(resp)
    assert body["ok"] is False
    assert "session" not in body


async def test_disabled_facade_has_no_addendum(facade_env):
    _, _ = facade_env
    get_facade.set_enabled(False)
    try:
        resp = await get_facade.call_tool_get(_request("where_am_i", {}))
    finally:
        get_facade.set_enabled(True)
    assert resp.status_code == 404
    body = _body(resp)
    assert body["ok"] is False
    assert "session" not in body


async def test_authenticated_session_label_echo_and_snapshot(facade_env):
    _, _ = facade_env
    key = tenants.add_tenant("alice")
    resp = await get_facade.call_tool_get(_request("where_am_i", {"key": key, "session": "bob"}))
    body = _body(resp)
    assert body["ok"] is True
    assert body["session"] == "bob"
    assert body["tools_changed"] is False
    assert ("alice", "bob") in get_facade._snapshots
