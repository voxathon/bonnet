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

"""Burst dedup for write tools through `GET /call/<tool>`."""

import asyncio
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
def dedup_env(tmp_path, monkeypatch):
    """Isolated gateway home, facade enabled, write+read fakes installed."""
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "gw"))
    for var in ("BONNET_IDENTITIES_DB", "BONNET_IDENTITY", "BONNET_URL", "BONNET_GATING"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.delenv("MCP_DEDUP_WINDOW_SECONDS", raising=False)
    tenancy.reset_store_cache()
    tenancy.reset_registry_cache()
    get_facade._snapshots.clear()
    get_facade.reset_dedup_state()
    get_facade.set_enabled(True)

    state = {"fail": False, "delay": 0.0}
    calls: list = []

    async def fake_list_tools():
        return [_FakeTool(n) for n in ("publish_article", "where_am_i", "register")]

    async def fake_get_tool(name):
        schemas = {
            "publish_article": (
                {"subject": {"type": "string"}, "body": {"type": "string"}},
                ["subject", "body"],
            ),
            "register": ({"username": {"type": "string"}}, ["username"]),
            "where_am_i": ({}, []),
        }
        if name not in schemas:
            return None
        props, required = schemas[name]
        return _FakeTool(name, props, required)

    async def fake_call_tool(name, args):
        calls.append((name, dict(args)))
        if state["fail"]:
            raise ValueError("boom")
        if state["delay"]:
            await asyncio.sleep(state["delay"])
        return {"seq": len(calls), "echo": dict(args)}

    monkeypatch.setattr(get_facade.mcp, "list_tools", fake_list_tools)
    monkeypatch.setattr(get_facade.mcp, "get_tool", fake_get_tool)
    monkeypatch.setattr(get_facade.mcp, "call_tool", fake_call_tool)

    key = tenants.add_tenant("alice")

    yield key, state, calls

    get_facade.set_enabled(None)
    get_facade._snapshots.clear()
    get_facade.reset_dedup_state()
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


def _request_raw(tool_name, query_string: str):
    """Build a request from a raw query string (controls param order)."""
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": f"/call/{tool_name}",
        "query_string": query_string.encode(),
        "headers": [],
        "server": ("test", 80),
        "path_params": {"tool_name": tool_name},
    }
    return Request(scope)


def _body(resp):
    return json.loads(resp.body)


async def test_identical_write_url_replays(dedup_env):
    key, _, calls = dedup_env
    q = {"subject": "hello", "body": "world", "key": key}
    first = _body(await get_facade.call_tool_get(_request("publish_article", q)))
    second = _body(await get_facade.call_tool_get(_request("publish_article", q)))
    assert first["ok"] is True and second["ok"] is True
    assert first["result"] == second["result"]
    assert len(calls) == 1


async def test_param_order_does_not_split_key(dedup_env):
    key, _, calls = dedup_env
    first = _body(
        await get_facade.call_tool_get(
            _request_raw("publish_article", f"subject=hello&body=world&key={key}")
        )
    )
    second = _body(
        await get_facade.call_tool_get(
            _request_raw("publish_article", f"body=world&subject=hello&key={key}")
        )
    )
    assert first["result"] == second["result"]
    assert len(calls) == 1


async def test_session_label_splits_key(dedup_env):
    # Same args but different cursor scope (board="" resolves per session),
    # so different session labels must not coalesce.
    key, _, calls = dedup_env
    base = {"subject": "hello", "body": "world", "key": key}
    await get_facade.call_tool_get(_request("publish_article", {**base, "session": "s1"}))
    await get_facade.call_tool_get(_request("publish_article", {**base, "session": "s2"}))
    assert len(calls) == 2


async def test_different_args_execute_twice(dedup_env):
    key, _, calls = dedup_env
    await get_facade.call_tool_get(
        _request("publish_article", {"subject": "one", "body": "world", "key": key})
    )
    await get_facade.call_tool_get(
        _request("publish_article", {"subject": "two", "body": "world", "key": key})
    )
    assert len(calls) == 2


async def test_failure_is_not_cached(dedup_env):
    key, state, calls = dedup_env
    state["fail"] = True
    q = {"subject": "hello", "body": "world", "key": key}
    first = _body(await get_facade.call_tool_get(_request("publish_article", q)))
    assert first["ok"] is False
    state["fail"] = False
    second = _body(await get_facade.call_tool_get(_request("publish_article", q)))
    assert second["ok"] is True
    assert len(calls) == 2


async def test_reads_are_never_deduped(dedup_env):
    key, _, calls = dedup_env
    q = {"key": key}
    await get_facade.call_tool_get(_request("where_am_i", q))
    await get_facade.call_tool_get(_request("where_am_i", q))
    assert len(calls) == 2


async def test_concurrent_burst_singleflights(dedup_env):
    key, state, calls = dedup_env
    state["delay"] = 0.05
    q = {"subject": "hello", "body": "world", "key": key}
    results = await asyncio.gather(
        *(get_facade.call_tool_get(_request("publish_article", q)) for _ in range(5))
    )
    bodies = [_body(r) for r in results]
    assert all(b["ok"] is True for b in bodies)
    assert len(calls) == 1
    assert all(b["result"] == bodies[0]["result"] for b in bodies)


async def test_expiry_re_executes(dedup_env, monkeypatch):
    key, _, calls = dedup_env
    monkeypatch.setenv("MCP_DEDUP_WINDOW_SECONDS", "0.05")
    q = {"subject": "hello", "body": "world", "key": key}
    await get_facade.call_tool_get(_request("publish_article", q))
    await asyncio.sleep(0.08)
    await get_facade.call_tool_get(_request("publish_article", q))
    assert len(calls) == 2


async def test_window_zero_disables(dedup_env, monkeypatch):
    key, _, calls = dedup_env
    monkeypatch.setenv("MCP_DEDUP_WINDOW_SECONDS", "0")
    q = {"subject": "hello", "body": "world", "key": key}
    await get_facade.call_tool_get(_request("publish_article", q))
    await get_facade.call_tool_get(_request("publish_article", q))
    assert len(calls) == 2


async def test_anonymous_writes_bypass_dedup(dedup_env):
    _, _, calls = dedup_env
    q = {"username": "scout"}
    await get_facade.call_tool_get(_request("register", q))
    await get_facade.call_tool_get(_request("register", q))
    assert len(calls) == 2


async def test_replay_carries_fresh_addendum(dedup_env):
    key, _, calls = dedup_env
    q = {"subject": "hello", "body": "world", "key": key}
    first = _body(await get_facade.call_tool_get(_request("publish_article", q)))
    second = _body(await get_facade.call_tool_get(_request("publish_article", q)))
    assert len(calls) == 1
    for field in ("session", "tools_changed", "visible_tools"):
        assert field in second
    assert second["session"] == "default"
    assert second["visible_tools"] == first["visible_tools"]
