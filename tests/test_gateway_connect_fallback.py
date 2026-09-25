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

"""Gateway 443 <-> 2272 port fallback.

Bare/` :443` https URLs retry once on `:2272` when nothing answers, and
`:2272` URLs retry once on 443 — same host, connect-level failures only.
The rule lives under every connection a tool call makes, so `connect`,
the first call after `switch_origin`, and a remembered origin on a fresh
start all fail over alike, and a fallback that works is remembered.
"""

from types import SimpleNamespace

import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("fastmcp")

from bonnet.gateway import tenancy, tools
from bonnet.net.firehose_transport import FirehoseClientError
from bonnet.net.http_auth import canonicalize_url


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "gw"))
    monkeypatch.setenv("BONNET_IDENTITIES_DB", str(tmp_path / "identities.db"))
    for var in ("BONNET_IDENTITY", "BONNET_URL", "BONNET_GATING", "BONNET_PIN_PROMPT"):
        monkeypatch.delenv(var, raising=False)
    tenancy.reset_store_cache()
    tenancy.current_tenant.set(tenancy.DEFAULT_TENANT)
    tools.current_origin_url.set(None)
    tools.current_origin_verify.set(None)
    tools.current_origin.set(None)
    tools.current_username.set(None)
    tools.current_password.set(None)
    tools._origin_loaded.set(False)
    tools._manifest_cache_clear()
    yield
    tenancy.reset_store_cache()
    tools.current_origin_url.set(None)
    tools.current_origin_verify.set(None)
    tools.current_origin.set(None)
    tools.current_username.set(None)
    tools._origin_loaded.set(False)
    tools._manifest_cache_clear()


class FakeClient:
    """Stand-in for the client tool calls drive: connects per a shared script.

    `script` has one entry per connection attempt, across every client:
    None succeeds, anything else is raised. Each attempt records the URL
    it dialed, which is what a fallback changes.
    """

    def __init__(self, url, script, attempts):
        self._base_url = url
        self._script = script
        self._attempts = attempts
        self.server_origin = None
        self.discovery = None
        self.closed = False

    @property
    def base_url(self):
        return self._base_url

    async def connect_anonymous(self):
        idx = len(self._attempts)
        self._attempts.append(self._base_url)
        action = self._script[idx] if idx < len(self._script) else None
        if action is not None:
            raise action
        self.server_origin = "test-origin"
        self.discovery = SimpleNamespace(
            known_origins=[],
            signature_lifetime_seconds=300,
            clock_skew_seconds=300,
        )

    async def close(self):
        self.closed = True

    async def refresh_epoch_cache(self, origin):
        return False

    async def list_boards(self, origin=""):
        return []

    def advertised_address(self):
        return None

    def export_discovery(self):
        return {
            "origin": "test-origin",
            "public_key": "ab" * 32,
            "anonymous_key": "cd" * 32,
            "anonymous_private_key": "ef" * 32,
        }


def _install(monkeypatch, script):
    """Route _make_client at fakes that follow `script`.

    Returns the URLs each connection attempt dialed, the created
    FakeClients, and a counter of attempts.
    """
    attempts: list[str] = []
    created = []

    def make_client(url=None, verify=None):
        target = url if url is not None else tools._current_url()
        client = FakeClient(target, script, attempts)
        created.append(client)
        return client

    async def unlock():
        return []

    monkeypatch.setattr(tools, "_make_client", make_client)
    monkeypatch.setattr(tools, "_unlock_origin_tools", unlock)
    return attempts, created, _Count(attempts)


class _Count(dict):
    def __init__(self, attempts):
        super().__init__()
        self._attempts = attempts

    def __getitem__(self, key):
        return len(self._attempts)


async def test_bare_host_falls_back_to_2272(isolated, monkeypatch):
    seen, _, _ = _install(
        monkeypatch,
        [FirehoseClientError("could not reach https://bbs.example: ConnectError"), None],
    )
    result = await tools.connect("https://bbs.example")
    assert result["url"] == canonicalize_url("https://bbs.example:2272")
    assert result["port_fallback"] is True
    assert seen == ["https://bbs.example", "https://bbs.example:2272"]


async def test_explicit_443_falls_back_to_2272(isolated, monkeypatch):
    seen, _, _ = _install(
        monkeypatch,
        [FirehoseClientError("could not reach https://bbs.example: ConnectError"), None],
    )
    result = await tools.connect("https://bbs.example:443")
    assert result["url"] == canonicalize_url("https://bbs.example:2272")
    assert result["port_fallback"] is True
    assert len(seen) == 2
    assert seen[1] == "https://bbs.example:2272"


async def test_explicit_2272_falls_back_to_443(isolated, monkeypatch):
    seen, _, _ = _install(
        monkeypatch,
        [FirehoseClientError("could not reach https://bbs.example:2272: refused"), None],
    )
    result = await tools.connect("https://bbs.example:2272")
    assert result["url"] == canonicalize_url("https://bbs.example")
    assert result["port_fallback"] is True
    assert len(seen) == 2
    assert seen[1] == canonicalize_url("https://bbs.example")


async def test_double_failure_restores_cursor(isolated, monkeypatch):
    seen, _, calls = _install(
        monkeypatch,
        [
            FirehoseClientError("could not reach https://bbs.example: refused"),
            FirehoseClientError("could not reach https://bbs.example:2272: refused"),
        ],
    )
    with pytest.raises(FirehoseClientError, match="could not reach"):
        await tools.connect("https://bbs.example:2272")
    assert calls["n"] == 2
    assert len(seen) == 2
    # Cursor restored: nothing remembered, no active origin.
    assert tools.current_origin_url.get() is None
    assert tools.current_origin.get() is None


async def test_explicit_other_port_does_not_fall_back(isolated, monkeypatch):
    seen, _, calls = _install(
        monkeypatch, [FirehoseClientError("could not reach https://bbs.example:8443: refused")]
    )
    with pytest.raises(FirehoseClientError, match="could not reach"):
        await tools.connect("https://bbs.example:8443")
    assert calls["n"] == 1
    assert len(seen) == 1


async def test_http_error_does_not_fall_back(isolated, monkeypatch):
    seen, _, calls = _install(monkeypatch, [FirehoseClientError("HTTP 500: Internal Server Error")])
    with pytest.raises(FirehoseClientError, match="HTTP 500"):
        await tools.connect("https://bbs.example")
    assert calls["n"] == 1
    assert len(seen) == 1


async def test_ipv6_fallback_target_stays_bracketed(isolated, monkeypatch):
    seen, _, _ = _install(
        monkeypatch, [FirehoseClientError("could not reach https://[2001:db8::1]: refused"), None]
    )
    result = await tools.connect("https://[2001:db8::1]")
    assert result["url"] == canonicalize_url("https://[2001:db8::1]:2272")
    assert result["port_fallback"] is True
    assert seen[1] == canonicalize_url("https://[2001:db8::1]:2272")


async def test_switch_origin_falls_back_and_remembers(isolated, monkeypatch):
    """switch_origin takes the remembered URL as-is; the first call after it
    used to fail flat when that address had gone quiet. Now it fails over
    like connect, and the working address replaces the dead one in the
    store so the next process start doesn't repeat the detour."""
    seen, _, _ = _install(
        monkeypatch,
        [FirehoseClientError("could not reach https://bbs.example: refused"), None],
    )
    store = tools._get_origin_store()
    store.remember("test-origin", "https://bbs.example", True, "")
    await tools.switch_origin("test-origin")

    client = tools._make_client()
    await tools._connect_with_default(client, None)

    assert seen == ["https://bbs.example", "https://bbs.example:2272"]
    assert tools.current_origin_url.get() == "https://bbs.example:2272"
    assert store.get("test-origin")["url"] == "https://bbs.example:2272"


async def test_remembered_origin_on_a_fresh_start_falls_back(isolated, monkeypatch):
    """A fresh process adopts the remembered origin without any network
    call; its first real connection is where the fallback happens."""
    tools._get_origin_store().remember("test-origin", "https://bbs.example:2272", True, "")
    seen, _, _ = _install(
        monkeypatch,
        [FirehoseClientError("could not reach https://bbs.example:2272: refused"), None],
    )
    client = tools._make_client()
    await tools._connect_with_default(client, None)

    assert seen == ["https://bbs.example:2272", "https://bbs.example"]
    assert tools._get_origin_store().get("test-origin")["url"] == "https://bbs.example"


async def test_no_fallback_once_discovery_succeeded(isolated, monkeypatch):
    """A client that got as far as discovery has committed to its address;
    a failure after that is that address's, not a reason to go elsewhere."""
    seen, _, _ = _install(monkeypatch, [None])
    client = tools._make_client("https://bbs.example")
    await client.connect_anonymous()

    async def fails_after_discovery():
        raise FirehoseClientError("could not reach https://bbs.example: reset")

    with pytest.raises(FirehoseClientError, match="reset"):
        await tools._with_port_fallback(client, fails_after_discovery)
    assert client.base_url == "https://bbs.example"


async def test_double_failure_names_both_addresses(isolated, monkeypatch):
    _install(
        monkeypatch,
        [
            FirehoseClientError("could not reach https://bbs.example: refused"),
            FirehoseClientError("could not reach https://bbs.example:2272: refused"),
        ],
    )
    client = tools._make_client("https://bbs.example")
    with pytest.raises(FirehoseClientError, match="also tried https://bbs.example:2272"):
        await tools._connect_with_default(client, None)
    assert client.base_url == "https://bbs.example"
