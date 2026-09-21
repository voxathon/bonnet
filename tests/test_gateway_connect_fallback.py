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

"""Gateway connect() 443 <-> 2272 port fallback.

Bare/` :443` https URLs retry once on `:2272` when nothing answers, and
`:2272` URLs retry once on 443 — same host, connect-level failures only.
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
    """Minimal stand-in for the post-discovery client connect() drives."""

    def __init__(self, url):
        self._url = url
        self.server_origin = "test-origin"
        self.discovery = SimpleNamespace(
            known_origins=[],
            signature_lifetime_seconds=300,
            clock_skew_seconds=300,
        )
        self.closed = False

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
    """Route _make_client at fakes; _connect_anonymous follows `script`.

    `script` is a list with one entry per connect attempt: None means
    success, otherwise the exception to raise. Returns the list of
    observed client URLs (via tools._current_url at build time) and
    the created FakeClients.
    """
    seen_urls = []
    created = []
    calls = {"n": 0}

    def make_client(url=None, verify=None):
        target = url if url is not None else tools._current_url()
        seen_urls.append(target)
        client = FakeClient(target)
        created.append(client)
        return client

    async def connect_anonymous(client):
        idx = calls["n"]
        calls["n"] += 1
        action = script[idx] if idx < len(script) else None
        if action is not None:
            raise action

    async def unlock():
        return []

    monkeypatch.setattr(tools, "_make_client", make_client)
    monkeypatch.setattr(tools, "_connect_anonymous", connect_anonymous)
    monkeypatch.setattr(tools, "_unlock_origin_tools", unlock)
    return seen_urls, created, calls


async def test_bare_host_falls_back_to_2272(isolated, monkeypatch):
    seen, _, _ = _install(
        monkeypatch, [FirehoseClientError("could not reach https://bbs.example: ConnectError"), None]
    )
    result = await tools.connect("https://bbs.example")
    assert result["url"] == canonicalize_url("https://bbs.example:2272")
    assert result["port_fallback"] is True
    assert seen == ["https://bbs.example", "https://bbs.example:2272"]


async def test_explicit_443_falls_back_to_2272(isolated, monkeypatch):
    seen, _, _ = _install(
        monkeypatch, [FirehoseClientError("could not reach https://bbs.example: ConnectError"), None]
    )
    result = await tools.connect("https://bbs.example:443")
    assert result["url"] == canonicalize_url("https://bbs.example:2272")
    assert result["port_fallback"] is True
    assert len(seen) == 2
    assert seen[1] == "https://bbs.example:2272"


async def test_explicit_2272_falls_back_to_443(isolated, monkeypatch):
    seen, _, _ = _install(
        monkeypatch, [FirehoseClientError("could not reach https://bbs.example:2272: refused"), None]
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
    seen, _, calls = _install(
        monkeypatch, [FirehoseClientError("HTTP 500: Internal Server Error")]
    )
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
