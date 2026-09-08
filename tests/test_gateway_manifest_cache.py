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

"""Session-scoped UNTP manifest cache.

`connect()` fetches `/.well-known/untp` once per MCP session; later tool
calls hydrate their transport from the cached manifest instead of
re-fetching. A stale entry fails closed in `_verify_response` (the gateway
client refreshes once) — these tests cover the cache mechanics: export /
apply round-trip, hydration skipping discovery, URL-keyed hits and misses,
and the session snapshot carrying the entry across requests.
"""

import httpx
import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("cryptography")
pytest.importorskip("fastmcp")

from bonnet.gateway import session as session_module
from bonnet.gateway import tenancy, tools
from bonnet.gateway.firehose_client import FirehoseHTTPClient
from bonnet.net.firehose_transport import FirehoseClientError, FirehoseTransport
from tests.test_firehose_http_server import server_stack  # noqa: F401


@pytest.fixture
def gateway_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("BONNET_IDENTITIES_DB", raising=False)
    monkeypatch.delenv("BONNET_IDENTITY", raising=False)
    monkeypatch.delenv("BONNET_URL", raising=False)
    monkeypatch.delenv("BONNET_VERIFY_TLS", raising=False)

    tenancy.reset_store_cache()
    tools.current_origin_url.set(None)
    tools.current_origin_verify.set(None)
    tools.current_origin.set(None)
    tools._origin_loaded.set(False)
    tools.current_username.set(None)
    tools._manifest_cache_clear()

    yield tmp_path / "state" / "tenants" / tenancy.DEFAULT_TENANT

    tenancy.reset_store_cache()
    tools.current_origin_url.set(None)
    tools.current_origin_verify.set(None)
    tools.current_origin.set(None)
    tools._origin_loaded.set(False)
    tools.current_username.set(None)
    tools._manifest_cache_clear()


def _client(app, base_url: str, trust_path: str) -> FirehoseHTTPClient:
    client = FirehoseHTTPClient(base_url, verify=False, trust_store_path=trust_path)
    client._http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url=base_url,
        timeout=30.0,
        verify=False,
    )
    return client


async def test_export_is_empty_before_discovery(gateway_dir):
    from bonnet.gateway.paths import trust_db_path

    client = FirehoseTransport("https://bbs.test", trust_store_path=trust_db_path())
    try:
        assert client.export_discovery() == {}
    finally:
        await client.close()


async def test_apply_rejects_malformed_entries(gateway_dir):
    from bonnet.gateway.paths import trust_db_path

    client = FirehoseTransport("https://bbs.test", trust_store_path=trust_db_path())
    try:
        with pytest.raises(FirehoseClientError):
            client.apply_cached_discovery({})
        with pytest.raises(FirehoseClientError):
            client.apply_cached_discovery({"origin": "bbs.test"})  # no keys
        with pytest.raises(FirehoseClientError):
            client.apply_cached_discovery(
                {
                    "origin": "bbs.test",
                    "public_key": "zz",
                    "anonymous_key": "zz",
                    "anonymous_private_key": "zz",
                }
            )
    finally:
        await client.close()


async def test_hydrated_client_skips_discovery(server_stack, gateway_dir):  # noqa: F811
    """export -> apply round-trips; the hydrated client never fetches."""
    from bonnet.gateway.paths import trust_db_path

    path = trust_db_path()
    first = _client(server_stack["server"], "https://bbs.test", path)
    try:
        await first.connect_anonymous()
        payload = first.export_discovery()
    finally:
        await first.close()
    assert payload["origin"] and payload["public_key"]

    second = _client(server_stack["server"], "https://bbs.test", path)
    try:
        second.apply_cached_discovery(payload)

        async def _no_discovery() -> None:
            raise AssertionError("discover must not be called on a hydrated client")

        second.discover = _no_discovery  # type: ignore[method-assign]
        await second.connect_anonymous()
        boards = await second.list_boards("")
        assert isinstance(boards, list)
    finally:
        await second.close()


async def test_cache_is_keyed_by_canonical_url(gateway_dir):
    payload = {"origin": "h", "public_key": "ab" * 32}
    tools._manifest_cache_store("https://h:443", payload)
    # Default-port and case variants are the same socket either way.
    assert tools._manifest_cache_get("https://H.") == payload
    assert tools._manifest_cache_get("https://other.test") is None
    tools._manifest_cache_clear()
    assert tools._manifest_cache_get("https://h:443") is None


async def test_make_client_hydrates_from_cache(gateway_dir):
    """_make_client picks up the session entry; a cleared cache misses."""
    tools.current_origin_url.set("https://bbs.test")
    tools.current_origin_verify.set(False)
    tools._origin_loaded.set(True)
    payload = {
        "origin": "bbs.test",
        "hostname": "bbs.test",
        "protocol": "untp-1",
        "public_key": "ab" * 32,
        "anonymous_key": "cd" * 32,
        "anonymous_private_key": "ef" * 32,
        "command_endpoint": "/command",
        "capabilities": [],
        "known_origins": ["bbs.test"],
        "signature_lifetime_seconds": 300,
        "clock_skew_seconds": 300,
        "peer_max_lifetime": 300,
    }
    tools._manifest_cache_store("https://bbs.test", payload)

    hydrated = tools._make_client()
    try:
        assert hydrated.discovery is not None
        assert hydrated.discovery.origin == "bbs.test"
        assert hydrated.server_origin == "bbs.test"
    finally:
        await hydrated.close()

    # connect() stashes and clears up front so establishment always
    # re-fetches; after a clear, clients come up undiscovered again.
    tools._manifest_cache_clear()
    assert tools._manifest_cache_get("https://bbs.test") is None
    unhydrated = tools._make_client()
    try:
        assert unhydrated.discovery is None
    finally:
        await unhydrated.close()


async def test_session_snapshot_carries_the_manifest(gateway_dir):
    tools.current_origin_url.set("https://bbs.test")
    tools._origin_loaded.set(True)
    payload = {"origin": "bbs.test", "public_key": "ab" * 32}
    tools._manifest_cache_store("https://bbs.test", payload)

    snap = session_module.snapshot()
    assert snap["manifest_url"] == "https://bbs.test"
    assert snap["manifest"] == payload

    tools._manifest_cache_clear()
    assert tools._manifest_cache_get("https://bbs.test") is None
    session_module.restore(snap)
    assert tools._manifest_cache_get("https://bbs.test") == payload


async def test_session_restore_ignores_corrupt_manifest(gateway_dir):
    session_module.restore({"manifest_url": "https://bbs.test", "manifest": {"nope": 1}})
    assert tools._manifest_cache_get("https://bbs.test") is None
    session_module.restore(None)
    session_module.restore({})
    assert tools._manifest_cache_get("https://bbs.test") is None
