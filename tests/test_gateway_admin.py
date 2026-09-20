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

"""HTTP tenant administration (`gateway.admin`).

Drives the route handlers directly with Starlette Requests against an
isolated gateway home: auth gating (disabled→404, wrong→403), the full
matrix, and the destructive guards (delete needs {"confirm": id},
last-live-key revoke→409 unless {"force": true}).
"""

import json

import pytest

pytest.importorskip("fastmcp")

from starlette.requests import Request

from bonnet.gateway import admin, tenancy


@pytest.fixture
def admin_env(tmp_path, monkeypatch):
    """Isolated gateway home, no admin secret unless a test sets one."""
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "gw"))
    monkeypatch.delenv(admin.ADMIN_TOKEN_ENV, raising=False)
    for var in ("BONNET_IDENTITIES_DB", "BONNET_IDENTITY", "BONNET_URL", "BONNET_GATING"):
        monkeypatch.delenv(var, raising=False)
    tenancy.reset_store_cache()
    tenancy.reset_registry_cache()
    yield
    tenancy.reset_store_cache()
    tenancy.reset_registry_cache()


def _request(method="GET", path="/", path_params=None, token=None, query=b"", body=None):
    raw = json.dumps(body).encode() if body is not None else b""
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": raw, "more_body": False}

    headers = []
    if token is not None:
        headers.append((b"authorization", f"Bearer {token}".encode("latin-1")))
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "query_string": query,
            "headers": headers,
            "server": ("test", 80),
            "path_params": path_params or {},
        },
        receive,
    )


def _body(resp):
    return json.loads(resp.body)


async def test_disabled_without_secret_is_404(admin_env):
    resp = await admin.admin_tenant_list(_request())
    assert resp.status_code == 404


async def test_disabled_without_secret_even_with_bearer(admin_env):
    resp = await admin.admin_tenant_list(_request(token="anything"))
    assert resp.status_code == 404


async def test_wrong_secret_is_403(admin_env, monkeypatch):
    monkeypatch.setenv(admin.ADMIN_TOKEN_ENV, "correct")
    resp = await admin.admin_tenant_list(_request(token="wrong"))
    assert resp.status_code == 403


async def test_missing_bearer_is_403(admin_env, monkeypatch):
    monkeypatch.setenv(admin.ADMIN_TOKEN_ENV, "correct")
    resp = await admin.admin_tenant_list(_request())
    assert resp.status_code == 403


async def test_file_token_works(admin_env, tmp_path, monkeypatch):
    home = tmp_path / "gw"
    (home).mkdir(parents=True, exist_ok=True)
    (home / "gateway.toml").write_text('[gateway]\nadmin_token = "file-secret"\n')
    resp = await admin.admin_tenant_list(_request(token="file-secret"))
    assert resp.status_code == 200
    assert _body(resp) == {"ok": True, "tenants": []}


async def test_env_wins_over_file(admin_env, tmp_path, monkeypatch):
    home = tmp_path / "gw"
    (home).mkdir(parents=True, exist_ok=True)
    (home / "gateway.toml").write_text('[gateway]\nadmin_token = "file-secret"\n')
    monkeypatch.setenv(admin.ADMIN_TOKEN_ENV, "env-secret")
    assert (await admin.admin_tenant_list(_request(token="env-secret"))).status_code == 200
    assert (await admin.admin_tenant_list(_request(token="file-secret"))).status_code == 403


async def _authed_env(admin_env, monkeypatch):
    monkeypatch.setenv(admin.ADMIN_TOKEN_ENV, "s3cret")
    return "s3cret"


async def test_tenant_add_list_get_roundtrip(admin_env, monkeypatch):
    token = await _authed_env(admin_env, monkeypatch)
    resp = await admin.admin_tenant_add(
        _request("POST", body={"tenant_id": "alice", "note": "hi"}, token=token)
    )
    assert resp.status_code == 201
    data = _body(resp)
    assert data["ok"] is True and data["tenant_id"] == "alice"
    assert data["api_key"].startswith("bnt_")

    listed = _body(await admin.admin_tenant_list(_request(token=token)))
    assert [t["tenant_id"] for t in listed["tenants"]] == ["alice"]

    got = _body(
        await admin.admin_tenant_get(_request(path_params={"tenant_id": "alice"}, token=token))
    )
    assert got["tenant"]["tenant_id"] == "alice"

    missing = await admin.admin_tenant_get(
        _request(path_params={"tenant_id": "nobody"}, token=token)
    )
    assert missing.status_code == 404


async def test_tenant_add_rejects_bad_and_duplicate(admin_env, monkeypatch):
    token = await _authed_env(admin_env, monkeypatch)
    bad = await admin.admin_tenant_add(_request("POST", body={"tenant_id": "../evil"}, token=token))
    assert bad.status_code == 400
    first = await admin.admin_tenant_add(_request("POST", body={"tenant_id": "bob"}, token=token))
    assert first.status_code == 201
    dup = await admin.admin_tenant_add(_request("POST", body={"tenant_id": "bob"}, token=token))
    assert dup.status_code == 400


async def test_enable_disable_roundtrip(admin_env, monkeypatch):
    token = await _authed_env(admin_env, monkeypatch)
    await admin.admin_tenant_add(_request("POST", body={"tenant_id": "carol"}, token=token))
    dis = await admin.admin_tenant_disable(
        _request("POST", path_params={"tenant_id": "carol"}, token=token)
    )
    assert dis.status_code == 200 and _body(dis)["enabled"] is False
    ena = await admin.admin_tenant_enable(
        _request("POST", path_params={"tenant_id": "carol"}, token=token)
    )
    assert ena.status_code == 200 and _body(ena)["enabled"] is True
    missing = await admin.admin_tenant_disable(
        _request("POST", path_params={"tenant_id": "ghost"}, token=token)
    )
    assert missing.status_code == 404


async def test_key_add_list_and_last_live_revoke_refused(admin_env, monkeypatch):
    token = await _authed_env(admin_env, monkeypatch)
    await admin.admin_tenant_add(_request("POST", body={"tenant_id": "dave"}, token=token))

    # The initial key is the only live one: revoking it must 409, not lock out.
    only = _body(await admin.admin_key_list(_request(query=b"tenant_id=dave", token=token)))
    assert len(only["keys"]) == 1
    last_id = only["keys"][0]["key_id"]
    refused = await admin.admin_key_revoke(
        _request("POST", path_params={"key_id": last_id}, token=token)
    )
    assert refused.status_code == 409

    # Mint a second key, then revoking the first succeeds.
    second = await admin.admin_key_add(
        _request("POST", body={"tenant_id": "dave", "label": "extra"}, token=token)
    )
    assert second.status_code == 201
    ok = await admin.admin_key_revoke(
        _request("POST", path_params={"key_id": last_id}, token=token)
    )
    assert ok.status_code == 200

    # Unknown key id 404s; key add for unknown tenant 404s.
    assert (
        await admin.admin_key_revoke(
            _request("POST", path_params={"key_id": "deadbeef"}, token=token)
        )
    ).status_code == 404
    assert (
        await admin.admin_key_add(_request("POST", body={"tenant_id": "ghost"}, token=token))
    ).status_code == 404


async def test_delete_route_guarded_by_confirm(admin_env, monkeypatch):
    """Delete exists but requires {"confirm": id}; anything else is a 400 no-op."""
    from bonnet.gateway import tenants

    monkeypatch.setenv(admin.ADMIN_TOKEN_ENV, "s3cret")
    token = "s3cret"

    def _body(resp):
        return json.loads(resp.body.decode())

    await admin.admin_tenant_add(
        _request("POST", body={"tenant_id": "erin"}, token=token)
    )
    assert tenants.get_tenant("erin") is not None

    # Missing/wrong confirm: 400, tenant survives.
    assert (
        await admin.admin_tenant_delete(
            _request(
                "POST",
                path_params={"tenant_id": "erin"},
                body={},
                token=token,
            )
        )
    ).status_code == 400
    assert (
        await admin.admin_tenant_delete(
            _request(
                "POST",
                path_params={"tenant_id": "erin"},
                body={"confirm": "someone-else"},
                token=token,
            )
        )
    ).status_code == 400
    assert tenants.get_tenant("erin") is not None

    # Echoed confirm: deleted (registry row and directory).
    ok = await admin.admin_tenant_delete(
        _request(
            "POST",
            path_params={"tenant_id": "erin"},
            body={"confirm": "erin"},
            token=token,
        )
    )
    assert ok.status_code == 200
    assert _body(ok)["deleted"] is True
    assert tenants.get_tenant("erin") is None

    # Unknown tenant 404s.
    assert (
        await admin.admin_tenant_delete(
            _request(
                "POST",
                path_params={"tenant_id": "ghost"},
                body={"confirm": "ghost"},
                token=token,
            )
        )
    ).status_code == 404


async def test_last_live_key_revoke_force(admin_env, monkeypatch):
    """Last-live-key revoke 409s by default but honors {"force": true}."""
    monkeypatch.setenv(admin.ADMIN_TOKEN_ENV, "s3cret")
    token = "s3cret"

    await admin.admin_tenant_add(_request("POST", body={"tenant_id": "fred"}, token=token))

    def _body(resp):
        return json.loads(resp.body.decode())

    only = _body(await admin.admin_key_list(_request(query=b"tenant_id=fred", token=token)))
    last_id = only["keys"][0]["key_id"]
    refused = await admin.admin_key_revoke(
        _request("POST", path_params={"key_id": last_id}, token=token)
    )
    assert refused.status_code == 409

    forced = await admin.admin_key_revoke(
        _request(
            "POST",
            path_params={"key_id": last_id},
            body={"force": True},
            token=token,
        )
    )
    assert forced.status_code == 200


async def test_delete_route_registered():
    from bonnet.gateway.tools import mcp

    routes = [r.path for r in mcp._additional_http_routes if r.path.startswith("/admin")]
    assert "/admin/tenants" in routes
    assert "/admin/tenants/{tenant_id}/delete" in routes
    assert len(routes) == 9
