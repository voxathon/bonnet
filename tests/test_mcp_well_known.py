"""Tests for the bonnet-gateway discovery proxy endpoint sanitization."""

import json

import httpx
import pytest

pytest.importorskip("fastmcp")

from bonnet.gateway.server import well_known_bonnet


class FakeResponse:
    status_code = 200

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class FakeSuccessfulClient:
    def __init__(self, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url):
        return FakeResponse({"origin": "bbs.test"})


class FakeFailingClient(FakeSuccessfulClient):
    async def get(self, url):
        raise RuntimeError("dial tcp 10.0.0.1:2272 refused (secret detail)")


@pytest.mark.asyncio
async def test_well_known_proxies_discovery_json(monkeypatch):
    monkeypatch.setenv("BONNET_URL", "https://board.example")
    monkeypatch.setattr(httpx, "AsyncClient", FakeSuccessfulClient)

    resp = await well_known_bonnet(None)

    assert resp.status_code == 200
    assert json.loads(resp.body) == {"origin": "bbs.test"}


@pytest.mark.asyncio
async def test_well_known_failure_is_sanitized(monkeypatch):
    monkeypatch.setenv("BONNET_URL", "https://board.example")
    monkeypatch.setattr(httpx, "AsyncClient", FakeFailingClient)

    resp = await well_known_bonnet(None)

    assert resp.status_code == 502
    assert resp.body == b"Failed to reach Bonnet server"
    assert b"secret detail" not in resp.body
    assert b"10.0.0.1" not in resp.body
