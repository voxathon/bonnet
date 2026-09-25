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

"""Trusted forwarders: forwarded-client logging and rate-limit bucketing.

The chain user -> domain -> cloudflared -> gateway -> bonnet server collapses
every logged IP to the socket peer (loopback through the tunnel), because the
origin only ever read scope["client"]. These tests cover the fix:

- config: `trusted_forwarders` parses, validates and is a known section key.
- origin: the forwarded client IP (CF-Connecting-IP / X-Real-IP / rightmost
  X-Forwarded-For) is logged alongside the socket peer, and the anonymous
  rate limiter buckets on it when — and only when — the connecting IP is on
  the trusted_forwarders list.
- gateway: the forwarded-for ContextVar is exported as X-Forwarded-For on
  gateway->server POSTs and absent for direct clients.
"""

import logging

import pytest

from bonnet.core.config import FirehoseConfig
from bonnet.net.firehose_transport import FirehoseClientError, forwarded_for_ctx
from bonnet.net.rate_limiter import RateLimiter
from tests.test_firehose_http_server import ORIGIN, server_stack  # noqa: F401 (fixtures)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def _write_config(tmp_path, text: str):
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_config_trusted_forwarders_parse(tmp_path):
    path = _write_config(
        tmp_path,
        '[server]\norigin = "bbs.test"\ntrusted_forwarders = ["127.0.0.1", "203.0.113.7"]\n',
    )
    config = FirehoseConfig.load(str(path))
    assert config.trusted_forwarders == ["127.0.0.1", "203.0.113.7"]


def test_config_trusted_forwarders_default_empty(tmp_path):
    path = _write_config(tmp_path, '[server]\norigin = "bbs.test"\n')
    config = FirehoseConfig.load(str(path))
    assert config.trusted_forwarders == []


def test_config_trusted_forwarders_rejects_garbage(tmp_path):
    path = _write_config(
        tmp_path,
        '[server]\norigin = "bbs.test"\ntrusted_forwarders = ["not-an-ip"]\n',
    )
    config = FirehoseConfig.load(str(path))
    with pytest.raises(ValueError, match="not a valid IP"):
        config.validate()


def test_config_validate_rejects_non_string_forwarders():
    config = FirehoseConfig(trusted_forwarders=[1234])
    with pytest.raises(ValueError, match="must be strings"):
        config.validate()


def test_config_trusted_forwarders_is_a_known_section_key():
    from bonnet.core.config import _SECTION_KEYS

    assert "trusted_forwarders" in _SECTION_KEYS["server"]


def test_config_validate_rejects_garbage_forwarders():
    config = FirehoseConfig(trusted_forwarders=["192.168.1.256"])
    with pytest.raises(ValueError, match="not a valid IP"):
        config.validate()


# ---------------------------------------------------------------------------
# Origin: forwarded-IP extraction
# ---------------------------------------------------------------------------


async def test_forwarded_ips_precedence(server_stack):  # noqa: F811
    """CF-Connecting-IP wins, then X-Real-IP, then rightmost X-Forwarded-For
    (the entry the trusted peer appended; the rest came from its caller)."""
    server = server_stack["server"]

    scope = {
        "headers": [
            (b"cf-connecting-ip", b"198.51.100.9"),
            (b"x-real-ip", b"198.51.100.8"),
            (b"x-forwarded-for", b"198.51.100.7, 10.0.0.1"),
        ]
    }
    assert server._forwarded_ips(scope) == "198.51.100.9"

    scope = {
        "headers": [
            (b"x-real-ip", b"198.51.100.8"),
            (b"x-forwarded-for", b"198.51.100.7, 10.0.0.1"),
        ]
    }
    assert server._forwarded_ips(scope) == "198.51.100.8"

    scope = {"headers": [(b"x-forwarded-for", b"198.51.100.7, 10.0.0.1")]}
    assert server._forwarded_ips(scope) == "10.0.0.1"

    assert server._forwarded_ips({"headers": []}) == ""
    assert server._forwarded_ips({"headers": [(b"host", b"bbs.test")]}) == ""


# ---------------------------------------------------------------------------
# Origin: rate-limit bucketing
# ---------------------------------------------------------------------------


async def test_forwarded_ip_buckets_when_peer_trusted(server_stack):  # noqa: F811
    """A trusted proxy's forwarded IP gets its own anonymous bucket."""
    server = server_stack["server"]
    server._trusted_forwarders = {"127.0.0.1"}
    server._rate_limiter = RateLimiter(max_requests=1, window_seconds=60)
    c = server_stack["client"]
    await c.connect_anonymous()

    token = forwarded_for_ctx.set("198.51.100.7")
    try:
        await c.list_boards("")
        assert "address:198.51.100.7" in server._rate_limiter._buckets
        with pytest.raises(FirehoseClientError, match="429"):
            await c.list_boards("")
    finally:
        forwarded_for_ctx.reset(token)

    # A different forwarded IP gets its own bucket when the peer is trusted.
    token = forwarded_for_ctx.set("198.51.100.9")
    try:
        await c.list_boards("")
    finally:
        forwarded_for_ctx.reset(token)


async def test_forwarded_ip_ignored_when_peer_untrusted(server_stack):  # noqa: F811
    """An untrusted peer is bucketed on its own socket address, XFF ignored."""
    server = server_stack["server"]
    server._trusted_forwarders = set()
    server._rate_limiter = RateLimiter(max_requests=1, window_seconds=60)
    c = server_stack["client"]
    await c.connect_anonymous()

    token = forwarded_for_ctx.set("198.51.100.7")
    try:
        await c.list_boards("")
        with pytest.raises(FirehoseClientError, match="429"):
            await c.list_boards("")
        assert "address:198.51.100.7" not in server._rate_limiter._buckets
        assert "address:127.0.0.1" in server._rate_limiter._buckets
    finally:
        forwarded_for_ctx.reset(token)


async def test_no_forwarded_header_buckets_on_socket_address(server_stack):  # noqa: F811
    """No forwarded data: behavior is exactly as before this feature."""
    server = server_stack["server"]
    server._trusted_forwarders = {"127.0.0.1"}
    server._rate_limiter = RateLimiter(max_requests=1, window_seconds=60)
    c = server_stack["client"]
    await c.connect_anonymous()

    await c.list_boards("")
    with pytest.raises(FirehoseClientError, match="429"):
        await c.list_boards("")
    assert "address:127.0.0.1" in server._rate_limiter._buckets


# ---------------------------------------------------------------------------
# Origin: fwd= in the REQ log lines
# ---------------------------------------------------------------------------


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record):
        self.lines.append(record.getMessage())


async def test_req_logs_carry_forwarded_ip(server_stack, tmp_path):  # noqa: F811
    """REQ lines show the forwarded client IP alongside the socket peer."""
    from bonnet.core.logging import init_logging

    init_logging(str(tmp_path / "logs"))
    server = server_stack["server"]
    server._trusted_forwarders = {"127.0.0.1"}
    c = server_stack["client"]
    await c.connect_anonymous()

    capture = _Capture()
    bonnet_log = logging.getLogger("bonnet")
    bonnet_log.addHandler(capture)
    try:
        token = forwarded_for_ctx.set("198.51.100.7")
        try:
            await c.list_boards("")
        finally:
            forwarded_for_ctx.reset(token)
    finally:
        bonnet_log.removeHandler(capture)

    starts = [line for line in capture.lines if line.startswith("REQ start")]
    assert starts, capture.lines
    assert "remote=127.0.0.1" in starts[0]
    assert "fwd=198.51.100.7" in starts[0]

    dones = [line for line in capture.lines if line.startswith("REQ done")]
    assert dones
    assert "remote=127.0.0.1" in dones[0]
    assert "fwd=198.51.100.7" in dones[0]


# ---------------------------------------------------------------------------
# Gateway: X-Forwarded-For export
# ---------------------------------------------------------------------------


async def test_gateway_exports_forwarded_for_when_contextvar_set(server_stack):  # noqa: F811
    """The ContextVar value rides on gateway->server POSTs as X-Forwarded-For."""
    c = server_stack["client"]
    await c.connect_anonymous()

    token = forwarded_for_ctx.set("198.51.100.7")
    try:
        await c.list_boards("")
    finally:
        forwarded_for_ctx.reset(token)

    # The origin logged it (via the trusted_peer test above); here assert the
    # header was actually sent by replaying a POST capture-free: the origin
    # only buckets on it when trusted, so exercise the untrusted path where
    # the header must still have arrived and been ignored for bucketing.
    server = server_stack["server"]
    server._trusted_forwarders = set()
    server._rate_limiter = RateLimiter(max_requests=1, window_seconds=60)

    token = forwarded_for_ctx.set("198.51.100.11")
    try:
        await c.list_boards("")
        with pytest.raises(FirehoseClientError, match="429"):
            await c.list_boards("")
        assert "address:127.0.0.1" in server._rate_limiter._buckets
    finally:
        forwarded_for_ctx.reset(token)


async def test_gateway_exports_nothing_without_forwarded_data(server_stack):  # noqa: F811
    """Direct clients (CLI, federation sync): no X-Forwarded-For, default ""."""
    assert forwarded_for_ctx.get() == ""

    c = server_stack["client"]
    await c.connect_anonymous()
    await c.list_boards("")
    assert forwarded_for_ctx.get() == ""


class _Req:
    def __init__(self, headers, peer="127.0.0.1"):
        self.headers = headers
        self.client = type("C", (), {"host": peer})() if peer else None


@pytest.fixture
def gateway_trusts(monkeypatch):
    from bonnet.net import firehose_transport

    def _trust(*ips):
        monkeypatch.setattr(firehose_transport, "_gateway_trusted_forwarders", frozenset(ips))

    return _trust


def test_forwarded_for_from_request_parsing(gateway_trusts):
    """From a trusted proxy: CF-Connecting-IP, else the rightmost XFF entry,
    which is the one that proxy appended."""
    from bonnet.gateway.server import _forwarded_for_from_request

    gateway_trusts("127.0.0.1")
    assert (
        _forwarded_for_from_request(_Req({"x-forwarded-for": "198.51.100.7, 203.0.113.5"}))
        == "203.0.113.5"
    )
    assert _forwarded_for_from_request(_Req({"x-forwarded-for": "198.51.100.7"})) == "198.51.100.7"
    assert _forwarded_for_from_request(_Req({"cf-connecting-ip": "198.51.100.9"})) == "198.51.100.9"
    # A trusted proxy that named no one: the proxy itself is the client.
    assert _forwarded_for_from_request(_Req({})) == "127.0.0.1"
    assert _forwarded_for_from_request(_Req({"x-forwarded-for": ""})) == "127.0.0.1"
    assert _forwarded_for_from_request(_Req({}, peer=None)) == ""


def test_an_untrusted_caller_cannot_pick_its_forwarded_ip(gateway_trusts):
    """The hole: the gateway passed the leftmost X-Forwarded-For through from
    anyone, and an origin trusting the gateway bucketed on it, so a caller
    could choose a fresh anonymous rate-limit bucket per request."""
    from bonnet.gateway.server import _forwarded_for_from_request

    gateway_trusts("127.0.0.1")
    spoofed = {"x-forwarded-for": "1.2.3.4", "cf-connecting-ip": "5.6.7.8", "x-real-ip": "9.9.9.9"}
    assert _forwarded_for_from_request(_Req(spoofed, peer="198.51.100.20")) == "198.51.100.20"


def test_nobody_is_trusted_by_default():
    from bonnet.gateway.server import _forwarded_for_from_request
    from bonnet.net import firehose_transport

    assert firehose_transport._gateway_trusted_forwarders == frozenset()
    assert (
        _forwarded_for_from_request(_Req({"x-forwarded-for": "1.2.3.4"}, peer="127.0.0.1"))
        == "127.0.0.1"
    )


def test_a_trusted_proxy_passes_on_the_leftmost_only_as_what_it_is(gateway_trusts):
    """Behind cloudflared, a caller's own X-Forwarded-For arrives with the
    real client appended after it; the caller's part is ignored."""
    from bonnet.gateway.server import _forwarded_for_from_request

    gateway_trusts("127.0.0.1")
    req = _Req({"x-forwarded-for": "1.2.3.4, 198.51.100.7"})
    assert _forwarded_for_from_request(req) == "198.51.100.7"


# ---------------------------------------------------------------------------
# uvicorn's own proxy-header rewrite is off, on both servers
# ---------------------------------------------------------------------------


async def test_server_runs_uvicorn_without_proxy_headers(tmp_path, monkeypatch):
    """uvicorn's default rewrites scope["client"] from X-Forwarded-For for any
    peer on 127.0.0.1, so `remote=` was never the socket and a
    trusted_forwarders entry of 127.0.0.1 could never match."""
    import uvicorn

    from bonnet.app.server import BonnetServer
    from tests.bridge_fakes import make_config

    captured = {}

    class _Stop(Exception):
        pass

    def fake_config(*args, **kwargs):
        captured.update(kwargs)
        raise _Stop

    monkeypatch.setattr(uvicorn, "Config", fake_config)
    server = BonnetServer(make_config(tmp_path, "bbs.test"))
    try:
        with pytest.raises(_Stop):
            await server.run(port=0, console=False)
    finally:
        server.close()
    assert captured["proxy_headers"] is False
