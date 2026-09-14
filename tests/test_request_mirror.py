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

"""Path-capable BONNET_VERIFY_TLS and the console request mirror.

Routing an origin behind a Cloudflare Origin CA cert over loopback needs
full chain + hostname verification, not `verify=false`: BONNET_VERIFY_TLS
now accepts a CA bundle path, validated at parse time. The operator
console gets one `HTTP` line per request (method, path, remote, forwarded
IP, status) through RequestLogMiddleware + a REQ-only stderr mirror.
"""

import datetime
import logging

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from bonnet.core.logging import close_logging, enable_request_mirror, init_logging
from bonnet.gateway.firehose_client import (
    FirehoseHTTPClient,
    default_verify_tls,
    resolve_verify_tls,
)
from bonnet.net.firehose_http_server import RequestLogMiddleware
from bonnet.net.firehose_transport import forwarded_for_ctx
from tests.test_firehose_http_server import server_stack  # noqa: F401 (fixtures)


def _write_ca(tmp_path) -> str:
    """A real, loadable self-signed CA cert (path-mode must construct an
    ssl context from it, so a stub PEM would fail before asserting)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-origin-ca")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    ca = tmp_path / "origin_ca_root.pem"
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(ca)


# ---------------------------------------------------------------------------
# BONNET_VERIFY_TLS parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["false", "0", "no", "FALSE"])
def test_verify_tls_false_literals(monkeypatch, value):
    monkeypatch.setenv("BONNET_VERIFY_TLS", value)
    assert resolve_verify_tls("https://bbs.test") is False


@pytest.mark.parametrize("value", ["true", "1", "yes", "on", "TRUE"])
def test_verify_tls_true_literals(monkeypatch, value):
    monkeypatch.setenv("BONNET_VERIFY_TLS", value)
    assert resolve_verify_tls("https://bbs.test") is True
    # Explicit true stays true even on loopback, as before paths were accepted.
    assert resolve_verify_tls("https://localhost:2272") is True


def test_verify_tls_unset_defaults(monkeypatch):
    monkeypatch.delenv("BONNET_VERIFY_TLS", raising=False)
    assert resolve_verify_tls("https://bbs.test") == default_verify_tls("https://bbs.test")
    assert resolve_verify_tls("https://bbs.test") is True
    assert resolve_verify_tls("https://localhost:2272") == default_verify_tls(
        "https://localhost:2272"
    )
    assert resolve_verify_tls("https://localhost:2272") is False


def test_verify_tls_path_returned_as_is(monkeypatch, tmp_path):
    ca = _write_ca(tmp_path)
    monkeypatch.setenv("BONNET_VERIFY_TLS", ca)
    assert resolve_verify_tls("https://bbs.test") == ca


def test_verify_tls_missing_path_raises(monkeypatch, tmp_path):
    monkeypatch.setenv("BONNET_VERIFY_TLS", str(tmp_path / "nope.pem"))
    with pytest.raises(ValueError, match="neither a boolean nor an existing"):
        resolve_verify_tls("https://bbs.test")


def test_verify_tls_garbage_value_raises(monkeypatch):
    monkeypatch.setenv("BONNET_VERIFY_TLS", "kinda-verify")
    with pytest.raises(ValueError, match="neither a boolean nor an existing"):
        resolve_verify_tls("https://bbs.test")


async def test_client_constructs_with_ca_path(tmp_path):
    """The transport's httpx client accepts a CA bundle path end to end."""
    client = FirehoseHTTPClient("https://bbs.test", verify=_write_ca(tmp_path))
    try:
        assert isinstance(client._http, httpx.AsyncClient)
    finally:
        await client.close()


def test_current_verify_picks_up_path(monkeypatch, tmp_path):
    from bonnet.gateway import tools

    ca = _write_ca(tmp_path)
    monkeypatch.setenv("BONNET_VERIFY_TLS", ca)
    assert tools._current_verify() == ca


# ---------------------------------------------------------------------------
# RequestLogMiddleware
# ---------------------------------------------------------------------------


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record):
        self.lines.append(record.getMessage())


async def test_middleware_logs_one_line_per_request(server_stack, tmp_path):  # noqa: F811
    """One `HTTP` line per request with method, path, remote, fwd, status."""
    init_logging(str(tmp_path / "logs"))
    http_server = server_stack["server"]
    c = server_stack["client"]
    c._http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=RequestLogMiddleware(http_server, http_server)),
        base_url="https://bbs.test",
        timeout=30.0,
        verify=False,
    )

    capture = _Capture()
    bonnet_log = logging.getLogger("bonnet")
    bonnet_log.addHandler(capture)
    try:
        await c.connect_anonymous()
        token = forwarded_for_ctx.set("198.51.100.7")
        try:
            await c.list_boards("")
        finally:
            forwarded_for_ctx.reset(token)
    finally:
        bonnet_log.removeHandler(capture)
        await c.close()

    board_lines = [
        line for line in capture.lines if line.startswith("HTTP ") and "path=/command" in line
    ]
    assert board_lines
    assert "method=POST" in board_lines[0]
    assert "remote=127.0.0.1" in board_lines[0]
    assert "fwd=198.51.100.7" in board_lines[0]
    assert "status=200" in board_lines[0]
    assert "ms=" in board_lines[0]
    # Exactly one HTTP line for this request.
    assert len(board_lines) == 1


async def test_middleware_passes_through_non_http(tmp_path):
    """Lifespan (and websocket) scopes pass through untouched, no HTTP line."""
    seen = []

    class _Inner:
        async def __call__(self, scope, receive, send):
            seen.append(scope["type"])

    class _Helpers:
        def _get_remote_addr(self, scope):
            return "127.0.0.1"

        def _forwarded_ips(self, scope):
            return ""

    init_logging(str(tmp_path / "logs"))
    capture = _Capture()
    bonnet_log = logging.getLogger("bonnet")
    bonnet_log.addHandler(capture)
    try:
        mw = RequestLogMiddleware(_Inner(), _Helpers())
        await mw({"type": "lifespan", "asgi": {}}, None, None)
    finally:
        bonnet_log.removeHandler(capture)

    assert seen == ["lifespan"]
    assert [line for line in capture.lines if line.startswith("HTTP ")] == []


async def test_middleware_reports_status_and_never_raises(tmp_path):
    """Status comes from http.response.start; an erroring app still logs."""

    class _Broken:
        async def __call__(self, scope, receive, send):
            await send({"type": "http.response.start", "status": 500, "headers": []})
            raise RuntimeError("boom")

    class _Helpers:
        def _get_remote_addr(self, scope):
            return "127.0.0.1"

        def _forwarded_ips(self, scope):
            return ""

    init_logging(str(tmp_path / "logs"))
    capture = _Capture()
    bonnet_log = logging.getLogger("bonnet")
    bonnet_log.addHandler(capture)
    try:
        mw = RequestLogMiddleware(_Broken(), _Helpers())
        sent = []

        async def _send(message):
            sent.append(message)

        with pytest.raises(RuntimeError, match="boom"):
            await mw({"type": "http", "method": "GET", "path": "/x", "headers": []}, None, _send)
    finally:
        bonnet_log.removeHandler(capture)

    lines = [line for line in capture.lines if line.startswith("HTTP ")]
    assert len(lines) == 1
    assert "method=GET" in lines[0]
    assert "path=/x" in lines[0]
    assert "status=500" in lines[0]


# ---------------------------------------------------------------------------
# REQ-only stderr mirror
# ---------------------------------------------------------------------------


def _mirror_handlers():
    from bonnet.core.logging import _RequestMirrorHandler

    return [h for h in logging.getLogger("bonnet").handlers if isinstance(h, _RequestMirrorHandler)]


def test_mirror_adds_one_handler_only(tmp_path):
    init_logging(str(tmp_path / "logs"))
    try:
        enable_request_mirror()
        enable_request_mirror()
        assert len(_mirror_handlers()) == 1
    finally:
        close_logging()


def test_mirror_filter_passes_http_lines_only(tmp_path):
    init_logging(str(tmp_path / "logs"))
    try:
        enable_request_mirror()
        handler = _mirror_handlers()[0]

        def _record(msg: str) -> logging.LogRecord:
            return logging.LogRecord("bonnet", logging.INFO, "x", 1, msg, (), None)

        assert handler.filter(_record("HTTP method=POST path=/command remote=1.2.3.4"))
        assert not handler.filter(_record("REQ done remote=1.2.3.4 ok=True"))
        assert not handler.filter(_record("HTTP_COMMAND: dispatch error: boom"))
        assert not handler.filter(_record("INIT: complete"))
    finally:
        close_logging()


def test_mirror_noop_without_init():
    close_logging()
    enable_request_mirror()
    assert _mirror_handlers() == []
