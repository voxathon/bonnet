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

"""Transport selection for the `bonnet gateway` bridge.

stdio is the default because an agent host launching this process over pipes
needs no port, no listener and no supervision. http remains available for one
bridge serving several callers, and binds loopback unless told otherwise.
"""

import pytest

pytest.importorskip("fastmcp")

from bonnet.gateway import server as srv


@pytest.fixture
def recorded(monkeypatch):
    """Capture what run() would hand to FastMCP.run."""
    calls: list[dict] = []
    monkeypatch.setattr(srv.mcp, "run", lambda **kw: calls.append(kw))
    return calls


def test_default_transport_is_stdio(recorded, monkeypatch):
    monkeypatch.delenv("MCP_TRANSPORT", raising=False)

    srv.run([])

    assert recorded[0]["transport"] == "stdio"


def test_stdio_suppresses_the_banner(recorded, monkeypatch):
    """stdout is the MCP framing stream in this mode; anything else written
    there corrupts the session."""
    monkeypatch.delenv("MCP_TRANSPORT", raising=False)

    srv.run([])

    assert recorded[0]["show_banner"] is False


def test_stdio_opens_no_listener(recorded, monkeypatch):
    monkeypatch.delenv("MCP_TRANSPORT", raising=False)

    srv.run([])

    assert "host" not in recorded[0]
    assert "port" not in recorded[0]


def test_http_binds_loopback_by_default(recorded, monkeypatch):
    """The bridge holds unwrapped signing keys and takes its identity from a
    request header, so it must not be reachable off-box unless asked."""
    monkeypatch.delenv("MCP_HOST", raising=False)
    monkeypatch.delenv("MCP_PORT", raising=False)

    srv.run(["--transport", "http"])

    assert recorded[0]["transport"] == "http"
    assert recorded[0]["host"] == "127.0.0.1"
    assert recorded[0]["port"] == 8080


def test_http_host_and_port_are_overridable(recorded):
    srv.run(["--transport", "http", "--host", "0.0.0.0", "--port", "9001"])

    assert recorded[0]["host"] == "0.0.0.0"
    assert recorded[0]["port"] == 9001


def test_non_loopback_bind_warns(recorded, capsys):
    srv.run(["--transport", "http", "--host", "0.0.0.0"])

    assert "beyond this machine" in capsys.readouterr().err


def test_env_selects_transport(recorded, monkeypatch):
    monkeypatch.setenv("MCP_TRANSPORT", "http")
    monkeypatch.delenv("MCP_HOST", raising=False)

    srv.run([])

    assert recorded[0]["transport"] == "http"


def test_flag_beats_env(recorded, monkeypatch):
    monkeypatch.setenv("MCP_TRANSPORT", "http")

    srv.run(["--transport", "stdio"])

    assert recorded[0]["transport"] == "stdio"


def test_env_host_and_port_are_honoured(recorded, monkeypatch):
    monkeypatch.setenv("MCP_HOST", "10.0.0.5")
    monkeypatch.setenv("MCP_PORT", "7000")

    srv.run(["--transport", "http"])

    assert recorded[0]["host"] == "10.0.0.5"
    assert recorded[0]["port"] == 7000
