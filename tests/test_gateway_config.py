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

"""gateway.toml: the http-mode-only config file `gateway.server.run` reads,
and its precedence under CLI flags and $MCP_* env vars.
"""

import os

import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("cryptography")
pytest.importorskip("fastmcp")

from bonnet.gateway import gateway_config, tenancy
from bonnet.gateway.server import run as gateway_run
from bonnet.gateway.tools import mcp

_MCP_ENV = ("MCP_TRANSPORT", "MCP_HOST", "MCP_PORT", "MCP_TLS_CERT", "MCP_TLS_KEY")


# --- gateway_config.load ----------------------------------------------------


def test_load_returns_none_when_the_file_is_absent(tmp_path):
    assert gateway_config.load(str(tmp_path / "gateway.toml")) is None


def test_load_parses_the_gateway_table(tmp_path):
    path = tmp_path / "gateway.toml"
    path.write_text(
        '[gateway]\ntransport = "http"\nhost = "0.0.0.0"\nport = 9090\n'
        'tls_cert = "/c.pem"\ntls_key = "/k.pem"\ngating = false\n',
        encoding="utf-8",
    )

    config = gateway_config.load(str(path))

    assert config is not None
    assert config.transport == "http"
    assert config.host == "0.0.0.0"
    assert config.port == 9090
    assert config.tls_cert == "/c.pem"
    assert config.tls_key == "/k.pem"
    assert config.gating is False


def test_load_defaults_absent_fields_to_none(tmp_path):
    path = tmp_path / "gateway.toml"
    path.write_text('[gateway]\nhost = "0.0.0.0"\n', encoding="utf-8")

    config = gateway_config.load(str(path))

    assert config.host == "0.0.0.0"
    assert config.transport is None
    assert config.port is None
    assert config.gating is None


def test_load_raises_on_malformed_toml(tmp_path):
    path = tmp_path / "gateway.toml"
    path.write_text("[gateway\nbroken", encoding="utf-8")

    with pytest.raises(Exception):
        gateway_config.load(str(path))


# --- precedence in run() ----------------------------------------------------


@pytest.fixture
def gw(tmp_path, monkeypatch):
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "gw"))
    for var in _MCP_ENV:
        monkeypatch.delenv(var, raising=False)
    tenancy.reset_store_cache()
    tenancy.reset_registry_cache()

    calls = []
    monkeypatch.setattr(mcp, "run", lambda **kwargs: calls.append(kwargs))

    yield tmp_path / "gw", calls

    tenancy.reset_store_cache()
    tenancy.reset_registry_cache()


def test_a_fresh_install_with_no_gateway_toml_behaves_as_before(gw):
    home, calls = gw

    gateway_run(["--http"])

    assert calls[-1]["host"] == "127.0.0.1"
    assert calls[-1]["port"] == 8080


def test_gateway_toml_supplies_defaults_cli_omits(gw):
    home, calls = gw
    os.makedirs(home, exist_ok=True)
    (home / "gateway.toml").write_text(
        '[gateway]\nhost = "0.0.0.0"\nport = 9191\n', encoding="utf-8"
    )

    gateway_run(["--http"])

    assert calls[-1]["host"] == "0.0.0.0"
    assert calls[-1]["port"] == 9191


def test_cli_flag_overrides_gateway_toml(gw):
    home, calls = gw
    os.makedirs(home, exist_ok=True)
    (home / "gateway.toml").write_text("[gateway]\nport = 9191\n", encoding="utf-8")

    gateway_run(["--http", "--port", "7000"])

    assert calls[-1]["port"] == 7000


def test_env_var_overrides_gateway_toml(gw, monkeypatch):
    home, calls = gw
    os.makedirs(home, exist_ok=True)
    (home / "gateway.toml").write_text("[gateway]\nport = 9191\n", encoding="utf-8")

    gateway_run(["--http"])
    # sanity: file value took effect with nothing else set
    assert calls[-1]["port"] == 9191
    calls.clear()

    monkeypatch.setenv("MCP_PORT", "6000")
    gateway_run(["--http"])

    assert calls[-1]["port"] == 6000


def test_gateway_toml_gating_false_sets_env_when_cli_does_not_override(gw, monkeypatch):
    home, calls = gw
    monkeypatch.delenv("BONNET_GATING", raising=False)
    os.makedirs(home, exist_ok=True)
    (home / "gateway.toml").write_text("[gateway]\ngating = false\n", encoding="utf-8")

    try:
        gateway_run([])  # stdio, default transport
        assert os.environ.get("BONNET_GATING") == "off"
    finally:
        # run() sets this directly on os.environ, not through monkeypatch, so
        # it survives the test unless cleared here.
        os.environ.pop("BONNET_GATING", None)


def test_gateway_toml_transport_is_the_lowest_precedence_layer(gw):
    home, calls = gw
    os.makedirs(home, exist_ok=True)
    (home / "gateway.toml").write_text('[gateway]\ntransport = "http"\n', encoding="utf-8")

    gateway_run([])

    assert calls[-1]["transport"] == "http"
