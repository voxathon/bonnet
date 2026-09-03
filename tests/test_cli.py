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

"""The `bonnet` dispatcher (bonnet.cli): --version, -h, and delegation to
`server`/`gateway` with the sliced argv. Not a merged argparse tree — see
cli.py's own docstring for why — so these tests only exercise the dispatch
logic itself; each delegate's own flags are tested where that delegate lives
(tests/test_server_cli.py, tests/test_gateway_registry.py).
"""

from bonnet import __version__
from bonnet.cli import main


def test_version_flag_prints_version_and_exits(capsys):
    code = main(["--version"])

    assert code == 0
    out = capsys.readouterr().out
    assert out == f"bonnet {__version__}\n"


def test_short_version_flag(capsys):
    code = main(["-V"])

    assert code == 0
    assert capsys.readouterr().out == f"bonnet {__version__}\n"


def test_no_args_prints_usage_and_returns_nonzero(capsys):
    code = main([])

    assert code == 2
    err = capsys.readouterr().err
    assert "server" in err
    assert "gateway" in err


def test_help_flag_prints_usage_and_succeeds(capsys):
    code = main(["-h"])

    assert code == 0
    out = capsys.readouterr().out
    assert "server" in out
    assert "gateway" in out


def test_unknown_command_reports_the_two_valid_ones(capsys):
    code = main(["frobnicate"])

    assert code == 2
    err = capsys.readouterr().err
    assert "frobnicate" in err
    assert "server" in err
    assert "gateway" in err


def test_server_command_delegates_with_the_sliced_argv(monkeypatch):
    seen = {}

    def fake_main(argv):
        seen["argv"] = argv
        return 0

    monkeypatch.setattr("bonnet.app.main.main", fake_main)

    code = main(["server", "--config", "x.toml", "--port", "9"])

    assert code == 0
    assert seen["argv"] == ["--config", "x.toml", "--port", "9"]


def test_gateway_command_delegates_with_the_sliced_argv(monkeypatch):
    seen = {}

    def fake_run(argv):
        seen["argv"] = argv
        return 0

    monkeypatch.setattr("bonnet.gateway.server.run", fake_run)

    code = main(["gateway", "--http", "--port", "9090"])

    assert code == 0
    assert seen["argv"] == ["--http", "--port", "9090"]


def test_delegate_returning_none_is_treated_as_success(monkeypatch):
    """Both delegates fall off the end with an implicit None on their normal
    (non-SystemExit) path today; the dispatcher must not propagate that as a
    truthy/odd exit code."""
    monkeypatch.setattr("bonnet.app.main.main", lambda argv: None)

    assert main(["server"]) == 0


def test_delegate_systemexit_propagates_unwrapped(tmp_path, monkeypatch):
    """`--dir`/config errors and the admin subcommands raise SystemExit(n)
    directly; the dispatcher must not swallow or reinterpret that."""
    import pytest

    # main() resolves a server home for logging before it gets to validating
    # --config, even though --config here makes that home otherwise
    # irrelevant — isolate it so this doesn't write into the real per-user dir.
    monkeypatch.setenv("BONNET_SERVER_HOME", str(tmp_path / "srvhome"))

    with pytest.raises(SystemExit) as exc:
        main(["server", "--config", "/does/not/exist/nope.toml"])

    assert exc.value.code == 1
