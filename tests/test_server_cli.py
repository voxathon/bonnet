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

"""CLI behavior tests for `bonnet.app.main.main`, the delegate `bonnet server`
dispatches to (see `bonnet.cli`). `--version` lives on the dispatcher now, not
here — see tests/test_cli.py."""

import asyncio
import os
import signal

import pytest

from bonnet.app.main import _serve_until_signal, main


@pytest.fixture(autouse=True)
def _isolated_server_home(tmp_path, monkeypatch):
    """Every test here calls `main()`, which resolves a server home (for
    logs, and for --config's default) even when an explicit --config makes
    the config path itself irrelevant to that home. Without this, a test
    that reaches that resolution with no isolation writes into the real
    per-user directory instead of tmp_path.

    Both layers are isolated, not just the env var: `--dir` writes its
    pointer file under `platformdirs.user_config_dir` regardless of any env
    var, so a test exercising `--dir` without mocking that too leaves a real,
    persistent pointer on the machine running the tests — silently redirecting
    a later real `bonnet server` invocation at a deleted tmp_path. Tests that
    specifically exercise home resolution override these with their own
    monkeypatch calls."""
    monkeypatch.setenv("BONNET_SERVER_HOME", str(tmp_path / "srvhome"))
    monkeypatch.setattr("platformdirs.user_config_dir", lambda *a, **k: str(tmp_path / "cfg"))
    monkeypatch.setattr("platformdirs.user_data_dir", lambda *a, **k: str(tmp_path / "data"))


def test_missing_config_prints_friendly_error(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    missing = str(tmp_path / "nope.toml")

    with pytest.raises(SystemExit) as exc:
        main(["--config", missing])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert f"config file not found: {missing}" in err
    # Regression for the chaos-testing report's #1.6: README's walkthrough
    # only ever mentions --init, so the primary suggestion here has to match
    # it rather than pointing exclusively at the lower-level --create-config.
    assert "--init" in err
    assert "--create-config" in err


def test_invalid_config_prints_friendly_error(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "config.toml"
    cfg.write_text('[server]\norigin = "test"\nport = 999999\n', encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        main(["--config", str(cfg)])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "invalid configuration" in err
    assert "port" in err


def test_malformed_toml_prints_friendly_error(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "config.toml"
    cfg.write_text("[server]\norigin = \nbroken", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        main(["--config", str(cfg)])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert f"could not parse {cfg}" in err
    assert "Traceback" not in err


def test_create_config_refuses_existing_file_friendly_error(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "config.toml"
    cfg.write_text("[server]\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        main(["--create-config", "--config", str(cfg)])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "already exists" in err
    assert "--force" in err
    assert os.path.exists(cfg)


# ---------------------------------------------------------------------------
# --check-config
# ---------------------------------------------------------------------------


def test_check_config_valid_file_prints_summary(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "config.toml"
    main(["--create-config", "--config", str(cfg)])
    capsys.readouterr()

    main(["--config", str(cfg), "--check-config"])

    out = capsys.readouterr().out
    assert f"OK: {cfg} is valid." in out
    assert "origin:" in out
    assert "listen:" in out
    assert "peers: 0" in out
    # The generated default ships five bootstrap rules (anonymous read,
    # unknown PERMISSIONS, unknown self-registration, registered-user read,
    # registered-user publish/board-create) so the documented first-run flow
    # works out of the box — see FirehoseConfig._write_default. Registered
    # users need their own read rule because the principal matchers are
    # mutually exclusive: once a key registers it stops matching `anonymous`,
    # and without this it could publish but not read anything back. The
    # `unknown` class gets PERMISSIONS so a caller can ask what it may do
    # before it has done anything.
    assert "acl rules: 5" in out


def test_check_config_does_not_start_server(tmp_path, capsys, monkeypatch):
    """--check-config must exit before touching data/boards/event_bodies dirs."""
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "config.toml"
    main(["--create-config", "--config", str(cfg)])
    capsys.readouterr()

    main(["--config", str(cfg), "--check-config"])

    assert not (tmp_path / "data").exists()


def test_check_config_missing_file_friendly_error(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    missing = str(tmp_path / "nope.toml")

    with pytest.raises(SystemExit) as exc:
        main(["--config", missing, "--check-config"])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert f"config file not found: {missing}" in err


def test_check_config_invalid_config_friendly_error(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "config.toml"
    cfg.write_text('[server]\norigin = "test"\nport = 999999\n', encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        main(["--config", str(cfg), "--check-config"])

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "invalid configuration" in captured.err
    assert "port" in captured.err
    assert "OK:" not in captured.out


def test_check_config_bad_acl_rule_friendly_error(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        '[server]\norigin = "bbs.test"\n\n'
        "[[acl]]\n"
        'effect = "allow"\n'
        'match.pubkey = "hex:not-hex"\n'
        'actions = ["read"]\n'
        'commands = ["*"]\n',
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as exc:
        main(["--config", str(cfg), "--check-config"])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "invalid configuration in" in err


def test_check_config_reports_unknown_acl_command(tmp_path, capsys, monkeypatch):
    """A typo'd command name in an ACL rule used to pass --check-config
    silently as fully valid - the rule can never match anything (allow
    grants nothing, deny blocks nothing), but nothing said so."""
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        '[server]\norigin = "bbs.test"\n\n'
        "[[acl]]\n"
        'effect = "allow"\n'
        "match.registered = true\n"
        'actions = ["read"]\n'
        'commands = ["PUBLSH_RECORD"]\n',
        encoding="utf-8",
    )

    main(["--config", str(cfg), "--check-config"])

    err = capsys.readouterr().err
    assert "unknown command 'PUBLSH_RECORD'" in err


def test_check_config_reports_unrecognized_keys(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "config.toml"
    cfg.write_text('[server]\norigin = "bbs.test"\ntypo_field = 1\n', encoding="utf-8")

    main(["--config", str(cfg), "--check-config"])

    captured = capsys.readouterr()
    assert "unrecognized config key 'server.typo_field'" in captured.err
    assert "unrecognized key(s) ignored" in captured.out


# ---------------------------------------------------------------------------
# --dir / home directory resolution
# ---------------------------------------------------------------------------


def test_dir_flag_sets_config_default(tmp_path, capsys, monkeypatch):
    """With no --config, --dir <path> makes <path>/config.toml the target —
    in the same invocation that set it, not just future ones."""
    monkeypatch.delenv("BONNET_SERVER_HOME", raising=False)
    home_dir = tmp_path / "srvhome"

    with pytest.raises(SystemExit) as exc:
        main(["--dir", str(home_dir)])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert f"config file not found: {os.path.join(str(home_dir), 'config.toml')}" in err


def test_dir_flag_persists_for_a_later_call_with_no_dir(tmp_path, capsys, monkeypatch):
    """--dir X --create-config, then a later call with neither --dir nor
    --config resolves to X/config.toml via the pointer file --dir wrote —
    the whole point of --dir over a one-shot env var."""
    monkeypatch.delenv("BONNET_SERVER_HOME", raising=False)
    monkeypatch.setattr("platformdirs.user_config_dir", lambda *a, **k: str(tmp_path / "cfg"))
    monkeypatch.setattr("platformdirs.user_data_dir", lambda *a, **k: str(tmp_path / "data"))
    home_dir = tmp_path / "srvhome"

    main(["--dir", str(home_dir), "--create-config"])
    capsys.readouterr()

    # --check-config exits cleanly either way and never starts the server,
    # so a resolution failure shows up as a friendly "not found" on stderr
    # rather than the process trying to bind a port.
    main(["--check-config"])

    out = capsys.readouterr().out
    assert f"OK: {os.path.join(str(home_dir), 'config.toml')} is valid." in out


# ---------------------------------------------------------------------------
# SIGTERM handling
# ---------------------------------------------------------------------------
#
# Regression for the chaos-testing report's #1.5: the prior SIGTERM handler
# called `raise KeyboardInterrupt` directly from inside signal.signal's
# synchronous callback, which Python delivers between arbitrary bytecode
# instructions - including inside asyncio's own shutdown machinery. ~2 of 6
# real `bonnet server` + SIGTERM runs produced "RuntimeError: coroutine
# ignored GeneratorExit" / "Task was destroyed but it is pending!"; another
# produced "RuntimeError: Event loop is closed". The process still exited,
# but it read exactly like a crash on an ordinary shutdown.
#
# These exercise `_serve_until_signal` directly with a stub server, rather
# than sending a real SIGTERM to a subprocess (which the project's test
# suite has no existing pattern for, and which SIGTERM's semantics on
# Windows make especially unreliable) - the property being tested is that
# the signal callback only ever schedules an ordinary loop callback, never
# raises into arbitrary code, which is fully exercised without the OS
# actually delivering anything.


class _StubArgs:
    port = None
    cert = None
    key = None


class _StubServerBeforeBind:
    """Stands in for a BonnetServer whose run() hasn't reached startup()
    yet - _uvicorn_server is still None, so SIGTERM has nothing bound to
    stop gracefully and must cancel the run() coroutine instead."""

    _uvicorn_server = None

    async def run(self, port=None, ssl_certfile=None, ssl_keyfile=None):
        await asyncio.sleep(10)
        return True  # pragma: no cover - only reached if not cancelled


class _StubUvicornServer:
    def __init__(self):
        self.should_exit = False


class _StubServerAfterBind:
    """Stands in for a BonnetServer whose run() has bound and is in its
    main loop - SIGTERM must flip should_exit, the same flag uvicorn's own
    signal handling would, and let run() notice it and return normally
    rather than being cancelled out from under it."""

    def __init__(self):
        self._uvicorn_server = _StubUvicornServer()

    async def run(self, port=None, ssl_certfile=None, ssl_keyfile=None):
        for _ in range(200):
            if self._uvicorn_server.should_exit:
                return True
            await asyncio.sleep(0.01)
        raise AssertionError("should_exit was never observed")  # pragma: no cover


async def test_sigterm_before_bind_cancels_cleanly():
    server = _StubServerBeforeBind()
    task = asyncio.ensure_future(_serve_until_signal(server, _StubArgs()))
    await asyncio.sleep(0.05)

    # signal.raise_signal, not os.kill(os.getpid(), ...): on Windows the
    # latter calls TerminateProcess unconditionally for an arbitrary signum,
    # bypassing any registered Python handler entirely rather than invoking
    # it - this needs the handler to actually run, in-process, on both
    # platforms.
    signal.raise_signal(signal.SIGTERM)

    result = await asyncio.wait_for(task, timeout=5)
    assert result is True


async def test_sigterm_after_bind_sets_should_exit_without_cancelling():
    server = _StubServerAfterBind()
    task = asyncio.ensure_future(_serve_until_signal(server, _StubArgs()))
    await asyncio.sleep(0.05)

    # signal.raise_signal, not os.kill(os.getpid(), ...): on Windows the
    # latter calls TerminateProcess unconditionally for an arbitrary signum,
    # bypassing any registered Python handler entirely rather than invoking
    # it - this needs the handler to actually run, in-process, on both
    # platforms.
    signal.raise_signal(signal.SIGTERM)

    result = await asyncio.wait_for(task, timeout=5)
    assert result is True
    assert server._uvicorn_server.should_exit is True
