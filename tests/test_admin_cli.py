"""One-shot `bonnet admin` CLI: headless root access for background services."""

import os

import pytest

from bonnet.app.admin_cli import main as admin_main
from bonnet.app.console import OperatorConsole
from bonnet.app.server import BonnetServer
from bonnet.core.config import FirehoseConfig

BASE_TOML = """\
[server]
origin = "bbs.test"
hostname = "bbs.test"
data_dir = "{data}"
boards_dir = "{boards}"
events_bodies_dir = "{events}"
port = 2272
acl_poll_interval_seconds = 30

[[acl]]
effect = "allow"
match.registered = true
actions = ["read"]
commands = ["PERMISSIONS"]
boards = ["*"]
"""


def _q(p) -> str:
    return str(p).replace("\\", "/")


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("BONNET_SERVER_HOME", str(tmp_path / "srvhome"))
    monkeypatch.setattr("platformdirs.user_config_dir", lambda *a, **k: str(tmp_path / "cfg"))
    monkeypatch.setattr("platformdirs.user_data_dir", lambda *a, **k: str(tmp_path / "data"))
    data = tmp_path / "data"
    boards = tmp_path / "boards"
    events = tmp_path / "event_bodies"
    for d in (data, boards, events):
        os.makedirs(d, exist_ok=True)
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        BASE_TOML.format(data=_q(data), boards=_q(boards), events=_q(events)),
        encoding="utf-8",
    )
    # Boot once so the server identity + root registration exist.
    config = FirehoseConfig.load(str(cfg_path))
    s = BonnetServer(config, config_path=str(cfg_path))
    s.close()
    return cfg_path


def test_admin_whoami(home, capsys):
    assert admin_main(["--config", str(home), "whoami"]) == 0
    out = capsys.readouterr().out
    assert "administrator" in out


def test_admin_grant_role_and_ban_status(home, capsys):
    pk = os.urandom(32).hex()
    assert admin_main(["--config", str(home), "grant-role", pk, "moderator", "newbie"]) == 0
    capsys.readouterr()
    assert admin_main(["--config", str(home), "ban-status", pk]) == 0
    assert "No pending punishments" in capsys.readouterr().out


def test_admin_create_board_headless_flag(home, capsys):
    assert (
        admin_main(["--config", str(home), "create-board", "general", "--display-name=General"])
        == 0
    )
    assert "created" in capsys.readouterr().out


def test_admin_publish_article_requires_flags_headless(home, capsys):
    assert admin_main(["--config", str(home), "create-board", "general"]) == 0
    capsys.readouterr()
    rc = admin_main(["--config", str(home), "publish-article", "general"])
    assert rc == 1
    assert "--subject" in capsys.readouterr().out


def test_admin_publish_article_headless_full(home, capsys, tmp_path):
    assert admin_main(["--config", str(home), "create-board", "general"]) == 0
    capsys.readouterr()
    body = tmp_path / "body.txt"
    body.write_text("hello from admin", encoding="utf-8")
    assert (
        admin_main(
            [
                "--config",
                str(home),
                "publish-article",
                "general",
                "--subject=Hello world",
                f"--body-file={body}",
                "--tags=a,b",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "published" in out


def test_admin_register_user(home, capsys):
    assert admin_main(["--config", str(home), "register-user", "boss"]) == 0
    assert "boss" in capsys.readouterr().out


def test_admin_quoted_subject_with_spaces(home, capsys):
    # argv-level quoting (shell) must survive as one flag value.
    assert admin_main(["--config", str(home), "create-board", "general"]) == 0
    capsys.readouterr()
    assert (
        admin_main(
            [
                "--config",
                str(home),
                "publish-article",
                "general",
                "--subject=Hello world today",
                "--body=some body",
            ]
        )
        == 0
    )
    assert "Hello world today" in capsys.readouterr().out


def test_admin_unknown_command_returns_error(home, capsys):
    assert admin_main(["--config", str(home), "frobnicate"]) == 1
    assert "Unknown command" in capsys.readouterr().out


def test_admin_missing_config_errors(capsys, tmp_path):
    with pytest.raises(SystemExit):
        admin_main(["--config", str(tmp_path / "nope.toml"), "whoami"])


def test_admin_no_command_prints_help(home, capsys):
    assert admin_main(["--config", str(home)]) == 2


def test_headless_console_never_prompts(tmp_path, monkeypatch):
    """dispatch_argv in headless mode must not call input()."""
    monkeypatch.setenv("BONNET_SERVER_HOME", str(tmp_path / "srvhome"))
    config = FirehoseConfig(
        origin="bbs.test",
        hostname="bbs.test",
        data_dir=str(tmp_path / "data"),
        boards_dir=str(tmp_path / "boards"),
        events_bodies_dir=str(tmp_path / "event_bodies"),
    )
    for d in (config.data_dir, config.boards_dir, config.events_bodies_dir):
        os.makedirs(d, exist_ok=True)
    s = BonnetServer(config)
    try:
        console = OperatorConsole(s, headless=True)
        monkeypatch.setattr(
            "builtins.input",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt")),
        )
        assert console.dispatch_argv(["create-board", "b1"]) == "Board 'b1' created."
        assert "--subject" in console.dispatch_argv(["publish-article", "b1"])
    finally:
        s.close()
