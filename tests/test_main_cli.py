"""CLI behavior tests for the server entry point (bonnet.app.main)."""

import os

import pytest

from bonnet.app.main import main


def test_version_flag_prints_version_and_exits(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])

    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert out.startswith("bonnet-server ")
    assert len(out.split()) == 2


def test_missing_config_prints_friendly_error(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    missing = str(tmp_path / "nope.toml")

    with pytest.raises(SystemExit) as exc:
        main(["--config", missing])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert f"config file not found: {missing}" in err
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


def test_check_config_reports_unrecognized_keys(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "config.toml"
    cfg.write_text('[server]\norigin = "bbs.test"\ntypo_field = 1\n', encoding="utf-8")

    main(["--config", str(cfg), "--check-config"])

    captured = capsys.readouterr()
    assert "unrecognized config key 'server.typo_field'" in captured.err
    assert "unrecognized key(s) ignored" in captured.out
