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
