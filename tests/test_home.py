"""core.home: the three-step directory resolution shared by `server` and
`gateway` — env var, then the pointer file `--dir` writes, then the
platformdirs per-user default. See core/home.py for the precedence rationale.
"""

from bonnet.core import home


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr("platformdirs.user_config_dir", lambda *a, **k: str(tmp_path / "cfg"))
    monkeypatch.setattr("platformdirs.user_data_dir", lambda *a, **k: str(tmp_path / "data"))
    monkeypatch.delenv("BONNET_SERVER_HOME", raising=False)
    monkeypatch.delenv("BONNET_GATEWAY_HOME", raising=False)


def test_default_is_platformdirs_data_dir_plus_component(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)

    assert home.resolve_home("server", "BONNET_SERVER_HOME") == str(tmp_path / "data" / "server")
    assert home.resolve_home("gateway", "BONNET_GATEWAY_HOME") == str(tmp_path / "data" / "gateway")


def test_env_var_wins_over_default(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setenv("BONNET_SERVER_HOME", str(tmp_path / "explicit"))

    assert home.resolve_home("server", "BONNET_SERVER_HOME") == str(tmp_path / "explicit")


def test_pointer_file_wins_over_default(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)

    home.set_home("server", str(tmp_path / "remembered"))

    assert home.resolve_home("server", "BONNET_SERVER_HOME") == str(tmp_path / "remembered")


def test_env_var_wins_over_pointer_file(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)

    home.set_home("server", str(tmp_path / "remembered"))
    monkeypatch.setenv("BONNET_SERVER_HOME", str(tmp_path / "explicit"))

    assert home.resolve_home("server", "BONNET_SERVER_HOME") == str(tmp_path / "explicit")


def test_set_home_is_picked_up_by_a_fresh_resolve_call(tmp_path, monkeypatch):
    """The whole point of --dir: set it once, a later, unrelated call to
    resolve_home (a different process, in reality) sees it."""
    _isolate(tmp_path, monkeypatch)

    before = home.resolve_home("gateway", "BONNET_GATEWAY_HOME")
    home.set_home("gateway", str(tmp_path / "chosen"))
    after = home.resolve_home("gateway", "BONNET_GATEWAY_HOME")

    assert before != after
    assert after == str(tmp_path / "chosen")


def test_components_do_not_collide(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)

    home.set_home("server", str(tmp_path / "srv"))
    home.set_home("gateway", str(tmp_path / "gw"))

    assert home.resolve_home("server", "BONNET_SERVER_HOME") == str(tmp_path / "srv")
    assert home.resolve_home("gateway", "BONNET_GATEWAY_HOME") == str(tmp_path / "gw")


def test_set_home_stores_an_absolute_path(tmp_path, monkeypatch):
    import os

    _isolate(tmp_path, monkeypatch)
    monkeypatch.chdir(tmp_path)

    home.set_home("server", "relative-dir")

    resolved = home.resolve_home("server", "BONNET_SERVER_HOME")
    assert resolved == os.path.abspath("relative-dir")
    assert os.path.isabs(resolved)
