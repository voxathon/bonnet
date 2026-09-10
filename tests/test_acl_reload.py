"""ACL hot-reload: poller + fail-closed reload + console command."""

import asyncio
import os

import pytest

from bonnet.app.console import OperatorConsole
from bonnet.app.server import BonnetServer
from bonnet.core.acl import AuthContext
from bonnet.core.config import FirehoseConfig


def _write(path, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


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
def live_server(tmp_path):
    data = tmp_path / "data"
    boards = tmp_path / "boards"
    events = tmp_path / "event_bodies"
    for d in (data, boards, events):
        os.makedirs(d, exist_ok=True)
    cfg_path = tmp_path / "config.toml"
    _write(
        str(cfg_path),
        BASE_TOML.format(data=_q(data), boards=_q(boards), events=_q(events)),
    )
    config = FirehoseConfig.load(str(cfg_path))
    s = BonnetServer(config, config_path=str(cfg_path))
    yield s, cfg_path
    try:
        s.close()
    except Exception:
        pass


def test_reload_picks_up_new_rule(live_server):
    s, cfg_path = live_server
    ctx = AuthContext(is_registered=True)
    assert s.acl.check(ctx, "read", command="PERMISSIONS", board="general")
    assert not s.acl.check(ctx, "read", command="ARTICLE_GET", board="general")

    text = open(cfg_path, encoding="utf-8").read()
    text += """
[[acl]]
effect = "allow"
match.registered = true
actions = ["read"]
commands = ["ARTICLE_GET"]
boards = ["*"]
"""
    _write(str(cfg_path), text)
    result = s.reload_acl_from_disk(reason="test")
    assert "Reloaded ACL" in result
    assert s.acl.check(ctx, "read", command="ARTICLE_GET", board="general")
    # Same object the command handler reads through.
    assert s.command_handler._acl is s.acl


def test_reload_torn_toml_keeps_old_rules(live_server):
    s, cfg_path = live_server
    before = len(s.acl._rules)
    _write(str(cfg_path), "[[acl\nbroken = tru")
    result = s.reload_acl_from_disk(reason="test")
    assert result.startswith("Error:")
    assert len(s.acl._rules) == before


def test_reload_console_command(live_server):
    s, _ = live_server
    console = OperatorConsole(s)
    result = console.dispatch_local_command("reload-acl")
    assert "Reloaded ACL" in result


def test_reload_no_config_path(tmp_path):
    from bonnet.app.server import BonnetServer as _BS

    os.makedirs(tmp_path / "data", exist_ok=True)
    os.makedirs(tmp_path / "boards", exist_ok=True)
    os.makedirs(tmp_path / "event_bodies", exist_ok=True)
    config = FirehoseConfig(
        origin="bbs.test",
        hostname="bbs.test",
        data_dir=str(tmp_path / "data"),
        boards_dir=str(tmp_path / "boards"),
        events_bodies_dir=str(tmp_path / "event_bodies"),
    )
    s = _BS(config)
    try:
        assert s.reload_acl_from_disk().startswith("Error:")
    finally:
        try:
            s.close()
        except Exception:
            pass


def test_config_validation():
    c = FirehoseConfig(acl_poll_interval_seconds=0)
    c.validate()
    with pytest.raises(ValueError):
        FirehoseConfig(acl_poll_interval_seconds=-1).validate()
    with pytest.raises(ValueError):
        FirehoseConfig(acl_poll_interval_seconds=True).validate()


def test_watcher_two_tick_settle(live_server):
    s, cfg_path = live_server
    s.config.acl_poll_interval_seconds = 1
    s._acl_watched_at = s._acl_snapshot()
    s._acl_pending = None

    async def _run_two_ticks():
        task = asyncio.ensure_future(s._watch_acl_periodically())
        await asyncio.sleep(0.2)
        # Mutate mid-watch: first tick pends, second tick applies.
        text = open(cfg_path, encoding="utf-8").read()
        text += """
[[acl]]
effect = "allow"
match.registered = true
actions = ["read"]
commands = ["ARTICLE_GET"]
boards = ["*"]
"""
        _write(str(cfg_path), text)
        await asyncio.sleep(2.6)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(_run_two_ticks())
    ctx = AuthContext(is_registered=True)
    assert s.acl.check(ctx, "read", command="ARTICLE_GET", board="general")
