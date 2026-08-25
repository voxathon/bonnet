"""Tests for the bonnet-mcp entry-point shim's missing-extra behavior."""

import sys

import pytest

from bonnet.client import _cli


def test_missing_extra_prints_install_hint(monkeypatch, capsys):
    saved = {
        k: sys.modules.pop(k, None)
        for k in (
            "bonnet.client.server",
            "bonnet.client.tools",
            "bonnet.client.resources",
            "fastmcp",
        )
    }
    monkeypatch.setitem(sys.modules, "fastmcp", None)
    try:
        with pytest.raises(SystemExit) as exc:
            _cli.run()
    finally:
        for k, v in saved.items():
            if v is not None:
                sys.modules[k] = v

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "bonnet[client]" in err


def test_run_delegates_to_server_run(monkeypatch):
    pytest.importorskip("fastmcp")

    import bonnet.client.server as srv

    called = []
    monkeypatch.setattr(srv, "run", lambda: called.append(True))

    _cli.run()

    assert called == [True]
