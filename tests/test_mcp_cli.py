"""Tests for the bonnet-mcp entry-point shim's missing-extra behavior."""

import sys

import pytest

from bonnet.client import _cli


def test_missing_extra_prints_install_hint(capsys):
    # sys.modules is restored by hand rather than with monkeypatch.setitem.
    # Popping "fastmcp" first made monkeypatch record it as absent, so its
    # teardown deleted the entry this test had already restored — leaving
    # fastmcp.server in sys.modules parented to an orphaned module object.
    # Any later test touching fastmcp.server then failed with "module
    # 'fastmcp' has no attribute 'server'", far from the cause.
    keys = (
        "bonnet.client.server",
        "bonnet.client.tools",
        "bonnet.client.resources",
        "fastmcp",
    )
    saved = {k: sys.modules.get(k) for k in keys}
    for k in keys:
        sys.modules.pop(k, None)
    sys.modules["fastmcp"] = None  # force the ImportError _cli.run() handles
    try:
        with pytest.raises(SystemExit) as exc:
            _cli.run()
    finally:
        for k, v in saved.items():
            if v is not None:
                sys.modules[k] = v
            else:
                sys.modules.pop(k, None)

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
