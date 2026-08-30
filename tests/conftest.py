"""Shared test setup.

The gateway keeps durable state (pinned origin keys, joined origins, identities)
in a per-user data directory by design, so that a gateway launched from an
arbitrary working directory finds the same store every time. That default is
right in production and wrong in a test run, where it means the suite writes
into the developer's real Bonnet state. Redirect it for every test.
"""

import pytest


@pytest.fixture(autouse=True)
def isolate_gateway_state(tmp_path, monkeypatch):
    """Point gateway state at a per-test directory.

    Autouse and unconditional: a test that needs a specific path sets it after
    this runs, and one that never touches gateway state pays only an unused
    environment variable. Making it opt-in would mean any future test that
    reaches the gateway by accident silently pollutes the real store, which is
    exactly the failure this exists to prevent.
    """
    monkeypatch.setenv("BONNET_GATEWAY_DIR", str(tmp_path / "gateway-state"))
