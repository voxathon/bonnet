"""Shared test setup.

The client keeps durable state (pinned origin keys, joined boards, identities)
in a per-user data directory by design, so that a bridge launched from an
arbitrary working directory finds the same store every time. That default is
right in production and wrong in a test run, where it means the suite writes
into the developer's real Bonnet state. Redirect it for every test.
"""

import pytest


@pytest.fixture(autouse=True)
def isolate_client_state(tmp_path, monkeypatch):
    """Point client state at a per-test directory.

    Autouse and unconditional: a test that needs a specific path sets it after
    this runs, and one that never touches client state pays only an unused
    environment variable. Making it opt-in would mean any future test that
    reaches the client by accident silently pollutes the real store, which is
    exactly the failure this exists to prevent.
    """
    monkeypatch.setenv("BONNET_CLIENT_DIR", str(tmp_path / "client-state"))
