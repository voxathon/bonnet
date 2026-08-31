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
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "gateway-state"))


@pytest.fixture(autouse=True)
def isolate_gateway_context():
    """Restore the gateway's per-caller ContextVars after every test.

    Sibling of isolate_gateway_state, and the same argument one layer in: that
    one keeps a test from writing into another's *files*, this one keeps a test
    from writing into another's *context*.

    The cursor, active origin and selected identity are ContextVars, which is
    correct for a process serving several callers at once — but a pytest run is
    one long-lived context, so anything a test leaves set is visible to every
    test that follows. It stays invisible until two modules disagree about it:
    a session test that opened a board left `cursor.current_board` at 'general',
    and a gating test asserting the cursor was untouched then failed — in serial
    order only, and only when both modules ran, which is the worst shape a test
    failure can have.

    Snapshot-and-restore rather than reset-to-default, so a fixture that
    deliberately establishes state for the test it wraps still sees it.
    """
    try:
        from bonnet.gateway import cursor, tools
        from bonnet.gateway.paths import current_tenant
    except ImportError:
        # fastmcp/bcrypt absent — the gateway tests are skipped anyway, and
        # there are no ContextVars to isolate.
        yield
        return

    variables = (
        current_tenant,
        tools._origin_loaded,
        tools.current_origin,
        tools.current_origin_url,
        tools.current_origin_verify,
        tools.current_username,
        tools.current_password,
        cursor.current_board,
        cursor.current_article_board,
        cursor.current_article_num,
        cursor.current_article_id,
    )
    before = [(var, var.get()) for var in variables]
    try:
        yield
    finally:
        for var, value in before:
            var.set(value)
