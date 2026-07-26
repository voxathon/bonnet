"""Tests for server lifecycle: construction, root registration, and close."""

import os
import pytest

from core.config import FirehoseConfig
from core.crypto import Identity


@pytest.fixture
def config(tmp_path):
    return FirehoseConfig(
        origin="bbs.test",
        hostname="bbs.test",
        data_dir=str(tmp_path / "data"),
        boards_dir=str(tmp_path / "boards"),
        events_bodies_dir=str(tmp_path / "event_bodies"),
        port=2272,
        tls_enabled=False,
    )


@pytest.fixture
def server(config):
    os.makedirs(config.data_dir, exist_ok=True)
    os.makedirs(config.boards_dir, exist_ok=True)
    os.makedirs(config.events_bodies_dir, exist_ok=True)

    from app.server import BonnetFirehoseServer
    s = BonnetFirehoseServer(config)
    yield s
    try:
        s.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

def test_server_constructs(server):
    """Server constructs with all components wired."""
    assert server.server_identity is not None
    assert server.config.origin == "bbs.test"
    assert server.firehose is not None
    assert server.nav is not None
    assert server.users is not None
    assert server.policy is not None
    assert server.body_store is not None
    assert server.dispatcher is not None
    assert server.command_handler is not None
    assert server.http_server is not None
    assert server.replay_ledger is not None
    assert server.rate_limiter is not None


def test_server_identity_persisted(server, config):
    """Server identity is persisted to disk and stable across restarts."""
    identity_path = config.identity_path
    assert os.path.exists(identity_path)

    with open(identity_path, "rb") as f:
        saved_key = f.read()
    assert saved_key == server.server_identity.private_key


# ---------------------------------------------------------------------------
# Root registration
# ---------------------------------------------------------------------------

def test_root_user_registered(server):
    """Root user is registered on first startup."""
    user = server.users.get_user_by_pubkey("bbs.test", server.server_identity.public_key)
    assert user is not None
    assert user["username"] == "root"
    assert user.get("flags", 0) & 0x01, "root should have admin flag"


def test_root_registration_idempotent(server, config):
    """Restarting the server does not create a second root user."""
    server_identity = server.server_identity

    from app.server import BonnetFirehoseServer
    server2 = BonnetFirehoseServer(config)
    try:
        user = server2.users.get_user_by_pubkey("bbs.test", server_identity.public_key)
        assert user is not None
        assert user["username"] == "root"

        all_users = server2.users.list_users("bbs.test")
        root_users = [u for u in all_users if u["username"] == "root"]
        assert len(root_users) == 1
    finally:
        server2.close()


# ---------------------------------------------------------------------------
# Close
# ---------------------------------------------------------------------------

def test_double_close_safe(server):
    """close() can be called twice without raising."""
    server.close()
    server.close()


def test_close_releases_resources(server):
    """After close, SQLite connections are closed."""
    server.close()

    with pytest.raises(Exception):
        server.firehose.get_highest_seq("bbs.test")

    with pytest.raises(Exception):
        server.nav.list_boards()


# ---------------------------------------------------------------------------
# Identity persistence across restart
# ---------------------------------------------------------------------------

def test_identity_stable_across_restart(config):
    """Server identity is the same after restart."""
    os.makedirs(config.data_dir, exist_ok=True)
    os.makedirs(config.boards_dir, exist_ok=True)
    os.makedirs(config.events_bodies_dir, exist_ok=True)

    from app.server import BonnetFirehoseServer
    s1 = BonnetFirehoseServer(config)
    pubkey1 = s1.server_identity.public_key
    s1.close()

    s2 = BonnetFirehoseServer(config)
    pubkey2 = s2.server_identity.public_key
    s2.close()

    assert pubkey1 == pubkey2
