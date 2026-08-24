from pathlib import Path

import pytest

from bonnet.client import tools
from bonnet.client.identity import IdentityStore

pytestmark = pytest.mark.slow


def test_identity_store(tmp_path):
    store = IdentityStore(str(tmp_path / "identities.db"))
    try:
        # Register User
        priv, pub = store.register("alice", "secretpassword")
        assert pub is not None
        assert priv is not None

        # Verify Password
        assert store.verify_password("alice", "secretpassword")
        assert not store.verify_password("alice", "wrongpassword")

        # Get Private Key
        recovered_priv = store.get_private_key("alice", "secretpassword")
        assert priv == recovered_priv

        # Verify Wrong Password Failure
        with pytest.raises(ValueError, match="Invalid password"):
            store.get_private_key("alice", "wrongpassword")
    finally:
        store.close()


def test_identity_store_env_var_path(tmp_path, monkeypatch):
    db_path = str(tmp_path / "custom" / "identities.db")
    monkeypatch.setenv("BONNET_IDENTITIES_DB", db_path)

    original = tools.identity_store
    tools.identity_store = None
    try:
        store = tools._get_identity_store()
        assert str(store.db_path) == db_path
    finally:
        if tools.identity_store is not None:
            tools.identity_store.close()
        tools.identity_store = original


def test_identity_store_default_path_when_unset(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("BONNET_IDENTITIES_DB", raising=False)

    original = tools.identity_store
    tools.identity_store = None
    try:
        store = tools._get_identity_store()
        assert str(store.db_path) == str(Path(IdentityStore.DB_PATH))
    finally:
        if tools.identity_store is not None:
            tools.identity_store.close()
        tools.identity_store = original
