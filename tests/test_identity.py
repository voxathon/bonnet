import sqlite3
from pathlib import Path

import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("cryptography")
pytest.importorskip("fastmcp")

from bonnet.client import tools
from bonnet.client.identity import IdentityStore

pytestmark = pytest.mark.slow


def test_identity_store_migrates_legacy_yescrypt_hash_column(tmp_path):
    """A DB created before the yescrypt_hash -> scrypt_hash rename must keep
    working: the column gets renamed in place on open, not left stale."""
    db_path = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE identities (
            username TEXT PRIMARY KEY,
            yescrypt_hash TEXT NOT NULL,
            auth_salt BLOB NOT NULL,
            key_salt BLOB NOT NULL,
            encrypted_private_key BLOB NOT NULL,
            public_key BLOB NOT NULL,
            registered INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

    store = IdentityStore(db_path)
    try:
        columns = {row[1] for row in store._get_conn().execute("PRAGMA table_info(identities)")}
        assert "scrypt_hash" in columns
        assert "yescrypt_hash" not in columns

        priv, pub = store.register("alice", "secretpassword")
        assert store.verify_password("alice", "secretpassword")
        assert store.get_private_key("alice", "secretpassword") == priv
    finally:
        store.close()


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
    monkeypatch.delenv("BONNET_IDENTITIES_DB", raising=False)
    fake_default = str(tmp_path / "default" / "identities.db")
    monkeypatch.setattr(IdentityStore, "default_db_path", staticmethod(lambda: fake_default))

    original = tools.identity_store
    tools.identity_store = None
    try:
        store = tools._get_identity_store()
        assert str(store.db_path) == str(Path(IdentityStore.default_db_path()))
    finally:
        if tools.identity_store is not None:
            tools.identity_store.close()
        tools.identity_store = original
