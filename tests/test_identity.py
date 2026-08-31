import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("cryptography")
pytest.importorskip("fastmcp")

from bonnet.gateway import tenancy, tools
from bonnet.gateway.identity import IdentityStore

ORIGIN = "bbs.test"


def test_identity_store(tmp_path):
    store = IdentityStore(str(tmp_path / "identities.db"))
    try:
        # Register User
        priv, pub = store.register(ORIGIN, "alice", "secretpassword")
        assert pub is not None
        assert priv is not None

        # Verify Password
        assert store.verify_password(ORIGIN, "alice", "secretpassword")
        assert not store.verify_password(ORIGIN, "alice", "wrongpassword")

        # Get Private Key
        recovered_priv = store.get_private_key(ORIGIN, "alice", "secretpassword")
        assert priv == recovered_priv

        # Verify Wrong Password Failure
        with pytest.raises(ValueError, match="Invalid password"):
            store.get_private_key(ORIGIN, "alice", "wrongpassword")
    finally:
        store.close()


def test_same_username_on_two_origins_is_two_keypairs(tmp_path):
    """Usernames only mean anything within the registrar that accepted them —
    the same name on two origins must not share key material."""
    store = IdentityStore(str(tmp_path / "identities.db"))
    try:
        priv_a, pub_a = store.register("origin-a", "alice")
        priv_b, pub_b = store.register("origin-b", "alice")

        assert priv_a != priv_b
        assert pub_a != pub_b
        assert store.get_pubkey("origin-a", "alice") == pub_a
        assert store.get_pubkey("origin-b", "alice") == pub_b
    finally:
        store.close()


def test_identity_store_env_var_path(tmp_path, monkeypatch):
    db_path = str(tmp_path / "custom" / "identities.db")
    monkeypatch.setenv("BONNET_IDENTITIES_DB", db_path)

    tenancy.reset_store_cache()
    try:
        store = tools._get_identity_store()
        assert str(store.db_path) == db_path
    finally:
        tenancy.reset_store_cache()


def test_identity_store_defaults_into_the_tenant_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("BONNET_IDENTITIES_DB", raising=False)
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "gw"))

    tenancy.reset_store_cache()
    try:
        store = tools._get_identity_store()
        assert str(store.db_path) == str(
            tmp_path / "gw" / "tenants" / tenancy.DEFAULT_TENANT / "identities.db"
        )
    finally:
        tenancy.reset_store_cache()


def test_identities_db_override_is_ignored_for_other_tenants(tmp_path, monkeypatch):
    """$BONNET_IDENTITIES_DB names one file and predates tenancy.

    Honouring it for every tenant would point them all at a single identity
    store, which is exactly the isolation failure the per-tenant layout
    exists to prevent — so it applies to the default tenant only.
    """
    override = str(tmp_path / "legacy" / "identities.db")
    monkeypatch.setenv("BONNET_IDENTITIES_DB", override)
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "gw"))

    tenancy.reset_store_cache()
    token = tenancy.current_tenant.set("alice")
    try:
        store = tools._get_identity_store()
        assert str(store.db_path) != override
        assert str(store.db_path) == str(tmp_path / "gw" / "tenants" / "alice" / "identities.db")
    finally:
        tenancy.current_tenant.reset(token)
        tenancy.reset_store_cache()
