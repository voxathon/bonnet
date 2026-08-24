import pytest

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
