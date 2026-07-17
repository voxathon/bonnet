import pytest
import os
from client.identity import IdentityStore

def test_identity_store():
    store = IdentityStore("test_identities.db")
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
        if os.path.exists("test_identities.db"):
            os.remove("test_identities.db")
