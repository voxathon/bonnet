from src.client.identity import IdentityStore
import os

store = IdentityStore("test_identities.db")
try:
    print("Registering user...")
    priv, pub = store.register("alice", "secretpassword")
    print(f"Pubkey hex: {pub.hex()}")

    print("Verifying password...")
    assert store.verify_password("alice", "secretpassword") == True
    assert store.verify_password("alice", "wrongpassword") == False
    print("Password verification passed.")

    print("Retrieving private key...")
    recovered_priv = store.get_private_key("alice", "secretpassword")
    assert priv == recovered_priv
    print("Private key recovered successfully.")

    try:
        store.get_private_key("alice", "wrongpassword")
        print("FAIL: Should not recover key with wrong password")
    except ValueError:
        print("Correctly rejected wrong password for key recovery.")
finally:
    store.close()
    if os.path.exists("test_identities.db"):
        os.remove("test_identities.db")
