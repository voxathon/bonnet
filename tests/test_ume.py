import pytest
import os
import time
from engine.ume import Ume, User
from core.crypto import Identity

@pytest.fixture
def ume_setup(temp_dir):
    userfile = os.path.join(temp_dir, 'userfile')
    ume = Ume(userfile)
    yield ume

def test_ume_put_and_get(ume_setup):
    ume = ume_setup
    pubkey = Identity.generate().public_key
    user = ume.put(
        username="alice",
        registrar="test_origin",
        publickey=pubkey,
        record_origin="test_origin",
        relay="test_origin",
        is_administrator=True
    )

    assert user is not None
    assert user.username == "alice"
    assert user.is_administrator is True

    # Get by username
    fetched = ume.get(username="alice")
    assert fetched is not None
    assert fetched.publickey == pubkey

    # Get by pubkey
    fetched_by_key = ume.get(publickey=pubkey)
    assert fetched_by_key is not None
    assert fetched_by_key.username == "alice"

def test_ume_update(ume_setup):
    ume = ume_setup
    pubkey = Identity.generate().public_key
    ume.put("bob", "test_origin", pubkey)

    success = ume.upd(username="bob", new_registrar="new_origin", new_banned=True)
    assert success is True

    updated = ume.get(username="bob")
    assert updated.registrar == "new_origin"
    assert updated.is_banned is True

def test_ume_delete(ume_setup):
    ume = ume_setup
    pubkey = Identity.generate().public_key
    ume.put("charlie", "test_origin", pubkey)

    assert ume.get("charlie") is not None

    success = ume.delete(username="charlie")
    assert success is True

    assert ume.get("charlie") is None

def test_ume_ensure_root(ume_setup):
    ume = ume_setup
    pubkey1 = Identity.generate().public_key

    # Creates root
    root1 = ume.ensure_root_user("test_origin", pubkey1)
    assert root1 is not None
    assert root1.username == "root"
    assert root1.publickey == pubkey1
    assert root1.is_administrator is True

    # Updates existing root's key
    pubkey2 = Identity.generate().public_key
    root2 = ume.ensure_root_user("test_origin", pubkey2)
    assert root2 is not None
    assert root2.username == "root"
    assert root2.publickey == pubkey2

def test_ume_upsert_remote_user(ume_setup):
    ume = ume_setup
    pubkey = Identity.generate().public_key

    # Insert new
    status = ume.upsert_remote_user("remote1", "remote_reg", pubkey, "remote_origin", "remote_relay")
    assert status == 1

    fetched = ume.get("remote1")
    assert fetched is not None
    assert fetched.record_origin == "remote_origin"

    # Update existing (same origin)
    status2 = ume.upsert_remote_user("remote1", "new_reg", pubkey, "remote_origin", "new_relay")
    assert status2 == 2

    fetched2 = ume.get("remote1")
    assert fetched2.registrar == "new_reg"
    assert fetched2.relay == "new_relay"

    # Conflict (different origin)
    status3 = ume.upsert_remote_user("remote1", "bad_reg", pubkey, "bad_origin", "bad_relay")
    assert status3 == 0

def test_ume_export(ume_setup, temp_dir):
    ume = ume_setup
    pubkey = Identity.generate().public_key
    ume.put("exportuser", "test_origin", pubkey, record_origin="orig", relay="rel")

    export_path = os.path.join(temp_dir, 'export.txt')
    ume.export(export_path)

    assert os.path.exists(export_path)
    with open(export_path, 'r') as f:
        content = f.read()

    assert "exportuser" in content
    assert "test_origin" in content
    assert pubkey.hex() in content
