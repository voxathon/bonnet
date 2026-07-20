import pytest
import os
import time
from engine.ume import Ume, User, RECORD_SIZE
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


# ---------------------------------------------------------------------------
# Snapshot raw records (amalgamated from test_user_registry.py)
# ---------------------------------------------------------------------------

class TestUmeSnapshotRawRecords:

    def test_returns_exact_record_size(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        ume.put("alice", "origin.test", Identity.generate().public_key,
                record_origin="origin.test", relay="origin.test")
        records = ume.snapshot_raw_records()
        assert len(records) == 1
        assert len(records[0]) == RECORD_SIZE

    def test_excludes_deleted_slots(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        ume.put("alice", "origin.test", Identity.generate().public_key)
        ume.put("bob", "origin.test", Identity.generate().public_key)
        ume.delete(username="alice")
        records = ume.snapshot_raw_records()
        assert len(records) == 1

    def test_empty_file_returns_empty_list(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        records = ume.snapshot_raw_records()
        assert records == []

    def test_round_trip_through_decode(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        pub = Identity.generate().public_key
        ume.put("alice", "origin.test", pub,
                record_origin="origin.test", relay="origin.test")
        records = ume.snapshot_raw_records()
        user = User.decode(records[0])
        assert user.username == "alice"
        assert user.publickey == pub
        assert user.record_origin == "origin.test"


class TestUmeExportTimestamps:

    def test_export_includes_creation_time(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        ume.put("alice", "origin.test", Identity.generate().public_key,
                record_origin="orig", relay="rel")
        export_path = os.path.join(temp_dir, "export.txt")
        ume.export(export_path)
        with open(export_path, "r") as f:
            content = f.read()
        assert "creation_time=" in content
        assert "relay_time=" in content


class TestUmeUpsertCreationTime:

    def test_insert_with_creation_time(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        pub = Identity.generate().public_key
        ct = 1609459200
        ume.upsert_remote_user("remote1", "remote.test", pub,
                               "remote.test", "relay.test", creation_time=ct)
        user = ume.get("remote1")
        assert user.creation_time == ct

    def test_insert_without_creation_time_uses_now(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        pub = Identity.generate().public_key
        before = int(time.time())
        ume.upsert_remote_user("remote1", "remote.test", pub,
                               "remote.test", "relay.test")
        after = int(time.time())
        user = ume.get("remote1")
        assert before <= user.creation_time <= after

    def test_update_corrects_creation_time(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        pub = Identity.generate().public_key
        ume.upsert_remote_user("remote1", "remote.test", pub,
                               "remote.test", "relay.test", creation_time=1000)
        ume.upsert_remote_user("remote1", "remote.test", pub,
                               "remote.test", "relay.test", creation_time=2000)
        user = ume.get("remote1")
        assert user.creation_time == 2000

    def test_update_rejects_future_creation_time(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        pub = Identity.generate().public_key
        ume.upsert_remote_user("remote1", "remote.test", pub,
                               "remote.test", "relay.test", creation_time=1000)
        with pytest.raises(ValueError, match="future"):
            ume.upsert_remote_user("remote1", "remote.test", pub,
                                   "remote.test", "relay.test",
                                   creation_time=int(time.time()) + 10000)

    def test_update_rejects_excessive_correction(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        pub = Identity.generate().public_key
        ume.upsert_remote_user("remote1", "remote.test", pub,
                               "remote.test", "relay.test", creation_time=1000)
        with pytest.raises(ValueError, match="exceeds"):
            ume.upsert_remote_user("remote1", "remote.test", pub,
                                   "remote.test", "relay.test",
                                   creation_time=1000 + 200000,
                                   max_creation_time_correction=86400)

    def test_update_preserves_local_moderation_state(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        pub = Identity.generate().public_key
        ume.upsert_remote_user("remote1", "remote.test", pub,
                               "remote.test", "relay.test", creation_time=1000)
        ume.upd(username="remote1", new_banned=True)
        ume.upsert_remote_user("remote1", "remote.test", pub,
                               "remote.test", "relay.test", creation_time=2000)
        user = ume.get("remote1")
        assert user.is_banned is True

    def test_backward_compatible_without_creation_time(self, temp_dir):
        ume = Ume(os.path.join(temp_dir, "userfile"))
        pub = Identity.generate().public_key
        status = ume.upsert_remote_user("remote1", "remote.test", pub,
                                        "remote.test", "relay.test")
        assert status == 1
        status2 = ume.upsert_remote_user("remote1", "new_reg", pub,
                                         "remote.test", "new_relay")
        assert status2 == 2
