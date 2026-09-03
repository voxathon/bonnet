# Copyright 2026 The Bonnet Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for depeering and origin lifecycle: depeer, purge-origin, reset-key."""

import os

import pytest

from bonnet.app.console import OperatorConsole
from bonnet.core.bodies import BodyStore
from bonnet.core.config import FirehoseConfig
from bonnet.core.crypto import Identity
from bonnet.core.firehose import KIND_ARTICLE, FirehoseStore
from bonnet.core.record import (
    Intent,
    MetadataMap,
    compute_body_hash,
    encode_intent,
    metadata_bytes,
    metadata_text,
    sign_intent,
)
from bonnet.net.firehose_sync import SyncClient

ORIGIN = Identity.from_private_key(bytes(range(1, 33)))
ACTOR = Identity.from_private_key(bytes(range(10, 42)))
ORIGIN_PUB = ORIGIN.public_key
ACTOR_PUB = ACTOR.public_key


def _rid(seed):
    return bytes([(seed + i) % 256 for i in range(32)])


def _make_article_intent(origin, eid, board="general", body=b"hello", aid_seed=99):
    return Intent(
        event_id=eid,
        kind=KIND_ARTICLE,
        origin=origin,
        actor_pubkey=ACTOR_PUB,
        board=board,
        article_id=_rid(aid_seed),
        metadata=MetadataMap(
            [
                metadata_text(1, "Test"),
                metadata_text(4, "text/plain"),
            ]
        ),
        body_hash=compute_body_hash(body),
        body_size=len(body),
    )


def _make_board_create_intent(origin, eid, board, owner_pubkey):
    return Intent(
        event_id=eid,
        kind="bonnet.board.create",
        origin=origin,
        actor_pubkey=ACTOR_PUB,
        board=board,
        metadata=MetadataMap(
            [
                metadata_bytes(1, owner_pubkey),
                metadata_text(2, "Test Board"),
            ]
        ),
    )


def _append(firehose, origin_identity, intent, body=b""):
    sig = sign_intent(ACTOR, encode_intent(intent))
    return firehose.append_record(origin_identity, intent, sig, body)


class MockSyncClient(SyncClient):
    async def fetch_head(self, origin):
        from bonnet.core.record import ZERO_HASH, Head

        return Head(
            origin=origin,
            latest_origin_seq=0,
            latest_event_hash=ZERO_HASH,
            event_count=0,
            generated_at=0,
            origin_pubkey=ORIGIN_PUB,
            origin_signature=b"\x00" * 64,
            head_hash=ZERO_HASH,
        ), b""

    async def fetch_range(self, origin, start_seq, max_count):
        return []

    async def close(self):
        pass


@pytest.fixture
def server(tmp_path):
    os.makedirs(tmp_path / "data", exist_ok=True)
    os.makedirs(tmp_path / "boards", exist_ok=True)
    os.makedirs(tmp_path / "event_bodies", exist_ok=True)

    from bonnet.app.server import BonnetServer

    config = FirehoseConfig(
        origin="bbs.test",
        hostname="bbs.test",
        data_dir=str(tmp_path / "data"),
        boards_dir=str(tmp_path / "boards"),
        events_bodies_dir=str(tmp_path / "event_bodies"),
        port=2272,
        tls_enabled=False,
    )
    s = BonnetServer(config)
    yield s
    try:
        s.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# FirehoseStore methods
# ---------------------------------------------------------------------------


@pytest.fixture
def firehose_with_remote_data(tmp_path):
    """FirehoseStore with local origin and a remote origin with data."""
    firehose = FirehoseStore(str(tmp_path / "events.db"))
    firehose.init_origin_key("bbs.test", ORIGIN_PUB)

    remote_identity = Identity.generate()
    firehose.init_origin_key("peer.test", remote_identity.public_key)

    for i in range(3):
        intent = _make_article_intent("peer.test", _rid(i + 1), aid_seed=i + 10)
        body = f"body{i}".encode()
        intent.body_hash = compute_body_hash(body)
        intent.body_size = len(body)
        sig = sign_intent(ACTOR, encode_intent(intent))
        firehose.append_record(remote_identity, intent, sig, body)

    yield firehose, remote_identity
    firehose.close()


def test_get_origin_summary(firehose_with_remote_data):
    firehose, _ = firehose_with_remote_data
    summary = firehose.get_origin_summary("peer.test")
    assert summary["origin"] == "peer.test"
    assert summary["event_count"] == 3
    assert summary["board_count"] == 1


def test_get_origin_summary_empty(firehose_with_remote_data):
    firehose, _ = firehose_with_remote_data
    summary = firehose.get_origin_summary("nonexistent.test")
    assert summary["event_count"] == 0


def test_reset_origin_key(firehose_with_remote_data):
    firehose, remote_identity = firehose_with_remote_data
    assert firehose.get_key_for_seq("peer.test", 1) == remote_identity.public_key

    firehose.reset_origin_key("peer.test")

    assert firehose.get_key_for_seq("peer.test", 1) is None
    assert firehose.get_highest_seq("peer.test") == 0
    events = firehose.get_events_range("peer.test", 1, 10)
    assert len(events) == 3


def test_delete_origin_data(firehose_with_remote_data):
    firehose, _ = firehose_with_remote_data
    counts = firehose.delete_origin_data("peer.test")

    assert counts["events"] == 3
    assert "peer.test" not in firehose.list_origins()
    assert firehose.get_events_range("peer.test", 1, 10) == []


def test_delete_origin_data_preserves_local(firehose_with_remote_data):
    firehose, remote_identity = firehose_with_remote_data
    for i in range(2):
        intent = _make_article_intent("bbs.test", _rid(i + 50), aid_seed=i + 50)
        body = f"local{i}".encode()
        intent.body_hash = compute_body_hash(body)
        intent.body_size = len(body)
        sig = sign_intent(ACTOR, encode_intent(intent))
        firehose.append_record(ORIGIN, intent, sig, body)

    firehose.delete_origin_data("peer.test")

    assert "bbs.test" in firehose.list_origins()
    local_events = firehose.get_events_range("bbs.test", 1, 10)
    assert len(local_events) == 2


# ---------------------------------------------------------------------------
# BodyStore.delete_origin_bodies
# ---------------------------------------------------------------------------


def test_delete_origin_bodies(tmp_path):
    bs = BodyStore(
        boards_dir=str(tmp_path / "boards"),
        events_dir=str(tmp_path / "event_bodies"),
    )
    body = b"test body"
    bh = compute_body_hash(body)
    bs.write_article_body("peer.test", "general", 1, body, bh, len(body))
    bs.write_article_body("peer.test", "general", 2, body, bh, len(body))
    bs.write_article_body("bbs.test", "general", 1, body, bh, len(body))

    count = bs.delete_origin_bodies("peer.test")
    assert count >= 2
    assert not bs.article_body_exists("peer.test", "general", 1)
    assert bs.article_body_exists("bbs.test", "general", 1)


# ---------------------------------------------------------------------------
# depeer REPL command
# ---------------------------------------------------------------------------


def test_depeer_rejects_local_origin(server):
    console = OperatorConsole(server)
    result = console._cmd_depeer(["depeer", "bbs.test"])
    assert "Cannot depeer" in result


def test_depeer_unknown_origin(server):
    console = OperatorConsole(server)
    result = console._cmd_depeer(["depeer", "unknown.test"])
    assert "not a configured peer" in result


# ---------------------------------------------------------------------------
# purge-origin REPL command
# ---------------------------------------------------------------------------


def test_purge_origin_rejects_local(server):
    console = OperatorConsole(server)
    result = console._cmd_purge_origin(["purge-origin", "bbs.test"])
    assert "Cannot purge" in result


@pytest.mark.xdist_group("sync_lifecycle")
async def test_purge_origin_rejects_active_sync(server):
    console = OperatorConsole(server)
    mock = MockSyncClient()
    server.sync_manager.start_origin("peer.test", mock, interval=999)

    result = console._cmd_purge_origin(["purge-origin", "peer.test"])
    assert "active sync" in result
    assert "depeer" in result

    await server.sync_manager.stop_all()


def test_purge_origin_no_data(server):
    console = OperatorConsole(server)
    result = console._cmd_purge_origin(["purge-origin", "empty.test"])
    assert "no data" in result


def test_purge_origin_removes_data(server, tmp_path):
    console = OperatorConsole(server)
    remote_identity = Identity.generate()
    server.firehose.init_origin_key("peer.test", remote_identity.public_key)

    for i in range(3):
        intent = _make_article_intent("peer.test", _rid(i + 1), aid_seed=i + 10)
        body = f"body{i}".encode()
        intent.body_hash = compute_body_hash(body)
        intent.body_size = len(body)
        sig = sign_intent(ACTOR, encode_intent(intent))
        server.body_store.stage_article_body(
            "peer.test",
            "general",
            intent.event_id,
            body,
            intent.body_hash,
            intent.body_size,
        )
        server.firehose.append_record(remote_identity, intent, sig, body)
        server.body_store.finalize_article_body(
            "peer.test",
            "general",
            intent.event_id,
            i + 1,
        )

    server.dispatcher.dispatch_origin("peer.test")

    result = console._cmd_purge_origin(["purge-origin", "peer.test"])
    assert "Purged" in result
    assert "peer.test" not in server.firehose.list_origins()
    assert server.firehose.get_events_range("peer.test", 1, 10) == []


def test_purge_origin_preserves_local(server):
    console = OperatorConsole(server)
    _result = console._cmd_purge_origin(["purge-origin", "empty.test"])
    assert "bbs.test" in server.firehose.list_origins()


# ---------------------------------------------------------------------------
# reset-key REPL command
# ---------------------------------------------------------------------------


def test_reset_key_rejects_local(server):
    console = OperatorConsole(server)
    result = console._cmd_reset_key(["reset-key", "bbs.test"])
    assert "Cannot reset" in result


def test_reset_key_no_data(server):
    console = OperatorConsole(server)
    result = console._cmd_reset_key(["reset-key", "empty.test"])
    assert "no data" in result


def test_reset_key_clears_pinning(server):
    console = OperatorConsole(server)
    remote_identity = Identity.generate()
    server.firehose.init_origin_key("peer.test", remote_identity.public_key)

    for i in range(2):
        intent = _make_article_intent("peer.test", _rid(i + 1), aid_seed=i + 10)
        body = f"body{i}".encode()
        intent.body_hash = compute_body_hash(body)
        intent.body_size = len(body)
        sig = sign_intent(ACTOR, encode_intent(intent))
        server.firehose.append_record(remote_identity, intent, sig, body)

    assert server.firehose.get_key_for_seq("peer.test", 1) == remote_identity.public_key

    result = console._cmd_reset_key(["reset-key", "peer.test"])
    assert "Reset key" in result

    assert server.firehose.get_key_for_seq("peer.test", 1) is None
    events = server.firehose.get_events_range("peer.test", 1, 10)
    assert len(events) == 2


# ---------------------------------------------------------------------------
# rotate-key REPL command
# ---------------------------------------------------------------------------


def test_rotate_key_publishes_record_and_closes_old_epoch(server):
    console = OperatorConsole(server)
    old_pubkey = server.server_identity.public_key

    result = console._cmd_rotate_key([])

    assert "Rotated origin" in result
    assert "no restart needed" in result
    assert old_pubkey.hex() in result

    epochs = server.firehose.get_key_epochs("bbs.test")
    assert len(epochs) == 2
    start1, end1, pk1 = epochs[0]
    start2, end2, pk2 = epochs[1]
    assert pk1 == old_pubkey
    assert end1 is not None
    assert pk2 != old_pubkey
    assert end2 is None
    assert start2 == end1 + 1


def test_rotate_key_record_is_a_valid_rotation(server):
    """The published record must be exactly what firehose.py's own rotation
    verification (_apply_rotation_locked) accepts — it already ran that
    check live when appending the record, but assert the record's shape
    directly so a regression here is legible without re-deriving it."""
    from bonnet.core.kinds import KIND_ORIGIN_KEY_ROTATE
    from bonnet.core.record import verify_key_rotation_proof, verify_record_signature

    console = OperatorConsole(server)
    old_pubkey = server.server_identity.public_key

    console._cmd_rotate_key([])

    events = server.firehose.get_events_range("bbs.test", 1, 10)
    rotate_records = [r for r in events if r.kind == KIND_ORIGIN_KEY_ROTATE]
    assert len(rotate_records) == 1
    rec = rotate_records[0]

    assert rec.actor_pubkey == old_pubkey
    new_pubkey = rec.metadata.get_bytes(1)
    proof = rec.metadata.get_bytes(2)
    assert new_pubkey is not None and proof is not None

    from bonnet.core.record import encode_unsigned_record

    assert verify_record_signature(old_pubkey, encode_unsigned_record(rec), rec.origin_signature)
    assert verify_key_rotation_proof(new_pubkey, "bbs.test", old_pubkey, proof)


def test_rotate_key_writes_new_identity_file_and_backs_up_old(server, tmp_path):
    console = OperatorConsole(server)
    old_key_bytes = server.server_identity.private_key

    result = console._cmd_rotate_key([])

    identity_path = server.config.identity_path
    with open(identity_path, "rb") as f:
        new_key_bytes = f.read()
    assert new_key_bytes != old_key_bytes

    backups = [
        f
        for f in os.listdir(os.path.dirname(identity_path))
        if f.startswith("identity.pre-rotate-")
    ]
    assert len(backups) == 1
    with open(os.path.join(os.path.dirname(identity_path), backups[0]), "rb") as f:
        assert f.read() == old_key_bytes

    assert "Old identity backed up" in result


def test_rotate_key_hot_swaps_every_component(server):
    """Every component that captured the old Identity object at bootstrap
    must be signing/matching against the new one immediately — this is the
    whole point of not requiring a restart."""
    console = OperatorConsole(server)
    old_pubkey = server.server_identity.public_key

    console._cmd_rotate_key([])

    new_pubkey = server.server_identity.public_key
    assert new_pubkey != old_pubkey

    assert server.command_handler._identity.public_key == new_pubkey
    assert server.http_server._server_identity.public_key == new_pubkey
    assert server.sync_manager._identity.public_key == new_pubkey
    assert server.local_conn.server_pubkey == new_pubkey


def test_rotate_key_http_server_signs_with_new_key(server):
    """The HTTP server's signer is rebuilt, not just repointed — a stale
    BonnetSigner would keep signing with the old private key even though the
    discovery document (built fresh from server_identity) started claiming
    the new public key, an internally inconsistent response no client could
    verify."""
    console = OperatorConsole(server)
    old_identity = server.server_identity
    console._cmd_rotate_key([])

    new_identity = server.server_identity
    assert new_identity.private_key != old_identity.private_key
    assert server.http_server._signer._private_key == new_identity.private_key

    # The keyid names the origin, not the key, so it is deliberately unchanged
    # by a rotation: a client addresses a response by the name it pinned, and
    # resolves that name to whatever key it currently holds. Which key signed
    # is settled by the signature, not by the keyid — so the assertion above,
    # on the private key the signer actually baked in, is the one carrying the
    # weight here.
    assert server.http_server._signer._key_id == f"origin:{server.config.origin}"


def test_rotate_key_console_still_has_admin_access_after(server):
    """The console must not lock itself out: after rotation, a subsequent
    admin-only command issued through the same console must still succeed.
    This is the regression the ACL-rule and local_conn updates exist for —
    without them, the console's peer_pubkey and/or the ACL's admin rule
    would still reference the old key and every later command would be
    denied."""
    console = OperatorConsole(server)
    console._cmd_rotate_key([])

    target_pubkey = Identity.generate().public_key.hex()
    result = console._cmd_grant_role(
        ["grant-role", target_pubkey, "moderator", "after-rotation-user"]
    )
    assert "Registered" in result

    registered = server.users.get_user_by_pubkey("bbs.test", bytes.fromhex(target_pubkey))
    assert registered is not None
    assert registered["username"] == "after-rotation-user"


def test_rotate_key_updates_live_acl_admin_rule(server):
    """The fallback admin rule server.py adds when nothing else grants
    admin must track the rotation, since it's synthesized state the server
    owns — not operator config it would be wrong to silently diverge from."""
    console = OperatorConsole(server)
    old_pubkey = server.server_identity.public_key

    assert server._acl_admin_rule is not None
    assert server._acl_admin_rule.matcher.pubkey == old_pubkey

    console._cmd_rotate_key([])

    new_pubkey = server.server_identity.public_key
    assert server._acl_admin_rule.matcher.pubkey == new_pubkey


# ---------------------------------------------------------------------------
# list-users REPL command
# ---------------------------------------------------------------------------


def test_list_users_parses_multi_user_response(server):
    """USER_LIST rows are always origin-prefixed on the wire (see
    _cmd_user_list in firehose_commands.py), even when a specific origin was
    requested. The console parser must account for that leading origin field
    plus reg_seq/created_at, or every field after the first user's pubkey is
    read from the wrong offset."""
    console = OperatorConsole(server)

    alice_pubkey = Identity.generate().public_key
    bob_pubkey = Identity.generate().public_key

    result = console._cmd_grant_role(["grant-role", alice_pubkey.hex(), "admin", "alice"])
    assert "Registered" in result
    result = console._cmd_grant_role(["grant-role", bob_pubkey.hex(), "moderator", "bob"])
    assert "Registered" in result

    result = console._cmd_list_users(["list-users"])

    assert "alice" in result
    assert "bob" in result
    assert alice_pubkey.hex() in result
    assert bob_pubkey.hex() in result
    alice_line = next(line for line in result.splitlines() if "alice" in line)
    bob_line = next(line for line in result.splitlines() if "bob" in line)
    assert "[admin]" in alice_line
    assert "[mod]" in bob_line


def test_list_users_truncates_long_username_for_display(server):
    """A username has no length policy beyond the wire's 4096-byte
    MAX_TEXT_FIELD (see kind_validator.py's identity_text_violation) - a
    long one must not flood the REPL with an unreadable line, but the
    truncation is display-only and must not touch the stored value."""
    console = OperatorConsole(server)
    long_username = "a" * 500
    pubkey = Identity.generate().public_key

    result = console._cmd_grant_role(["grant-role", pubkey.hex(), "admin", long_username])
    assert "Registered" in result

    result = console._cmd_list_users(["list-users"])
    assert "…" in result
    assert long_username not in result

    stored = server.users.get_user_by_pubkey(server.config.origin, pubkey)
    assert stored["username"] == long_username
