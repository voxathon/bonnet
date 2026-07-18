import pytest
import os
import time
import json
from engine.keibatsu import Keibatsu, Punishment, Report, Rule
from core.crypto import Identity
from core.orm import Database

@pytest.fixture
def keibatsu_setup(temp_dir):
    reports_path = os.path.join(temp_dir, 'reports.db')
    punishments_path = os.path.join(temp_dir, 'punishments.db')
    origin = "test_origin"
    ident = Identity.generate()

    # We need to manually initialize the rules table here if it's not set up
    with Database(reports_path).open() as ctx:
        ctx.execute("""
            CREATE TABLE IF NOT EXISTS rules (
                rule_num INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT NOT NULL,
                description TEXT NOT NULL
            )
        """)

    k = Keibatsu(reports_path, punishments_path, signing_key=ident.signing_key, origin=origin)
    yield k, ident
    k.shutdown()

def test_keibatsu_rules(keibatsu_setup):
    k, ident = keibatsu_setup

    rule = k.create_rule("No Spam", "Do not post spam").result(timeout=5)
    assert rule is not None
    assert rule.rule_num == 1
    assert rule.rule_name == "No Spam"

    rule_by_name = k.get_rule_by_name("No Spam").result(timeout=5)
    assert rule_by_name is not None
    assert rule_by_name.rule_num == 1

    updated_rule = k.update_rule(1, description="Do not post any spam ever").result(timeout=5)
    assert updated_rule.description == "Do not post any spam ever"

def test_keibatsu_reports(keibatsu_setup):
    k, ident = keibatsu_setup

    rule = k.create_rule("No Spam", "Spam").result(timeout=5)

    culprit_pubkey = Identity.generate().public_key
    reporter_pubkey = Identity.generate().public_key

    report = k.create_report(
        rule_num=rule.rule_num,
        culprit_pubkey=culprit_pubkey,
        reporter_pubkey=reporter_pubkey,
        description="Posted spam",
        culprit_board="board1",
        culprit_post_num=1
    ).result(timeout=5)

    assert report is not None
    assert report.report_num == 1
    assert report.origin == "test_origin"
    assert report.culprit_board == "board1"

    # signature by origin is applied automatically since signing_key is set
    assert report.origin_sig is not None

def test_keibatsu_punishments(keibatsu_setup):
    k, ident = keibatsu_setup
    pubkey = Identity.generate().public_key
    issuer = ident.public_key

    punish = k.create_punishment(
        pubkey=pubkey,
        report_ids=[1, 2],
        expires_at=int(time.time()) + 3600,
        ban_notes="Banned for spam",
        issued_by=issuer,
    ).result(timeout=5)

    assert punish is not None
    assert punish.punishment_id >= 1
    assert punish.punished_pubkey == pubkey
    assert punish.get_report_ids() == [1, 2]
    assert punish.ban_notes == "Banned for spam"
    assert punish.issued_by == issuer
    assert punish.created_at > 0

    fetched = k.get_punishment(punish.punishment_id).result(timeout=5)
    assert fetched is not None
    assert fetched.punishment_id == punish.punishment_id
    assert fetched.get_report_ids() == [1, 2]

    # test warning vs temporary vs permanent
    warn = k.create_punishment(Identity.generate().public_key, [3], expires_at=0).result(timeout=5)
    assert warn.is_warning() is True
    assert warn.is_active() is False

    perm = k.create_punishment(Identity.generate().public_key, [4], expires_at=-1).result(timeout=5)
    assert perm.is_permanent() is True
    assert perm.is_active() is True

    active_punishments = k.list_active_punishments().result(timeout=5)
    assert len(active_punishments) >= 1 # temporary and permanent

    # append-only: a second punishment for the same pubkey must NOT overwrite
    punish2 = k.create_punishment(
        pubkey=pubkey,
        report_ids=[5],
        expires_at=-1,
        ban_notes="Second offense",
        issued_by=issuer,
    ).result(timeout=5)

    assert punish2.punishment_id > punish.punishment_id
    assert punish2.punished_pubkey == pubkey

    all_for_pubkey = k.list_punishments_by_pubkey(pubkey).result(timeout=5)
    assert len(all_for_pubkey) == 2
    assert all_for_pubkey[0].punishment_id == punish.punishment_id
    assert all_for_pubkey[1].punishment_id == punish2.punishment_id
    # original row preserved (not overwritten)
    assert all_for_pubkey[0].get_report_ids() == [1, 2]
    assert all_for_pubkey[0].ban_notes == "Banned for spam"
    assert all_for_pubkey[1].get_report_ids() == [5]
    assert all_for_pubkey[1].ban_notes == "Second offense"

    # still banned (any active row)
    is_banned, notes = k.is_banned(pubkey).result(timeout=5)
    assert is_banned is True


def test_keibatsu_punishment_migration(temp_dir):
    """Old single-row-per-pubkey punishments schema migrates to append-only schema."""
    reports_path = os.path.join(temp_dir, 'reports.db')
    punishments_path = os.path.join(temp_dir, 'punishments.db')
    origin = "test_origin"
    ident = Identity.generate()

    # Pre-create the OLD schema with a single row keyed by pubkey (PRIMARY KEY).
    pubkey = Identity.generate().public_key
    with Database(punishments_path).open() as ctx:
        ctx.execute("""
            CREATE TABLE punishments (
                punished_pubkey  BLOB PRIMARY KEY,
                report_ids       TEXT NOT NULL,
                expires_at       INTEGER NOT NULL,
                ban_notes        TEXT
            )
        """)
        ctx.execute(
            "INSERT INTO punishments (punished_pubkey, report_ids, expires_at, ban_notes) VALUES (?, ?, ?, ?)",
            [pubkey, "[7]", -1, "legacy ban"],
        )

    # Instantiating Keibatsu triggers the migration block.
    k = Keibatsu(reports_path, punishments_path, signing_key=ident.signing_key, origin=origin)
    try:
        # The migrated row should be retrievable by its new monotonic ID.
        by_pubkey = k.list_punishments_by_pubkey(pubkey).result(timeout=5)
        assert len(by_pubkey) == 1
        migrated = by_pubkey[0]
        assert migrated.punishment_id >= 1
        assert migrated.punished_pubkey == pubkey
        assert migrated.get_report_ids() == [7]
        assert migrated.expires_at == -1
        assert migrated.ban_notes == "legacy ban"
        # Audit fields unknown for legacy rows.
        assert migrated.issued_by == b''
        assert migrated.created_at == 0

        # And retrievable by ID.
        by_id = k.get_punishment(migrated.punishment_id).result(timeout=5)
        assert by_id is not None
        assert by_id.punishment_id == migrated.punishment_id

        # The legacy ban is still active (expires_at=-1).
        is_banned, notes = k.is_banned(pubkey).result(timeout=5)
        assert is_banned is True
        assert notes == "legacy ban"
    finally:
        k.shutdown()
