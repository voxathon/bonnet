import pytest
import os
import time
from engine.keibatsu import Keibatsu, Punishment, Report, Rule
from core.crypto import Identity

@pytest.fixture
def keibatsu_setup(temp_dir):
    reports_path = os.path.join(temp_dir, 'reports.db')
    punishments_path = os.path.join(temp_dir, 'punishments.db')
    origin = "test_origin"
    ident = Identity.generate()

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

    punish = k.create_punishment(
        pubkey=pubkey,
        report_ids=[1, 2],
        expires_at=int(time.time()) + 3600,
        ban_notes="Banned for spam"
    ).result(timeout=5)

    assert punish is not None
    assert punish.punished_pubkey == pubkey
    assert punish.get_report_ids() == [1, 2]
    assert punish.ban_notes == "Banned for spam"

    fetched = k.get_punishment(pubkey).result(timeout=5)
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