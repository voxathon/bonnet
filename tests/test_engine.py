import pytest
import os
import time
from engine.ume import Ume
from engine.ame import Ame
from engine.keibatsu import Keibatsu
from core.crypto import Identity

def test_engine_integration(temp_dir):
    # initialize engine components
    userfile = os.path.join(temp_dir, 'userfile')
    ume = Ume(userfile)

    ame_path = os.path.join(temp_dir, 'ame')
    nav_db_path = os.path.join(temp_dir, 'nav.db')

    # ensure directories exist before initializing Keibatsu
    reports_path = os.path.join(temp_dir, 'reports.db')
    punishments_path = os.path.join(temp_dir, 'punishments.db')

    ident = Identity.generate()
    ame = Ame(ame_path, origin='test_origin', signing_key=ident.signing_key, nav_db_path=nav_db_path)

    keibatsu = Keibatsu(reports_path, punishments_path, ume=ume, signing_key=ident.signing_key, origin='test_origin')

    # Test UME
    user_pubkey = Identity.generate().public_key
    user = ume.put("testuser", "test_origin", user_pubkey, record_origin="test_origin", relay="test_origin")
    assert user is not None
    assert user.username == "testuser"
    assert ume.get(username="testuser") is not None

    # Test AME
    board = ame.create_board("test_board", owner_pubkey=user_pubkey)
    assert board is not None

    # Test AME Posts
    post_result = board.create_post(subject="Test Subject", content="Test Content", author="testuser", author_registrar="test_origin")
    post = post_result.result(timeout=5)
    assert post is not None
    assert post.subject == "Test Subject"
    assert post.content == "Test Content"

    # Test Keibatsu
    rule_result = keibatsu.create_rule("No Spam", "Do not post spam")
    rule = rule_result.result(timeout=5)
    assert rule is not None
    assert rule.rule_name == "No Spam"

    report_result = keibatsu.create_report(rule.rule_num, user_pubkey, ident.public_key, "Posted spam", culprit_board="test_board", culprit_post_num=post.post_num)
    report = report_result.result(timeout=5)
    assert report is not None
    assert report.description == "Posted spam"

    # Test Punishments
    punish_result = keibatsu.create_punishment(user_pubkey, [report.report_num], expires_at=int(time.time()) + 3600, ban_notes="Spamming")
    punishment = punish_result.result(timeout=5)
    assert punishment is not None

    is_banned_result = keibatsu.is_banned(user_pubkey)
    is_banned, notes = is_banned_result.result(timeout=5)
    assert is_banned is True
    assert notes == "Spamming"

    # Shutdown
    ame.shutdown()
    keibatsu.shutdown()