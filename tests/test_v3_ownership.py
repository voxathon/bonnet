"""Tests for v3 ARTICLE_PUBLISH ownership enforcement (§6.1, §6.2, §6.3).

Verifies that the handler enforces:
  - Supersede: only the original author may supersede (no moderator override)
  - Cancel: original author or moderator/administrator
  - Restore: original author or moderator/administrator
  - BOARD_LIST: lists all local boards regardless of read permission (metadata is public)

These tests call CommandHandler.handle_v3() directly with crafted CommandContext
objects, bypassing the HTTP layer.
"""

import os
import sys
import struct
import time
import random
import pytest
import pytest_asyncio
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.crypto import Identity
from core.config import Config, Matcher, ACLEntry
from core.orm import Database
from engine.ume import Ume
from engine.ame import Ame
from engine.keibatsu import Keibatsu
from engine.facade import BonnetEngine
from engine.article_service import ArticleService
from net.commands import CommandHandler
from net.context import CommandContext
from core.article_feed import (
    ArticleFeedStore,
    Submission,
    ArticleHeaders,
    EVENT_ARTICLE,
    EVENT_CANCEL,
    EVENT_RESTORE,
    SCHEME_V3,
    SUBMISSION_VERSION,
    ZERO_MESSAGE_ID,
    ZERO_HASH,
    encode_submission,
    compute_body_hash,
    sign_author,
)
from client.protocol import build_article_publish
from tests.helpers import default_test_acls


ORIGIN = "local.test"
BOARD = "testboard"


def _init_rules(reports_path):
    with Database(reports_path).open() as ctx:
        ctx.execute("""CREATE TABLE IF NOT EXISTS rules (
            rule_num INTEGER PRIMARY KEY, rule_name TEXT UNIQUE NOT NULL, description TEXT NOT NULL
        )""")


def _random_msgid(seed):
    rng = random.Random(seed)
    mid = rng.randbytes(32)
    while mid == ZERO_MESSAGE_ID:
        mid = rng.randbytes(32)
    return mid


def _make_article_submission(seed, author_identity, origin=ORIGIN, board=BOARD,
                             body=None, supersedes_message_id=ZERO_MESSAGE_ID):
    if body is None:
        body = f"article body {seed}".encode("utf-8")
    body_hash = compute_body_hash(body)
    sub = Submission(
        submission_version=SUBMISSION_VERSION,
        event_type=EVENT_ARTICLE,
        origin=origin, board=board,
        message_id=_random_msgid(seed),
        created_at=1700000000 + seed,
        actor_pubkey=author_identity.public_key,
        actor_username="author",
        actor_registrar=origin,
        root_message_id=ZERO_MESSAGE_ID,
        headers=ArticleHeaders(subject=f"Article {seed}", tags="test", options=""),
        body_hash=body_hash, body_size=len(body),
        supersedes_message_id=supersedes_message_id,
    )
    encoded_sub = encode_submission(sub)
    author_sig = sign_author(sub, author_identity)
    return sub, encoded_sub, body, author_sig


def _make_control_submission(seed, event_type, target_message_id,
                             author_identity, origin=ORIGIN, board=BOARD):
    body = b""
    body_hash = compute_body_hash(body)
    sub = Submission(
        submission_version=SUBMISSION_VERSION,
        event_type=event_type,
        origin=origin, board=board,
        message_id=_random_msgid(seed),
        created_at=1700000000 + seed,
        actor_pubkey=author_identity.public_key,
        actor_username="author",
        actor_registrar=origin,
        root_message_id=ZERO_MESSAGE_ID,
        headers=None,
        body_hash=body_hash, body_size=0,
        target_message_id=target_message_id,
    )
    encoded_sub = encode_submission(sub)
    author_sig = sign_author(sub, author_identity)
    return sub, encoded_sub, body, author_sig


def _make_ctx(peer_pubkey, is_mod=False, is_admin=False, origin=ORIGIN):
    user = MagicMock()
    user.username = "testuser"
    user.publickey = peer_pubkey
    user.is_administrator = is_admin
    user.is_moderator = is_mod
    user.is_banned = False
    user.record_origin = origin
    user.creation_time = int(time.time())
    return CommandContext(
        peer_public_key=peer_pubkey,
        user=user,
        username="testuser",
        is_anonymous=False,
        origin=origin,
    )


def _decode_error(response):
    if len(response) > 0 and response[0] == 0x01:
        code = struct.unpack(">H", response[1:3])[0]
        msg_len = response[3]
        return code, response[4:4 + msg_len].decode("utf-8", errors="replace")
    return None


@pytest_asyncio.fixture
async def setup(tmp_path):
    temp_dir = str(tmp_path)
    ident = Identity.generate()
    config = Config(
        origin=ORIGIN,
        registrars=[ORIGIN],
        ame_path=os.path.join(temp_dir, "boards"),
        data_dir=temp_dir,
        nav_db_path=os.path.join(temp_dir, "nav.db"),
        reports_db_path=os.path.join(temp_dir, "reports.db"),
        punishments_db_path=os.path.join(temp_dir, "punishments.db"),
        log_dir=os.path.join(temp_dir, "logs"),
        acls=default_test_acls(ORIGIN),
        anonymous_read=True,
    )
    ume = Ume(os.path.join(temp_dir, "userfile"))
    ame = Ame(config.ame_path, origin=ORIGIN, signing_key=ident.signing_key,
              nav_db_path=config.nav_db_path)
    _init_rules(config.reports_db_path)
    keibatsu = Keibatsu(config.reports_db_path, config.punishments_db_path,
                        ume=ume, signing_key=ident.signing_key, origin=ORIGIN)
    engine = BonnetEngine(ume, ame, keibatsu, config, ident)

    feed_store = ArticleFeedStore(
        os.path.join(temp_dir, "article_feeds.db"),
        os.path.join(temp_dir, "article_bodies"),
    )
    article_service = ArticleService(feed_store, ORIGIN, ident)
    engine.article_service = article_service

    handler = CommandHandler(engine)
    task = handler._sync_mgr._worker_task
    if task and not task.done():
        task.cancel()

    ame.create_board(BOARD, owner_pubkey=ident.public_key)

    yield {
        "ident": ident, "config": config, "ume": ume, "ame": ame,
        "keibatsu": keibatsu, "engine": engine, "handler": handler,
        "article_service": article_service, "feed_store": feed_store,
    }

    ame.shutdown()
    keibatsu.shutdown()
    feed_store.close()


class TestSupersedeOwnership:
    """§6.1: only the original author may supersede an article."""

    @pytest.mark.asyncio
    async def test_author_can_supersede_own_article(self, setup):
        s = setup
        handler = s["handler"]
        author_id = Identity.generate()

        # Publish original article
        sub1, enc1, body1, sig1 = _make_article_submission(1, author_id)
        cmd1 = build_article_publish(enc1, body1, SCHEME_V3, sig1)
        ctx1 = _make_ctx(author_id.public_key)
        resp1 = handler.handle_v3(cmd1, ctx1)
        assert resp1[0] == 0x00, f"publish failed: {_decode_error(resp1)}"

        # Supersede with a new article (same author)
        sub2, enc2, body2, sig2 = _make_article_submission(
            2, author_id, supersedes_message_id=sub1.message_id)
        cmd2 = build_article_publish(enc2, body2, SCHEME_V3, sig2)
        ctx2 = _make_ctx(author_id.public_key)
        resp2 = handler.handle_v3(cmd2, ctx2)
        assert resp2[0] == 0x00, f"supersede failed: {_decode_error(resp2)}"

    @pytest.mark.asyncio
    async def test_non_author_cannot_supersede(self, setup):
        s = setup
        handler = s["handler"]
        author_id = Identity.generate()
        other_id = Identity.generate()

        # Publish original article as author
        sub1, enc1, body1, sig1 = _make_article_submission(1, author_id)
        cmd1 = build_article_publish(enc1, body1, SCHEME_V3, sig1)
        ctx1 = _make_ctx(author_id.public_key)
        resp1 = handler.handle_v3(cmd1, ctx1)
        assert resp1[0] == 0x00, f"publish failed: {_decode_error(resp1)}"

        # Attempt supersede as a different user
        sub2, enc2, body2, sig2 = _make_article_submission(
            2, other_id, supersedes_message_id=sub1.message_id)
        cmd2 = build_article_publish(enc2, body2, SCHEME_V3, sig2)
        ctx2 = _make_ctx(other_id.public_key)
        resp2 = handler.handle_v3(cmd2, ctx2)
        err = _decode_error(resp2)
        assert err is not None, "expected error but got success"
        assert err[0] == 403
        assert "author" in err[1].lower()

    @pytest.mark.asyncio
    async def test_moderator_cannot_supersede(self, setup):
        s = setup
        handler = s["handler"]
        author_id = Identity.generate()
        mod_id = Identity.generate()

        # Publish original article as author
        sub1, enc1, body1, sig1 = _make_article_submission(1, author_id)
        cmd1 = build_article_publish(enc1, body1, SCHEME_V3, sig1)
        ctx1 = _make_ctx(author_id.public_key)
        resp1 = handler.handle_v3(cmd1, ctx1)
        assert resp1[0] == 0x00, f"publish failed: {_decode_error(resp1)}"

        # Attempt supersede as moderator — should be denied
        sub2, enc2, body2, sig2 = _make_article_submission(
            2, mod_id, supersedes_message_id=sub1.message_id)
        cmd2 = build_article_publish(enc2, body2, SCHEME_V3, sig2)
        ctx2 = _make_ctx(mod_id.public_key, is_mod=True)
        resp2 = handler.handle_v3(cmd2, ctx2)
        err = _decode_error(resp2)
        assert err is not None, "expected error but got success"
        assert err[0] == 403
        assert "author" in err[1].lower()


class TestCancelRestoreOwnership:
    """§6.2, §6.3: cancel/restore require original author or moderator/admin."""

    @pytest.mark.asyncio
    async def test_author_can_cancel_own_article(self, setup):
        s = setup
        handler = s["handler"]
        author_id = Identity.generate()

        sub1, enc1, body1, sig1 = _make_article_submission(1, author_id)
        cmd1 = build_article_publish(enc1, body1, SCHEME_V3, sig1)
        ctx1 = _make_ctx(author_id.public_key)
        resp1 = handler.handle_v3(cmd1, ctx1)
        assert resp1[0] == 0x00

        cancel_sub, cancel_enc, cancel_body, cancel_sig = _make_control_submission(
            2, EVENT_CANCEL, sub1.message_id, author_id)
        cmd2 = build_article_publish(cancel_enc, cancel_body, SCHEME_V3, cancel_sig)
        ctx2 = _make_ctx(author_id.public_key)
        resp2 = handler.handle_v3(cmd2, ctx2)
        assert resp2[0] == 0x00, f"cancel failed: {_decode_error(resp2)}"

    @pytest.mark.asyncio
    async def test_non_author_cannot_cancel(self, setup):
        s = setup
        handler = s["handler"]
        author_id = Identity.generate()
        other_id = Identity.generate()

        sub1, enc1, body1, sig1 = _make_article_submission(1, author_id)
        cmd1 = build_article_publish(enc1, body1, SCHEME_V3, sig1)
        ctx1 = _make_ctx(author_id.public_key)
        resp1 = handler.handle_v3(cmd1, ctx1)
        assert resp1[0] == 0x00

        cancel_sub, cancel_enc, cancel_body, cancel_sig = _make_control_submission(
            2, EVENT_CANCEL, sub1.message_id, other_id)
        cmd2 = build_article_publish(cancel_enc, cancel_body, SCHEME_V3, cancel_sig)
        ctx2 = _make_ctx(other_id.public_key)
        resp2 = handler.handle_v3(cmd2, ctx2)
        err = _decode_error(resp2)
        assert err is not None, "expected error but got success"
        assert err[0] == 403

    @pytest.mark.asyncio
    async def test_moderator_can_cancel(self, setup):
        s = setup
        handler = s["handler"]
        author_id = Identity.generate()
        mod_id = Identity.generate()

        sub1, enc1, body1, sig1 = _make_article_submission(1, author_id)
        cmd1 = build_article_publish(enc1, body1, SCHEME_V3, sig1)
        ctx1 = _make_ctx(author_id.public_key)
        resp1 = handler.handle_v3(cmd1, ctx1)
        assert resp1[0] == 0x00

        cancel_sub, cancel_enc, cancel_body, cancel_sig = _make_control_submission(
            2, EVENT_CANCEL, sub1.message_id, mod_id)
        cmd2 = build_article_publish(cancel_enc, cancel_body, SCHEME_V3, cancel_sig)
        ctx2 = _make_ctx(mod_id.public_key, is_mod=True)
        resp2 = handler.handle_v3(cmd2, ctx2)
        assert resp2[0] == 0x00, f"moderator cancel failed: {_decode_error(resp2)}"

    @pytest.mark.asyncio
    async def test_non_author_cannot_restore(self, setup):
        s = setup
        handler = s["handler"]
        author_id = Identity.generate()
        other_id = Identity.generate()

        # Publish + cancel as author
        sub1, enc1, body1, sig1 = _make_article_submission(1, author_id)
        cmd1 = build_article_publish(enc1, body1, SCHEME_V3, sig1)
        ctx1 = _make_ctx(author_id.public_key)
        resp1 = handler.handle_v3(cmd1, ctx1)
        assert resp1[0] == 0x00

        cancel_sub, cancel_enc, cancel_body, cancel_sig = _make_control_submission(
            2, EVENT_CANCEL, sub1.message_id, author_id)
        cmd2 = build_article_publish(cancel_enc, cancel_body, SCHEME_V3, cancel_sig)
        resp2 = handler.handle_v3(cmd2, ctx1)
        assert resp2[0] == 0x00

        # Attempt restore as different user
        restore_sub, restore_enc, restore_body, restore_sig = _make_control_submission(
            3, EVENT_RESTORE, sub1.message_id, other_id)
        cmd3 = build_article_publish(restore_enc, restore_body, SCHEME_V3, restore_sig)
        ctx3 = _make_ctx(other_id.public_key)
        resp3 = handler.handle_v3(cmd3, ctx3)
        err = _decode_error(resp3)
        assert err is not None, "expected error but got success"
        assert err[0] == 403

    @pytest.mark.asyncio
    async def test_author_can_restore_own_article(self, setup):
        s = setup
        handler = s["handler"]
        author_id = Identity.generate()

        sub1, enc1, body1, sig1 = _make_article_submission(1, author_id)
        cmd1 = build_article_publish(enc1, body1, SCHEME_V3, sig1)
        ctx1 = _make_ctx(author_id.public_key)
        resp1 = handler.handle_v3(cmd1, ctx1)
        assert resp1[0] == 0x00

        cancel_sub, cancel_enc, cancel_body, cancel_sig = _make_control_submission(
            2, EVENT_CANCEL, sub1.message_id, author_id)
        cmd2 = build_article_publish(cancel_enc, cancel_body, SCHEME_V3, cancel_sig)
        resp2 = handler.handle_v3(cmd2, ctx1)
        assert resp2[0] == 0x00

        restore_sub, restore_enc, restore_body, restore_sig = _make_control_submission(
            3, EVENT_RESTORE, sub1.message_id, author_id)
        cmd3 = build_article_publish(restore_enc, restore_body, SCHEME_V3, restore_sig)
        resp3 = handler.handle_v3(cmd3, ctx1)
        assert resp3[0] == 0x00, f"restore failed: {_decode_error(resp3)}"


class TestBoardListVisibility:
    """BOARD_LIST lists all local boards regardless of read permission."""

    @pytest.mark.asyncio
    async def test_board_list_shows_unreadable_boards(self, tmp_path):
        temp_dir = str(tmp_path)
        ident = Identity.generate()
        origin = "local.test"

        # Build a config with an ACL that denies read to a specific board
        from tests.helpers import anonymous_read_command_names
        local_acl = ACLEntry(
            "local-full-access",
            Matcher(origin_pattern=origin),
            ["*"], True, True,
            command_patterns=["*"],
            object_patterns=["*"],
        )
        # Anonymous can read everything EXCEPT "secret"
        anon_acl = ACLEntry(
            "anonymous-read",
            Matcher(anonymous=True),
            ["public"], True, False,  # only "public" board, not "secret"
            command_patterns=anonymous_read_command_names(),
            object_patterns=["articles"],
        )
        unknown_acl = ACLEntry(
            "unknown-read",
            Matcher(unknown=True),
            ["public"], True, False,
            command_patterns=anonymous_read_command_names(),
            object_patterns=["articles"],
        )
        unknown_reg_acl = ACLEntry(
            "unknown-registration",
            Matcher(unknown=True),
            ["*"], False, True,
            command_patterns=["REGISTER"],
        )
        config = Config(
            origin=origin,
            ame_path=os.path.join(temp_dir, "boards"),
            data_dir=temp_dir,
            nav_db_path=os.path.join(temp_dir, "nav.db"),
            reports_db_path=os.path.join(temp_dir, "reports.db"),
            punishments_db_path=os.path.join(temp_dir, "punishments.db"),
            log_dir=os.path.join(temp_dir, "logs"),
            acls=[local_acl, anon_acl, unknown_acl, unknown_reg_acl],
            anonymous_read=True,
        )
        ume = Ume(os.path.join(temp_dir, "userfile"))
        ame = Ame(config.ame_path, origin=origin, signing_key=ident.signing_key,
                  nav_db_path=config.nav_db_path)
        _init_rules(config.reports_db_path)
        keibatsu = Keibatsu(config.reports_db_path, config.punishments_db_path,
                            ume=ume, signing_key=ident.signing_key, origin=origin)
        engine = BonnetEngine(ume, ame, keibatsu, config, ident)
        handler = CommandHandler(engine)
        task = handler._sync_mgr._worker_task
        if task and not task.done():
            task.cancel()

        ame.create_board("public", owner_pubkey=ident.public_key)
        ame.create_board("secret", owner_pubkey=ident.public_key)

        # Anonymous context — can read "public" but NOT "secret"
        anon_ctx = CommandContext(
            peer_public_key=b"\x00" * 32,
            user=None,
            is_anonymous=True,
            origin=origin,
        )

        resp = handler.handle(bytes([0x11]), anon_ctx)  # BOARD_LIST
        assert resp[0] == 0x00
        count = struct.unpack(">H", resp[1:3])[0]
        board_names = []
        offset = 3
        for _ in range(count):
            name_len = resp[offset]
            offset += 1
            name = resp[offset:offset + name_len].decode("utf-8")
            offset += name_len
            origin_len = resp[offset]
            offset += 1 + origin_len
            sig_len = resp[offset]
            offset += 1 + sig_len
            closed = resp[offset]
            offset += 1
            board_names.append(name)

        # Both boards should be listed even though "secret" is not readable
        assert "public" in board_names
        assert "secret" in board_names
        assert count == 2

        ame.shutdown()
        keibatsu.shutdown()
