"""Firehose command handler, discovery, command transport, and federation sync."""

import hashlib
import struct
import time

import pytest

from bonnet.core.acl import ACLEvaluator, ACLRule, PrincipalMatcher, default_rules_for_admin
from bonnet.core.bodies import BodyStore
from bonnet.core.crypto import Identity
from bonnet.core.dispatcher import Dispatcher
from bonnet.core.firehose import FirehoseStore
from bonnet.core.global_projections import NavProjection, PolicyProjection, UserProjection
from bonnet.core.kind_validator import KindValidator
from bonnet.core.record import (
    Head,
    Intent,
    MetadataMap,
    Record,
    compute_body_hash,
    compute_event_hash,
    decode_head,
    decode_record,
    decode_witness,
    encode_head,
    encode_intent,
    encode_record,
    is_origin_witness,
    make_origin_witness,
    metadata_bytes,
    metadata_i64,
    metadata_text,
    sign_intent,
)
from bonnet.core.search import SearchService
from bonnet.net.firehose_commands import (
    OP_ARTICLE_BODY,
    OP_ARTICLE_GET,
    OP_ARTICLE_LIST,
    OP_ARTICLE_SEARCH,
    OP_BAN_STATUS,
    OP_EVENT_GET,
    OP_EVENT_HEAD,
    OP_EVENT_RANGE,
    OP_PUBLISH_RECORD,
    PUNISHMENT_TYPE_CODES,
    FirehoseCommandHandler,
    FirehoseContext,
)
from bonnet.net.firehose_sync import SyncClient, SyncManager

# ---------------------------------------------------------------------------
# Test identities
# ---------------------------------------------------------------------------

ORIGIN = Identity.from_private_key(bytes(range(1, 33)))
ACTOR = Identity.from_private_key(bytes(range(10, 42)))
ORIGIN_PUB = ORIGIN.public_key
ACTOR_PUB = ACTOR.public_key


def _rid(seed: int) -> bytes:
    return bytes([(seed + i) % 256 for i in range(32)])


def _enc_text16(s: str) -> bytes:
    encoded = s.encode("utf-8")
    return struct.pack(">H", len(encoded)) + encoded


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def firehose(tmp_path):
    f = FirehoseStore(str(tmp_path / "events.db"))
    f.init_origin_key("bbs.test", ORIGIN_PUB)
    yield f
    f.close()


@pytest.fixture
def stack(tmp_path, firehose):
    """Full server stack: nav, users, policy, bodies, dispatcher, search, handler."""
    nav = NavProjection(str(tmp_path / "nav.db"))
    users = UserProjection(str(tmp_path / "users.db"))
    policy = PolicyProjection(str(tmp_path / "policy.db"))
    body_store = BodyStore(
        boards_dir=str(tmp_path / "boards"),
        events_dir=str(tmp_path / "event_bodies"),
    )
    boards_dir = str(tmp_path / "boards")

    acl = ACLEvaluator(default_rules_for_admin(ACTOR_PUB.hex()))
    acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(wildcard=True),
            actions=["read"],
            commands=["*"],
            boards=["*"],
            objects=["*"],
        )
    )
    validator = KindValidator()
    search = SearchService(
        boards_dir=boards_dir,
        body_store=body_store,
        max_count=100,
        timeout_seconds=5,
        result_limit=50,
    )

    dispatcher = Dispatcher(
        firehose=firehose,
        nav=nav,
        users=users,
        policy=policy,
        boards_dir=boards_dir,
        body_store=body_store,
        local_origin="bbs.test",
    )

    handler = FirehoseCommandHandler(
        firehose=firehose,
        server_identity=ORIGIN,
        config_origin="bbs.test",
        nav=nav,
        users=users,
        policy=policy,
        body_store=body_store,
        boards_dir=boards_dir,
        acl=acl,
        validator=validator,
        search=search,
        hostname="bbs.test",
        dispatcher=dispatcher,
    )

    yield {
        "firehose": firehose,
        "nav": nav,
        "users": users,
        "policy": policy,
        "body_store": body_store,
        "dispatcher": dispatcher,
        "handler": handler,
        "acl": acl,
    }

    handler.close()
    dispatcher.close()
    nav.close()
    users.close()
    policy.close()


def _actor_ctx():
    return FirehoseContext(
        peer_pubkey=ACTOR_PUB,
        is_registered=True,
        origin="bbs.test",
    )


def _anon_ctx():
    return FirehoseContext(is_anonymous=True)


# ---------------------------------------------------------------------------
# PUBLISH_RECORD tests
# ---------------------------------------------------------------------------


class TestPublishRecord:
    def test_publish_article(self, stack):
        h = stack["handler"]
        _create_board(h, "general")
        body = b"hello world"
        intent = Intent(
            event_id=_rid(1),
            kind="bonnet.article",
            origin="bbs.test",
            actor_pubkey=ACTOR_PUB,
            board="general",
            article_id=_rid(2),
            metadata=MetadataMap(
                [
                    metadata_text(1, "Test"),
                    metadata_text(4, "text/plain"),
                ]
            ),
            body_hash=compute_body_hash(body),
            body_size=len(body),
        )
        encoded_intent = encode_intent(intent)
        actor_sig = sign_intent(ACTOR, encoded_intent)

        req = struct.pack(">B", OP_PUBLISH_RECORD)
        req += struct.pack(">I", len(encoded_intent)) + encoded_intent
        req += actor_sig
        req += struct.pack(">I", len(body)) + body

        resp = h.handle(req, _actor_ctx())
        assert resp[0] == 0  # success

        rec_len = struct.unpack(">I", resp[1:5])[0]
        rec_bytes = resp[5 : 5 + rec_len]
        rec = decode_record(rec_bytes)
        assert rec.origin_seq == 2  # seq 1 is this test's own board.create
        assert rec.kind == "bonnet.article"
        assert rec.article_num == 1

        witness_len = struct.unpack(">H", resp[5 + rec_len : 7 + rec_len])[0]
        witness_bytes = resp[7 + rec_len : 7 + rec_len + witness_len]
        witness = decode_witness(witness_bytes)
        assert is_origin_witness(witness)

    def test_publish_rejects_wrong_origin(self, stack):
        h = stack["handler"]
        intent = Intent(
            event_id=_rid(1),
            kind="bonnet.article",
            origin="bbs.evil",
            actor_pubkey=ACTOR_PUB,
            board="general",
            article_id=_rid(2),
            metadata=MetadataMap(
                [
                    metadata_text(1, "Test"),
                    metadata_text(4, "text/plain"),
                ]
            ),
        )
        encoded_intent = encode_intent(intent)
        actor_sig = sign_intent(ACTOR, encoded_intent)

        req = struct.pack(">B", OP_PUBLISH_RECORD)
        req += struct.pack(">I", len(encoded_intent)) + encoded_intent
        req += actor_sig
        req += struct.pack(">I", 0)

        resp = h.handle(req, _actor_ctx())
        assert resp[0] == 1  # error
        assert b"Origin mismatch" in resp

    def test_publish_rejects_wrong_actor_key(self, stack):
        h = stack["handler"]
        other = Identity.generate()
        intent = Intent(
            event_id=_rid(1),
            kind="bonnet.article",
            origin="bbs.test",
            actor_pubkey=other.public_key,
            board="general",
            article_id=_rid(2),
            metadata=MetadataMap(
                [
                    metadata_text(1, "Test"),
                    metadata_text(4, "text/plain"),
                ]
            ),
        )
        encoded_intent = encode_intent(intent)
        actor_sig = sign_intent(other, encoded_intent)

        req = struct.pack(">B", OP_PUBLISH_RECORD)
        req += struct.pack(">I", len(encoded_intent)) + encoded_intent
        req += actor_sig
        req += struct.pack(">I", 0)

        ctx = FirehoseContext(peer_pubkey=ACTOR_PUB, is_registered=True, origin="bbs.test")
        resp = h.handle(req, ctx)
        assert resp[0] == 1
        assert b"pubkey" in resp.lower()

    def test_publish_board_create(self, stack):
        h = stack["handler"]
        intent = Intent(
            event_id=_rid(1),
            kind="bonnet.board.create",
            origin="bbs.test",
            actor_pubkey=ACTOR_PUB,
            board="newboard",
            metadata=MetadataMap(
                [
                    metadata_bytes(1, ACTOR_PUB),
                    metadata_text(2, "New Board"),
                ]
            ),
        )
        encoded_intent = encode_intent(intent)
        actor_sig = sign_intent(ACTOR, encoded_intent)

        req = struct.pack(">B", OP_PUBLISH_RECORD)
        req += struct.pack(">I", len(encoded_intent)) + encoded_intent
        req += actor_sig
        req += struct.pack(">I", 0)

        resp = h.handle(req, _actor_ctx())
        assert resp[0] == 0

    def test_publish_board_create_rejects_duplicate_by_same_owner(self, stack):
        """A second bonnet.board.create for a name the *same* owner already
        holds must be refused, not silently appended — a repeat "I created
        this" claim on the append-only log with no indication it was a
        no-op. Regression for the chaos-testing report's #1.2: create_board
        used to accept the identical (origin, board, owner) twice."""
        h = stack["handler"]
        _create_board(h, "dupboard")

        intent = Intent(
            event_id=_rid(2),
            kind="bonnet.board.create",
            origin="bbs.test",
            actor_pubkey=ACTOR_PUB,
            board="dupboard",
            metadata=MetadataMap(
                [
                    metadata_bytes(1, ACTOR_PUB),
                    metadata_text(2, "New Board"),
                ]
            ),
        )
        encoded_intent = encode_intent(intent)
        actor_sig = sign_intent(ACTOR, encoded_intent)

        req = struct.pack(">B", OP_PUBLISH_RECORD)
        req += struct.pack(">I", len(encoded_intent)) + encoded_intent
        req += actor_sig
        req += struct.pack(">I", 0)

        resp = h.handle(req, _actor_ctx())
        assert resp[0] == 1
        assert b"already exists" in resp.lower()

    def test_publish_rejects_acl_denied(self, stack):
        h = stack["handler"]
        stack["acl"] = ACLEvaluator([])  # deny all
        h._acl = ACLEvaluator([])

        intent = Intent(
            event_id=_rid(1),
            kind="bonnet.article",
            origin="bbs.test",
            actor_pubkey=ACTOR_PUB,
            board="general",
            article_id=_rid(2),
            metadata=MetadataMap(
                [
                    metadata_text(1, "Test"),
                    metadata_text(4, "text/plain"),
                ]
            ),
        )
        encoded_intent = encode_intent(intent)
        actor_sig = sign_intent(ACTOR, encoded_intent)

        req = struct.pack(">B", OP_PUBLISH_RECORD)
        req += struct.pack(">I", len(encoded_intent)) + encoded_intent
        req += actor_sig
        req += struct.pack(">I", 0)

        resp = h.handle(req, _actor_ctx())
        assert resp[0] == 1
        assert b"not permitted" in resp.lower()

    def test_publish_rejects_oversized_body(self, stack):
        h = stack["handler"]
        _create_board(h, "general")
        h._max_body_size = 100

        body = b"\x00" * 200
        intent = Intent(
            event_id=_rid(1),
            kind="bonnet.article",
            origin="bbs.test",
            actor_pubkey=ACTOR_PUB,
            board="general",
            article_id=_rid(2),
            metadata=MetadataMap(
                [
                    metadata_text(1, "Test"),
                    metadata_text(4, "text/plain"),
                ]
            ),
            body_hash=compute_body_hash(body),
            body_size=len(body),
        )
        encoded_intent = encode_intent(intent)
        actor_sig = sign_intent(ACTOR, encoded_intent)

        req = struct.pack(">B", OP_PUBLISH_RECORD)
        req += struct.pack(">I", len(encoded_intent)) + encoded_intent
        req += actor_sig
        req += struct.pack(">I", len(body)) + body

        resp = h.handle(req, _actor_ctx())
        assert resp[0] == 1
        assert b"exceeds maximum" in resp.lower()


# ---------------------------------------------------------------------------
# Punishment write gate + BAN_STATUS
# ---------------------------------------------------------------------------


def _create_board(handler, board, actor=None):
    """Publish a real bonnet.board.create so a test can then publish articles
    to `board` — see firehose_commands._cmd_publish, which now refuses an
    article for a board nobody created. Idempotent: a no-op if the board
    already exists, so call sites that may run for the same stack more than
    once (e.g. an article and a report on the same board) don't collide."""
    if handler._nav.get_board("bbs.test", board) is not None:
        return
    actor = actor or ACTOR
    event_id = hashlib.sha256(f"test-board-create:{board}".encode()).digest()
    intent = Intent(
        event_id=event_id,
        kind="bonnet.board.create",
        origin="bbs.test",
        actor_pubkey=actor.public_key,
        board=board,
        metadata=MetadataMap([metadata_bytes(1, actor.public_key)]),
    )
    resp = handler.handle(_publish_request(intent, actor), _user_ctx(actor))
    assert resp[0] == 0x00, resp


def _publish_request(intent, actor_identity, body=b""):
    encoded_intent = encode_intent(intent)
    actor_sig = sign_intent(actor_identity, encoded_intent)
    req = struct.pack(">B", OP_PUBLISH_RECORD)
    req += struct.pack(">I", len(encoded_intent)) + encoded_intent
    req += actor_sig
    req += struct.pack(">I", len(body)) + body
    return req


def _user_ctx(user_identity):
    return FirehoseContext(
        peer_pubkey=user_identity.public_key,
        is_registered=True,
        origin="bbs.test",
    )


class TestPunishmentGate:
    @pytest.fixture
    def punished(self):
        return Identity.from_private_key(bytes(range(60, 92)))

    def _grant_write_all(self, stack):
        stack["acl"].add_rule(
            ACLRule(
                effect="allow",
                matcher=PrincipalMatcher(wildcard=True),
                actions=["read", "write"],
                commands=["*"],
                kinds=["*"],
                boards=["*"],
                objects=["*"],
            )
        )

    def _apply_punishment(self, policy, kind, pubkey, seq, expires=None):
        fields = [metadata_bytes(1, pubkey)]
        if expires is not None:
            fields.append(metadata_i64(2, expires))
        rec = Record(
            origin="bbs.test",
            origin_seq=seq,
            event_id=_rid(seq),
            kind=kind,
            actor_pubkey=ACTOR_PUB,
            board="moderation.actions",
            metadata=MetadataMap(fields),
            body_hash=compute_body_hash(b"reason"),
            body_size=len(b"reason"),
            created_at=int(time.time()),
        )
        if kind == "bonnet.punishment.revoke":
            rec.target_origin = "bbs.test"
            rec.target_event_id = _rid(expires)
            policy.apply_punishment_revoke(rec)
        else:
            policy.apply_punishment(rec)

    def _article_req(self, user, seed=1):
        body = b"hello world"
        intent = Intent(
            event_id=_rid(seed),
            kind="bonnet.article",
            origin="bbs.test",
            actor_pubkey=user.public_key,
            board="general",
            article_id=_rid(seed + 100),
            metadata=MetadataMap(
                [
                    metadata_text(1, "Test"),
                    metadata_text(4, "text/plain"),
                ]
            ),
            body_hash=compute_body_hash(body),
            body_size=len(body),
        )
        return _publish_request(intent, user, body), intent

    def test_warn_blocks_publish(self, stack, punished):
        h = stack["handler"]
        self._grant_write_all(stack)
        _create_board(h, "general")
        self._apply_punishment(stack["policy"], "bonnet.punishment.warn", punished.public_key, 1)

        req, _ = self._article_req(punished)
        resp = h.handle(req, _user_ctx(punished))
        assert resp[0] == 1
        assert struct.unpack(">H", resp[1:3])[0] == 0x000A
        assert b"warning" in resp
        assert b"event=" + _rid(1).hex().encode() in resp

    def test_ack_clears_warning_then_publish_succeeds(self, stack, punished):
        h = stack["handler"]
        self._grant_write_all(stack)
        _create_board(h, "general")
        self._apply_punishment(stack["policy"], "bonnet.punishment.warn", punished.public_key, 1)

        req, _ = self._article_req(punished)
        assert h.handle(req, _user_ctx(punished))[0] == 1

        ack = Intent(
            event_id=_rid(50),
            kind="bonnet.punishment.ack",
            origin="bbs.test",
            actor_pubkey=punished.public_key,
            metadata=MetadataMap([metadata_bytes(1, _rid(1))]),
        )
        ack_resp = h.handle(_publish_request(ack, punished), _user_ctx(punished))
        assert ack_resp[0] == 0
        assert stack["policy"].list_pending_for_pubkey(punished.public_key) == []

        req2, _ = self._article_req(punished, seed=2)
        assert h.handle(req2, _user_ctx(punished))[0] == 0

    def test_active_ban_and_permaban_block(self, stack, punished):
        h = stack["handler"]
        self._grant_write_all(stack)
        _create_board(h, "general")
        future = int(time.time()) + 3600
        self._apply_punishment(
            stack["policy"], "bonnet.punishment.ban", punished.public_key, 1, expires=future
        )
        req, _ = self._article_req(punished)
        resp = h.handle(req, _user_ctx(punished))
        assert struct.unpack(">H", resp[1:3])[0] == 0x000A
        assert b"ban" in resp

        permaban_user = Identity.from_private_key(bytes(range(70, 102)))
        self._apply_punishment(
            stack["policy"], "bonnet.punishment.permaban", permaban_user.public_key, 2
        )
        req2, _ = self._article_req(permaban_user)
        resp2 = h.handle(req2, _user_ctx(permaban_user))
        assert struct.unpack(">H", resp2[1:3])[0] == 0x000A
        assert b"permaban" in resp2

    def test_expired_ban_does_not_block(self, stack, punished):
        h = stack["handler"]
        self._grant_write_all(stack)
        _create_board(h, "general")
        past = int(time.time()) - 3600
        self._apply_punishment(
            stack["policy"], "bonnet.punishment.ban", punished.public_key, 1, expires=past
        )
        req, _ = self._article_req(punished)
        assert h.handle(req, _user_ctx(punished))[0] == 0

    def test_revoked_permaban_does_not_block(self, stack, punished):
        h = stack["handler"]
        self._grant_write_all(stack)
        _create_board(h, "general")
        self._apply_punishment(
            stack["policy"], "bonnet.punishment.permaban", punished.public_key, 1
        )
        revoke_rec = Record(
            origin="bbs.test",
            origin_seq=2,
            event_id=_rid(2),
            kind="bonnet.punishment.revoke",
            actor_pubkey=ACTOR_PUB,
            target_origin="bbs.test",
            target_event_id=_rid(1),
            created_at=int(time.time()),
        )
        stack["policy"].apply_punishment_revoke(revoke_rec)

        req, _ = self._article_req(punished)
        assert h.handle(req, _user_ctx(punished))[0] == 0

    def test_administrator_bypasses_gate(self, stack, punished):
        h = stack["handler"]
        self._grant_write_all(stack)
        _create_board(h, "general")
        self._apply_punishment(
            stack["policy"], "bonnet.punishment.permaban", punished.public_key, 1
        )

        admin = Identity.from_private_key(bytes(range(80, 112)))
        self._apply_punishment(stack["policy"], "bonnet.punishment.permaban", admin.public_key, 2)
        ctx = FirehoseContext(
            peer_pubkey=admin.public_key,
            is_registered=True,
            role="administrator",
            origin="bbs.test",
        )
        req, _ = self._article_req(admin)
        assert h.handle(req, ctx)[0] == 0


class TestBanStatusV2:
    def test_empty_status(self, stack):
        h = stack["handler"]
        req = struct.pack(">B", OP_BAN_STATUS) + struct.pack(">B", 32) + b"\x01" * 32
        resp = h.handle(req, _actor_ctx())
        assert resp[0] == 0
        assert resp[1] == 0

    def test_multi_pending_with_types(self, stack):
        h = stack["handler"]
        policy = stack["policy"]
        target = Identity.from_private_key(bytes(range(90, 122))).public_key
        future = int(time.time()) + 7200

        for seq, kind in (
            (1, "bonnet.punishment.warn"),
            (2, "bonnet.punishment.ban"),
            (3, "bonnet.punishment.permaban"),
        ):
            fields = [metadata_bytes(1, target)]
            if kind == "bonnet.punishment.ban":
                fields.append(metadata_i64(2, future))
            rec = Record(
                origin="bbs.test",
                origin_seq=seq,
                event_id=_rid(seq),
                kind=kind,
                actor_pubkey=ACTOR_PUB,
                board="moderation.actions",
                metadata=MetadataMap(fields),
                body_hash=b"\x33" * 32,
                body_size=7,
                created_at=int(time.time()) + seq,
            )
            policy.apply_punishment(rec)

        req = struct.pack(">B", OP_BAN_STATUS) + struct.pack(">B", len(target)) + target
        resp = h.handle(req, _actor_ctx())
        assert resp[0] == 0

        payload = resp[1:]
        count = payload[0]
        assert count == 3

        offset = 1
        seen_types = []
        for _ in range(count):
            type_code = payload[offset]
            offset += 1
            (expires_at,) = struct.unpack(">q", payload[offset : offset + 8])
            offset += 8
            (body_size,) = struct.unpack(">I", payload[offset : offset + 4])
            offset += 4
            body_hash = payload[offset : offset + 32]
            offset += 32
            _event_id = payload[offset : offset + 32]
            offset += 32
            origin_len = struct.unpack(">H", payload[offset : offset + 2])[0]
            offset += 2
            origin = payload[offset : offset + origin_len].decode()
            offset += origin_len

            seen_types.append(type_code)
            assert body_hash == b"\x33" * 32
            assert body_size == 7
            assert origin == "bbs.test"

        assert seen_types == [
            PUNISHMENT_TYPE_CODES["warning"],
            PUNISHMENT_TYPE_CODES["ban"],
            PUNISHMENT_TYPE_CODES["permaban"],
        ]

    def test_expired_and_revoked_excluded(self, stack):
        h = stack["handler"]
        policy = stack["policy"]
        target = Identity.from_private_key(bytes(range(95, 127))).public_key
        past = int(time.time()) - 7200

        expired = Record(
            origin="bbs.test",
            origin_seq=1,
            event_id=_rid(1),
            kind="bonnet.punishment.ban",
            actor_pubkey=ACTOR_PUB,
            board="moderation.actions",
            metadata=MetadataMap([metadata_bytes(1, target), metadata_i64(2, past)]),
            body_hash=b"\x33" * 32,
            body_size=7,
            created_at=int(time.time()),
        )
        policy.apply_punishment(expired)

        req = struct.pack(">B", OP_BAN_STATUS) + struct.pack(">B", len(target)) + target
        resp = h.handle(req, _actor_ctx())
        assert resp[0] == 0
        assert resp[1] == 0


# ---------------------------------------------------------------------------
# EVENT_HEAD tests
# ---------------------------------------------------------------------------


class TestEventHead:
    def test_head_after_publication(self, stack):
        h = stack["handler"]
        fh = stack["firehose"]

        body = b"hello"
        intent = Intent(
            event_id=_rid(1),
            kind="bonnet.article",
            origin="bbs.test",
            actor_pubkey=ACTOR_PUB,
            board="general",
            article_id=_rid(2),
            metadata=MetadataMap(
                [
                    metadata_text(1, "Test"),
                    metadata_text(4, "text/plain"),
                ]
            ),
            body_hash=compute_body_hash(body),
            body_size=len(body),
        )
        fh.append_record(ORIGIN, intent, sign_intent(ACTOR, encode_intent(intent)), body)

        req = struct.pack(">B", OP_EVENT_HEAD) + _enc_text16("bbs.test")
        resp = h.handle(req, _anon_ctx())
        assert resp[0] == 0

        head_len = struct.unpack(">H", resp[1:3])[0]
        head = decode_head(resp[3 : 3 + head_len])
        assert head.latest_origin_seq == 1
        assert head.origin_pubkey == ORIGIN_PUB


# ---------------------------------------------------------------------------
# EVENT_RANGE tests
# ---------------------------------------------------------------------------


class TestEventRange:
    def test_fetch_range(self, stack):
        h = stack["handler"]
        fh = stack["firehose"]

        for i in range(3):
            body = f"body{i}".encode()
            intent = Intent(
                event_id=_rid(i + 1),
                kind="bonnet.article",
                origin="bbs.test",
                actor_pubkey=ACTOR_PUB,
                board="general",
                article_id=_rid(i + 10),
                metadata=MetadataMap(
                    [
                        metadata_text(1, f"Article {i}"),
                        metadata_text(4, "text/plain"),
                    ]
                ),
                body_hash=compute_body_hash(body),
                body_size=len(body),
            )
            fh.append_record(ORIGIN, intent, sign_intent(ACTOR, encode_intent(intent)), body)

        req = struct.pack(">B", OP_EVENT_RANGE)
        req += _enc_text16("bbs.test")
        req += struct.pack(">Q", 1)
        req += struct.pack(">H", 10)
        req += struct.pack(">I", 0)

        resp = h.handle(req, _anon_ctx())
        assert resp[0] == 0

        count = struct.unpack(">H", resp[1:3])[0]
        assert count == 3


# ---------------------------------------------------------------------------
# EVENT_GET tests
# ---------------------------------------------------------------------------


class TestEventGet:
    def test_get_existing_event(self, stack):
        h = stack["handler"]
        fh = stack["firehose"]

        eid = _rid(1)
        body = b"hello"
        intent = Intent(
            event_id=eid,
            kind="bonnet.article",
            origin="bbs.test",
            actor_pubkey=ACTOR_PUB,
            board="general",
            article_id=_rid(2),
            metadata=MetadataMap(
                [
                    metadata_text(1, "Test"),
                    metadata_text(4, "text/plain"),
                ]
            ),
            body_hash=compute_body_hash(body),
            body_size=len(body),
        )
        fh.append_record(ORIGIN, intent, sign_intent(ACTOR, encode_intent(intent)), body)

        req = struct.pack(">B", OP_EVENT_GET)
        req += _enc_text16("bbs.test")
        req += eid

        resp = h.handle(req, _anon_ctx())
        assert resp[0] == 0

        rec_len = struct.unpack(">I", resp[1:5])[0]
        rec = decode_record(resp[5 : 5 + rec_len])
        assert rec.event_id == eid

    def test_get_missing_event(self, stack):
        h = stack["handler"]
        req = struct.pack(">B", OP_EVENT_GET)
        req += _enc_text16("bbs.test")
        req += _rid(99)

        resp = h.handle(req, _anon_ctx())
        assert resp[0] == 1


# ---------------------------------------------------------------------------
# Projection read tests
# ---------------------------------------------------------------------------


class TestProjectionReads:
    def _publish_and_dispatch(self, stack):
        _h = stack["handler"]
        d = stack["dispatcher"]
        fh = stack["firehose"]
        bs = stack["body_store"]
        _create_board(_h, "general")

        body = b"hello world"
        intent = Intent(
            event_id=_rid(1),
            kind="bonnet.article",
            origin="bbs.test",
            actor_pubkey=ACTOR_PUB,
            board="general",
            article_id=_rid(2),
            metadata=MetadataMap(
                [
                    metadata_text(1, "Test Article"),
                    metadata_text(4, "text/plain"),
                ]
            ),
            body_hash=compute_body_hash(body),
            body_size=len(body),
        )
        bs.stage_article_body(
            "bbs.test", "general", intent.event_id, body, intent.body_hash, intent.body_size
        )
        fh.append_record(ORIGIN, intent, sign_intent(ACTOR, encode_intent(intent)), body)
        d.dispatch_origin("bbs.test")

    def test_article_get_by_num(self, stack):
        self._publish_and_dispatch(stack)
        h = stack["handler"]

        req = struct.pack(">B", OP_ARTICLE_GET)
        req += _enc_text16("bbs.test")
        req += _enc_text16("general")
        req += struct.pack(">B", 0x01)  # by article_num
        req += struct.pack(">Q", 1)
        req += struct.pack(">B", 0)  # no body

        resp = h.handle(req, _anon_ctx())
        assert resp[0] == 0
        art_num = struct.unpack(">Q", resp[1:9])[0]
        assert art_num == 1

    def test_article_get_by_id(self, stack):
        self._publish_and_dispatch(stack)
        h = stack["handler"]

        req = struct.pack(">B", OP_ARTICLE_GET)
        req += _enc_text16("bbs.test")
        req += _enc_text16("general")
        req += struct.pack(">B", 0x02)  # by article_id
        req += _rid(2)
        req += struct.pack(">B", 0)

        resp = h.handle(req, _anon_ctx())
        assert resp[0] == 0

    def test_article_get_with_body(self, stack):
        self._publish_and_dispatch(stack)
        h = stack["handler"]

        req = struct.pack(">B", OP_ARTICLE_GET)
        req += _enc_text16("bbs.test")
        req += _enc_text16("general")
        req += struct.pack(">B", 0x01)
        req += struct.pack(">Q", 1)
        req += struct.pack(">B", 1)  # include body

        resp = h.handle(req, _anon_ctx())
        assert resp[0] == 0

    def test_article_list(self, stack):
        self._publish_and_dispatch(stack)
        h = stack["handler"]

        req = struct.pack(">B", OP_ARTICLE_LIST)
        req += _enc_text16("bbs.test")
        req += _enc_text16("general")
        req += struct.pack(">I", 0)  # offset
        req += struct.pack(">H", 10)  # limit
        req += struct.pack(">B", 0)  # flags

        resp = h.handle(req, _anon_ctx())
        assert resp[0] == 0
        count = struct.unpack(">H", resp[1:3])[0]
        assert count == 1

    def test_article_list_include_purged_flag(self, stack):
        """ARTICLE_LIST flag 0x04 must reach the projection instead of being dropped.

        A purge clears the body but leaves the article active, so the metadata row
        survives and ARTICLE_GET still returns it. The list flag decides only whether
        the listing walks past it.
        """
        self._publish_and_dispatch(stack)
        h = stack["handler"]

        bp = h._get_board_projection("bbs.test", "general")
        bp.apply_purge(
            Record(
                origin="bbs.test",
                origin_seq=2,
                event_id=_rid(3),
                kind="bonnet.article.purge",
                actor_pubkey=ACTOR_PUB,
                board="general",
                target_origin="bbs.test",
                target_board="general",
                target_article_id=_rid(2),
            )
        )

        def _count(flags):
            req = struct.pack(">B", OP_ARTICLE_LIST)
            req += _enc_text16("bbs.test")
            req += _enc_text16("general")
            req += struct.pack(">I", 0)  # offset
            req += struct.pack(">H", 10)  # limit
            req += struct.pack(">B", flags)
            resp = h.handle(req, _anon_ctx())
            assert resp[0] == 0
            return struct.unpack(">H", resp[1:3])[0]

        assert _count(0x00) == 0
        assert _count(0x04) == 1

    def test_article_body(self, stack):
        self._publish_and_dispatch(stack)
        h = stack["handler"]

        req = struct.pack(">B", OP_ARTICLE_BODY)
        req += _enc_text16("bbs.test")
        req += _enc_text16("general")
        req += struct.pack(">Q", 1)

        resp = h.handle(req, _anon_ctx())
        assert resp[0] == 0
        body_len = struct.unpack(">I", resp[1:5])[0]
        assert body_len == len(b"hello world")
        assert resp[5 : 5 + body_len] == b"hello world"

    def test_article_search_metadata(self, stack):
        self._publish_and_dispatch(stack)
        h = stack["handler"]

        req = struct.pack(">B", OP_ARTICLE_SEARCH)
        req += _enc_text16("bbs.test")
        req += _enc_text16("general")
        req += _enc_text16("Test")  # meta query
        req += _enc_text16("")  # no body query
        req += struct.pack(">I", 0)
        req += struct.pack(">H", 10)
        req += struct.pack(">B", 0)

        resp = h.handle(req, _anon_ctx())
        assert resp[0] == 0
        count = struct.unpack(">H", resp[1:3])[0]
        assert count == 1

    def test_board_scoped_grant_is_not_widened_by_an_unrelated_wildcard_rule(self, stack):
        """End-to-end proof that `_board_read_allowed` (the real per-board
        enforcement gate, not just `ACLEvaluator` in isolation) honors a
        command's own board scoping, even when some other rule for the same
        principal+action grants a *different* command on every board. This
        is exactly the shape `_board_read_allowed`'s own docstring warns
        about: "an ACL rule scoped to boards=[...] becomes a no-op" if the
        evaluator ever lets one rule's wildcard leak into another's grant."""
        self._publish_and_dispatch(stack)
        # Matching content on the excluded board too -- otherwise a wrongly
        # granted search and a correctly denied one both come back empty
        # (nothing there either way), and the test would prove nothing.
        fh = stack["firehose"]
        bs = stack["body_store"]
        body2 = b"hello elsewhere"
        intent2 = Intent(
            event_id=_rid(4),
            kind="bonnet.article",
            origin="bbs.test",
            actor_pubkey=ACTOR_PUB,
            board="some-other-board",
            article_id=_rid(5),
            metadata=MetadataMap(
                [metadata_text(1, "Test Article Too"), metadata_text(4, "text/plain")]
            ),
            body_hash=compute_body_hash(body2),
            body_size=len(body2),
        )
        bs.stage_article_body(
            "bbs.test",
            "some-other-board",
            intent2.event_id,
            body2,
            intent2.body_hash,
            intent2.body_size,
        )
        _create_board(stack["handler"], "some-other-board")
        fh.append_record(ORIGIN, intent2, sign_intent(ACTOR, encode_intent(intent2)), body2)
        stack["dispatcher"].dispatch_origin("bbs.test")

        h = stack["handler"]
        scout_pub = _rid(200)  # registered, but not the ACTOR_PUB admin key
        ctx = FirehoseContext(peer_pubkey=scout_pub, is_registered=True, origin="bbs.test")

        # `stack["acl"]` carries the fixture's own wildcard-principal,
        # wildcard-everything read rule, which would grant scout access to
        # everything regardless of what this test adds -- swapped for a
        # dedicated evaluator so the test actually exercises board scoping.
        acl = ACLEvaluator(default_rules_for_admin(ACTOR_PUB.hex()))
        h._acl = acl
        # Unrelated command, wildcard board -- present precisely because a
        # real deployment always has *some* such rule (the shipped default
        # bundles most read commands this way); it must not leak into
        # ARTICLE_SEARCH's own, narrower grant below.
        acl.add_rule(
            ACLRule(
                effect="allow",
                matcher=PrincipalMatcher(registered=True),
                actions=["read"],
                commands=["ARTICLE_GET"],
                boards=["*"],
            )
        )
        acl.add_rule(
            ACLRule(
                effect="allow",
                matcher=PrincipalMatcher(registered=True),
                actions=["read"],
                commands=["ARTICLE_SEARCH"],
                boards=["general"],
            )
        )

        def _search(board):
            req = struct.pack(">B", OP_ARTICLE_SEARCH)
            req += _enc_text16("bbs.test")
            req += _enc_text16(board)
            req += _enc_text16("Test")
            req += _enc_text16("")
            req += struct.pack(">I", 0)
            req += struct.pack(">H", 10)
            req += struct.pack(">B", 0)
            return h.handle(req, ctx)

        allowed = _search("general")
        assert allowed[0] == 0
        assert struct.unpack(">H", allowed[1:3])[0] == 1

        # _cmd_article_search denies by returning an empty result set, not
        # an error response -- see `_board_read_allowed`'s call site.
        denied = _search("some-other-board")
        assert denied[0] == 0
        assert struct.unpack(">H", denied[1:3])[0] == 0

    def test_ban_status_no_ban(self, stack):
        h = stack["handler"]

        req = struct.pack(">B", OP_BAN_STATUS)
        req += struct.pack(">B", 32) + ACTOR_PUB

        resp = h.handle(req, _anon_ctx())
        assert resp[0] == 0
        assert resp[1] == 0  # not banned


# ---------------------------------------------------------------------------
# Federation sync tests
# ---------------------------------------------------------------------------


class TestFederationSync:
    def test_sync_from_remote(self, tmp_path):
        """Two firehose stores: one as origin, one as receiver."""
        origin_store = FirehoseStore(str(tmp_path / "origin_events.db"))
        origin_store.init_origin_key("bbs.test", ORIGIN_PUB)

        body = b"remote article"
        intent = Intent(
            event_id=_rid(1),
            kind="bonnet.article",
            origin="bbs.test",
            actor_pubkey=ACTOR_PUB,
            board="general",
            article_id=_rid(2),
            metadata=MetadataMap(
                [
                    metadata_text(1, "Remote"),
                    metadata_text(4, "text/plain"),
                ]
            ),
            body_hash=compute_body_hash(body),
            body_size=len(body),
        )
        rec = origin_store.append_record(
            ORIGIN,
            intent,
            sign_intent(ACTOR, encode_intent(intent)),
            body,
        )

        head = origin_store.get_head("bbs.test")
        encoded_rec = encode_record(rec)
        event_hash = compute_event_hash(encoded_rec)

        origin_witness = make_origin_witness(
            origin="bbs.test",
            event_id=rec.event_id,
            event_hash=event_hash,
            origin_identity=ORIGIN,
            hostname="bbs.test",
            seen_at=1700000000,
        )

        receiver_store = FirehoseStore(str(tmp_path / "receiver_events.db"))
        receiver_store.init_origin_key("bbs.test", ORIGIN_PUB)

        class MockClient(SyncClient):
            async def fetch_head(self, origin):
                return head, encode_head(head)

            async def fetch_range(self, origin, start_seq, max_count):
                return [(rec, [origin_witness])]

            def peer_identity(self):
                return ORIGIN_PUB, "bbs.test"

        relay_identity = Identity.from_private_key(bytes(range(20, 52)))
        sync_mgr = SyncManager(receiver_store, relay_identity, "relay.test")
        result = sync_mgr.sync_manual("bbs.test", MockClient())

        assert result.accepted
        assert receiver_store.get_highest_seq("bbs.test") == 1

        fetched = receiver_store.get_event_by_id("bbs.test", rec.event_id)
        assert fetched is not None
        assert fetched.kind == "bonnet.article"

        origin_store.close()
        receiver_store.close()

    def test_sync_rejects_rollback(self, tmp_path):
        receiver_store = FirehoseStore(str(tmp_path / "receiver.db"))
        receiver_store.init_origin_key("bbs.test", ORIGIN_PUB)

        class MockClient(SyncClient):
            async def fetch_head(self, origin):
                return Head(
                    origin=origin,
                    latest_origin_seq=0,
                    origin_pubkey=ORIGIN_PUB,
                ), b""

            async def fetch_range(self, origin, start, count):
                return []

            def peer_identity(self):
                return ORIGIN_PUB, "bbs.test"

        sync_mgr = SyncManager(receiver_store, ORIGIN, "bbs.test")
        result = sync_mgr.sync_manual("bbs.test", MockClient())
        assert not result.accepted

        receiver_store.close()

    def test_sync_witness_created(self, tmp_path):
        """Verify the receiver creates its own witness."""
        origin_store = FirehoseStore(str(tmp_path / "origin.db"))
        origin_store.init_origin_key("bbs.test", ORIGIN_PUB)

        body = b"test body"
        intent = Intent(
            event_id=_rid(1),
            kind="bonnet.article",
            origin="bbs.test",
            actor_pubkey=ACTOR_PUB,
            board="general",
            article_id=_rid(2),
            metadata=MetadataMap(
                [
                    metadata_text(1, "Test"),
                    metadata_text(4, "text/plain"),
                ]
            ),
            body_hash=compute_body_hash(body),
            body_size=len(body),
        )
        rec = origin_store.append_record(
            ORIGIN,
            intent,
            sign_intent(ACTOR, encode_intent(intent)),
            body,
        )
        head = origin_store.get_head("bbs.test")
        encoded_rec = encode_record(rec)
        event_hash = compute_event_hash(encoded_rec)
        origin_w = make_origin_witness(
            origin="bbs.test",
            event_id=rec.event_id,
            event_hash=event_hash,
            origin_identity=ORIGIN,
            hostname="bbs.test",
            seen_at=1700000000,
        )

        receiver_store = FirehoseStore(str(tmp_path / "receiver.db"))
        receiver_store.init_origin_key("bbs.test", ORIGIN_PUB)

        relay_identity = Identity.from_private_key(bytes(range(20, 52)))

        class MockClient(SyncClient):
            async def fetch_head(self, origin):
                return head, encode_head(head)

            async def fetch_range(self, origin, start, count):
                return [(rec, [origin_w])]

            def peer_identity(self):
                # The mock peer here *is* the origin's own server, so the
                # authenticated peer and the origin coincide - which is why
                # these assertions read the same as before the witness stopped
                # being copied from the upstream's self-description.
                return ORIGIN_PUB, "bbs.test"

        sync_mgr = SyncManager(receiver_store, relay_identity, "relay.test")
        result = sync_mgr.sync_manual("bbs.test", MockClient())
        assert result.accepted

        local_w = receiver_store.get_witness("bbs.test", rec.event_id, relay_identity.public_key)
        assert local_w is not None
        assert local_w.relay_hostname == "relay.test"
        assert local_w.received_from_pubkey == ORIGIN_PUB
        assert local_w.received_from_hostname == "bbs.test"

        origin_store.close()
        receiver_store.close()
