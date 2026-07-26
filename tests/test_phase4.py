"""Phase 4 tests: firehose command handler and federation sync.

Tests PROTOCOL.md §18 (discovery), §19 (command transport), §17 (sync).
"""

import struct

import pytest

from core.acl import ACLEvaluator, ACLRule, PrincipalMatcher, default_rules_for_admin
from core.bodies import BodyStore
from core.crypto import Identity
from core.dispatcher import Dispatcher
from core.firehose import FirehoseStore
from core.global_projections import NavProjection, PolicyProjection, UserProjection
from core.kind_validator import KindValidator
from core.record import (
    Head,
    Intent,
    MetadataMap,
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
    metadata_text,
    sign_intent,
)
from core.search import SearchService
from net.firehose_commands import (
    OP_ARTICLE_BODY,
    OP_ARTICLE_GET,
    OP_ARTICLE_LIST,
    OP_ARTICLE_SEARCH,
    OP_BAN_STATUS,
    OP_EVENT_GET,
    OP_EVENT_HEAD,
    OP_EVENT_RANGE,
    OP_PUBLISH_RECORD,
    FirehoseCommandHandler,
    FirehoseContext,
)
from net.firehose_sync import SyncClient, SyncManager

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
        assert rec.origin_seq == 1
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
        h = stack["handler"]
        d = stack["dispatcher"]
        fh = stack["firehose"]
        bs = stack["body_store"]

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
                return [(rec, origin_witness)]

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
                return [(rec, origin_w)]

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
