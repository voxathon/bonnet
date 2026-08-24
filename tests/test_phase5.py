"""Phase 5 tests: firehose client protocol builders/parsers and models.

Tests round-trip encoding/decoding of all 13 command builders and response
parsers. Uses mock data — no HTTP required.
"""

import struct

import pytest

from bonnet.client.firehose_protocol import (
    OP_ARTICLE_BODY,
    OP_ARTICLE_GET,
    OP_ARTICLE_LIST,
    OP_ARTICLE_SEARCH,
    OP_BAN_STATUS,
    OP_BOARD_LIST,
    OP_EVENT_BODY,
    OP_EVENT_GET,
    OP_EVENT_HEAD,
    OP_EVENT_RANGE,
    OP_PUBLISH_RECORD,
    OP_USER_GET,
    OP_USER_LIST,
    SELECTOR_BY_ID,
    SELECTOR_BY_NUM,
    ProtocolError,
    build_article_body,
    build_article_get,
    build_article_list,
    build_article_search,
    build_ban_status,
    build_board_list,
    build_event_body,
    build_event_get,
    build_event_head,
    build_event_range,
    build_publish_record,
    build_user_get,
    build_user_list,
    parse_article_body_response,
    parse_article_get_response,
    parse_article_list_response,
    parse_article_search_response,
    parse_ban_status_response,
    parse_board_list_response,
    parse_event_body_response,
    parse_event_get_response,
    parse_event_head_response,
    parse_event_range_response,
    parse_publish_response,
    parse_publish_response_raw,
    parse_response,
    parse_user_get_response,
    parse_user_list_response,
)
from bonnet.core.crypto import Identity
from bonnet.core.record import (
    ZERO_HASH,
    ZERO_ID,
    Head,
    Intent,
    MetadataMap,
    Record,
    Witness,
    compute_body_hash,
    compute_event_hash,
    encode_head,
    encode_intent,
    encode_record,
    encode_unsigned_head,
    encode_unsigned_record,
    encode_witness,
    metadata_text,
    sign_head,
    sign_intent,
    sign_record,
)

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
# Helpers to build mock server responses
# ---------------------------------------------------------------------------


def _success(payload: bytes = b"") -> bytes:
    return b"\x00" + payload


def _error_resp(code: int, msg: str) -> bytes:
    msg_bytes = msg.encode("utf-8")
    return b"\x01" + struct.pack(">H", code) + struct.pack(">H", len(msg_bytes)) + msg_bytes


def _make_record(
    origin="bbs.test",
    seq=1,
    eid=None,
    kind="bonnet.article",
    article_num=1,
    board="general",
    actor=ACTOR,
) -> Record:
    eid = eid or _rid(seq)
    body = b"test body"
    intent = Intent(
        event_id=eid,
        kind=kind,
        origin=origin,
        actor_pubkey=actor.public_key,
        board=board,
        article_id=_rid(seq + 10) if kind == "bonnet.article" else ZERO_ID,
        metadata=MetadataMap(
            [
                metadata_text(1, "Test Subject"),
                metadata_text(4, "text/plain"),
            ]
        ),
        body_hash=compute_body_hash(body) if body else ZERO_HASH,
        body_size=len(body) if body else 0,
    )
    actor_sig = sign_intent(actor, encode_intent(intent))
    rec = Record(
        origin=origin,
        origin_seq=seq,
        previous_event_hash=ZERO_HASH,
        event_id=eid,
        kind=kind,
        actor_pubkey=actor.public_key,
        board=board,
        article_id=intent.article_id,
        article_num=article_num if kind == "bonnet.article" else 0,
        metadata=intent.metadata,
        body_hash=intent.body_hash,
        body_size=intent.body_size,
        actor_signature=actor_sig,
    )
    unsigned = encode_unsigned_record(rec)
    rec.origin_signature = sign_record(ORIGIN, unsigned)
    return rec


def _make_witness(rec: Record, hostname="bbs.test") -> Witness:
    encoded = encode_record(rec)
    event_hash = compute_event_hash(encoded)
    from bonnet.core.record import make_origin_witness

    return make_origin_witness(
        origin=rec.origin,
        event_id=rec.event_id,
        event_hash=event_hash,
        origin_identity=ORIGIN,
        hostname=hostname,
        seen_at=1700000000,
    )


# ---------------------------------------------------------------------------
# Response parser tests
# ---------------------------------------------------------------------------


class TestResponseParser:
    def test_success(self):
        status, payload = parse_response(b"\x00hello")
        assert status == 0
        assert payload == b"hello"

    def test_error(self):
        with pytest.raises(ProtocolError, match="error 5"):
            parse_response(_error_resp(5, "bad request"))

    def test_empty(self):
        with pytest.raises(ProtocolError, match="empty"):
            parse_response(b"")


# ---------------------------------------------------------------------------
# PUBLISH_RECORD
# ---------------------------------------------------------------------------


class TestPublishRecord:
    def test_build_and_parse(self):
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
                    metadata_text(1, "Subject"),
                    metadata_text(4, "text/plain"),
                ]
            ),
            body_hash=compute_body_hash(body),
            body_size=len(body),
        )
        actor_sig = sign_intent(ACTOR, encode_intent(intent))
        cmd = build_publish_record(intent, actor_sig, body)
        assert cmd[0] == OP_PUBLISH_RECORD

        rec = _make_record()
        witness = _make_witness(rec)
        encoded_rec = encode_record(rec)
        encoded_w = encode_witness(witness)
        resp = _success(
            struct.pack(">I", len(encoded_rec))
            + encoded_rec
            + struct.pack(">H", len(encoded_w))
            + encoded_w
        )

        result = parse_publish_response(resp)
        assert result.origin_seq == 1
        assert result.kind == "bonnet.article"
        assert result.article_num == 1

    def test_parse_raw(self):
        rec = _make_record()
        witness = _make_witness(rec)
        encoded_rec = encode_record(rec)
        encoded_w = encode_witness(witness)
        resp = _success(
            struct.pack(">I", len(encoded_rec))
            + encoded_rec
            + struct.pack(">H", len(encoded_w))
            + encoded_w
        )
        raw_rec, raw_w = parse_publish_response_raw(resp)
        assert raw_rec.event_id == rec.event_id
        assert raw_w.relay_pubkey == ORIGIN_PUB


# ---------------------------------------------------------------------------
# EVENT_HEAD
# ---------------------------------------------------------------------------


class TestEventHead:
    def test_build(self):
        cmd = build_event_head("bbs.test")
        assert cmd[0] == OP_EVENT_HEAD

    def test_parse(self):
        head = Head(
            origin="bbs.test",
            latest_origin_seq=42,
            origin_pubkey=ORIGIN_PUB,
        )
        unsigned = encode_unsigned_head(head)
        head.origin_signature = sign_head(ORIGIN, unsigned)
        encoded = encode_head(head)
        resp = _success(struct.pack(">H", len(encoded)) + encoded)

        info = parse_event_head_response(resp)
        assert info.origin == "bbs.test"
        assert info.latest_origin_seq == 42
        assert info.origin_pubkey == ORIGIN_PUB.hex()


# ---------------------------------------------------------------------------
# EVENT_RANGE
# ---------------------------------------------------------------------------


class TestEventRange:
    def test_build(self):
        cmd = build_event_range("bbs.test", 1, 50, 1024)
        assert cmd[0] == OP_EVENT_RANGE

    def test_parse(self):
        recs = [_make_record(seq=i + 1) for i in range(3)]
        out = struct.pack(">H", 3)
        for rec in recs:
            w = _make_witness(rec)
            er = encode_record(rec)
            ew = encode_witness(w)
            out += struct.pack(">I", len(er)) + er
            out += struct.pack(">H", len(ew)) + ew
        resp = _success(out)

        results = parse_event_range_response(resp)
        assert len(results) == 3
        assert results[0][0].origin_seq == 1
        assert results[2][0].origin_seq == 3


# ---------------------------------------------------------------------------
# EVENT_GET
# ---------------------------------------------------------------------------


class TestEventGet:
    def test_build(self):
        eid = _rid(5)
        cmd = build_event_get("bbs.test", eid)
        assert cmd[0] == OP_EVENT_GET
        assert eid in cmd

    def test_parse(self):
        rec = _make_record()
        w = _make_witness(rec)
        er = encode_record(rec)
        ew = encode_witness(w)
        resp = _success(struct.pack(">I", len(er)) + er + struct.pack(">H", len(ew)) + ew)
        raw_rec, raw_w = parse_event_get_response(resp)
        assert raw_rec.event_id == rec.event_id
        assert raw_w.relay_pubkey == ORIGIN_PUB


# ---------------------------------------------------------------------------
# BOARD_LIST
# ---------------------------------------------------------------------------


class TestBoardList:
    def test_build(self):
        cmd = build_board_list("bbs.test")
        assert cmd[0] == OP_BOARD_LIST

    def test_parse(self):
        out = struct.pack(">H", 2)
        for name, closed, owner, display in [
            ("general", False, ACTOR_PUB, "General"),
            ("secret", True, ACTOR_PUB, "Secret Board"),
        ]:
            out += _enc_text16(name)
            out += struct.pack(">B", 1 if closed else 0)
            out += struct.pack(">B", len(owner)) + owner
            out += _enc_text16(display)
        resp = _success(out)

        boards = parse_board_list_response(resp)
        assert len(boards) == 2
        assert boards[0].name == "general"
        assert not boards[0].closed
        assert boards[0].display_name == "General"
        assert boards[1].name == "secret"
        assert boards[1].closed


# ---------------------------------------------------------------------------
# ARTICLE_GET
# ---------------------------------------------------------------------------


class TestArticleGet:
    def test_build_by_num(self):
        cmd = build_article_get("bbs.test", "general", SELECTOR_BY_NUM, 5, include_body=True)
        assert cmd[0] == OP_ARTICLE_GET

    def test_build_by_id(self):
        aid = _rid(5)
        cmd = build_article_get("bbs.test", "general", SELECTOR_BY_ID, aid)
        assert cmd[0] == OP_ARTICLE_GET

    def test_parse(self):
        aid = _rid(2)
        eid = _rid(1)
        bh = compute_body_hash(b"hello")
        ap = ACTOR_PUB

        out = struct.pack(">Q", 1)  # article_num
        out += struct.pack(">B", 32) + aid  # article_id
        out += struct.pack(">B", 32) + eid  # event_id
        out += struct.pack(">B", 0)  # visibility=active
        out += struct.pack(">B", 0)  # body_state=available
        out += struct.pack(">B", 32) + bh  # body_hash
        out += struct.pack(">Q", 5)  # body_size
        out += struct.pack(">q", 1700000000)  # created_at
        out += struct.pack(">B", 32) + ap  # author_pubkey
        out += _enc_text16("root")  # author_username
        out += _enc_text16("bbs.test")  # author_registrar
        out += _enc_text16("Test Subject")
        out += _enc_text16("news,tech")
        out += _enc_text16("text/plain")
        out += struct.pack(">B", 32) + ZERO_ID  # root_article_id
        out += struct.pack(">B", 32) + ZERO_ID  # reply_to_article_id
        out += struct.pack(">B", 0)  # no replacement
        out += _enc_text16("unpinned")  # pin_state
        out += _enc_text16("open")  # thread_state
        body = b"hello world"
        out += struct.pack(">I", len(body)) + body
        resp = _success(out)

        art = parse_article_get_response(resp)
        assert art.article_num == 1
        assert art.visibility == "active"
        assert art.body_state == "available"
        assert art.subject == "Test Subject"
        assert art.tags == "news,tech"
        assert art.body == body
        assert art.author_username == "root"
        assert art.author_registrar == "bbs.test"
        assert art.pin_state == "unpinned"
        assert art.thread_state == "open"


# ---------------------------------------------------------------------------
# ARTICLE_LIST
# ---------------------------------------------------------------------------


class TestArticleList:
    def test_build(self):
        cmd = build_article_list("bbs.test", "general", 0, 10, include_cancelled=True)
        assert cmd[0] == OP_ARTICLE_LIST

    def test_parse(self):
        aid = _rid(2)
        eid = _rid(1)
        bh = compute_body_hash(b"hello")
        ap = ACTOR_PUB

        item = struct.pack(">Q", 1)
        item += struct.pack(">B", 32) + aid
        item += struct.pack(">B", 32) + eid
        item += struct.pack(">B", 0)  # active
        item += struct.pack(">B", 0)  # available
        item += struct.pack(">B", 32) + bh
        item += struct.pack(">Q", 5)
        item += struct.pack(">q", 1700000000)
        item += struct.pack(">B", 32) + ap
        item += _enc_text16("root")
        item += _enc_text16("bbs.test")
        item += _enc_text16("Subject")
        item += _enc_text16("")
        item += _enc_text16("text/plain")
        item += struct.pack(">B", 32) + ZERO_ID  # root_article_id
        item += struct.pack(">B", 32) + ZERO_ID  # reply_to_article_id
        item += struct.pack(">B", 0)  # no replacement
        item += _enc_text16("unpinned")
        item += _enc_text16("open")
        item += struct.pack(">I", 0)  # body blob (empty for list)

        resp = _success(struct.pack(">H", 1) + item)
        articles = parse_article_list_response(resp)
        assert len(articles.results) == 1
        assert articles.results[0].article_num == 1
        assert articles.results[0].subject == "Subject"


# ---------------------------------------------------------------------------
# ARTICLE_SEARCH
# ---------------------------------------------------------------------------


class TestArticleSearch:
    def test_build(self):
        cmd = build_article_search("bbs.test", "general", "hello", "", 0, 10)
        assert cmd[0] == OP_ARTICLE_SEARCH

    def test_parse(self):
        aid = _rid(2)
        ap = ACTOR_PUB
        out = struct.pack(">H", 1)  # count
        out += struct.pack(">I", 1)  # total
        out += struct.pack(">B", 0)  # not truncated
        out += struct.pack(">Q", 1)  # article_num
        out += struct.pack(">B", 32) + aid
        out += struct.pack(">B", 4) + b"Test"
        out += struct.pack(">B", 32) + ap
        out += struct.pack(">q", 1700000000)
        out += struct.pack(">B", 1)  # body available
        out += _enc_text16("excerpt text")
        resp = _success(out)

        result = parse_article_search_response(resp)
        assert len(result.results) == 1
        assert result.results[0].article_num == 1
        assert result.results[0].subject == "Test"
        assert result.results[0].excerpt == "excerpt text"
        assert result.total == 1
        assert not result.truncated


# ---------------------------------------------------------------------------
# ARTICLE_BODY
# ---------------------------------------------------------------------------


class TestArticleBody:
    def test_build(self):
        cmd = build_article_body("bbs.test", "general", 1)
        assert cmd[0] == OP_ARTICLE_BODY

    def test_parse(self):
        body = b"hello world"
        resp = _success(struct.pack(">I", len(body)) + body)
        result = parse_article_body_response(resp)
        assert result == body


# ---------------------------------------------------------------------------
# USER_GET
# ---------------------------------------------------------------------------


class TestUserGet:
    def test_build(self):
        cmd = build_user_get("bbs.test", ACTOR_PUB)
        assert cmd[0] == OP_USER_GET

    def test_parse(self):
        pk = ACTOR_PUB
        out = struct.pack(">B", 32) + pk
        out += _enc_text16("alice")
        out += struct.pack(">Q", 0x01)  # flags
        out += struct.pack(">Q", 1)  # reg_seq
        out += struct.pack(">q", 1700000000)  # created_at
        out += struct.pack(">B", 0)  # not revoked
        out += struct.pack(">Q", 0)  # revoked_seq
        resp = _success(out)

        user = parse_user_get_response(resp)
        assert user.username == "alice"
        assert user.flags == 0x01
        assert not user.revoked
        assert user.revoked_seq == 0


# ---------------------------------------------------------------------------
# USER_LIST
# ---------------------------------------------------------------------------


class TestUserList:
    def test_build(self):
        cmd = build_user_list("bbs.test", include_revoked=True)
        assert cmd[0] == OP_USER_LIST

    def test_parse(self):
        pk = ACTOR_PUB
        item = _enc_text16("bbs.test")  # origin
        item += struct.pack(">B", 32) + pk
        item += _enc_text16("bob")
        item += struct.pack(">Q", 0)  # flags
        item += struct.pack(">Q", 1)  # reg_seq
        item += struct.pack(">q", 1700000000)  # created_at
        item += struct.pack(">B", 0)  # not revoked
        resp = _success(struct.pack(">H", 1) + item)

        users = parse_user_list_response(resp)
        assert len(users) == 1
        assert users[0].username == "bob"
        assert users[0].origin == "bbs.test"
        assert users[0].reg_seq == 1


# ---------------------------------------------------------------------------
# BAN_STATUS
# ---------------------------------------------------------------------------


class TestBanStatus:
    def test_build(self):
        cmd = build_ban_status(ACTOR_PUB)
        assert cmd[0] == OP_BAN_STATUS

    def test_parse_empty(self):
        resp = _success(struct.pack(">B", 0))
        result = parse_ban_status_response(resp)
        assert result.punishments == []
        assert not result.banned
        assert not result.blocked

    def _encode_punishment(
        self, type_code, event_id, origin="bbs.test", expires_at=0, body_hash=None, body_size=0
    ):
        out = struct.pack(">B", type_code)
        out += struct.pack(">q", expires_at)
        out += struct.pack(">I", body_size)
        out += body_hash if body_hash is not None else b"\x00" * 32
        out += event_id
        out += _enc_text16(origin)
        return out

    def test_parse_multi_pending(self):
        eid_ban = _rid(1)
        eid_warn = _rid(2)
        out = struct.pack(">B", 2)
        out += self._encode_punishment(2, eid_ban, expires_at=1800000000, body_size=7)
        out += self._encode_punishment(1, eid_warn, body_hash=b"\x44" * 32)
        resp = _success(out)

        result = parse_ban_status_response(resp)
        assert result.blocked
        assert result.banned
        ban = result.punishments[0]
        warn = result.punishments[1]
        assert ban.type == "ban"
        assert ban.event_id == eid_ban.hex()
        assert ban.origin == "bbs.test"
        assert ban.expires_at == 1800000000
        assert ban.body_size == 7

        assert warn.type == "warning"
        assert warn.expires_at == 0
        assert warn.body_hash == ("44" * 32)

    def test_parse_permaban_sets_banned(self):
        out = struct.pack(">B", 1)
        out += self._encode_punishment(3, _rid(3))
        result = parse_ban_status_response(resp=_success(out))
        assert result.banned

    def test_parse_unknown_type_code(self):
        out = struct.pack(">B", 1)
        out += self._encode_punishment(9, _rid(4))
        result = parse_ban_status_response(_success(out))
        assert result.punishments[0].type.startswith("unknown")


# ---------------------------------------------------------------------------
# EVENT_BODY
# ---------------------------------------------------------------------------


class TestEventBody:
    def test_build(self):
        eid = _rid(5)
        cmd = build_event_body("bbs.test", eid)
        assert cmd[0] == OP_EVENT_BODY

    def test_parse(self):
        body = b"event body content"
        resp = _success(struct.pack(">I", len(body)) + body)
        result = parse_event_body_response(resp)
        assert result == body
