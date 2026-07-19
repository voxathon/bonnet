"""Tests for protocol v3 article feed primitives (Phase 1).

Covers ARTICLE_FEED_PROTOCOL_V3_IMPLEMENTATION_PLAN.md §23.1–23.5:
  - Canonical encoding vectors (§23.1)
  - Origin normalization (§7.1)
  - Local append tests (§23.2)
  - Feed acceptance tests (§23.4)
  - Body store tests (§23.5)
  - Wire fixture reproducibility
"""

import os
import sys
import struct
import threading
import random
from concurrent.futures import ThreadPoolExecutor

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.article_feed import (
    FORMAT_VERSION,
    SUBMISSION_VERSION,
    HEAD_FORMAT_VERSION,
    EVENT_ARTICLE,
    EVENT_CANCEL,
    EVENT_RESTORE,
    EVENT_PURGE,
    EVENT_RULE,
    EVENT_RULE_REVOKE,
    EVENT_REPORT,
    EVENT_PUNISHMENT,
    EVENT_PUNISHMENT_REVOKE,
    EVENT_BOARD_CLOSE,
    EVENT_BOARD_REOPEN,
    EVENT_ARTICLE_PIN,
    EVENT_ARTICLE_UNPIN,
    EVENT_THREAD_CLOSE,
    EVENT_THREAD_REOPEN,
    SCHEME_NONE,
    SCHEME_V3,
    SCHEME_LEGACY_V2,
    EXT_LEGACY_DESCRIPTOR,
    EXT_LEGACY_AUTHOR_SIGNED_PAYLOAD,
    EXT_LEGACY_AUTHOR_SIGNATURE,
    EXT_LEGACY_UNRESOLVED_REFERENCES,
    ZERO_HASH,
    ZERO_MESSAGE_ID,
    DOMAIN_EVENT_HASH,
    DOMAIN_BODY_HASH,
    DOMAIN_AUTHOR_SIG,
    DOMAIN_ORIGIN_SIG,
    DOMAIN_HEAD_SIG,
    DOMAIN_HEAD_HASH,
    MAX_ORIGIN_LEN,
    MAX_BOARD_LEN,
    MAX_ACTOR_NAME_LEN,
    MAX_HEADERS_LEN,
    MAX_EXTENSIONS_LEN,
    DEFAULT_MAX_BODY_SIZE,
    InvalidOrigin,
    DecodeError,
    MessageIdCollision,
    FeedAcceptanceError,
    AcceptResult,
    normalize_origin,
    ArticleHeaders,
    RuleHeaders,
    ReportHeaders,
    PunishmentHeaders,
    PinHeaders,
    Extension,
    Submission,
    Event,
    FeedHead,
    encode_submission,
    decode_submission,
    validate_submission,
    encode_event,
    decode_event,
    validate_event,
    encode_head,
    decode_head,
    make_empty_head,
    encode_head_payload,
    compute_event_hash,
    compute_body_hash,
    compute_head_hash,
    author_signature_payload,
    sign_author,
    verify_author_signature,
    sign_origin,
    verify_origin_signature,
    sign_head,
    verify_head_signature,
    ArticleFeedStore,
    _event_to_submission,
)
from core.crypto import Identity
from tests.fixtures.protocol_v3.wire_fixtures import (
    ORIGIN_SEED,
    ORIGIN_PUBLIC,
    ORIGIN_PRIVATE,
    AUTHOR_SEED,
    AUTHOR_PUBLIC,
    AUTHOR_PRIVATE,
    FIXED_ORIGIN,
    FIXED_BOARD,
    FIXED_CREATED_AT,
    FIXED_SNAPSHOT_TS,
    FIXED_ARTICLE_MSGID,
    FIXED_CANCEL_MSGID,
    FIXED_REPORT_MSGID,
    FIXED_PUNISHMENT_MSGID,
    FIXED_BODY,
    FIXED_BODY_HASH,
    FIXED_BODY_SIZE,
    EMPTY_BODY_HASH,
    FIXED_ARTICLE_SUBMISSION,
    FIXED_ARTICLE_SUBMISSION_BYTES,
    FIXED_AUTHOR_SIGNATURE,
    FIXED_ARTICLE_EVENT,
    FIXED_ARTICLE_EVENT_BYTES,
    FIXED_ARTICLE_EVENT_HASH,
    FIXED_CANCEL_EVENT,
    FIXED_CANCEL_EVENT_BYTES,
    FIXED_CANCEL_EVENT_HASH,
    FIXED_REPORT_EVENT,
    FIXED_REPORT_EVENT_BYTES,
    FIXED_REPORT_EVENT_HASH,
    FIXED_PUNISHMENT_EVENT,
    FIXED_PUNISHMENT_EVENT_BYTES,
    FIXED_PUNISHMENT_EVENT_HASH,
    FIXED_HEAD,
    FIXED_HEAD_BYTES,
    FIXED_HEAD_HASH,
    FIXED_EMPTY_HEAD,
    FIXED_EMPTY_HEAD_BYTES,
    FIXED_EMPTY_HEAD_HASH,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _origin_identity():
    return Identity.from_private_key(ORIGIN_SEED)

def _author_identity():
    return Identity.from_private_key(AUTHOR_SEED)

def _random_msgid(seed: int) -> bytes:
    rng = random.Random(seed)
    mid = rng.randbytes(32)
    while mid == ZERO_MESSAGE_ID:
        mid = rng.randbytes(32)
    return mid

def _make_article_submission(seed: int, origin=FIXED_ORIGIN, board=FIXED_BOARD,
                             body=None, author_identity=None):
    if author_identity is None:
        author_identity = _author_identity()
    if body is None:
        body = f"body content {seed}".encode("utf-8")
    body_hash = compute_body_hash(body)
    sub = Submission(
        submission_version=SUBMISSION_VERSION,
        event_type=EVENT_ARTICLE,
        origin=origin,
        board=board,
        message_id=_random_msgid(seed),
        created_at=FIXED_CREATED_AT + seed,
        actor_pubkey=author_identity.public_key,
        actor_username="alice",
        actor_registrar=origin,
        headers=ArticleHeaders(subject=f"Article {seed}", tags="test", options=""),
        body_hash=body_hash,
        body_size=len(body),
    )
    sig = sign_author(sub, author_identity)
    return sub, body, sig

def _make_store(temp_dir, max_body_size=DEFAULT_MAX_BODY_SIZE):
    db_path = os.path.join(temp_dir, "article_feeds.db")
    bodies_dir = os.path.join(temp_dir, "article_bodies")
    return ArticleFeedStore(db_path, bodies_dir, max_body_size=max_body_size)


# ---------------------------------------------------------------------------
# A. Canonical encoding vectors (§23.1)
# ---------------------------------------------------------------------------

class TestCanonicalEncodingVectors:

    def test_article_vector_roundtrip(self):
        decoded = decode_event(FIXED_ARTICLE_EVENT_BYTES)
        assert decoded == FIXED_ARTICLE_EVENT
        assert decoded.event_type == EVENT_ARTICLE
        assert decoded.feed_seq == 1
        assert decoded.article_num == 1
        assert isinstance(decoded.headers, ArticleHeaders)
        assert decoded.headers.subject == "Test Article"
        assert decoded.headers.tags == "test,v3"

    def test_cancel_vector_roundtrip(self):
        decoded = decode_event(FIXED_CANCEL_EVENT_BYTES)
        assert decoded == FIXED_CANCEL_EVENT
        assert decoded.event_type == EVENT_CANCEL
        assert decoded.headers is None
        assert decoded.target_message_id == FIXED_ARTICLE_MSGID

    def test_report_vector_roundtrip(self):
        decoded = decode_event(FIXED_REPORT_EVENT_BYTES)
        assert decoded == FIXED_REPORT_EVENT
        assert isinstance(decoded.headers, ReportHeaders)
        assert decoded.headers.culprit_pubkey == ORIGIN_PUBLIC
        assert decoded.headers.target_article_id == FIXED_ARTICLE_MSGID

    def test_punishment_vector_roundtrip(self):
        decoded = decode_event(FIXED_PUNISHMENT_EVENT_BYTES)
        assert decoded == FIXED_PUNISHMENT_EVENT
        assert isinstance(decoded.headers, PunishmentHeaders)
        assert decoded.headers.punished_pubkey == AUTHOR_PUBLIC
        assert decoded.headers.expires_at == -1
        assert decoded.headers.report_ids == [FIXED_REPORT_MSGID]

    def test_empty_and_max_length_fields(self):
        # Empty strings
        sub = Submission(
            event_type=EVENT_ARTICLE, origin="x", board="y",
            message_id=_random_msgid(99), created_at=1,
            actor_pubkey=AUTHOR_PUBLIC, actor_username="",
            actor_registrar="",
            headers=ArticleHeaders(subject="", tags="", options=""),
            body_hash=EMPTY_BODY_HASH, body_size=0,
        )
        encoded = encode_submission(sub)
        decoded = decode_submission(encoded)
        assert decoded == sub

        # Max-length origin (255 bytes UTF-8)
        max_origin = "a" * MAX_ORIGIN_LEN
        sub2 = Submission(
            event_type=EVENT_ARTICLE, origin=max_origin, board="y",
            message_id=_random_msgid(98), created_at=1,
            actor_pubkey=AUTHOR_PUBLIC, actor_username="",
            actor_registrar="",
            headers=ArticleHeaders(subject="", tags="", options=""),
            body_hash=EMPTY_BODY_HASH, body_size=0,
        )
        encoded2 = encode_submission(sub2)
        decoded2 = decode_submission(encoded2)
        assert decoded2 == sub2

    def test_author_signature_vector(self):
        assert verify_author_signature(
            FIXED_ARTICLE_SUBMISSION, FIXED_AUTHOR_SIGNATURE, AUTHOR_PUBLIC)
        # Tamper one byte
        tampered = bytearray(FIXED_AUTHOR_SIGNATURE)
        tampered[0] ^= 1
        assert not verify_author_signature(
            FIXED_ARTICLE_SUBMISSION, bytes(tampered), AUTHOR_PUBLIC)

    def test_origin_signature_vector(self):
        assert verify_origin_signature(FIXED_ARTICLE_EVENT, ORIGIN_PUBLIC)
        # Tamper origin signature
        tampered = Event(**{**FIXED_ARTICLE_EVENT.__dict__})
        tampered_sig = bytearray(FIXED_ARTICLE_EVENT.origin_signature)
        tampered_sig[0] ^= 1
        tampered.origin_signature = bytes(tampered_sig)
        assert not verify_origin_signature(tampered, ORIGIN_PUBLIC)

    def test_body_hash_vector(self):
        assert FIXED_BODY_HASH == compute_body_hash(FIXED_BODY)
        # Empty body has a real hash, not zero bytes
        assert EMPTY_BODY_HASH == compute_body_hash(b"")
        assert EMPTY_BODY_HASH != ZERO_HASH

    def test_event_hash_vector(self):
        assert FIXED_ARTICLE_EVENT_HASH == compute_event_hash(
            FIXED_ARTICLE_EVENT_BYTES)
        # Different event has different hash
        assert FIXED_ARTICLE_EVENT_HASH != FIXED_CANCEL_EVENT_HASH

    def test_head_hash_vector(self):
        assert FIXED_HEAD_HASH == compute_head_hash(FIXED_HEAD_BYTES)
        assert FIXED_EMPTY_HEAD_HASH == compute_head_hash(
            FIXED_EMPTY_HEAD_BYTES)
        assert FIXED_HEAD_HASH != FIXED_EMPTY_HEAD_HASH

    def test_cross_domain_signature_replay(self):
        # Author payload cannot verify as origin signature
        author_payload = author_signature_payload(FIXED_ARTICLE_SUBMISSION)
        fake_sig = _author_identity().sign(author_payload)
        # This should NOT verify as an origin signature over any event
        assert not Identity.verify(
            ORIGIN_PUBLIC,
            DOMAIN_ORIGIN_SIG + author_payload,
            fake_sig,
        )
        # Head payload cannot verify as event signature
        head_payload = encode_head_payload(FIXED_HEAD)
        fake_head_sig = _origin_identity().sign(head_payload)
        assert head_payload[:len(DOMAIN_HEAD_SIG)] != DOMAIN_ORIGIN_SIG

    def test_submission_vector_roundtrip(self):
        decoded = decode_submission(FIXED_ARTICLE_SUBMISSION_BYTES)
        assert decoded == FIXED_ARTICLE_SUBMISSION

    def test_head_vector_roundtrip(self):
        decoded = decode_head(FIXED_HEAD_BYTES)
        assert decoded == FIXED_HEAD
        assert decoded.latest_feed_seq == 4
        assert decoded.event_count == 4
        assert decoded.article_count == 1

    def test_empty_head_roundtrip(self):
        decoded = decode_head(FIXED_EMPTY_HEAD_BYTES)
        assert decoded == FIXED_EMPTY_HEAD
        assert decoded.latest_feed_seq == 0
        assert decoded.latest_event_hash == ZERO_HASH
        assert decoded.article_count == 0
        assert decoded.event_count == 0

    # --- Adversarial decoder tests ---

    def test_decoder_rejects_truncation(self):
        with pytest.raises(DecodeError):
            decode_event(FIXED_ARTICLE_EVENT_BYTES[:-1])
        with pytest.raises(DecodeError):
            decode_submission(FIXED_ARTICLE_SUBMISSION_BYTES[:-1])
        with pytest.raises(DecodeError):
            decode_head(FIXED_HEAD_BYTES[:-1])

    def test_decoder_rejects_trailing_bytes(self):
        with pytest.raises(DecodeError):
            decode_event(FIXED_ARTICLE_EVENT_BYTES + b"\x00")
        with pytest.raises(DecodeError):
            decode_submission(FIXED_ARTICLE_SUBMISSION_BYTES + b"\x00")
        with pytest.raises(DecodeError):
            decode_head(FIXED_HEAD_BYTES + b"\x00")

    def test_decoder_rejects_invalid_utf8(self):
        tampered = bytearray(FIXED_ARTICLE_SUBMISSION_BYTES)
        # Corrupt a string length field to point at invalid UTF-8
        # The origin field starts at offset 2 (after submission_version + event_type)
        # origin_len is at offset 2, origin bytes start at offset 4
        # Set origin_len to 3 and put invalid UTF-8 in the next 3 bytes
        tampered[2] = 0x00
        tampered[3] = 0x03
        tampered[4] = 0xFF
        tampered[5] = 0xFE
        tampered[6] = 0xFD
        with pytest.raises(DecodeError):
            decode_submission(bytes(tampered))

    def test_decoder_rejects_overflow(self):
        # Headers length > MAX_HEADERS_LEN
        tampered = bytearray(FIXED_ARTICLE_SUBMISSION_BYTES)
        # Find the headers length field (u32) — it's after all the fixed fields
        # Just set it to a huge value
        # The exact offset is complex; instead test with a synthetic event
        sub = Submission(
            event_type=EVENT_ARTICLE, origin="x", board="y",
            message_id=_random_msgid(97), created_at=1,
            actor_pubkey=AUTHOR_PUBLIC,
            headers=ArticleHeaders(subject="s", tags="", options=""),
            body_hash=EMPTY_BODY_HASH, body_size=0,
        )
        encoded = bytearray(encode_submission(sub))
        # The headers u32 length is after the 4 message_id fields (4*32=128 bytes)
        # and after origin(2+len), board(2+len), message_id(32), created_at(8),
        # actor_pubkey(32), actor_username(2+len), actor_registrar(2+len),
        # root/reply/supersede/target (4*32=128)
        # For this fixture: 1+1+2+1+2+1+32+8+32+2+0+2+0+128 = 243
        # headers_len is at offset 243, u32
        offset = 1 + 1 + 2 + 1 + 2 + 1 + 32 + 8 + 32 + 2 + 0 + 2 + 0 + 128
        struct.pack_into(">I", encoded, offset, MAX_HEADERS_LEN + 1)
        with pytest.raises(DecodeError):
            decode_submission(bytes(encoded))

    def test_extensions_strict_ordering(self):
        # Duplicate extension type
        exts = [Extension(EXT_LEGACY_DESCRIPTOR, b"\x01"), Extension(EXT_LEGACY_DESCRIPTOR, b"\x02")]
        with pytest.raises(DecodeError):
            from core.article_feed import _encode_extensions
            _encode_extensions(exts)

        # Out-of-order
        exts = [Extension(EXT_LEGACY_AUTHOR_SIGNATURE, b"\x01"), Extension(EXT_LEGACY_DESCRIPTOR, b"\x02")]
        with pytest.raises(DecodeError):
            from core.article_feed import _encode_extensions
            _encode_extensions(exts)

    def test_extensions_roundtrip(self):
        from core.article_feed import _encode_extensions, _decode_extensions
        exts = [
            Extension(EXT_LEGACY_DESCRIPTOR, b"\x01\x02\x03"),
            Extension(EXT_LEGACY_AUTHOR_SIGNED_PAYLOAD, b"hello"),
        ]
        encoded = _encode_extensions(exts)
        decoded, _ = _decode_extensions(encoded, MAX_EXTENSIONS_LEN)
        assert decoded == exts

    def test_normal_publication_rejects_nonempty_extensions(self):
        event = Event(
            event_type=EVENT_ARTICLE, origin="x", board="y",
            feed_seq=1, message_id=_random_msgid(96), created_at=1,
            actor_pubkey=AUTHOR_PUBLIC,
            headers=ArticleHeaders(subject="s", tags="", options=""),
            extensions=[Extension(EXT_LEGACY_DESCRIPTOR, b"\x01")],
            body_hash=EMPTY_BODY_HASH, body_size=0,
            author_signature_scheme=SCHEME_V3,
            author_signature=b"\x01" * 64,
            origin_signature=b"\x00" * 64,
        )
        with pytest.raises(DecodeError):
            validate_event(event, allow_extensions=False)
        # With allow_extensions=True, it should pass
        validate_event(event, allow_extensions=True)


# ---------------------------------------------------------------------------
# B. Origin normalization (§7.1)
# ---------------------------------------------------------------------------

class TestOriginNormalization:

    def test_normalize_dns_lowercase(self):
        assert normalize_origin("BBS.Example.COM") == "bbs.example.com"

    def test_normalize_dns_idna(self):
        assert normalize_origin("Bücher.example") == "xn--bcher-kva.example"

    def test_normalize_dns_trailing_dot_stripped(self):
        assert normalize_origin("bbs.example.com.") == "bbs.example.com"

    def test_normalize_ipv4(self):
        assert normalize_origin("192.168.1.1") == "192.168.1.1"

    def test_normalize_ipv6_compressed_no_brackets(self):
        assert normalize_origin("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"

    def test_normalize_ipv6_brackets_rejected(self):
        with pytest.raises(InvalidOrigin):
            normalize_origin("[2001:db8::1]")

    def test_rejects_scheme(self):
        with pytest.raises(InvalidOrigin):
            normalize_origin("https://bbs.example.com")

    def test_rejects_port(self):
        with pytest.raises(InvalidOrigin):
            normalize_origin("bbs.example.com:8080")

    def test_rejects_path(self):
        with pytest.raises(InvalidOrigin):
            normalize_origin("bbs.example.com/path")

    def test_rejects_whitespace(self):
        with pytest.raises(InvalidOrigin):
            normalize_origin("bbs.example.com ")
        with pytest.raises(InvalidOrigin):
            normalize_origin(" bbs.example.com")
        with pytest.raises(InvalidOrigin):
            normalize_origin("bbs .example.com")

    def test_rejects_empty_label(self):
        with pytest.raises(InvalidOrigin):
            normalize_origin("bbs..example.com")

    def test_round_trip_idempotent(self):
        for origin in ["bbs.example.com", "192.168.1.1", "2001:db8::1",
                        "Bücher.example", "a.b.c.d.e.f.g.h"]:
            canonical = normalize_origin(origin)
            assert normalize_origin(canonical) == canonical


# ---------------------------------------------------------------------------
# C. Local append tests (§23.2)
# ---------------------------------------------------------------------------

class TestLocalAppend:

    def test_first_event_seq1_zero_previous_hash(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            sub, body, sig = _make_article_submission(1)
            event, head = store.append_authoritative(
                sub, body, SCHEME_V3, sig, _origin_identity(),
                expected_origin=sub.origin)
            assert event.feed_seq == 1
            assert event.previous_event_hash == ZERO_HASH
            assert event.article_num == 1
            assert head.latest_feed_seq == 1
            assert head.latest_event_hash == compute_event_hash(encode_event(event))
            assert head.article_count == 1
            assert head.event_count == 1
        finally:
            store.close()

    def test_concurrent_publication_unique_contiguous_sequences(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            N = 20
            def append_one(seed):
                sub, body, sig = _make_article_submission(seed)
                return store.append_authoritative(
                    sub, body, SCHEME_V3, sig, _origin_identity(),
                    expected_origin=sub.origin)
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(append_one, range(1, N + 1)))
            seqs = sorted(r[0].feed_seq for r in results)
            assert seqs == list(range(1, N + 1))
            article_nums = sorted(r[0].article_num for r in results)
            assert article_nums == list(range(1, N + 1))
            state = store.get_feed_state(FIXED_ORIGIN, FIXED_BOARD)
            assert state["highest_accepted_seq"] == N
            assert state["current_article_count"] == N
            assert state["current_event_count"] == N
        finally:
            store.close()

    def test_article_numbers_contiguous_article_only(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            origin_id = _origin_identity()
            author_id = _author_identity()

            # Append ARTICLE
            sub1, body1, sig1 = _make_article_submission(1)
            ev1, _ = store.append_authoritative(
                sub1, body1, SCHEME_V3, sig1, origin_id, expected_origin=sub1.origin)
            assert ev1.article_num == 1

            # Append CANCEL (targeting article 1)
            cancel_sub = Submission(
                event_type=EVENT_CANCEL, origin=FIXED_ORIGIN, board=FIXED_BOARD,
                message_id=_random_msgid(101), created_at=FIXED_CREATED_AT + 10,
                actor_pubkey=author_id.public_key, actor_username="alice",
                actor_registrar=FIXED_ORIGIN,
                target_message_id=sub1.message_id,
                headers=None, body_hash=EMPTY_BODY_HASH, body_size=0,
            )
            cancel_sig = sign_author(cancel_sub, author_id)
            ev2, _ = store.append_authoritative(
                cancel_sub, b"", SCHEME_V3, cancel_sig, origin_id,
                expected_origin=FIXED_ORIGIN)
            assert ev2.article_num == 0
            assert ev2.feed_seq == 2

            # Append another ARTICLE — article_num should be 2 (not 3)
            sub3, body3, sig3 = _make_article_submission(3)
            ev3, _ = store.append_authoritative(
                sub3, body3, SCHEME_V3, sig3, origin_id,
                expected_origin=sub3.origin)
            assert ev3.article_num == 2
            assert ev3.feed_seq == 3
        finally:
            store.close()

    def test_duplicate_message_id_identical_idempotent(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            sub, body, sig = _make_article_submission(1)
            ev1, head1 = store.append_authoritative(
                sub, body, SCHEME_V3, sig, _origin_identity(),
                expected_origin=sub.origin)
            # Same submission again — should be idempotent
            ev2, head2 = store.append_authoritative(
                sub, body, SCHEME_V3, sig, _origin_identity(),
                expected_origin=sub.origin)
            assert ev1 == ev2
            assert head2.latest_feed_seq == head1.latest_feed_seq
            state = store.get_feed_state(FIXED_ORIGIN, FIXED_BOARD)
            assert state["highest_accepted_seq"] == 1
            assert state["current_event_count"] == 1
        finally:
            store.close()

    def test_duplicate_message_id_different_rejected(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            sub1, body1, sig1 = _make_article_submission(1)
            store.append_authoritative(
                sub1, body1, SCHEME_V3, sig1, _origin_identity(),
                expected_origin=sub1.origin)
            # Same message_id but different body/content
            body2 = b"different body content"
            sub2 = Submission(
                submission_version=SUBMISSION_VERSION,
                event_type=EVENT_ARTICLE, origin=FIXED_ORIGIN, board=FIXED_BOARD,
                message_id=sub1.message_id,  # same message_id
                created_at=FIXED_CREATED_AT + 1,
                actor_pubkey=AUTHOR_PUBLIC, actor_username="alice",
                actor_registrar=FIXED_ORIGIN,
                headers=ArticleHeaders(subject="Different", tags="", options=""),
                body_hash=compute_body_hash(body2), body_size=len(body2),
            )
            sig2 = sign_author(sub2, _author_identity())
            with pytest.raises(MessageIdCollision):
                store.append_authoritative(
                    sub2, body2, SCHEME_V3, sig2, _origin_identity(),
                    expected_origin=sub2.origin)
        finally:
            store.close()

    def test_invalid_author_signature_rejected_before_allocation(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            sub, body, _ = _make_article_submission(1)
            bad_sig = b"\x01" * 64
            with pytest.raises(FeedAcceptanceError):
                store.append_authoritative(
                    sub, body, SCHEME_V3, bad_sig, _origin_identity(),
                    expected_origin=sub.origin)
            # No event, no state advance, no body ref
            state = store.get_feed_state(FIXED_ORIGIN, FIXED_BOARD)
            assert state is None or state["highest_accepted_seq"] == 0
            assert store.get_event_by_message_id(sub.message_id) is None
        finally:
            store.close()

    def test_origin_signature_covers_allocated_seq_and_previous_hash(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            # Append two events so the second has a non-zero previous_event_hash
            sub1, body1, sig1 = _make_article_submission(1)
            ev1, _ = store.append_authoritative(
                sub1, body1, SCHEME_V3, sig1, _origin_identity(),
                expected_origin=sub1.origin)
            sub2, body2, sig2 = _make_article_submission(2)
            ev2, _ = store.append_authoritative(
                sub2, body2, SCHEME_V3, sig2, _origin_identity(),
                expected_origin=sub2.origin)
            # Verify origin signature covers allocated fields
            assert ev2.feed_seq == 2
            assert ev2.previous_event_hash == compute_event_hash(encode_event(ev1))
            assert verify_origin_signature(ev2, ORIGIN_PUBLIC)
            # Tamper feed_seq → verification should fail
            tampered = Event(**{**ev2.__dict__})
            tampered.feed_seq = 99
            # Re-encode with the tampered seq to get the signature payload
            # The origin signature was computed over the original encoding,
            # so verification against the tampered event should fail
            assert not verify_origin_signature(tampered, ORIGIN_PUBLIC)
        finally:
            store.close()

    def test_transaction_rollback_no_db_orphan(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            # First append succeeds
            sub1, body1, sig1 = _make_article_submission(1)
            store.append_authoritative(
                sub1, body1, SCHEME_V3, sig1, _origin_identity(),
                expected_origin=sub1.origin)

            # Force a mid-transaction failure by injecting a bad projection update
            original_proj = store._update_article_projection
            def failing_proj(event):
                if event.message_id != sub1.message_id:
                    raise RuntimeError("injected failure")
                original_proj(event)
            store._update_article_projection = failing_proj

            sub2, body2, sig2 = _make_article_submission(2)
            with pytest.raises(RuntimeError):
                store.append_authoritative(
                    sub2, body2, SCHEME_V3, sig2, _origin_identity(),
                    expected_origin=sub2.origin)

            # Restore and verify DB is consistent — only 1 event
            store._update_article_projection = original_proj
            state = store.get_feed_state(FIXED_ORIGIN, FIXED_BOARD)
            assert state["highest_accepted_seq"] == 1
            assert state["current_event_count"] == 1
            assert store.get_event(FIXED_ORIGIN, FIXED_BOARD, 2) is None
        finally:
            store.close()

    def test_head_stored_and_retrievable(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            sub, body, sig = _make_article_submission(1)
            ev, head = store.append_authoritative(
                sub, body, SCHEME_V3, sig, _origin_identity(),
                expected_origin=sub.origin)
            retrieved = store.get_head(FIXED_ORIGIN, FIXED_BOARD)
            assert retrieved is not None
            assert retrieved.latest_feed_seq == 1
            assert retrieved.latest_event_hash == head.latest_event_hash
        finally:
            store.close()

    def test_empty_head_for_new_feed(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            state = store.get_feed_state(FIXED_ORIGIN, FIXED_BOARD)
            assert state is None
            head = store.get_head(FIXED_ORIGIN, FIXED_BOARD)
            assert head is None
        finally:
            store.close()


# ---------------------------------------------------------------------------
# D. Feed acceptance tests (§23.4)
# ---------------------------------------------------------------------------

class TestFeedAcceptance:

    def _setup_origin_feed(self, store, n_events=1):
        """Append n_events authoritative events and return (events, heads, origin_id)."""
        origin_id = _origin_identity()
        events = []
        heads = []
        for i in range(1, n_events + 1):
            sub, body, sig = _make_article_submission(i)
            ev, head = store.append_authoritative(
                sub, body, SCHEME_V3, sig, origin_id,
                expected_origin=sub.origin)
            events.append(ev)
            heads.append(head)
        return events, heads, origin_id

    def _build_head_for_events(self, events, origin_id, board=FIXED_BOARD):
        """Build a signed head covering the given events."""
        last_ev = events[-1]
        article_count = sum(1 for e in events if e.event_type == EVENT_ARTICLE)
        head = FeedHead(
            format_version=HEAD_FORMAT_VERSION,
            origin=last_ev.origin, board=board,
            latest_feed_seq=last_ev.feed_seq,
            latest_event_hash=compute_event_hash(encode_event(last_ev)),
            article_count=article_count,
            event_count=len(events),
            snapshot_timestamp=FIXED_SNAPSHOT_TS,
            signature=b"\x00" * 64,
        )
        sign_head(head, origin_id)
        return head

    def test_contiguous_range_advances_state(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            # Build 3 events on origin
            events, heads, origin_id = self._setup_origin_feed(store, n_events=3)
            # Now simulate a remote sync: create a fresh store and accept the range
            store.close()
            store2 = _make_store(temp_dir + "_receiver")
            try:
                head = self._build_head_for_events(events, origin_id)
                result = store2.accept_remote_range(
                    FIXED_ORIGIN, FIXED_BOARD, head, events, ORIGIN_PUBLIC,
                    source_relay="relay.test")
                assert result.accepted
                assert result.accepted_count == 3
                state = store2.get_feed_state(FIXED_ORIGIN, FIXED_BOARD)
                assert state["highest_accepted_seq"] == 3
                assert state["current_event_count"] == 3
            finally:
                store2.close()
        finally:
            if store._conn:
                store.close()

    def test_missing_sequence_rejects_complete_range(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            events, heads, origin_id = self._setup_origin_feed(store, n_events=3)
            store.close()
            store2 = _make_store(temp_dir + "_receiver")
            try:
                # Skip event 2 — send [1, 3] which is non-contiguous
                bad_events = [events[0], events[2]]
                head = self._build_head_for_events(events, origin_id)
                result = store2.accept_remote_range(
                    FIXED_ORIGIN, FIXED_BOARD, head, bad_events, ORIGIN_PUBLIC,
                    source_relay="relay.test")
                assert not result.accepted
                assert "non-contiguous" in result.reason
            finally:
                store2.close()
        finally:
            if store._conn:
                store.close()

    def test_wrong_previous_hash_rejects(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            events, heads, origin_id = self._setup_origin_feed(store, n_events=1)
            store.close()
            store2 = _make_store(temp_dir + "_receiver")
            try:
                # Accept event 1 first
                head1 = self._build_head_for_events(events[:1], origin_id)
                result1 = store2.accept_remote_range(
                    FIXED_ORIGIN, FIXED_BOARD, head1, events[:1], ORIGIN_PUBLIC,
                    source_relay="relay.test")
                assert result1.accepted

                # Now build event 2 with wrong previous_event_hash
                sub2, body2, sig2 = _make_article_submission(2)
                bad_ev = Event(
                    format_version=FORMAT_VERSION, event_type=EVENT_ARTICLE,
                    origin=FIXED_ORIGIN, board=FIXED_BOARD, feed_seq=2,
                    previous_event_hash=b"\xFF" * 32,  # wrong
                    message_id=sub2.message_id, article_num=2,
                    created_at=sub2.created_at, actor_pubkey=AUTHOR_PUBLIC,
                    actor_username="alice", actor_registrar=FIXED_ORIGIN,
                    headers=sub2.headers, extensions=[],
                    body_hash=sub2.body_hash, body_size=sub2.body_size,
                    author_signature_scheme=SCHEME_V3, author_signature=sig2,
                    origin_signature=b"\x00" * 64,
                )
                bad_ev.origin_signature = sign_origin(bad_ev, origin_id)
                head2 = self._build_head_for_events([bad_ev], origin_id)
                # Need to build a head covering events 1 and 2
                all_events = events[:1] + [bad_ev]
                head2 = self._build_head_for_events(all_events, origin_id)
                result2 = store2.accept_remote_range(
                    FIXED_ORIGIN, FIXED_BOARD, head2, [bad_ev], ORIGIN_PUBLIC,
                    source_relay="relay.test")
                assert not result2.accepted
                assert "previous_event_hash" in result2.reason or "mismatch" in result2.reason
            finally:
                store2.close()
        finally:
            if store._conn:
                store.close()

    def test_wrong_origin_or_board_rejects(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            events, heads, origin_id = self._setup_origin_feed(store, n_events=1)
            # Tamper event origin
            tampered = Event(**{**events[0].__dict__})
            tampered.origin = "evil.example"
            tampered.origin_signature = sign_origin(tampered, origin_id)
            head = self._build_head_for_events([tampered], origin_id)
            result = store.accept_remote_range(
                FIXED_ORIGIN, FIXED_BOARD, head, [tampered], ORIGIN_PUBLIC,
                source_relay="relay.test")
            assert not result.accepted
        finally:
            store.close()

    def test_invalid_origin_signature_rejects(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            events, heads, origin_id = self._setup_origin_feed(store, n_events=1)
            store.close()
            store2 = _make_store(temp_dir + "_receiver")
            try:
                # Tamper origin signature
                bad_ev = Event(**{**events[0].__dict__})
                bad_sig = bytearray(bad_ev.origin_signature)
                bad_sig[0] ^= 1
                bad_ev.origin_signature = bytes(bad_sig)
                head = self._build_head_for_events([bad_ev], origin_id)
                result = store2.accept_remote_range(
                    FIXED_ORIGIN, FIXED_BOARD, head, [bad_ev], ORIGIN_PUBLIC,
                    source_relay="relay.test")
                assert not result.accepted
                assert "signature" in result.reason.lower()
            finally:
                store2.close()
        finally:
            if store._conn:
                store.close()

    def test_lower_head_seq_rejects_rollback(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            # Accept 3 events on receiver
            events, heads, origin_id = self._setup_origin_feed(store, n_events=3)
            store.close()
            store2 = _make_store(temp_dir + "_receiver")
            try:
                head3 = self._build_head_for_events(events, origin_id)
                result = store2.accept_remote_range(
                    FIXED_ORIGIN, FIXED_BOARD, head3, events, ORIGIN_PUBLIC,
                    source_relay="relay.test")
                assert result.accepted

                # Try to accept a head with seq=2 (rollback)
                head2 = self._build_head_for_events(events[:2], origin_id)
                result2 = store2.accept_remote_range(
                    FIXED_ORIGIN, FIXED_BOARD, head2, events[:2], ORIGIN_PUBLIC,
                    source_relay="relay.test")
                assert not result2.accepted
                assert "rollback" in result2.reason
            finally:
                store2.close()
        finally:
            if store._conn:
                store.close()

    def test_same_seq_same_hash_idempotent(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            events, heads, origin_id = self._setup_origin_feed(store, n_events=2)
            store.close()
            store2 = _make_store(temp_dir + "_receiver")
            try:
                head = self._build_head_for_events(events, origin_id)
                result1 = store2.accept_remote_range(
                    FIXED_ORIGIN, FIXED_BOARD, head, events, ORIGIN_PUBLIC,
                    source_relay="relay.test")
                assert result1.accepted
                # Same range again
                result2 = store2.accept_remote_range(
                    FIXED_ORIGIN, FIXED_BOARD, head, events, ORIGIN_PUBLIC,
                    source_relay="relay.test")
                assert result2.accepted
                assert "idempotent" in result2.reason
                state = store2.get_feed_state(FIXED_ORIGIN, FIXED_BOARD)
                assert state["highest_accepted_seq"] == 2
                assert state["current_event_count"] == 2
            finally:
                store2.close()
        finally:
            if store._conn:
                store.close()

    def test_same_seq_different_hash_equivocation_retained(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            events, heads, origin_id = self._setup_origin_feed(store, n_events=1)
            store.close()
            store2 = _make_store(temp_dir + "_receiver")
            try:
                head1 = self._build_head_for_events(events, origin_id)
                result1 = store2.accept_remote_range(
                    FIXED_ORIGIN, FIXED_BOARD, head1, events, ORIGIN_PUBLIC,
                    source_relay="relay.test")
                assert result1.accepted

                # Build a different head at same seq with a different event
                sub2, body2, sig2 = _make_article_submission(2)
                evil_ev = Event(
                    format_version=FORMAT_VERSION, event_type=EVENT_ARTICLE,
                    origin=FIXED_ORIGIN, board=FIXED_BOARD, feed_seq=1,
                    previous_event_hash=ZERO_HASH,
                    message_id=sub2.message_id, article_num=1,
                    created_at=sub2.created_at, actor_pubkey=AUTHOR_PUBLIC,
                    actor_username="alice", actor_registrar=FIXED_ORIGIN,
                    headers=sub2.headers, extensions=[],
                    body_hash=sub2.body_hash, body_size=sub2.body_size,
                    author_signature_scheme=SCHEME_V3, author_signature=sig2,
                    origin_signature=b"\x00" * 64,
                )
                evil_ev.origin_signature = sign_origin(evil_ev, origin_id)
                evil_head = self._build_head_for_events([evil_ev], origin_id)
                result2 = store2.accept_remote_range(
                    FIXED_ORIGIN, FIXED_BOARD, evil_head, [evil_ev], ORIGIN_PUBLIC,
                    source_relay="relay.test")
                assert not result2.accepted
                assert "equivocation" in result2.reason
                # Conflict should be retained
                conflicts = store2.list_conflicts(FIXED_ORIGIN, FIXED_BOARD)
                assert len(conflicts) >= 1
                # State should not have advanced
                state = store2.get_feed_state(FIXED_ORIGIN, FIXED_BOARD)
                assert state["highest_accepted_seq"] == 1
            finally:
                store2.close()
        finally:
            if store._conn:
                store.close()

    def test_final_event_must_match_head_tip(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            events, heads, origin_id = self._setup_origin_feed(store, n_events=1)
            store.close()
            store2 = _make_store(temp_dir + "_receiver")
            try:
                # Build head with wrong tip
                head = FeedHead(
                    format_version=HEAD_FORMAT_VERSION,
                    origin=FIXED_ORIGIN, board=FIXED_BOARD,
                    latest_feed_seq=1, latest_event_hash=b"\xFF" * 32,
                    article_count=1, event_count=1,
                    snapshot_timestamp=FIXED_SNAPSHOT_TS, signature=b"\x00" * 64,
                )
                sign_head(head, origin_id)
                result = store2.accept_remote_range(
                    FIXED_ORIGIN, FIXED_BOARD, head, events, ORIGIN_PUBLIC,
                    source_relay="relay.test")
                assert not result.accepted
                assert "final event hash" in result.reason or "tip" in result.reason
            finally:
                store2.close()
        finally:
            if store._conn:
                store.close()

    def test_partial_range_never_advances_state(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            events, heads, origin_id = self._setup_origin_feed(store, n_events=3)
            store.close()
            store2 = _make_store(temp_dir + "_receiver")
            try:
                # Send only events 1-2 but head says seq=3
                head = self._build_head_for_events(events, origin_id)
                result = store2.accept_remote_range(
                    FIXED_ORIGIN, FIXED_BOARD, head, events[:2], ORIGIN_PUBLIC,
                    source_relay="relay.test")
                assert not result.accepted
                # State should not have advanced
                state = store2.get_feed_state(FIXED_ORIGIN, FIXED_BOARD)
                assert state is None or state["highest_accepted_seq"] == 0
            finally:
                store2.close()
        finally:
            if store._conn:
                store.close()

    def test_multi_page_staging_invisible_until_promotion(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            events, heads, origin_id = self._setup_origin_feed(store, n_events=4)
            store.close()
            store2 = _make_store(temp_dir + "_receiver")
            try:
                head = self._build_head_for_events(events, origin_id)
                candidate_hash = compute_head_hash(encode_head(head))

                # Stage first 2 events
                store2.stage_events(candidate_hash, events[:2])
                # State should not have advanced
                state = store2.get_feed_state(FIXED_ORIGIN, FIXED_BOARD)
                assert state is None or state["highest_accepted_seq"] == 0

                # Stage remaining events
                store2.stage_events(candidate_hash, events[2:])
                state = store2.get_feed_state(FIXED_ORIGIN, FIXED_BOARD)
                assert state is None or state["highest_accepted_seq"] == 0

                # Promote
                result = store2.promote_staged(
                    FIXED_ORIGIN, FIXED_BOARD, head, ORIGIN_PUBLIC,
                    source_relay="relay.test")
                assert result.accepted
                assert result.accepted_count == 4
                state = store2.get_feed_state(FIXED_ORIGIN, FIXED_BOARD)
                assert state["highest_accepted_seq"] == 4
            finally:
                store2.close()
        finally:
            if store._conn:
                store.close()

    def test_stale_staging_cleaned_without_affecting_accepted(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            events, heads, origin_id = self._setup_origin_feed(store, n_events=2)
            store.close()
            store2 = _make_store(temp_dir + "_receiver")
            try:
                # Accept the range normally
                head = self._build_head_for_events(events, origin_id)
                result = store2.accept_remote_range(
                    FIXED_ORIGIN, FIXED_BOARD, head, events, ORIGIN_PUBLIC,
                    source_relay="relay.test")
                assert result.accepted

                # Stage some bogus events
                bogus_hash = b"\xAA" * 32
                store2.stage_events(bogus_hash, events[:1])

                # Clean staging with negative max age (cleans everything)
                cleaned = store2.clean_staging(max_age_seconds=-1)
                assert cleaned >= 1

                # Accepted state should be unchanged
                state = store2.get_feed_state(FIXED_ORIGIN, FIXED_BOARD)
                assert state["highest_accepted_seq"] == 2
            finally:
                store2.close()
        finally:
            if store._conn:
                store.close()


# ---------------------------------------------------------------------------
# E. Body store tests (§23.5)
# ---------------------------------------------------------------------------

class TestBodyStore:

    def test_body_stored_and_verified(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            sub, body, sig = _make_article_submission(1, body=b"test body content")
            store.append_authoritative(
                sub, body, SCHEME_V3, sig, _origin_identity(),
                expected_origin=sub.origin)
            assert store.has_body(sub.body_hash)
            retrieved = store.get_body(sub.body_hash)
            assert retrieved == body
        finally:
            store.close()

    def test_substituted_body_rejects(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            body = b"original content"
            sub, _, sig = _make_article_submission(1, body=body)
            store.append_authoritative(
                sub, body, SCHEME_V3, sig, _origin_identity(),
                expected_origin=sub.origin)
            # Substitute the body file
            rel_path = store._body_rel_path(sub.body_hash)
            full_path = os.path.join(store._bodies_dir, rel_path)
            with open(full_path, "wb") as f:
                f.write(b"tampered content!!!")
            # get_body should detect hash mismatch and return None
            retrieved = store.get_body(sub.body_hash)
            assert retrieved is None
            # Body should be marked as not present
            assert not store.has_body(sub.body_hash)
        finally:
            store.close()

    def test_truncated_body_rejects(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            body = b"original content that is long enough"
            sub, _, sig = _make_article_submission(1, body=body)
            store.append_authoritative(
                sub, body, SCHEME_V3, sig, _origin_identity(),
                expected_origin=sub.origin)
            # Truncate the body file
            rel_path = store._body_rel_path(sub.body_hash)
            full_path = os.path.join(store._bodies_dir, rel_path)
            with open(full_path, "wb") as f:
                f.write(b"short")
            retrieved = store.get_body(sub.body_hash)
            assert retrieved is None
        finally:
            store.close()

    def test_oversized_body_rejects_before_buffering(self, temp_dir):
        store = _make_store(temp_dir, max_body_size=16)
        try:
            body = b"x" * 32  # exceeds 16-byte limit
            sub, _, sig = _make_article_submission(1, body=body)
            with pytest.raises(FeedAcceptanceError):
                store.append_authoritative(
                    sub, body, SCHEME_V3, sig, _origin_identity(),
                    expected_origin=sub.origin)
        finally:
            store.close()

    def test_known_metadata_missing_body_represented_honestly(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            # Create an event, then delete the body file manually
            body = b"temporary content"
            sub, _, sig = _make_article_submission(1, body=body)
            store.append_authoritative(
                sub, body, SCHEME_V3, sig, _origin_identity(),
                expected_origin=sub.origin)
            rel_path = store._body_rel_path(sub.body_hash)
            full_path = os.path.join(store._bodies_dir, rel_path)
            os.remove(full_path)
            # get_body detects the missing file and marks it unavailable
            retrieved = store.get_body(sub.body_hash)
            assert retrieved is None
            assert not store.has_body(sub.body_hash)
        finally:
            store.close()

    def test_identical_bodies_deduplicate(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            body = b"same content for both articles"
            sub1, _, sig1 = _make_article_submission(1, body=body)
            store.append_authoritative(
                sub1, body, SCHEME_V3, sig1, _origin_identity(),
                expected_origin=sub1.origin)
            sub2, _, sig2 = _make_article_submission(2, body=body)
            store.append_authoritative(
                sub2, body, SCHEME_V3, sig2, _origin_identity(),
                expected_origin=sub2.origin)
            # Both should have the same body_hash
            assert sub1.body_hash == sub2.body_hash
            assert store.has_body(sub1.body_hash)
            # Body should be stored only once (same file path)
            rel_path = store._body_rel_path(sub1.body_hash)
            full_path = os.path.join(store._bodies_dir, rel_path)
            assert os.path.exists(full_path)
        finally:
            store.close()

    def test_ref_counting_purge_safety(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            body = b"shared body content"
            sub1, _, sig1 = _make_article_submission(1, body=body)
            store.append_authoritative(
                sub1, body, SCHEME_V3, sig1, _origin_identity(),
                expected_origin=sub1.origin)
            sub2, _, sig2 = _make_article_submission(2, body=body)
            store.append_authoritative(
                sub2, body, SCHEME_V3, sig2, _origin_identity(),
                expected_origin=sub2.origin)

            # Mark one ref as not retained
            store.mark_ref_not_retained(sub1.body_hash, sub1.message_id)
            # Purge should NOT remove the blob (sub2 still retains it)
            purged = store.purge_body_if_unreferenced(sub1.body_hash)
            assert not purged
            assert store.has_body(sub1.body_hash)

            # Mark the other ref as not retained
            store.mark_ref_not_retained(sub1.body_hash, sub2.message_id)
            # Now purge should remove the blob
            purged = store.purge_body_if_unreferenced(sub1.body_hash)
            assert purged
            assert not store.has_body(sub1.body_hash)
        finally:
            store.close()

    def test_empty_body_stored_correctly(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            sub, _, sig = _make_article_submission(1, body=b"")
            store.append_authoritative(
                sub, b"", SCHEME_V3, sig, _origin_identity(),
                expected_origin=sub.origin)
            assert sub.body_hash == EMPTY_BODY_HASH
            assert store.has_body(EMPTY_BODY_HASH)
        finally:
            store.close()


# ---------------------------------------------------------------------------
# F. Wire fixture reproducibility
# ---------------------------------------------------------------------------

class TestWireFixtureReproducibility:
    """Verify that frozen fixtures are byte-for-byte reproducible."""

    def test_article_event_reproducible(self):
        assert encode_event(FIXED_ARTICLE_EVENT) == FIXED_ARTICLE_EVENT_BYTES

    def test_cancel_event_reproducible(self):
        assert encode_event(FIXED_CANCEL_EVENT) == FIXED_CANCEL_EVENT_BYTES

    def test_report_event_reproducible(self):
        assert encode_event(FIXED_REPORT_EVENT) == FIXED_REPORT_EVENT_BYTES

    def test_punishment_event_reproducible(self):
        assert encode_event(FIXED_PUNISHMENT_EVENT) == FIXED_PUNISHMENT_EVENT_BYTES

    def test_head_reproducible(self):
        assert encode_head(FIXED_HEAD) == FIXED_HEAD_BYTES

    def test_empty_head_reproducible(self):
        assert encode_head(FIXED_EMPTY_HEAD) == FIXED_EMPTY_HEAD_BYTES

    def test_submission_reproducible(self):
        assert encode_submission(FIXED_ARTICLE_SUBMISSION) == FIXED_ARTICLE_SUBMISSION_BYTES

    def test_keys_are_deterministic_and_32_bytes(self):
        assert len(ORIGIN_PUBLIC) == 32
        assert len(AUTHOR_PUBLIC) == 32
        assert len(ORIGIN_PRIVATE) == 32
        assert len(AUTHOR_PRIVATE) == 32
        # Same seed must produce same key
        from core.crypto import Identity
        assert Identity.from_private_key(ORIGIN_SEED).public_key == ORIGIN_PUBLIC
        assert Identity.from_private_key(AUTHOR_SEED).public_key == AUTHOR_PUBLIC
        # Origin and author keys must differ
        assert ORIGIN_PUBLIC != AUTHOR_PUBLIC

    def test_head_signature_verifies(self):
        assert verify_head_signature(FIXED_HEAD, ORIGIN_PUBLIC)

    def test_empty_head_signature_verifies(self):
        assert verify_head_signature(FIXED_EMPTY_HEAD, ORIGIN_PUBLIC)

    def test_event_signatures_verify(self):
        for ev in [FIXED_ARTICLE_EVENT, FIXED_CANCEL_EVENT,
                   FIXED_REPORT_EVENT, FIXED_PUNISHMENT_EVENT]:
            assert verify_origin_signature(ev, ORIGIN_PUBLIC), \
                f"origin sig failed for event_type {ev.event_type:#04x}"

    def test_author_signatures_verify(self):
        for sub, sig in [
            (FIXED_ARTICLE_SUBMISSION, FIXED_AUTHOR_SIGNATURE),
        ]:
            assert verify_author_signature(sub, sig, AUTHOR_PUBLIC)


# ---------------------------------------------------------------------------
# G. Projection rebuild
# ---------------------------------------------------------------------------

class TestProjectionRebuild:

    def test_rebuild_article_projection(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            for i in range(1, 5):
                sub, body, sig = _make_article_submission(i)
                store.append_authoritative(
                    sub, body, SCHEME_V3, sig, _origin_identity(),
                    expected_origin=sub.origin)
            count = store.rebuild_article_projection(FIXED_ORIGIN, FIXED_BOARD)
            assert count == 4
        finally:
            store.close()

    def test_rebuild_punishment_projection(self, temp_dir):
        store = _make_store(temp_dir)
        try:
            # Append an article first
            sub, body, sig = _make_article_submission(1)
            store.append_authoritative(
                sub, body, SCHEME_V3, sig, _origin_identity(),
                expected_origin=sub.origin)

            # Append a punishment
            pun_sub = Submission(
                event_type=EVENT_PUNISHMENT, origin=FIXED_ORIGIN, board=FIXED_BOARD,
                message_id=_random_msgid(50), created_at=FIXED_CREATED_AT + 10,
                actor_pubkey=ORIGIN_PUBLIC, actor_username="admin",
                actor_registrar=FIXED_ORIGIN,
                headers=PunishmentHeaders(
                    punished_pubkey=AUTHOR_PUBLIC, expires_at=-1,
                    report_ids=[], rule_ids=[]),
                body_hash=EMPTY_BODY_HASH, body_size=0,
            )
            pun_sig = sign_author(pun_sub, _origin_identity())
            store.append_authoritative(
                pun_sub, b"", SCHEME_V3, pun_sig, _origin_identity(),
                expected_origin=FIXED_ORIGIN)

            count = store.rebuild_punishment_projection(FIXED_ORIGIN, FIXED_BOARD)
            assert count == 1
        finally:
            store.close()
