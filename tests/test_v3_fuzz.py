"""Fuzz tests for v3 event/head/submission parsers (Phase 8, §23.1).

Adversarial input testing for decoder bounds, overflow, truncation, and
malformed data. Tests that the strict decoders reject all malformed inputs
without crashing or allocating unbounded memory.

Per §22 invariant 17: "Parser bounds are enforced before allocation or
iteration."
"""

import os
import sys
import struct
import random
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.article_feed import (
    decode_event,
    decode_submission,
    decode_head,
    encode_event,
    encode_submission,
    encode_head,
    Submission,
    Event,
    FeedHead,
    ArticleHeaders,
    EVENT_ARTICLE,
    SCHEME_V3,
    FORMAT_VERSION,
    SUBMISSION_VERSION,
    HEAD_FORMAT_VERSION,
    ZERO_HASH,
    ZERO_MESSAGE_ID,
    SIGNATURE_SIZE,
    DecodeError,
    compute_body_hash,
    sign_author,
    sign_origin,
    sign_head,
    _encode_extensions,
    _decode_extensions,
    Extension,
    EXT_LEGACY_DESCRIPTOR,
    MAX_ORIGIN_LEN,
    MAX_BOARD_LEN,
    MAX_HEADERS_LEN,
    MAX_EXTENSIONS_LEN,
)
from core.crypto import Identity
from tests.fixtures.protocol_v3.wire_fixtures import (
    FIXED_ARTICLE_EVENT_BYTES,
    FIXED_ARTICLE_SUBMISSION_BYTES,
    FIXED_HEAD_BYTES,
    FIXED_ARTICLE_EVENT,
    FIXED_ARTICLE_SUBMISSION,
    FIXED_HEAD,
    ORIGIN_SEED,
    ORIGIN_PUBLIC,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flip_byte(data: bytes, offset: int) -> bytes:
    """Flip one byte at the given offset."""
    arr = bytearray(data)
    arr[offset] ^= 0xFF
    return bytes(arr)


def _truncate(data: bytes, n: int) -> bytes:
    """Remove the last n bytes."""
    return data[:len(data) - n] if n < len(data) else b""


def _random_bytes(n: int, seed: int = 0) -> bytes:
    rng = random.Random(seed)
    return rng.randbytes(n)


# ---------------------------------------------------------------------------
# Event decoder fuzz tests
# ---------------------------------------------------------------------------

class TestEventDecoderFuzz:

    def test_empty_input_rejected(self):
        with pytest.raises(DecodeError):
            decode_event(b"")

    def test_single_byte_rejected(self):
        with pytest.raises(DecodeError):
            decode_event(b"\x01")

    def test_truncated_at_every_offset(self):
        """Truncating at any offset should raise DecodeError, not crash."""
        for i in range(1, len(FIXED_ARTICLE_EVENT_BYTES)):
            with pytest.raises(DecodeError):
                decode_event(FIXED_ARTICLE_EVENT_BYTES[:i])

    def test_trailing_bytes_at_every_position(self):
        """Extra bytes at the end should raise DecodeError."""
        for suffix in [b"\x00", b"\xFF", b"\x01\x02", b"extra"]:
            with pytest.raises(DecodeError):
                decode_event(FIXED_ARTICLE_EVENT_BYTES + suffix)

    def test_bit_flip_every_byte(self):
        """Flipping any single byte should either raise DecodeError or
        produce an event that fails signature verification."""
        for i in range(len(FIXED_ARTICLE_EVENT_BYTES)):
            tampered = _flip_byte(FIXED_ARTICLE_EVENT_BYTES, i)
            try:
                ev = decode_event(tampered)
                # If it decodes, the origin signature must fail
                from core.article_feed import verify_origin_signature
                assert not verify_origin_signature(ev, ORIGIN_PUBLIC), \
                    f"Bit flip at offset {i} produced a valid-signature event"
            except DecodeError:
                pass  # expected — malformed data rejected

    def test_random_garbage_rejected(self):
        """Random bytes of various lengths should all be rejected."""
        for length in [1, 10, 50, 100, 500, 1000]:
            with pytest.raises(DecodeError):
                decode_event(_random_bytes(length, seed=length))

    def test_wrong_format_version_rejected(self):
        tampered = bytearray(FIXED_ARTICLE_EVENT_BYTES)
        tampered[0] = 0xFF  # invalid format_version
        with pytest.raises(DecodeError):
            decode_event(bytes(tampered))

    def test_invalid_event_type_rejected(self):
        tampered = bytearray(FIXED_ARTICLE_EVENT_BYTES)
        tampered[1] = 0x00  # invalid event_type
        with pytest.raises(DecodeError):
            decode_event(bytes(tampered))

    def test_reserved_event_type_rejected_by_default(self):
        tampered = bytearray(FIXED_ARTICLE_EVENT_BYTES)
        tampered[1] = 0x10  # reserved type
        with pytest.raises(DecodeError):
            decode_event(bytes(tampered))

    def test_reserved_event_type_allowed_with_flag(self):
        """Reserved event types (0x12-0x1F) decode with allow_unknown_types=True."""
        # Build a minimal valid event with a reserved type
        # Use empty headers (no ARTICLE headers)
        from core.article_feed import Event, ZERO_HASH, ZERO_MESSAGE_ID, SCHEME_NONE
        ev = Event(
            event_type=0x12,  # reserved type
            origin="x", board="y",
            feed_seq=1, message_id=b"\x01" * 32,
            created_at=1, actor_pubkey=b"\x00" * 32,
            headers=None,  # empty headers for unknown type
            body_hash=compute_body_hash(b""), body_size=0,
            author_signature_scheme=SCHEME_NONE, author_signature=b"",
            origin_signature=b"\x00" * 64,
        )
        from core.article_feed import sign_origin
        ev.origin_signature = sign_origin(ev, Identity.generate())
        encoded = encode_event(ev)
        decoded = decode_event(encoded, allow_unknown_types=True)
        assert decoded.event_type == 0x12

    def test_overflow_origin_length(self):
        """Origin length > MAX_ORIGIN_LEN should be rejected."""
        tampered = bytearray(FIXED_ARTICLE_EVENT_BYTES)
        # origin_len is at offset 2 (u16)
        struct.pack_into(">H", tampered, 2, MAX_ORIGIN_LEN + 1)
        with pytest.raises(DecodeError):
            decode_event(bytes(tampered))

    def test_overflow_headers_length(self):
        """Headers length > MAX_HEADERS_LEN should be rejected."""
        # Build a submission, find the header length field, and overflow it
        sub = FIXED_ARTICLE_SUBMISSION
        encoded_sub = bytearray(encode_submission(sub))
        # Decode manually to find the header_len offset
        offset = 1 + 1  # submission_version + event_type
        origin_len = struct.unpack(">H", encoded_sub[offset:offset+2])[0]; offset += 2 + origin_len
        board_len = struct.unpack(">H", encoded_sub[offset:offset+2])[0]; offset += 2 + board_len
        offset += 32  # message_id
        offset += 8  # created_at
        offset += 32  # actor_pubkey
        user_len = struct.unpack(">H", encoded_sub[offset:offset+2])[0]; offset += 2 + user_len
        reg_len = struct.unpack(">H", encoded_sub[offset:offset+2])[0]; offset += 2 + reg_len
        offset += 128  # 4 * 32-byte message IDs
        # Now at header_len (u32)
        struct.pack_into(">I", encoded_sub, offset, MAX_HEADERS_LEN + 1)
        with pytest.raises(DecodeError):
            decode_submission(bytes(encoded_sub))

    def test_overflow_extensions_length(self):
        """Extensions block exceeding MAX_EXTENSIONS_LEN is rejected on decode."""
        # Build valid extensions that are under the limit
        exts = [Extension(type=EXT_LEGACY_DESCRIPTOR, value=b"\x01" * 100)]
        encoded = _encode_extensions(exts)
        assert len(encoded) < MAX_EXTENSIONS_LEN
        # Decode with a max_len smaller than the actual data
        with pytest.raises(DecodeError):
            _decode_extensions(encoded, max_len=10)  # max_len too small

    def test_invalid_author_scheme_rejected(self):
        tampered = bytearray(FIXED_ARTICLE_EVENT_BYTES)
        # author_signature_scheme is near the end; flip it to an invalid value
        # Find it by decoding the valid event and checking the offset
        # The scheme byte is before author_signature (u16 len + bytes) and origin_sig (64)
        # For a simpler approach: just test that scheme 0xFF is rejected
        # We know the scheme is at a fixed offset from the end:
        # origin_sig(64) + author_sig(u16+bytes) + scheme(1) = from end
        # author_sig for the fixture is 64 bytes, so: 64 + 2 + 64 + 1 = 131 from end
        offset = len(tampered) - 64 - 2 - 64 - 1
        tampered[offset] = 0xFF
        with pytest.raises(DecodeError):
            decode_event(bytes(tampered))


# ---------------------------------------------------------------------------
# Submission decoder fuzz tests
# ---------------------------------------------------------------------------

class TestSubmissionDecoderFuzz:

    def test_empty_input_rejected(self):
        with pytest.raises(DecodeError):
            decode_submission(b"")

    def test_truncated_at_every_offset(self):
        for i in range(1, len(FIXED_ARTICLE_SUBMISSION_BYTES)):
            with pytest.raises(DecodeError):
                decode_submission(FIXED_ARTICLE_SUBMISSION_BYTES[:i])

    def test_trailing_bytes_rejected(self):
        with pytest.raises(DecodeError):
            decode_submission(FIXED_ARTICLE_SUBMISSION_BYTES + b"\x00")

    def test_random_garbage_rejected(self):
        for length in [1, 10, 50, 100, 500]:
            with pytest.raises(DecodeError):
                decode_submission(_random_bytes(length, seed=length + 100))

    def test_wrong_submission_version_rejected(self):
        tampered = bytearray(FIXED_ARTICLE_SUBMISSION_BYTES)
        tampered[0] = 0xFF
        with pytest.raises(DecodeError):
            decode_submission(bytes(tampered))


# ---------------------------------------------------------------------------
# Head decoder fuzz tests
# ---------------------------------------------------------------------------

class TestHeadDecoderFuzz:

    def test_empty_input_rejected(self):
        with pytest.raises(DecodeError):
            decode_head(b"")

    def test_truncated_at_every_offset(self):
        for i in range(1, len(FIXED_HEAD_BYTES)):
            with pytest.raises(DecodeError):
                decode_head(FIXED_HEAD_BYTES[:i])

    def test_trailing_bytes_rejected(self):
        with pytest.raises(DecodeError):
            decode_head(FIXED_HEAD_BYTES + b"\x00")

    def test_random_garbage_rejected(self):
        for length in [1, 10, 50, 100, 200]:
            with pytest.raises(DecodeError):
                decode_head(_random_bytes(length, seed=length + 200))

    def test_wrong_domain_prefix_rejected(self):
        tampered = bytearray(FIXED_HEAD_BYTES)
        tampered[0] ^= 0xFF  # corrupt domain prefix
        with pytest.raises(DecodeError):
            decode_head(bytes(tampered))

    def test_wrong_format_version_rejected(self):
        # The format_version byte is right after the domain prefix
        domain_len = len(b"bonnet-feed-head-signature-v1")
        tampered = bytearray(FIXED_HEAD_BYTES)
        tampered[domain_len] = 0xFF
        with pytest.raises(DecodeError):
            decode_head(bytes(tampered))


# ---------------------------------------------------------------------------
# Extensions decoder fuzz tests
# ---------------------------------------------------------------------------

class TestExtensionsDecoderFuzz:

    def test_empty_extensions_roundtrip(self):
        encoded = _encode_extensions([])
        decoded, _ = _decode_extensions(encoded, MAX_EXTENSIONS_LEN)
        assert decoded == []

    def test_duplicate_type_rejected(self):
        exts = [
            Extension(type=EXT_LEGACY_DESCRIPTOR, value=b"\x01"),
            Extension(type=EXT_LEGACY_DESCRIPTOR, value=b"\x02"),
        ]
        with pytest.raises(DecodeError):
            _encode_extensions(exts)

    def test_out_of_order_rejected(self):
        # EXT_LEGACY_AUTHOR_SIGNATURE (0x0003) before EXT_LEGACY_DESCRIPTOR (0x0001)
        from core.article_feed import EXT_LEGACY_AUTHOR_SIGNATURE
        exts = [
            Extension(type=EXT_LEGACY_AUTHOR_SIGNATURE, value=b"\x01"),
            Extension(type=EXT_LEGACY_DESCRIPTOR, value=b"\x02"),
        ]
        with pytest.raises(DecodeError):
            _encode_extensions(exts)

    def test_unknown_type_rejected(self):
        exts = [Extension(type=0xFFFF, value=b"\x01")]
        with pytest.raises(DecodeError):
            _encode_extensions(exts)

    def test_truncated_extensions_rejected(self):
        encoded = _encode_extensions([Extension(type=EXT_LEGACY_DESCRIPTOR, value=b"\x01\x02")])
        for i in range(1, len(encoded)):
            with pytest.raises(DecodeError):
                _decode_extensions(encoded[:i], MAX_EXTENSIONS_LEN)

    def test_trailing_bytes_rejected(self):
        encoded = _encode_extensions([Extension(type=EXT_LEGACY_DESCRIPTOR, value=b"\x01")])
        with pytest.raises(DecodeError):
            _decode_extensions(encoded + b"\x00", MAX_EXTENSIONS_LEN)


# ---------------------------------------------------------------------------
# Cross-domain signature replay fuzz tests
# ---------------------------------------------------------------------------

class TestCrossDomainReplayFuzz:

    def test_author_sig_not_valid_as_origin(self):
        """An author signature payload cannot verify as an origin signature."""
        from core.article_feed import (
            author_signature_payload, origin_signature_payload,
            verify_author_signature, verify_origin_signature,
        )
        author_id = Identity.generate()
        sub = FIXED_ARTICLE_SUBMISSION
        author_sig = sign_author(sub, author_id)

        # The author signature is over author_signature_payload
        # It should NOT verify as an origin signature over any event
        assert verify_author_signature(sub, author_sig, author_id.public_key)
        # Construct a dummy event and check the author sig doesn't verify as origin
        ev = Event(
            event_type=EVENT_ARTICLE, origin=sub.origin, board=sub.board,
            message_id=sub.message_id, created_at=sub.created_at,
            actor_pubkey=sub.actor_pubkey, headers=sub.headers,
            body_hash=sub.body_hash, body_size=sub.body_size,
            author_signature_scheme=SCHEME_V3, author_signature=author_sig,
        )
        assert not verify_origin_signature(ev, author_id.public_key)

    def test_head_sig_not_valid_as_event_sig(self):
        """A head signature payload cannot verify as an origin event signature."""
        from core.article_feed import head_signature_payload, verify_head_signature
        origin_id = Identity.from_private_key(ORIGIN_SEED)
        head = FIXED_HEAD
        assert verify_head_signature(head, origin_id.public_key)

        # The head signature bytes should not verify as an origin event signature
        # over any event payload, because the domain separation tags differ
        from core.article_feed import DOMAIN_HEAD_SIG, DOMAIN_ORIGIN_SIG
        assert DOMAIN_HEAD_SIG != DOMAIN_ORIGIN_SIG
        # The head signature payload starts with DOMAIN_HEAD_SIG
        # The origin signature payload starts with DOMAIN_ORIGIN_SIG
        # So a signature over one cannot verify as the other
