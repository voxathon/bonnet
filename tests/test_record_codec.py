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

"""Conformance tests for the firehose protocol's canonical codec.

All golden vectors use fixed Ed25519 private keys so signatures and hashes
are deterministic and reproducible across implementations.
"""

import hashlib
import struct
import unicodedata

import pytest

from bonnet.core.crypto import Identity
from bonnet.core.record import (
    DOMAIN_BODY,
    DOMAIN_EVENT_HASH,
    MAX_U63,
    SIG_SIZE,
    VT_TEXT,
    VT_TEXT_LIST,
    ZERO_HASH,
    ZERO_ID,
    # Errors
    Head,
    # Intent
    Intent,
    InvalidValue,
    LengthExceeded,
    # Metadata
    MetadataField,
    MetadataMap,
    NonCanonical,
    # Record
    Record,
    TrailingInput,
    TruncatedInput,
    # Witness
    Witness,
    # Hash/signature domains
    compute_body_hash,
    compute_event_hash,
    compute_head_hash,
    decode_head,
    decode_intent,
    decode_metadata,
    decode_record,
    decode_unsigned_record,
    decode_witness,
    enc_i64,
    enc_id32,
    enc_sig64,
    enc_text16,
    # Primitives
    enc_u8,
    enc_u16,
    enc_u64,
    encode_head,
    encode_intent,
    encode_metadata,
    encode_record,
    encode_unsigned_head,
    encode_unsigned_record,
    encode_unsigned_witness,
    encode_witness,
    is_origin_witness,
    make_origin_witness,
    metadata_bool,
    metadata_bytes,
    metadata_i64,
    metadata_id_list,
    metadata_text,
    metadata_text_list,
    metadata_u64,
    reconstruct_intent_from_record,
    sign_head,
    sign_intent,
    sign_key_rotation_proof,
    sign_record,
    sign_witness,
    verify_head_signature,
    verify_intent_signature,
    verify_key_rotation_proof,
    verify_record_signature,
    verify_witness_signature,
)

# ---------------------------------------------------------------------------
# Fixed test identities (deterministic Ed25519 keys)
# ---------------------------------------------------------------------------

_ACTOR_PRIV = bytes(range(32))
_ORIGIN_PRIV = bytes(range(1, 33))
_RELAY_PRIV = bytes(range(2, 34))
_NEW_ORIGIN_PRIV = bytes(range(3, 35))

ACTOR = Identity.from_private_key(_ACTOR_PRIV)
ORIGIN = Identity.from_private_key(_ORIGIN_PRIV)
RELAY = Identity.from_private_key(_RELAY_PRIV)
NEW_ORIGIN = Identity.from_private_key(_NEW_ORIGIN_PRIV)

ACTOR_PUB = ACTOR.public_key
ORIGIN_PUB = ORIGIN.public_key
RELAY_PUB = RELAY.public_key
NEW_ORIGIN_PUB = NEW_ORIGIN.public_key

EVENT_ID_1 = bytes.fromhex("aa" * 32)
ARTICLE_ID_1 = bytes.fromhex("bb" * 32)
BODY = b"Hello, bonnet!"
BODY_HASH = hashlib.sha256(DOMAIN_BODY + BODY).digest()


# ---------------------------------------------------------------------------
# Primitive encoding tests
# ---------------------------------------------------------------------------


class TestPrimitives:
    def test_u8_roundtrip(self):
        assert enc_u8(0) == b"\x00"
        assert enc_u8(255) == b"\xff"
        with pytest.raises(InvalidValue):
            enc_u8(-1)
        with pytest.raises(InvalidValue):
            enc_u8(256)

    def test_u16_roundtrip(self):
        assert enc_u16(0) == b"\x00\x00"
        assert enc_u16(0xFFFF) == b"\xff\xff"

    def test_u64_max_u63(self):
        assert enc_u64(MAX_U63) == struct.pack(">Q", MAX_U63)
        with pytest.raises(InvalidValue):
            enc_u64(MAX_U63 + 1)
        with pytest.raises(InvalidValue):
            enc_u64(-1)

    def test_i64_roundtrip(self):
        assert enc_i64(0) == b"\x00" * 8
        assert enc_i64(-1) == b"\xff\xff\xff\xff\xff\xff\xff\xff"

    def test_id32_rejects_wrong_length(self):
        with pytest.raises(InvalidValue):
            enc_id32(b"short")
        with pytest.raises(InvalidValue):
            enc_id32(b"x" * 33)

    def test_sig64_rejects_wrong_length(self):
        with pytest.raises(InvalidValue):
            enc_sig64(b"short")

    def test_text16_basic(self):
        assert enc_text16("hi") == struct.pack(">H", 2) + b"hi"

    def test_text16_max_len(self):
        with pytest.raises(LengthExceeded):
            enc_text16("x" * 300, max_len=255)


# ---------------------------------------------------------------------------
# Metadata map tests
# ---------------------------------------------------------------------------


class TestMetadata:
    def test_empty_metadata(self):
        m = MetadataMap()
        encoded = encode_metadata(m)
        assert encoded == struct.pack(">H", 0)
        decoded = decode_metadata(encoded)
        assert len(decoded.fields) == 0

    def test_single_text_field(self):
        m = MetadataMap([metadata_text(1, "hello")])
        encoded = encode_metadata(m)
        decoded = decode_metadata(encoded)
        assert decoded.get_text(1) == "hello"

    def test_multiple_fields_ordered(self):
        m = MetadataMap(
            [
                metadata_text(1, "subject"),
                metadata_u64(2, 42),
                metadata_bool(3, True),
            ]
        )
        encoded = encode_metadata(m)
        decoded = decode_metadata(encoded)
        assert decoded.get_text(1) == "subject"
        assert decoded.get_u64(2) == 42
        assert decoded.get_bool(3) is True

    def test_fields_must_be_strictly_increasing(self):
        m = MetadataMap(
            [
                metadata_text(2, "b"),
                metadata_text(1, "a"),
            ]
        )
        with pytest.raises(NonCanonical):
            encode_metadata(m)

    def test_duplicate_field_ids_rejected(self):
        m = MetadataMap(
            [
                metadata_text(1, "a"),
                metadata_text(1, "b"),
            ]
        )
        with pytest.raises(NonCanonical):
            encode_metadata(m)

    def test_bytes_field(self):
        m = MetadataMap([metadata_bytes(1, b"\xde\xad\xbe\xef")])
        decoded = decode_metadata(encode_metadata(m))
        assert decoded.get_bytes(1) == b"\xde\xad\xbe\xef"

    def test_i64_field(self):
        m = MetadataMap([metadata_i64(1, -12345)])
        decoded = decode_metadata(encode_metadata(m))
        assert decoded.get_i64(1) == -12345

    def test_id_list_field(self):
        ids = [bytes([i] * 32) for i in range(3)]
        m = MetadataMap([metadata_id_list(1, ids)])
        decoded = decode_metadata(encode_metadata(m))
        assert decoded.get_id_list(1) == ids

    def test_text_list_sorted(self):
        m = MetadataMap([metadata_text_list(1, ["banana", "apple", "cherry"])])
        encoded = encode_metadata(m)
        decoded = decode_metadata(encoded)
        assert decoded.get_text_list(1) == ["apple", "banana", "cherry"]

    def test_text_list_duplicates_rejected(self):
        m = MetadataMap([metadata_text_list(1, ["dup", "dup"])])
        with pytest.raises(NonCanonical):
            decode_metadata(encode_metadata(m))

    def test_text_list_unsorted_rejected_on_decode(self):
        field = MetadataField(
            1, VT_TEXT_LIST, struct.pack(">H", 2) + enc_text16("z") + enc_text16("a")
        )
        m = MetadataMap([field])
        encoded = encode_metadata(m)
        with pytest.raises(NonCanonical):
            decode_metadata(encoded)

    def test_unknown_value_type_rejected(self):
        field = MetadataField(1, 0xFF, b"junk")
        m = MetadataMap([field])
        with pytest.raises(InvalidValue):
            encode_metadata(m)

    def test_nfc_text_rejected_on_decode(self):
        # é can be encoded as decomposed (NFD) — two codepoints U+0065 U+0301
        nfd_bytes = "e\u0301".encode("utf-8")
        nfc_bytes = "é".encode()
        assert nfd_bytes != nfc_bytes
        field = MetadataField(1, VT_TEXT, nfd_bytes)
        m = MetadataMap([field])
        encoded = encode_metadata(m)
        with pytest.raises(NonCanonical):
            decode_metadata(encoded)

    def test_metadata_nfc_normalized_on_encode(self):
        nfd_text = "e\u0301"
        nfc_text = unicodedata.normalize("NFC", nfd_text)
        m = MetadataMap([metadata_text(1, nfd_text)])
        encoded = encode_metadata(m)
        decoded = decode_metadata(encoded)
        assert decoded.get_text(1) == nfc_text

    def test_truncated_metadata(self):
        with pytest.raises(TruncatedInput):
            decode_metadata(b"\x00\x01")

    def test_trailing_bytes_in_metadata(self):
        m = MetadataMap([metadata_text(1, "hi")])
        encoded = encode_metadata(m) + b"\x00"
        with pytest.raises(TrailingInput):
            decode_metadata(encoded)

    def test_field_count_limit(self):
        fields = [metadata_text(i, "x") for i in range(257)]
        m = MetadataMap(fields)
        with pytest.raises(LengthExceeded):
            encode_metadata(m)


# ---------------------------------------------------------------------------
# Hash and signature domain tests
# ---------------------------------------------------------------------------


class TestCryptoDomains:
    def test_body_hash_deterministic(self):
        h1 = compute_body_hash(b"hello")
        h2 = compute_body_hash(b"hello")
        assert h1 == h2
        assert len(h1) == 32

    def test_body_hash_differs_for_different_input(self):
        assert compute_body_hash(b"a") != compute_body_hash(b"b")

    def test_empty_body_hash(self):
        h = compute_body_hash(b"")
        assert len(h) == 32
        assert h != ZERO_HASH

    def test_intent_signature_verifies(self):
        intent = Intent(
            event_id=EVENT_ID_1,
            kind="bonnet.article",
            origin="bbs.test",
            actor_pubkey=ACTOR_PUB,
            board="general",
            article_id=ARTICLE_ID_1,
            body_hash=BODY_HASH,
            body_size=len(BODY),
        )
        encoded = encode_intent(intent)
        sig = sign_intent(ACTOR, encoded)
        assert verify_intent_signature(ACTOR_PUB, encoded, sig)

    def test_intent_signature_wrong_key_fails(self):
        intent = Intent(
            event_id=EVENT_ID_1,
            kind="bonnet.article",
            origin="bbs.test",
            actor_pubkey=ACTOR_PUB,
            board="general",
        )
        encoded = encode_intent(intent)
        sig = sign_intent(ACTOR, encoded)
        assert not verify_intent_signature(ORIGIN_PUB, encoded, sig)

    def test_record_signature_verifies(self):
        rec = Record(
            origin="bbs.test",
            origin_seq=1,
            event_id=EVENT_ID_1,
            kind="bonnet.article",
            actor_pubkey=ACTOR_PUB,
            board="general",
            article_id=ARTICLE_ID_1,
            article_num=1,
            body_hash=BODY_HASH,
            body_size=len(BODY),
        )
        unsigned = encode_unsigned_record(rec)
        rec.origin_signature = sign_record(ORIGIN, unsigned)
        assert verify_record_signature(ORIGIN_PUB, unsigned, rec.origin_signature)

    def test_event_hash_deterministic(self):
        rec = Record(
            origin="bbs.test",
            origin_seq=1,
            event_id=EVENT_ID_1,
            kind="bonnet.article",
            actor_pubkey=ACTOR_PUB,
            board="general",
            article_id=ARTICLE_ID_1,
            article_num=1,
        )
        encoded = encode_record(rec)
        h1 = compute_event_hash(encoded)
        h2 = compute_event_hash(encoded)
        assert h1 == h2
        assert len(h1) == 32

    def test_head_signature_verifies(self):
        h = Head(
            origin="bbs.test",
            latest_origin_seq=1,
            origin_pubkey=ORIGIN_PUB,
        )
        unsigned = encode_unsigned_head(h)
        h.origin_signature = sign_head(ORIGIN, unsigned)
        assert verify_head_signature(ORIGIN_PUB, unsigned, h.origin_signature)

    def test_witness_signature_verifies(self):
        w = Witness(
            event_origin="bbs.test",
            event_id=EVENT_ID_1,
            event_hash=ZERO_HASH,
            relay_pubkey=RELAY_PUB,
            relay_hostname="relay.test",
            seen_at=1700000000,
        )
        unsigned = encode_unsigned_witness(w)
        w.relay_signature = sign_witness(RELAY, unsigned)
        assert verify_witness_signature(RELAY_PUB, unsigned, w.relay_signature)


# ---------------------------------------------------------------------------
# Intent codec tests
# ---------------------------------------------------------------------------


class TestIntent:
    def _make_intent(self) -> Intent:
        return Intent(
            event_id=EVENT_ID_1,
            kind="bonnet.article",
            schema_version=1,
            origin="bbs.test",
            actor_pubkey=ACTOR_PUB,
            board="general",
            article_id=ARTICLE_ID_1,
            metadata=MetadataMap(
                [
                    metadata_text(1, "Test Article"),
                    metadata_text_list(2, ["news", "tech"]),
                    metadata_text(4, "text/plain"),
                ]
            ),
            body_hash=BODY_HASH,
            body_size=len(BODY),
        )

    def test_encode_decode_roundtrip(self):
        intent = self._make_intent()
        encoded = encode_intent(intent)
        decoded = decode_intent(encoded)
        assert decoded.event_id == EVENT_ID_1
        assert decoded.kind == "bonnet.article"
        assert decoded.origin == "bbs.test"
        assert decoded.actor_pubkey == ACTOR_PUB
        assert decoded.board == "general"
        assert decoded.article_id == ARTICLE_ID_1
        assert decoded.body_hash == BODY_HASH
        assert decoded.body_size == len(BODY)
        assert decoded.metadata.get_text(1) == "Test Article"
        assert decoded.metadata.get_text_list(2) == ["news", "tech"]
        assert decoded.metadata.get_text(4) == "text/plain"

    def test_intent_rejects_zero_event_id(self):
        intent = Intent(event_id=ZERO_ID, kind="bonnet.article")
        with pytest.raises(InvalidValue):
            encode_intent(intent)

    def test_intent_trailing_bytes(self):
        intent = self._make_intent()
        encoded = encode_intent(intent) + b"\x00"
        with pytest.raises(TrailingInput):
            decode_intent(encoded)

    def test_intent_truncated(self):
        intent = self._make_intent()
        encoded = encode_intent(intent)
        with pytest.raises(TruncatedInput):
            decode_intent(encoded[:-1])

    def test_intent_wrong_format(self):
        intent = self._make_intent()
        encoded = encode_intent(intent)
        with pytest.raises(InvalidValue):
            decode_intent(b"\x02" + encoded[1:])


# ---------------------------------------------------------------------------
# Record codec tests
# ---------------------------------------------------------------------------


class TestRecord:
    def _make_record(self) -> Record:
        intent = Intent(
            event_id=EVENT_ID_1,
            kind="bonnet.article",
            origin="bbs.test",
            actor_pubkey=ACTOR_PUB,
            board="general",
            article_id=ARTICLE_ID_1,
            metadata=MetadataMap(
                [
                    metadata_text(1, "Test Article"),
                    metadata_text(4, "text/plain"),
                ]
            ),
            body_hash=BODY_HASH,
            body_size=len(BODY),
        )
        encoded_intent = encode_intent(intent)
        actor_sig = sign_intent(ACTOR, encoded_intent)

        rec = Record(
            origin="bbs.test",
            origin_seq=1,
            previous_event_hash=ZERO_HASH,
            event_id=EVENT_ID_1,
            kind="bonnet.article",
            created_at=1700000000,
            actor_pubkey=ACTOR_PUB,
            board="general",
            article_id=ARTICLE_ID_1,
            article_num=1,
            metadata=intent.metadata,
            body_hash=BODY_HASH,
            body_size=len(BODY),
            actor_signature=actor_sig,
        )
        unsigned = encode_unsigned_record(rec)
        rec.origin_signature = sign_record(ORIGIN, unsigned)
        return rec

    def test_encode_decode_roundtrip(self):
        rec = self._make_record()
        encoded = encode_record(rec)
        decoded = decode_record(encoded)
        assert decoded.origin == "bbs.test"
        assert decoded.origin_seq == 1
        assert decoded.event_id == EVENT_ID_1
        assert decoded.kind == "bonnet.article"
        assert decoded.article_num == 1
        assert decoded.actor_pubkey == ACTOR_PUB
        assert decoded.board == "general"
        assert decoded.article_id == ARTICLE_ID_1
        assert decoded.body_hash == BODY_HASH
        assert decoded.body_size == len(BODY)
        assert decoded.actor_signature == rec.actor_signature
        assert decoded.origin_signature == rec.origin_signature

    def test_decode_unsigned_and_verify(self):
        rec = self._make_record()
        encoded = encode_record(rec)
        decoded_rec, origin_sig = decode_unsigned_record(encoded)
        unsigned_bytes = encoded[:-SIG_SIZE]
        assert verify_record_signature(ORIGIN_PUB, unsigned_bytes, origin_sig)

    def test_reconstruct_intent_from_record(self):
        rec = self._make_record()
        intent = reconstruct_intent_from_record(rec)
        encoded_intent = encode_intent(intent)
        assert verify_intent_signature(ACTOR_PUB, encoded_intent, rec.actor_signature)

    def test_event_hash_covers_complete_record(self):
        rec = self._make_record()
        encoded = encode_record(rec)
        eh = compute_event_hash(encoded)
        assert len(eh) == 32
        assert eh != ZERO_HASH

    def test_record_trailing_bytes(self):
        rec = self._make_record()
        encoded = encode_record(rec) + b"\xff"
        with pytest.raises(TrailingInput):
            decode_record(encoded)

    def test_record_truncated(self):
        rec = self._make_record()
        encoded = encode_record(rec)
        with pytest.raises(TruncatedInput):
            decode_record(encoded[:-2])


# ---------------------------------------------------------------------------
# Head codec tests
# ---------------------------------------------------------------------------


class TestHead:
    def test_empty_head(self):
        h = Head(origin="bbs.test", origin_pubkey=ORIGIN_PUB)
        unsigned = encode_unsigned_head(h)
        h.origin_signature = sign_head(ORIGIN, unsigned)
        encoded = encode_head(h)
        decoded = decode_head(encoded)
        assert decoded.latest_origin_seq == 0
        assert decoded.latest_event_hash == ZERO_HASH
        assert decoded.event_count == 0
        assert decoded.origin_pubkey == ORIGIN_PUB

    def test_head_with_sequence(self):
        event_hash = bytes.fromhex("cd" * 32)
        h = Head(
            origin="bbs.test",
            latest_origin_seq=42,
            latest_event_hash=event_hash,
            event_count=42,
            generated_at=1700000000,
            origin_pubkey=ORIGIN_PUB,
        )
        unsigned = encode_unsigned_head(h)
        h.origin_signature = sign_head(ORIGIN, unsigned)
        encoded = encode_head(h)
        decoded = decode_head(encoded)
        assert decoded.latest_origin_seq == 42
        assert decoded.latest_event_hash == event_hash
        assert decoded.event_count == 42
        assert decoded.origin_pubkey == ORIGIN_PUB
        assert verify_head_signature(
            ORIGIN_PUB, encode_unsigned_head(decoded), decoded.origin_signature
        )

    def test_head_hash(self):
        h = Head(origin="bbs.test", origin_pubkey=ORIGIN_PUB)
        unsigned = encode_unsigned_head(h)
        h.origin_signature = sign_head(ORIGIN, unsigned)
        encoded = encode_head(h)
        hh = compute_head_hash(encoded)
        assert len(hh) == 32
        assert hh != ZERO_HASH


# ---------------------------------------------------------------------------
# Witness codec tests
# ---------------------------------------------------------------------------


class TestWitness:
    def test_relay_witness_roundtrip(self):
        event_hash = bytes.fromhex("ee" * 32)
        w = Witness(
            event_origin="bbs.test",
            event_id=EVENT_ID_1,
            event_hash=event_hash,
            relay_pubkey=RELAY_PUB,
            relay_hostname="relay.test",
            received_from_pubkey=ORIGIN_PUB,
            received_from_hostname="bbs.test",
            seen_at=1700000000,
        )
        unsigned = encode_unsigned_witness(w)
        w.relay_signature = sign_witness(RELAY, unsigned)
        encoded = encode_witness(w)
        decoded = decode_witness(encoded)
        assert decoded.event_origin == "bbs.test"
        assert decoded.event_id == EVENT_ID_1
        assert decoded.event_hash == event_hash
        assert decoded.relay_pubkey == RELAY_PUB
        assert decoded.relay_hostname == "relay.test"
        assert decoded.received_from_pubkey == ORIGIN_PUB
        assert decoded.received_from_hostname == "bbs.test"
        assert decoded.seen_at == 1700000000
        assert not is_origin_witness(decoded)

    def test_origin_witness_terminates_trace(self):
        event_hash = bytes.fromhex("ee" * 32)
        w = make_origin_witness(
            origin="bbs.test",
            event_id=EVENT_ID_1,
            event_hash=event_hash,
            origin_identity=ORIGIN,
            hostname="bbs.test",
            seen_at=1700000000,
        )
        assert is_origin_witness(w)
        encoded = encode_witness(w)
        decoded = decode_witness(encoded)
        assert is_origin_witness(decoded)
        assert decoded.relay_pubkey == ORIGIN_PUB
        assert verify_witness_signature(
            ORIGIN_PUB,
            encode_unsigned_witness(decoded),
            decoded.relay_signature,
        )

    def test_witness_trailing_bytes(self):
        w = Witness(
            event_origin="bbs.test",
            event_id=EVENT_ID_1,
            event_hash=ZERO_HASH,
            relay_pubkey=RELAY_PUB,
            relay_hostname="relay.test",
            seen_at=1700000000,
        )
        unsigned = encode_unsigned_witness(w)
        w.relay_signature = sign_witness(RELAY, unsigned)
        encoded = encode_witness(w) + b"\x00"
        with pytest.raises(TrailingInput):
            decode_witness(encoded)


# ---------------------------------------------------------------------------
# Key rotation proof tests
# ---------------------------------------------------------------------------


class TestKeyRotation:
    def test_proof_verifies(self):
        proof = sign_key_rotation_proof(NEW_ORIGIN, "bbs.test", ORIGIN_PUB, NEW_ORIGIN_PUB)
        assert verify_key_rotation_proof(NEW_ORIGIN_PUB, "bbs.test", ORIGIN_PUB, proof)

    def test_proof_wrong_new_key_fails(self):
        proof = sign_key_rotation_proof(NEW_ORIGIN, "bbs.test", ORIGIN_PUB, NEW_ORIGIN_PUB)
        assert not verify_key_rotation_proof(ORIGIN_PUB, "bbs.test", ORIGIN_PUB, proof)

    def test_proof_wrong_old_key_fails(self):
        proof = sign_key_rotation_proof(NEW_ORIGIN, "bbs.test", ORIGIN_PUB, NEW_ORIGIN_PUB)
        assert not verify_key_rotation_proof(NEW_ORIGIN_PUB, "bbs.test", RELAY_PUB, proof)


# ---------------------------------------------------------------------------
# Golden vector: full publication flow
# ---------------------------------------------------------------------------


class TestGoldenVectors:
    """Deterministic end-to-end encoding and signature vectors."""

    def test_full_article_publication(self):
        """A complete article publication: intent → record → head → witness.

        Every hash and signature is deterministic given the fixed keys.
        """
        # 1. Actor creates and signs intent
        body = b"Hello, bonnet!"
        body_hash = compute_body_hash(body)

        intent = Intent(
            event_id=EVENT_ID_1,
            kind="bonnet.article",
            schema_version=1,
            origin="bbs.test",
            actor_pubkey=ACTOR_PUB,
            board="general",
            article_id=ARTICLE_ID_1,
            metadata=MetadataMap(
                [
                    metadata_text(1, "First Post"),
                    metadata_text_list(2, ["intro", "test"]),
                    metadata_text(4, "text/plain"),
                ]
            ),
            body_hash=body_hash,
            body_size=len(body),
        )
        encoded_intent = encode_intent(intent)
        actor_sig = sign_intent(ACTOR, encoded_intent)
        assert verify_intent_signature(ACTOR_PUB, encoded_intent, actor_sig)

        # 2. Origin accepts and creates the record
        rec = Record(
            origin="bbs.test",
            origin_seq=1,
            previous_event_hash=ZERO_HASH,
            event_id=EVENT_ID_1,
            kind="bonnet.article",
            schema_version=1,
            created_at=1700000000,
            actor_pubkey=ACTOR_PUB,
            board="general",
            article_id=ARTICLE_ID_1,
            article_num=1,
            metadata=intent.metadata,
            body_hash=body_hash,
            body_size=len(body),
            actor_signature=actor_sig,
        )
        unsigned_rec = encode_unsigned_record(rec)
        rec.origin_signature = sign_record(ORIGIN, unsigned_rec)
        encoded_rec = encode_record(rec)

        # Verify both signatures
        assert verify_record_signature(ORIGIN_PUB, unsigned_rec, rec.origin_signature)
        reconstructed_intent = reconstruct_intent_from_record(rec)
        assert verify_intent_signature(
            ACTOR_PUB,
            encode_intent(reconstructed_intent),
            rec.actor_signature,
        )

        # Event hash is deterministic
        event_hash = compute_event_hash(encoded_rec)
        assert event_hash == hashlib.sha256(DOMAIN_EVENT_HASH + encoded_rec).digest()

        # 3. Origin publishes head
        head = Head(
            origin="bbs.test",
            latest_origin_seq=1,
            latest_event_hash=event_hash,
            event_count=1,
            generated_at=1700000001,
            origin_pubkey=ORIGIN_PUB,
        )
        unsigned_head = encode_unsigned_head(head)
        head.origin_signature = sign_head(ORIGIN, unsigned_head)
        assert verify_head_signature(ORIGIN_PUB, unsigned_head, head.origin_signature)

        # 4. Origin creates terminating witness
        witness = make_origin_witness(
            origin="bbs.test",
            event_id=EVENT_ID_1,
            event_hash=event_hash,
            origin_identity=ORIGIN,
            hostname="bbs.test",
            seen_at=1700000002,
        )
        assert is_origin_witness(witness)
        assert verify_witness_signature(
            ORIGIN_PUB,
            encode_unsigned_witness(witness),
            witness.relay_signature,
        )

        # 5. Full round-trip decode
        decoded_rec = decode_record(encoded_rec)
        assert decoded_rec.origin_seq == 1
        assert decoded_rec.event_id == EVENT_ID_1
        assert decoded_rec.kind == "bonnet.article"
        assert decoded_rec.article_num == 1

        decoded_head = decode_head(encode_head(head))
        assert decoded_head.latest_origin_seq == 1
        assert decoded_head.latest_event_hash == event_hash
        assert decoded_head.event_count == 1

        decoded_witness = decode_witness(encode_witness(witness))
        assert is_origin_witness(decoded_witness)
        assert decoded_witness.event_hash == event_hash

    def test_cancel_record_after_article(self):
        """A CANCEL control event targeting the article from the previous test."""
        cancel_event_id = bytes.fromhex("cc" * 32)

        intent = Intent(
            event_id=cancel_event_id,
            kind="bonnet.article.cancel",
            schema_version=1,
            origin="bbs.test",
            actor_pubkey=ACTOR_PUB,
            board="general",
            target_origin="bbs.test",
            target_board="general",
            target_article_id=ARTICLE_ID_1,
            body_hash=compute_body_hash(b"cancelled by author"),
            body_size=20,
        )
        encoded_intent = encode_intent(intent)
        actor_sig = sign_intent(ACTOR, encoded_intent)

        # Previous event hash would be the article's event hash
        article_event_hash = bytes.fromhex("11" * 32)

        rec = Record(
            origin="bbs.test",
            origin_seq=2,
            previous_event_hash=article_event_hash,
            event_id=cancel_event_id,
            kind="bonnet.article.cancel",
            schema_version=1,
            created_at=1700000010,
            actor_pubkey=ACTOR_PUB,
            board="general",
            target_origin="bbs.test",
            target_board="general",
            target_article_id=ARTICLE_ID_1,
            actor_signature=actor_sig,
        )
        unsigned = encode_unsigned_record(rec)
        rec.origin_signature = sign_record(ORIGIN, unsigned)
        encoded = encode_record(rec)
        decoded = decode_record(encoded)

        assert decoded.kind == "bonnet.article.cancel"
        assert decoded.target_article_id == ARTICLE_ID_1
        assert decoded.target_origin == "bbs.test"
        assert decoded.target_board == "general"
        assert decoded.article_num == 0  # non-article records use zero
        assert decoded.origin_seq == 2
        assert decoded.previous_event_hash == article_event_hash

    def test_relay_chain_two_hops(self):
        """Origin → Relay A → Relay B: two witnesses, traceable."""
        event_hash = bytes.fromhex("ee" * 32)

        # Origin witness
        origin_w = make_origin_witness(
            origin="bbs.test",
            event_id=EVENT_ID_1,
            event_hash=event_hash,
            origin_identity=ORIGIN,
            hostname="bbs.test",
            seen_at=1700000000,
        )

        # Relay A witness (received from origin)
        relay_a_w = Witness(
            event_origin="bbs.test",
            event_id=EVENT_ID_1,
            event_hash=event_hash,
            relay_pubkey=RELAY_PUB,
            relay_hostname="relay-a.test",
            received_from_pubkey=ORIGIN_PUB,
            received_from_hostname="bbs.test",
            seen_at=1700000005,
        )
        relay_a_w.relay_signature = sign_witness(RELAY, encode_unsigned_witness(relay_a_w))

        # Verify both witnesses
        assert is_origin_witness(origin_w)
        assert not is_origin_witness(relay_a_w)
        assert verify_witness_signature(
            RELAY_PUB,
            encode_unsigned_witness(relay_a_w),
            relay_a_w.relay_signature,
        )

        # Tracing: relay A's received_from points to origin
        assert relay_a_w.received_from_pubkey == ORIGIN_PUB
        assert relay_a_w.received_from_hostname == "bbs.test"

    def test_idempotent_resubmit(self):
        """Resubmitting a byte-identical intent produces the same actor signature."""
        intent = Intent(
            event_id=EVENT_ID_1,
            kind="bonnet.article",
            origin="bbs.test",
            actor_pubkey=ACTOR_PUB,
            board="general",
            article_id=ARTICLE_ID_1,
        )
        encoded = encode_intent(intent)
        sig1 = sign_intent(ACTOR, encoded)
        sig2 = sign_intent(ACTOR, encoded)
        assert sig1 == sig2  # Ed25519 is deterministic


# ---------------------------------------------------------------------------
# Edge cases and rejection tests
# ---------------------------------------------------------------------------


class TestRejections:
    def test_u64_exceeds_u63_rejected(self):
        with pytest.raises(InvalidValue):
            enc_u64(1 << 63)

    def test_origin_text_too_long(self):
        intent = Intent(
            event_id=EVENT_ID_1,
            kind="bonnet.article",
            origin="x" * 300,
            actor_pubkey=ACTOR_PUB,
        )
        with pytest.raises(LengthExceeded):
            encode_intent(intent)

    def test_kind_too_long(self):
        intent = Intent(
            event_id=EVENT_ID_1,
            kind="x" * 200,
            origin="bbs.test",
            actor_pubkey=ACTOR_PUB,
        )
        with pytest.raises(LengthExceeded):
            encode_intent(intent)

    def test_record_wrong_format_byte(self):
        rec = Record(
            origin="bbs.test",
            origin_seq=1,
            event_id=EVENT_ID_1,
            kind="bonnet.article",
            actor_pubkey=ACTOR_PUB,
        )
        unsigned = encode_unsigned_record(rec)
        rec.origin_signature = sign_record(ORIGIN, unsigned)
        encoded = encode_record(rec)
        with pytest.raises(InvalidValue):
            decode_record(b"\x99" + encoded[1:])

    def test_head_wrong_format_byte(self):
        h = Head(origin="bbs.test", origin_pubkey=ORIGIN_PUB)
        unsigned = encode_unsigned_head(h)
        h.origin_signature = sign_head(ORIGIN, unsigned)
        encoded = encode_head(h)
        with pytest.raises(InvalidValue):
            decode_head(b"\x99" + encoded[1:])

    def test_witness_wrong_format_byte(self):
        w = Witness(
            event_origin="bbs.test",
            event_id=EVENT_ID_1,
            event_hash=ZERO_HASH,
            relay_pubkey=RELAY_PUB,
            relay_hostname="r.test",
            seen_at=1700000000,
        )
        unsigned = encode_unsigned_witness(w)
        w.relay_signature = sign_witness(RELAY, unsigned)
        encoded = encode_witness(w)
        with pytest.raises(InvalidValue):
            decode_witness(b"\x99" + encoded[1:])
