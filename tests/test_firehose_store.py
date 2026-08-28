"""Tests for the FirehoseStore.

Tests: sequence allocation, article-number allocation, idempotent resubmit,
event ID collision, article ID collision, chain continuity, head management,
key epoch tracking, remote range acceptance, rollback rejection, equivocation
conflict storage, witness storage, and projection checkpoints.
"""

import threading

import pytest

from bonnet.core.crypto import Identity
from bonnet.core.firehose import (
    KIND_ARTICLE,
    KIND_ORIGIN_KEY_ROTATE,
    ArticleIdCollision,
    ChainBreak,
    EventIdCollision,
    FirehoseStore,
    HeadMismatch,
    SignatureInvalid,
)
from bonnet.core.record import (
    ZERO_HASH,
    Head,
    Intent,
    MetadataMap,
    Record,
    Witness,
    compute_body_hash,
    compute_event_hash,
    encode_intent,
    encode_record,
    encode_unsigned_head,
    encode_unsigned_record,
    encode_unsigned_witness,
    metadata_bytes,
    metadata_text,
    sign_head,
    sign_intent,
    sign_record,
    sign_witness,
    verify_head_signature,
)

# ---------------------------------------------------------------------------
# Fixed test identities
# ---------------------------------------------------------------------------

ORIGIN_A = Identity.from_private_key(bytes(range(1, 33)))
ORIGIN_B = Identity.from_private_key(bytes(range(5, 37)))
ACTOR = Identity.from_private_key(bytes(range(10, 42)))
RELAY = Identity.from_private_key(bytes(range(15, 47)))
NEW_ORIGIN = Identity.from_private_key(bytes(range(20, 52)))

ORIGIN_A_PUB = ORIGIN_A.public_key
ORIGIN_B_PUB = ORIGIN_B.public_key
ACTOR_PUB = ACTOR.public_key
RELAY_PUB = RELAY.public_key
NEW_ORIGIN_PUB = NEW_ORIGIN.public_key


def _random_id(seed: int) -> bytes:
    return bytes([(seed + i) % 256 for i in range(32)])


def _make_article_intent(
    origin: str,
    event_id: bytes,
    article_id: bytes,
    board: str = "general",
    actor: Identity = ACTOR,
    body: bytes = b"test body",
) -> Intent:
    return Intent(
        event_id=event_id,
        kind=KIND_ARTICLE,
        schema_version=1,
        origin=origin,
        actor_pubkey=actor.public_key,
        board=board,
        article_id=article_id,
        metadata=MetadataMap(
            [
                metadata_text(1, "Test"),
                metadata_text(4, "text/plain"),
            ]
        ),
        body_hash=compute_body_hash(body),
        body_size=len(body),
    )


def _sign_intent(intent: Intent, identity: Identity = ACTOR) -> bytes:
    return sign_intent(identity, encode_intent(intent))


def _make_head(origin: str, seq: int, event_hash: bytes, identity: Identity) -> Head:
    h = Head(
        origin=origin,
        latest_origin_seq=seq,
        latest_event_hash=event_hash,
        event_count=seq,
        origin_pubkey=identity.public_key,
    )
    unsigned = encode_unsigned_head(h)
    h.origin_signature = sign_head(identity, unsigned)
    return h


def _make_remote_records(origin: str, identity: Identity, count: int, start_seq: int = 1):
    """Create a chain of signed records (not stored in any FirehoseStore)."""
    records = []
    prev_hash = ZERO_HASH if start_seq == 1 else None
    for i in range(count):
        seq = start_seq + i
        eid = _random_id(seq * 10 + 1)
        aid = _random_id(seq * 10 + 2)
        intent = _make_article_intent(origin, eid, aid)
        actor_sig = _sign_intent(intent)
        rec = Record(
            origin=origin,
            origin_seq=seq,
            previous_event_hash=prev_hash if prev_hash else ZERO_HASH,
            event_id=eid,
            kind=KIND_ARTICLE,
            actor_pubkey=ACTOR_PUB,
            board="general",
            article_id=aid,
            article_num=seq,
            metadata=intent.metadata,
            body_hash=intent.body_hash,
            body_size=intent.body_size,
            actor_signature=actor_sig,
        )
        unsigned = encode_unsigned_record(rec)
        rec.origin_signature = sign_record(identity, unsigned)
        encoded = encode_record(rec)
        prev_hash = compute_event_hash(encoded)
        records.append(rec)
    return records, prev_hash


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path):
    s = FirehoseStore(str(tmp_path / "events.db"))
    yield s
    s.close()


# ---------------------------------------------------------------------------
# Sequence allocation
# ---------------------------------------------------------------------------


class TestSequenceAllocation:
    def test_first_record_seq_1(self, store):
        store.init_origin_key("bbs.a", ORIGIN_A_PUB)
        eid = _random_id(1)
        aid = _random_id(2)
        intent = _make_article_intent("bbs.a", eid, aid)
        sig = _sign_intent(intent)
        rec = store.append_record(ORIGIN_A, intent, sig, b"test body")
        assert rec.origin_seq == 1
        assert rec.previous_event_hash == ZERO_HASH

    def test_second_record_seq_2(self, store):
        store.init_origin_key("bbs.a", ORIGIN_A_PUB)
        for i in range(2):
            intent = _make_article_intent("bbs.a", _random_id(i + 1), _random_id(i + 10))
            sig = _sign_intent(intent)
            store.append_record(ORIGIN_A, intent, sig, b"test body")
        assert store.get_highest_seq("bbs.a") == 2

    def test_sequence_no_gaps(self, store):
        store.init_origin_key("bbs.a", ORIGIN_A_PUB)
        seqs = []
        for i in range(5):
            intent = _make_article_intent("bbs.a", _random_id(i + 1), _random_id(i + 10))
            sig = _sign_intent(intent)
            rec = store.append_record(ORIGIN_A, intent, sig, b"test body")
            seqs.append(rec.origin_seq)
        assert seqs == [1, 2, 3, 4, 5]


# ---------------------------------------------------------------------------
# Article number allocation
# ---------------------------------------------------------------------------


class TestArticleNumberAllocation:
    def test_first_article_num_1(self, store):
        store.init_origin_key("bbs.a", ORIGIN_A_PUB)
        intent = _make_article_intent("bbs.a", _random_id(1), _random_id(2))
        rec = store.append_record(ORIGIN_A, intent, _sign_intent(intent), b"test body")
        assert rec.article_num == 1

    def test_article_nums_increment_per_board(self, store):
        store.init_origin_key("bbs.a", ORIGIN_A_PUB)
        nums = []
        for i in range(3):
            intent = _make_article_intent("bbs.a", _random_id(i + 1), _random_id(i + 10))
            rec = store.append_record(ORIGIN_A, intent, _sign_intent(intent), b"test body")
            nums.append(rec.article_num)
        assert nums == [1, 2, 3]

    def test_article_nums_independent_boards(self, store):
        store.init_origin_key("bbs.a", ORIGIN_A_PUB)
        intent1 = _make_article_intent("bbs.a", _random_id(1), _random_id(2), board="board1")
        rec1 = store.append_record(ORIGIN_A, intent1, _sign_intent(intent1), b"test body")
        intent2 = _make_article_intent("bbs.a", _random_id(3), _random_id(4), board="board2")
        rec2 = store.append_record(ORIGIN_A, intent2, _sign_intent(intent2), b"test body")
        assert rec1.article_num == 1
        assert rec2.article_num == 1

    def test_non_article_records_have_zero_article_num(self, store):
        store.init_origin_key("bbs.a", ORIGIN_A_PUB)
        intent = Intent(
            event_id=_random_id(1),
            kind="bonnet.article.cancel",
            origin="bbs.a",
            actor_pubkey=ACTOR_PUB,
            board="general",
            target_origin="bbs.a",
            target_board="general",
            target_article_id=_random_id(2),
        )
        rec = store.append_record(ORIGIN_A, intent, _sign_intent(intent), b"")
        assert rec.article_num == 0


# ---------------------------------------------------------------------------
# Idempotent resubmit
# ---------------------------------------------------------------------------


class TestIdempotentResubmit:
    def test_same_event_id_returns_existing(self, store):
        store.init_origin_key("bbs.a", ORIGIN_A_PUB)
        intent = _make_article_intent("bbs.a", _random_id(1), _random_id(2))
        sig = _sign_intent(intent)
        rec1 = store.append_record(ORIGIN_A, intent, sig, b"test body")
        rec2 = store.append_record(ORIGIN_A, intent, sig, b"test body")
        assert rec1.origin_seq == rec2.origin_seq
        assert rec1.event_id == rec2.event_id
        assert encode_record(rec1) == encode_record(rec2)


# ---------------------------------------------------------------------------
# Collision rejection
# ---------------------------------------------------------------------------


class TestCollisions:
    def test_event_id_collision_rejected(self, store):
        store.init_origin_key("bbs.a", ORIGIN_A_PUB)
        eid = _random_id(1)
        intent1 = _make_article_intent("bbs.a", eid, _random_id(2), board="board1")
        store.append_record(ORIGIN_A, intent1, _sign_intent(intent1), b"test body")
        intent2 = _make_article_intent("bbs.a", eid, _random_id(3), board="board2")
        with pytest.raises(EventIdCollision):
            store.append_record(ORIGIN_A, intent2, _sign_intent(intent2), b"test body")

    def test_article_id_collision_rejected(self, store):
        store.init_origin_key("bbs.a", ORIGIN_A_PUB)
        aid = _random_id(5)
        intent1 = _make_article_intent("bbs.a", _random_id(1), aid, board="general")
        store.append_record(ORIGIN_A, intent1, _sign_intent(intent1), b"test body")
        intent2 = _make_article_intent("bbs.a", _random_id(2), aid, board="general")
        with pytest.raises(ArticleIdCollision):
            store.append_record(ORIGIN_A, intent2, _sign_intent(intent2), b"test body")

    def test_same_article_id_different_board_ok(self, store):
        store.init_origin_key("bbs.a", ORIGIN_A_PUB)
        aid = _random_id(5)
        intent1 = _make_article_intent("bbs.a", _random_id(1), aid, board="board1")
        store.append_record(ORIGIN_A, intent1, _sign_intent(intent1), b"test body")
        intent2 = _make_article_intent("bbs.a", _random_id(2), aid, board="board2")
        rec2 = store.append_record(ORIGIN_A, intent2, _sign_intent(intent2), b"test body")
        assert rec2.article_num == 1


# ---------------------------------------------------------------------------
# Chain continuity
# ---------------------------------------------------------------------------


class TestChainContinuity:
    def test_previous_event_hash_links_correctly(self, store):
        store.init_origin_key("bbs.a", ORIGIN_A_PUB)
        recs = []
        for i in range(3):
            intent = _make_article_intent("bbs.a", _random_id(i + 1), _random_id(i + 10))
            rec = store.append_record(ORIGIN_A, intent, _sign_intent(intent), b"test body")
            recs.append(rec)
        assert recs[0].previous_event_hash == ZERO_HASH
        assert recs[1].previous_event_hash == compute_event_hash(encode_record(recs[0]))
        assert recs[2].previous_event_hash == compute_event_hash(encode_record(recs[1]))

    def test_get_events_range(self, store):
        store.init_origin_key("bbs.a", ORIGIN_A_PUB)
        for i in range(5):
            intent = _make_article_intent("bbs.a", _random_id(i + 1), _random_id(i + 10))
            store.append_record(ORIGIN_A, intent, _sign_intent(intent), b"test body")
        events = store.get_events_range("bbs.a", 3, 2)
        assert len(events) == 2
        assert events[0].origin_seq == 3
        assert events[1].origin_seq == 4


# ---------------------------------------------------------------------------
# Head management
# ---------------------------------------------------------------------------


class TestHeadManagement:
    def test_empty_head(self, store):
        head = store.get_or_create_empty_head("bbs.a", ORIGIN_A)
        assert head.latest_origin_seq == 0
        assert head.latest_event_hash == ZERO_HASH
        assert head.event_count == 0
        assert head.origin_pubkey == ORIGIN_A_PUB

    def test_head_after_publication(self, store):
        store.init_origin_key("bbs.a", ORIGIN_A_PUB)
        head = store.get_or_create_empty_head("bbs.a", ORIGIN_A)
        assert head.latest_origin_seq == 0

        intent = _make_article_intent("bbs.a", _random_id(1), _random_id(2))
        rec = store.append_record(ORIGIN_A, intent, _sign_intent(intent), b"test body")
        head = store.get_head("bbs.a")
        assert head.latest_origin_seq == 1
        assert head.latest_event_hash == compute_event_hash(encode_record(rec))
        assert head.event_count == 1

    def test_head_signature_verifies(self, store):
        store.init_origin_key("bbs.a", ORIGIN_A_PUB)
        intent = _make_article_intent("bbs.a", _random_id(1), _random_id(2))
        store.append_record(ORIGIN_A, intent, _sign_intent(intent), b"test body")
        head = store.get_head("bbs.a")
        unsigned = encode_unsigned_head(head)
        assert verify_head_signature(ORIGIN_A_PUB, unsigned, head.origin_signature)


# ---------------------------------------------------------------------------
# Key epoch management
# ---------------------------------------------------------------------------


class TestKeyEpochs:
    def test_init_and_get_current_key(self, store):
        store.init_origin_key("bbs.a", ORIGIN_A_PUB)
        assert store.get_current_key("bbs.a") == ORIGIN_A_PUB

    def test_get_key_for_seq_before_rotation(self, store):
        store.init_origin_key("bbs.a", ORIGIN_A_PUB)
        assert store.get_key_for_seq("bbs.a", 1) == ORIGIN_A_PUB
        assert store.get_key_for_seq("bbs.a", 100) == ORIGIN_A_PUB

    def test_key_rotation(self, store):
        store.init_origin_key("bbs.a", ORIGIN_A_PUB)
        for i in range(3):
            intent = _make_article_intent("bbs.a", _random_id(i + 1), _random_id(i + 10))
            store.append_record(ORIGIN_A, intent, _sign_intent(intent), b"test body")

        from bonnet.core.record import sign_key_rotation_proof

        proof = sign_key_rotation_proof(NEW_ORIGIN, "bbs.a", ORIGIN_A_PUB, NEW_ORIGIN_PUB)

        rot_intent = Intent(
            event_id=_random_id(42),
            kind=KIND_ORIGIN_KEY_ROTATE,
            origin="bbs.a",
            actor_pubkey=ORIGIN_A_PUB,
            metadata=MetadataMap(
                [
                    metadata_bytes(1, NEW_ORIGIN_PUB),
                    metadata_bytes(2, proof),
                ]
            ),
        )
        rec = store.append_record(ORIGIN_A, rot_intent, _sign_intent(rot_intent, ORIGIN_A), b"")
        rot_seq = rec.origin_seq

        assert store.get_key_for_seq("bbs.a", rot_seq) == ORIGIN_A_PUB
        assert store.get_key_for_seq("bbs.a", rot_seq + 1) == NEW_ORIGIN_PUB
        assert store.get_current_key("bbs.a") == NEW_ORIGIN_PUB

    def test_init_origin_key_idempotent(self, store):
        store.init_origin_key("bbs.a", ORIGIN_A_PUB)
        store.init_origin_key("bbs.a", ORIGIN_B_PUB)
        assert store.get_current_key("bbs.a") == ORIGIN_A_PUB


# ---------------------------------------------------------------------------
# Remote range acceptance
# ---------------------------------------------------------------------------


class TestRemoteAcceptance:
    def test_accept_full_range(self, store):
        store.init_origin_key("bbs.b", ORIGIN_B_PUB)
        records, final_hash = _make_remote_records("bbs.b", ORIGIN_B, 3)
        head = _make_head("bbs.b", 3, final_hash, ORIGIN_B)
        result = store.accept_remote_range(
            "bbs.b", records, head, ORIGIN_B_PUB, source="relay.test"
        )
        assert result.accepted
        assert result.accepted_count == 3
        assert len(result.conflicts) == 0
        assert store.get_highest_seq("bbs.b") == 3

    def test_accept_idempotent_range(self, store):
        store.init_origin_key("bbs.b", ORIGIN_B_PUB)
        records, final_hash = _make_remote_records("bbs.b", ORIGIN_B, 3)
        head = _make_head("bbs.b", 3, final_hash, ORIGIN_B)
        store.accept_remote_range("bbs.b", records, head, ORIGIN_B_PUB)
        result2 = store.accept_remote_range("bbs.b", records, head, ORIGIN_B_PUB)
        assert result2.accepted
        assert result2.idempotent

    def test_reject_rollback(self, store):
        store.init_origin_key("bbs.b", ORIGIN_B_PUB)
        records, final_hash = _make_remote_records("bbs.b", ORIGIN_B, 3)
        head = _make_head("bbs.b", 3, final_hash, ORIGIN_B)
        store.accept_remote_range("bbs.b", records, head, ORIGIN_B_PUB)
        records2, final_hash2 = _make_remote_records("bbs.b", ORIGIN_B, 2)
        head2 = _make_head("bbs.b", 2, final_hash2, ORIGIN_B)
        result = store.accept_remote_range("bbs.b", records2, head2, ORIGIN_B_PUB)
        assert not result.accepted
        assert "rollback" in result.reason.lower()

    def test_reject_chain_break(self, store):
        store.init_origin_key("bbs.b", ORIGIN_B_PUB)
        records, final_hash = _make_remote_records("bbs.b", ORIGIN_B, 3)
        tampered = list(records)
        tampered[1] = Record(
            origin=tampered[1].origin,
            origin_seq=tampered[1].origin_seq,
            previous_event_hash=b"\xff" * 32,
            event_id=tampered[1].event_id,
            kind=tampered[1].kind,
            actor_pubkey=tampered[1].actor_pubkey,
            board=tampered[1].board,
            article_id=tampered[1].article_id,
            article_num=tampered[1].article_num,
            metadata=tampered[1].metadata,
            body_hash=tampered[1].body_hash,
            body_size=tampered[1].body_size,
            actor_signature=tampered[1].actor_signature,
            origin_signature=tampered[1].origin_signature,
        )
        head = _make_head("bbs.b", 3, final_hash, ORIGIN_B)
        with pytest.raises(ChainBreak):
            store.accept_remote_range("bbs.b", tampered, head, ORIGIN_B_PUB)

    def test_reject_bad_origin_signature(self, store):
        store.init_origin_key("bbs.b", ORIGIN_B_PUB)
        records, final_hash = _make_remote_records("bbs.b", ORIGIN_B, 1)
        bad_rec = Record(
            origin=records[0].origin,
            origin_seq=records[0].origin_seq,
            previous_event_hash=records[0].previous_event_hash,
            event_id=records[0].event_id,
            kind=records[0].kind,
            actor_pubkey=records[0].actor_pubkey,
            board=records[0].board,
            article_id=records[0].article_id,
            article_num=records[0].article_num,
            metadata=records[0].metadata,
            body_hash=records[0].body_hash,
            body_size=records[0].body_size,
            actor_signature=records[0].actor_signature,
            origin_signature=b"\x00" * 64,
        )
        head = _make_head("bbs.b", 1, compute_event_hash(encode_record(records[0])), ORIGIN_B)
        with pytest.raises(SignatureInvalid):
            store.accept_remote_range("bbs.b", [bad_rec], head, ORIGIN_B_PUB)

    def test_reject_event_id_collision(self, store):
        store.init_origin_key("bbs.b", ORIGIN_B_PUB)
        records1, final_hash1 = _make_remote_records("bbs.b", ORIGIN_B, 2)
        head1 = _make_head("bbs.b", 2, final_hash1, ORIGIN_B)
        store.accept_remote_range("bbs.b", records1, head1, ORIGIN_B_PUB)

        records2, final_hash2 = _make_remote_records("bbs.b", ORIGIN_B, 3)
        records2[2] = Record(
            origin=records2[2].origin,
            origin_seq=records2[2].origin_seq,
            previous_event_hash=records2[2].previous_event_hash,
            event_id=records1[0].event_id,
            kind=records2[2].kind,
            actor_pubkey=records2[2].actor_pubkey,
            board=records2[2].board,
            article_id=records2[2].article_id,
            article_num=records2[2].article_num,
            metadata=records2[2].metadata,
            body_hash=records2[2].body_hash,
            body_size=records2[2].body_size,
            actor_signature=records2[2].actor_signature,
            origin_signature=records2[2].origin_signature,
        )
        head2 = _make_head("bbs.b", 3, final_hash2, ORIGIN_B)
        with pytest.raises(EventIdCollision):
            store.accept_remote_range("bbs.b", records2, head2, ORIGIN_B_PUB)

    def test_head_event_count_mismatch(self, store):
        store.init_origin_key("bbs.b", ORIGIN_B_PUB)
        records, final_hash = _make_remote_records("bbs.b", ORIGIN_B, 3)
        bad_head = Head(
            origin="bbs.b",
            latest_origin_seq=3,
            latest_event_hash=final_hash,
            event_count=99,
            origin_pubkey=ORIGIN_B_PUB,
        )
        unsigned = encode_unsigned_head(bad_head)
        bad_head.origin_signature = sign_head(ORIGIN_B, unsigned)
        with pytest.raises(HeadMismatch):
            store.accept_remote_range("bbs.b", records, bad_head, ORIGIN_B_PUB)


# ---------------------------------------------------------------------------
# Equivocation / conflict storage
# ---------------------------------------------------------------------------


class TestEquivocation:
    def test_conflict_stored(self, store):
        store.init_origin_key("bbs.b", ORIGIN_B_PUB)
        records1, final_hash1 = _make_remote_records("bbs.b", ORIGIN_B, 1)
        head1 = _make_head("bbs.b", 1, final_hash1, ORIGIN_B)
        store.accept_remote_range("bbs.b", records1, head1, ORIGIN_B_PUB)

        fake_identity = Identity.generate()
        records2, _ = _make_remote_records("bbs.b", fake_identity, 1)
        head2 = _make_head(
            "bbs.b", 1, compute_event_hash(encode_record(records2[0])), fake_identity
        )

        _result = store.accept_remote_range(
            "bbs.b", records2, head2, fake_identity.public_key, source="evil.test"
        )
        conflicts = store.get_conflicts("bbs.b")
        assert len(conflicts) >= 1
        assert conflicts[0]["origin_seq"] == 1
        assert "equivocation" in conflicts[0]["reason"].lower()


# ---------------------------------------------------------------------------
# Witness storage
# ---------------------------------------------------------------------------


class TestWitnessStorage:
    def test_store_and_retrieve_witness(self, store):
        eid = _random_id(1)
        ehash = _random_id(2)
        w = Witness(
            event_origin="bbs.a",
            event_id=eid,
            event_hash=ehash,
            relay_pubkey=RELAY_PUB,
            relay_hostname="relay.test",
            received_from_pubkey=ORIGIN_A_PUB,
            received_from_hostname="bbs.a",
            seen_at=1700000000,
        )
        w.relay_signature = sign_witness(RELAY, encode_unsigned_witness(w))
        store.store_witness(w)

        retrieved = store.get_witness("bbs.a", eid, RELAY_PUB)
        assert retrieved is not None
        assert retrieved.relay_hostname == "relay.test"
        assert retrieved.received_from_pubkey == ORIGIN_A_PUB
        assert retrieved.seen_at == 1700000000

    def test_witness_not_found(self, store):
        assert store.get_witness("bbs.a", _random_id(1), RELAY_PUB) is None


# ---------------------------------------------------------------------------
# Projection checkpoint
# ---------------------------------------------------------------------------


class TestProjectionCheckpoint:
    def test_default_checkpoint_zero(self, store):
        assert store.get_checkpoint("bbs.a") == 0

    def test_set_and_get_checkpoint(self, store):
        store.set_checkpoint("bbs.a", 42)
        assert store.get_checkpoint("bbs.a") == 42


# ---------------------------------------------------------------------------
# Multi-origin independence
# ---------------------------------------------------------------------------


class TestMultiOrigin:
    def test_two_origins_independent_chains(self, store):
        store.init_origin_key("bbs.a", ORIGIN_A_PUB)
        store.init_origin_key("bbs.b", ORIGIN_B_PUB)

        intent_a = _make_article_intent("bbs.a", _random_id(1), _random_id(2))
        store.append_record(ORIGIN_A, intent_a, _sign_intent(intent_a), b"test body")

        intent_b = _make_article_intent("bbs.b", _random_id(3), _random_id(4))
        store.append_record(ORIGIN_B, intent_b, _sign_intent(intent_b), b"test body")

        assert store.get_highest_seq("bbs.a") == 1
        assert store.get_highest_seq("bbs.b") == 1

        intent_a2 = _make_article_intent("bbs.a", _random_id(5), _random_id(6))
        rec_a2 = store.append_record(ORIGIN_A, intent_a2, _sign_intent(intent_a2), b"test body")
        assert rec_a2.origin_seq == 2
        assert store.get_highest_seq("bbs.b") == 1


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


class TestConcurrency:
    def test_concurrent_appends_no_sequence_gaps(self, store, tmp_path):
        store.init_origin_key("bbs.a", ORIGIN_A_PUB)
        num_threads = 4
        per_thread = 5
        errors = []

        def worker(tid):
            try:
                for i in range(per_thread):
                    eid = _random_id(tid * 100 + i + 1)
                    aid = _random_id(tid * 100 + i + 50)
                    intent = _make_article_intent("bbs.a", eid, aid)
                    sig = _sign_intent(intent)
                    store.append_record(ORIGIN_A, intent, sig, b"test body")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        expected_total = num_threads * per_thread
        assert store.get_highest_seq("bbs.a") == expected_total

        seqs = [r.origin_seq for r in store.get_events_range("bbs.a", 1, expected_total + 1)]
        assert seqs == list(range(1, expected_total + 1))
