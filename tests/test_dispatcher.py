"""Dispatcher regression tests: checkpoint failure, multi-origin rebuild,
unknown-kind handling, and projection checkpoint invariants.

Tests marked xfail document bugs scheduled for Phase 2 fixes.
"""

import pytest

from core.board_projection import BoardProjection
from core.bodies import BodyStore
from core.crypto import Identity
from core.dispatcher import Dispatcher
from core.firehose import KIND_ARTICLE, FirehoseStore
from core.global_projections import (
    NavProjection,
    PolicyProjection,
    UserProjection,
)
from core.record import (
    Intent,
    MetadataMap,
    compute_body_hash,
    encode_intent,
    metadata_bytes,
    metadata_text,
    sign_intent,
)

ORIGIN_A = Identity.from_private_key(bytes(range(1, 33)))
ORIGIN_B = Identity.from_private_key(bytes(range(33, 65)))
ACTOR = Identity.from_private_key(bytes(range(10, 42)))
ORIGIN_A_PUB = ORIGIN_A.public_key
ORIGIN_B_PUB = ORIGIN_B.public_key
ACTOR_PUB = ACTOR.public_key


def _rid(seed: int) -> bytes:
    return bytes([(seed + i) % 256 for i in range(32)])


def _make_article_intent(origin, eid, board="general", body=b"hello", aid_seed=99):
    return Intent(
        event_id=eid, kind=KIND_ARTICLE, origin=origin,
        actor_pubkey=ACTOR_PUB, board=board, article_id=_rid(aid_seed),
        metadata=MetadataMap([
            metadata_text(1, "Test"),
            metadata_text(4, "text/plain"),
        ]),
        body_hash=compute_body_hash(body), body_size=len(body),
    )


def _make_board_create_intent(origin, eid, board, owner_pubkey):
    return Intent(
        event_id=eid, kind="bonnet.board.create", origin=origin,
        actor_pubkey=ACTOR_PUB, board=board,
        metadata=MetadataMap([
            metadata_bytes(1, owner_pubkey),
            metadata_text(2, "Test Board"),
        ]),
    )


def _make_unknown_intent(origin, eid, kind="bonnet.custom.event"):
    return Intent(
        event_id=eid, kind=kind, origin=origin,
        actor_pubkey=ACTOR_PUB, board="",
    )


def _append(firehose, origin_identity, intent, body=b""):
    sig = sign_intent(ACTOR, encode_intent(intent))
    return firehose.append_record(origin_identity, intent, sig, body)


@pytest.fixture
def stack(tmp_path):
    firehose = FirehoseStore(str(tmp_path / "events.db"))
    firehose.init_origin_key("bbs.a", ORIGIN_A_PUB)
    firehose.init_origin_key("bbs.b", ORIGIN_B_PUB)

    nav = NavProjection(str(tmp_path / "nav.db"))
    users = UserProjection(str(tmp_path / "users.db"))
    policy = PolicyProjection(str(tmp_path / "policy.db"))
    bs = BodyStore(
        boards_dir=str(tmp_path / "boards"),
        events_dir=str(tmp_path / "event_bodies"),
    )
    d = Dispatcher(
        firehose=firehose, nav=nav, users=users, policy=policy,
        boards_dir=str(tmp_path / "boards"), body_store=bs,
    )
    yield d, firehose, nav, users, policy, bs
    d.close()
    nav.close()
    users.close()
    policy.close()
    firehose.close()


# ---------------------------------------------------------------------------
# Checkpoint advancement on failure
# ---------------------------------------------------------------------------

def test_checkpoint_stays_before_failed_record(stack):
    """When a projection raises, the checkpoint must not advance past it."""
    d, firehose, nav, users, policy, bs = stack

    for i in range(3):
        intent = _make_article_intent("bbs.a", _rid(i + 1), aid_seed=i + 10)
        body = f"body{i}".encode()
        intent.body_hash = compute_body_hash(body)
        intent.body_size = len(body)
        bs.stage_article_body("bbs.a", "general", intent.event_id, body,
                              intent.body_hash, intent.body_size)
        _append(firehose, ORIGIN_A, intent, body)

    original_apply = BoardProjection.apply_article
    call_count = [0]

    def failing_apply(self, rec):
        call_count[0] += 1
        if call_count[0] == 2:
            raise RuntimeError("simulated projection failure")
        original_apply(self, rec)

    BoardProjection.apply_article = failing_apply
    try:
        d.dispatch_origin("bbs.a")
    finally:
        BoardProjection.apply_article = original_apply

    checkpoint = firehose.get_checkpoint("bbs.a")
    assert checkpoint == 1, f"checkpoint should be 1 (before failed record 2), got {checkpoint}"


def test_later_records_not_dispatched_after_failure(stack):
    """Records after a failed projection must not be dispatched."""
    d, firehose, nav, users, policy, bs = stack

    for i in range(3):
        intent = _make_article_intent("bbs.a", _rid(i + 1), aid_seed=i + 10)
        body = f"body{i}".encode()
        intent.body_hash = compute_body_hash(body)
        intent.body_size = len(body)
        bs.stage_article_body("bbs.a", "general", intent.event_id, body,
                              intent.body_hash, intent.body_size)
        _append(firehose, ORIGIN_A, intent, body)

    original_apply = BoardProjection.apply_article
    call_count = [0]

    def failing_apply(self, rec):
        call_count[0] += 1
        if call_count[0] == 2:
            raise RuntimeError("simulated projection failure")
        original_apply(self, rec)

    BoardProjection.apply_article = failing_apply
    try:
        d.dispatch_origin("bbs.a")
    finally:
        BoardProjection.apply_article = original_apply

    assert call_count[0] == 2, f"should have processed only 2 records (1 success + 1 fail), got {call_count[0]}"


def test_retry_after_fault_removed(stack):
    """After the fault is cleared, retrying dispatch should apply the failed record."""
    d, firehose, nav, users, policy, bs = stack

    for i in range(3):
        intent = _make_article_intent("bbs.a", _rid(i + 1), aid_seed=i + 10)
        body = f"body{i}".encode()
        intent.body_hash = compute_body_hash(body)
        intent.body_size = len(body)
        bs.stage_article_body("bbs.a", "general", intent.event_id, body,
                              intent.body_hash, intent.body_size)
        _append(firehose, ORIGIN_A, intent, body)

    original_apply = BoardProjection.apply_article
    call_count = [0]

    def failing_apply(self, rec):
        call_count[0] += 1
        if call_count[0] == 2:
            raise RuntimeError("simulated projection failure")
        original_apply(self, rec)

    BoardProjection.apply_article = failing_apply
    try:
        d.dispatch_origin("bbs.a")
    finally:
        BoardProjection.apply_article = original_apply

    call_count[0] = 0
    count = d.dispatch_origin("bbs.a")
    assert count >= 2, f"retry should dispatch remaining records, got {count}"

    bp = d._get_board_projection("bbs.a", "general")
    assert bp.article_count("bbs.a", "general") == 3


# ---------------------------------------------------------------------------
# Multi-origin rebuild isolation
# ---------------------------------------------------------------------------

def test_rebuild_preserves_other_origins(stack):
    """Rebuilding one origin must not clear projections for another origin."""
    d, firehose, nav, users, policy, bs = stack

    for origin, ident, board in [("bbs.a", ORIGIN_A, "alpha"), ("bbs.b", ORIGIN_B, "beta")]:
        intent = _make_board_create_intent(origin, _rid(ord(origin[-1])), board, ident.public_key)
        _append(firehose, ident, intent)

    d.dispatch_origin("bbs.a")
    d.dispatch_origin("bbs.b")

    boards_a_before = nav.list_boards("bbs.a")
    boards_b_before = nav.list_boards("bbs.b")
    assert len(boards_a_before) == 1
    assert len(boards_b_before) == 1

    d.rebuild_all("bbs.a")

    boards_a_after = nav.list_boards("bbs.a")
    boards_b_after = nav.list_boards("bbs.b")
    assert len(boards_a_after) == 1, "origin A boards should survive rebuild"
    assert len(boards_b_after) == 1, "origin B boards must not be cleared by rebuilding origin A"


# ---------------------------------------------------------------------------
# Dispatch idempotency
# ---------------------------------------------------------------------------

def test_dispatch_idempotent(stack):
    """Dispatching the same origin twice does not duplicate state."""
    d, firehose, nav, users, policy, bs = stack

    intent = _make_article_intent("bbs.a", _rid(1), body=b"idempotent")
    bs.stage_article_body("bbs.a", "general", intent.event_id, b"idempotent",
                          intent.body_hash, intent.body_size)
    _append(firehose, ORIGIN_A, intent, b"idempotent")

    count1 = d.dispatch_origin("bbs.a")
    count2 = d.dispatch_origin("bbs.a")
    assert count1 == 1
    assert count2 == 0

    bp = d._get_board_projection("bbs.a", "general")
    assert bp.article_count("bbs.a", "general") == 1


# ---------------------------------------------------------------------------
# Unknown-kind handling
# ---------------------------------------------------------------------------

def test_unknown_boardless_record_dispatched(stack):
    """Unknown boardless records should be tracked for idempotency without crashing."""
    d, firehose, nav, users, policy, bs = stack

    intent = _make_unknown_intent("bbs.a", _rid(1))
    _append(firehose, ORIGIN_A, intent)

    count = d.dispatch_origin("bbs.a")
    assert count == 1, "unknown boardless record should be dispatched without error"

    count2 = d.dispatch_origin("bbs.a")
    assert count2 == 0, "second dispatch should skip already-applied record"


def test_unknown_boarded_record_dispatched(stack):
    """Unknown boarded records should be tracked in the board projection."""
    d, firehose, nav, users, policy, bs = stack

    intent = Intent(
        event_id=_rid(1), kind="bonnet.custom.event", origin="bbs.a",
        actor_pubkey=ACTOR_PUB, board="general",
    )
    _append(firehose, ORIGIN_A, intent)

    count = d.dispatch_origin("bbs.a")
    assert count == 1

    count2 = d.dispatch_origin("bbs.a")
    assert count2 == 0


# ---------------------------------------------------------------------------
# Rebuild after crash
# ---------------------------------------------------------------------------

def test_rebuild_restores_state(stack):
    """Rebuild clears projections and replays all records from the firehose."""
    d, firehose, nav, users, policy, bs = stack

    for i in range(3):
        intent = _make_article_intent("bbs.a", _rid(i + 1), body=f"body{i}".encode(), aid_seed=i + 10)
        body = f"body{i}".encode()
        intent.body_hash = compute_body_hash(body)
        intent.body_size = len(body)
        bs.stage_article_body("bbs.a", "general", intent.event_id, body,
                              intent.body_hash, intent.body_size)
        _append(firehose, ORIGIN_A, intent, body)

    d.dispatch_origin("bbs.a")
    bp = d._get_board_projection("bbs.a", "general")
    assert bp.article_count("bbs.a", "general") == 3

    count = d.rebuild_all("bbs.a")
    assert count == 3

    bp2 = d._get_board_projection("bbs.a", "general")
    assert bp2.article_count("bbs.a", "general") == 3


def test_rebuild_is_idempotent(stack):
    """Rebuilding twice produces the same state."""
    d, firehose, nav, users, policy, bs = stack

    intent = _make_article_intent("bbs.a", _rid(1), body=b"rebuild me")
    body = b"rebuild me"
    intent.body_hash = compute_body_hash(body)
    intent.body_size = len(body)
    bs.stage_article_body("bbs.a", "general", intent.event_id, body,
                          intent.body_hash, intent.body_size)
    _append(firehose, ORIGIN_A, intent, body)

    d.dispatch_origin("bbs.a")

    count1 = d.rebuild_all("bbs.a")
    count2 = d.rebuild_all("bbs.a")
    assert count1 == 1
    assert count2 == 1

    bp = d._get_board_projection("bbs.a", "general")
    assert bp.article_count("bbs.a", "general") == 1
