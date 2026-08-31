"""Which ACL dimension gates each read opcode.

`handle()` checks only the *command* dimension; the board is not known at
that point. The board dimension is enforced per handler by
`_board_read_allowed`, and the substrate opcodes — EVENT_GET, EVENT_RANGE,
EVENT_BODY — do not call it.

These tests pin down exactly what that reaches, so the answer is a fact in
the suite rather than a claim in a document. They are not bug reports: see
the module-level note in `firehose_commands.py` on why the substrate cannot
be board-filtered.
"""

import struct

from bonnet.core.acl import ACLRule, PrincipalMatcher
from bonnet.core.record import (
    Intent,
    MetadataMap,
    compute_body_hash,
    decode_record,
    metadata_bytes,
    metadata_text,
)
from bonnet.net.firehose_wire import (
    OP_ARTICLE_BODY,
    OP_ARTICLE_GET,
    OP_EVENT_BODY,
    OP_EVENT_GET,
    OP_EVENT_RANGE,
    OP_PERMISSIONS,
    _enc_text16,
    _read_text16,
    _read_u16,
)
from tests.test_commands_and_sync import (  # noqa: F401
    ACTOR,
    ACTOR_PUB,
    _publish_request,
    _rid,
    _user_ctx,
    firehose,
    stack,
)

SECRET = "secret"
SUBJECT = "Board-scoped subject"
BODY = b"board-scoped body bytes"
REPORT_REASON = b"why this article is bad"


def _deny_reads_on_secret(stack):  # noqa: F811
    """Everything else stays granted; only the board dimension is withdrawn."""
    stack["acl"].add_rule(
        ACLRule(
            effect="deny",
            matcher=PrincipalMatcher(wildcard=True),
            actions=["read"],
            boards=[SECRET],
        )
    )


def _publish_article(stack):  # noqa: F811
    intent = Intent(
        event_id=_rid(1),
        kind="bonnet.article",
        origin="bbs.test",
        actor_pubkey=ACTOR_PUB,
        board=SECRET,
        article_id=_rid(2),
        metadata=MetadataMap([metadata_text(1, SUBJECT), metadata_text(4, "text/plain")]),
        body_hash=compute_body_hash(BODY),
        body_size=len(BODY),
    )
    resp = stack["handler"].handle(_publish_request(intent, ACTOR, BODY), _user_ctx(ACTOR))
    assert resp[0] == 0x00, resp
    return intent


def _publish_report(stack):  # noqa: F811
    """A non-article kind carrying a board. Its body lands in the event store."""
    intent = Intent(
        event_id=_rid(3),
        kind="bonnet.report",
        origin="bbs.test",
        actor_pubkey=ACTOR_PUB,
        board=SECRET,
        target_origin="bbs.test",
        target_event_id=_rid(1),
        metadata=MetadataMap([metadata_bytes(1, ACTOR_PUB)]),
        body_hash=compute_body_hash(REPORT_REASON),
        body_size=len(REPORT_REASON),
    )
    resp = stack["handler"].handle(
        _publish_request(intent, ACTOR, REPORT_REASON), _user_ctx(ACTOR)
    )
    assert resp[0] == 0x00, resp
    return intent


# ---------------------------------------------------------------------------
# The application opcodes honour the board dimension.
# ---------------------------------------------------------------------------


def test_article_get_is_refused_on_a_barred_board(stack):  # noqa: F811
    _publish_article(stack)
    _deny_reads_on_secret(stack)

    req = bytes([OP_ARTICLE_GET]) + _enc_text16("bbs.test") + _enc_text16(SECRET)
    req += struct.pack(">Q", 1)
    resp = stack["handler"].handle(req, _user_ctx(ACTOR))
    assert resp[0] == 0x01


def test_article_body_is_refused_on_a_barred_board(stack):  # noqa: F811
    _publish_article(stack)
    _deny_reads_on_secret(stack)

    req = bytes([OP_ARTICLE_BODY]) + _enc_text16("bbs.test") + _enc_text16(SECRET)
    req += struct.pack(">Q", 1)
    resp = stack["handler"].handle(req, _user_ctx(ACTOR))
    assert resp[0] == 0x01


# ---------------------------------------------------------------------------
# The substrate opcodes do not. This is the documented gap.
# ---------------------------------------------------------------------------


def test_event_get_returns_the_barred_boards_record_metadata(stack):  # noqa: F811
    """Everything about the article except its body bytes."""
    intent = _publish_article(stack)
    _deny_reads_on_secret(stack)

    req = bytes([OP_EVENT_GET]) + _enc_text16("bbs.test") + intent.event_id
    resp = stack["handler"].handle(req, _user_ctx(ACTOR))
    assert resp[0] == 0x00

    rec_len = struct.unpack(">I", resp[1:5])[0]
    rec = decode_record(resp[5 : 5 + rec_len])
    assert rec.board == SECRET
    assert rec.metadata.get_text(1) == SUBJECT
    assert rec.actor_pubkey == ACTOR_PUB
    assert rec.body_hash == compute_body_hash(BODY)
    assert rec.body_size == len(BODY)


def test_event_range_walks_the_barred_board(stack):  # noqa: F811
    _publish_article(stack)
    _deny_reads_on_secret(stack)

    req = bytes([OP_EVENT_RANGE]) + _enc_text16("bbs.test")
    req += struct.pack(">Q", 1) + struct.pack(">H", 100) + struct.pack(">I", 0)
    resp = stack["handler"].handle(req, _user_ctx(ACTOR))
    assert resp[0] == 0x00

    count = struct.unpack(">H", resp[1:3])[0]
    assert count >= 1
    rec_len = struct.unpack(">I", resp[3:7])[0]
    rec = decode_record(resp[7 : 7 + rec_len])
    assert rec.board == SECRET
    assert rec.metadata.get_text(1) == SUBJECT


def test_event_body_returns_non_article_bodies_on_a_barred_board(stack):  # noqa: F811
    """Report and punishment reasons are event bodies, and are reachable."""
    _publish_article(stack)
    report = _publish_report(stack)
    _deny_reads_on_secret(stack)

    req = bytes([OP_EVENT_BODY]) + _enc_text16("bbs.test") + report.event_id
    resp = stack["handler"].handle(req, _user_ctx(ACTOR))
    assert resp[0] == 0x00
    body_len = struct.unpack(">I", resp[1:5])[0]
    assert resp[5 : 5 + body_len] == REPORT_REASON


def test_event_body_does_not_reach_article_bodies(stack):  # noqa: F811
    """The one thing the substrate cannot reach.

    Article bodies are staged into the per-board store by
    `stage_article_body`; only non-article kinds go through
    `write_event_body`. So EVENT_BODY has nothing to hand back for an
    article, barred board or not, and ARTICLE_BODY's board check is the
    only door to those bytes.
    """
    intent = _publish_article(stack)

    req = bytes([OP_EVENT_BODY]) + _enc_text16("bbs.test") + intent.event_id
    resp = stack["handler"].handle(req, _user_ctx(ACTOR))
    assert resp[0] == 0x01


# ---------------------------------------------------------------------------
# PERMISSIONS promises, in its own docstring, that its answer "cannot drift
# from what a real request would get". For the substrate opcodes under a
# board-scoped deny, it does.
# ---------------------------------------------------------------------------


def _permissions(stack, board):  # noqa: F811
    resp = stack["handler"].handle(
        bytes([OP_PERMISSIONS]) + _enc_text16(board), _user_ctx(ACTOR)
    )
    assert resp[0] == 0x00
    payload = resp[1:]
    offset = 0
    for _ in range(3):  # principal, role, board
        _, offset = _read_text16(payload, offset)
    count, offset = _read_u16(payload, offset)
    names = []
    for _ in range(count):
        name, offset = _read_text16(payload, offset)
        names.append(name)
    return names


def test_permissions_matches_enforcement_for_both_opcode_classes(stack):  # noqa: F811
    """The introspection answer and the enforced answer must agree.

    PERMISSIONS used to scope *every* command check to the requested board,
    so a board-scoped deny dropped EVENT_GET from the reported list while a
    real EVENT_GET still succeeded — `handle()` gates it without a board and
    no handler re-checks. It now scopes only BOARD_SCOPED_OPS, so the list
    says what the relay will actually do.
    """
    intent = _publish_article(stack)
    _deny_reads_on_secret(stack)

    reported = _permissions(stack, SECRET)

    # Board-scoped: reported denied, and denied.
    assert "ARTICLE_GET" not in reported
    req = bytes([OP_ARTICLE_GET]) + _enc_text16("bbs.test") + _enc_text16(SECRET)
    req += struct.pack(">Q", 1)
    assert stack["handler"].handle(req, _user_ctx(ACTOR))[0] == 0x01

    # Board-agnostic: reported permitted, and permitted. The substrate is
    # not board-restrictable and the answer no longer pretends otherwise.
    assert "EVENT_GET" in reported
    req = bytes([OP_EVENT_GET]) + _enc_text16("bbs.test") + intent.event_id
    assert stack["handler"].handle(req, _user_ctx(ACTOR))[0] == 0x00


def test_permissions_still_scopes_the_board_dimension_where_it_applies(stack):  # noqa: F811
    """The unscoped substrate must not leak into the board-scoped answers."""
    _publish_article(stack)
    _deny_reads_on_secret(stack)

    barred = _permissions(stack, SECRET)
    open_board = _permissions(stack, "general")

    for name in ("ARTICLE_GET", "ARTICLE_LIST", "ARTICLE_BODY", "BOARD_LIST"):
        assert name not in barred, name
        assert name in open_board, name
