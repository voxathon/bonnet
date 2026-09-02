"""One origin, spelled several ways.

Hostnames are case-insensitive and a trailing dot is the same name, so
`bbs.example`, `BBS.Example` and `bbs.example.` are one origin. Config has
normalized its own strings since it was written; the wire did not, so a caller
asking for the wrong spelling looked up a key nothing was stored under and got
an empty answer rather than an error.

The boundary matters more than the normalization. A record's origin is inside
the bytes its signatures cover, so it is normalized *nowhere* on that path —
only request arguments, which are lookup keys.
"""

import struct

import pytest

from bonnet.core.record import (
    Record,
    encode_record,
    encode_unsigned_record,
    normalize_origin,
)
from bonnet.net.firehose_wire import OP_BOARD_LIST, _enc_text16
from tests.test_commands_and_sync import _anon_ctx, firehose, stack  # noqa: F401


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("bbs.example", "bbs.example"),
        ("BBS.Example", "bbs.example"),
        ("bbs.example.", "bbs.example"),
        ("  BBS.EXAMPLE.  ", "bbs.example"),
        ("", ""),
    ],
)
def test_spellings_collapse_to_one_name(raw, expected):
    assert normalize_origin(raw) == expected


def test_a_read_finds_the_origin_however_it_is_spelled(stack):  # noqa: F811
    """The symptom this fixes: an empty result that looks like 'no such board'
    but is really 'no such spelling'."""
    stack["nav"].apply_board_create(
        Record(
            origin="bbs.test",
            origin_seq=1,
            event_id=b"\x01" * 32,
            kind="bonnet.board.create",
            actor_pubkey=b"\x02" * 32,
            board="general",
            created_at=1,
        )
    )

    def board_list(origin):
        req = struct.pack(">B", OP_BOARD_LIST) + _enc_text16(origin)
        resp = stack["handler"].handle(req, _anon_ctx())
        assert resp[0] == 0
        return struct.unpack(">H", resp[1:3])[0]

    canonical = board_list("bbs.test")
    assert canonical == 1
    assert board_list("BBS.Test") == canonical
    assert board_list("bbs.test.") == canonical


def test_a_record_s_origin_is_never_normalized():
    """The line that must not be crossed. The origin is inside the signed
    bytes, so 'canonical' is whatever the publisher signed — rewriting it on
    decode would change what re-encoding produces and break every signature
    over the record."""
    rec = Record(
        origin="BBS.Example.",
        origin_seq=1,
        event_id=b"\x01" * 32,
        kind="bonnet.article",
        actor_pubkey=b"\x02" * 32,
        board="general",
        created_at=1,
    )

    round_tripped = encode_record(rec)
    assert b"BBS.Example." in round_tripped
    # and the bytes a signature is computed over are unchanged
    assert b"BBS.Example." in encode_unsigned_record(rec)
