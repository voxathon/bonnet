"""Truncation and malformed-frame handling in the client wire codec.

`firehose_wire` parses bytes from a remote origin: the client library reads
responses from whatever server it dialled, and the server's own federation
sync (`net/firehose_sync.py`) reads responses from peer relays. Every parser
here must reject a short or over-long frame with `ProtocolError` rather than
returning silently short data or raising a struct/index/unicode error that no
caller catches.
"""

import struct

import pytest

from tests.test_commands_and_sync import _anon_ctx, firehose, stack  # noqa: F401

from bonnet.net.firehose_wire import (
    OP_ARTICLE_QUERY,
    OP_BAN_STATUS,
    OP_EVENT_GET,
    OP_EVENT_HEAD,
    OP_REPORT_LIST,
    OP_USER_GET,
    ProtocolError,
    parse_ban_status_response,
    parse_board_list_response,
    parse_event_body_response,
    parse_event_get_response,
    parse_event_head_response_raw,
    parse_event_range_response,
    parse_key_epochs_response,
    parse_report_list_response,
    parse_response,
    parse_user_list_response,
)


def _ok(payload: bytes) -> bytes:
    """A success frame carrying `payload`."""
    return b"\x00" + payload


# ---------------------------------------------------------------------------
# parse_response
# ---------------------------------------------------------------------------


def test_error_frame_with_only_a_code_is_rejected():
    """An error frame needs 2 bytes of code *and* 2 of message length.

    The guard admits a 2-byte payload, then unpacks 4 bytes from it.
    """
    with pytest.raises(ProtocolError):
        parse_response(b"\x01" + struct.pack(">H", 0x0006))


def test_error_frame_with_overlong_message_length_is_rejected():
    with pytest.raises(ProtocolError):
        parse_response(b"\x01" + struct.pack(">H", 6) + struct.pack(">H", 500) + b"short")


# ---------------------------------------------------------------------------
# Fixed-width and length-prefixed primitives, exercised through real parsers
# ---------------------------------------------------------------------------


def test_event_head_truncated_before_length_prefix():
    with pytest.raises(ProtocolError):
        parse_event_head_response_raw(_ok(b"\x00"))


def test_event_head_length_prefix_longer_than_payload():
    """A short id32/head slice must raise, not decode fewer bytes than claimed."""
    with pytest.raises(ProtocolError):
        parse_event_head_response_raw(_ok(struct.pack(">H", 400) + b"\x00" * 10))


def test_event_get_truncated_record_slice():
    with pytest.raises(ProtocolError):
        parse_event_get_response(_ok(struct.pack(">I", 4096) + b"\x00" * 8))


def test_event_body_truncated_blob():
    with pytest.raises(ProtocolError):
        parse_event_body_response(_ok(struct.pack(">I", 4096) + b"abc"))


# ---------------------------------------------------------------------------
# Count-prefixed lists: a huge count over an empty payload must not be
# absorbed silently by Python's forgiving slicing.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "parser",
    [
        parse_event_range_response,
        parse_key_epochs_response,
        parse_report_list_response,
        parse_board_list_response,
        parse_user_list_response,
    ],
)
def test_list_count_exceeding_payload_is_rejected(parser):
    with pytest.raises(ProtocolError):
        parser(_ok(struct.pack(">H", 0xFFFF)))


def test_key_epochs_short_final_pubkey_is_rejected():
    """One epoch promised, its 32-byte pubkey cut to 4 bytes."""
    payload = struct.pack(">H", 1) + struct.pack(">Q", 1) + struct.pack(">Q", 0) + b"\x00" * 4
    with pytest.raises(ProtocolError):
        parse_key_epochs_response(_ok(payload))


def test_ban_status_truncated_is_rejected():
    with pytest.raises(ProtocolError):
        parse_ban_status_response(_ok(b"\x01"))


# ---------------------------------------------------------------------------
# ProtocolError must remain catchable as ValueError: the server handler's
# `except ValueError` at firehose_commands.handle() turns a malformed request
# into a 0x0006 error frame, and the shared codec has to keep landing there.
# ---------------------------------------------------------------------------


def test_protocol_error_is_a_value_error():
    assert issubclass(ProtocolError, ValueError)


# ---------------------------------------------------------------------------
# The server side of the same codec. A truncated *request* must come back as
# a 0x0006 protocol error, not as the 0x0000 "Internal error" that handle()'s
# catch-all produces when a decoder raises struct.error or IndexError.
# ---------------------------------------------------------------------------


def _error_code(resp: bytes) -> int:
    assert resp[0] == 0x01, "expected an error frame"
    return struct.unpack(">H", resp[1:3])[0]


@pytest.mark.parametrize(
    "req",
    [
        # EVENT_GET: origin text16 present, event_id cut to 4 bytes
        bytes([OP_EVENT_GET]) + struct.pack(">H", 8) + b"bbs.test" + bytes(4),
        # USER_GET: pubkey length claims 32, none supplied
        bytes([OP_USER_GET]) + struct.pack(">H", 8) + b"bbs.test" + bytes([32]),
        # BAN_STATUS: same shape, no origin prefix
        bytes([OP_BAN_STATUS]) + bytes([32]),
        # REPORT_LIST: culprit length claims 32, nothing follows
        bytes([OP_REPORT_LIST]) + bytes([32]),
        # EVENT_HEAD: text16 length prefix longer than the frame
        bytes([OP_EVENT_HEAD]) + struct.pack(">H", 64) + b"bbs",
    ],
)
def test_truncated_request_is_a_protocol_error_frame(stack, req):
    resp = stack["handler"].handle(req, _anon_ctx())
    assert _error_code(resp) == 0x0006


def test_article_query_short_filter_value_is_a_protocol_error(stack):
    """A u16 filter value_len longer than the frame.

    value_type 0x03 unpacked `>q` straight off the short slice, so this
    arrived as 0x0000 "Internal error" rather than a protocol error.
    """
    req = bytes([OP_ARTICLE_QUERY])
    req += struct.pack(">H", 8) + b"bbs.test"
    req += struct.pack(">H", 4) + b"test"
    req += bytes([1])  # one filter
    req += bytes([1, 1, 0x03])  # field_id, operator, value_type=i64
    req += struct.pack(">H", 8)  # claims 8 bytes of value
    req += bytes(1)  # supplies 1
    resp = stack["handler"].handle(req, _anon_ctx())
    assert _error_code(resp) == 0x0006
