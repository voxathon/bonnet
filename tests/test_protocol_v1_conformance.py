"""Protocol v1 conformance tests — verify frozen fixtures match current code.

These tests exist so that accidental changes to the v1 wire format are caught
before they ship.  Every fixture in tests/fixtures/protocol_v1/wire_fixtures.py
must be reproducible by the current code in src/client/protocol.py.

When protocol v2 replaces v1, these tests become the regression boundary:
they prove the binary command payloads (which v2 keeps) have not changed.
"""

import os
import sys
import struct
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from client.protocol import (
    build_register, build_get_user, build_list_users, build_list_peers,
    build_board_create, build_board_list, build_post_create, build_post_get,
    build_post_list, build_post_delete, build_board_close, build_board_delete,
    build_query_posts, build_post_content_search, build_user_promote,
    build_user_demote, build_post_sign, build_get_pubkey,
    build_rule_create, build_rule_get, build_rule_get_by_name, build_rule_list,
    build_rule_update, build_report_create, build_report_get,
    build_report_list_by_culprit, build_report_sign, build_report_list_since,
    build_punishment_create, build_punishment_get, build_punishment_list_active,
    build_punishment_list_by_pubkey, build_is_banned,
    build_post_update,
    encode_frame, decode_frame, encode_string, encode_long_string, encode_bytes,
    parse_response, parse_error_response, decode_redirect,
    parse_register_resp, parse_list_users_resp, parse_list_peers_resp,
    parse_board_list_resp, parse_post_create_resp, parse_post_get_resp,
    parse_post_list_resp,
    ResponseStatus, ErrorCode, COMMANDS,
    TLV_CONTENT, TLV_SUBJECT, TLV_OPTIONS, TLV_TAGS, TLV_STICKY, TLV_CLOSED,
    encode_tlv_str, encode_tlv_long_str, encode_tlv_i32, encode_tlv_u8,
)
from tests.fixtures.protocol_v1.wire_fixtures import (
    TEST_SEED, TEST_PRIVATE_KEY, TEST_PUBLIC_KEY, TEST2_PUBLIC_KEY,
    HANDSHAKE_CHALLENGE, HANDSHAKE_CLIENT_SIG,
    FRAME_EMPTY, FRAME_SINGLE_BYTE, FRAME_KNOWN,
    OPCODES, REQUESTS,
    RESP_SUCCESS_REGISTER, RESP_SUCCESS_GET_PUBKEY, RESP_SUCCESS_LIST_PEERS,
    RESP_SUCCESS_BOARD_LIST, RESP_SUCCESS_POST_CREATE, RESP_SUCCESS_POST_GET,
    RESP_SUCCESS_POST_LIST,
    RESP_ERROR_401, RESP_ERROR_403, RESP_ERROR_404, RESP_ERROR_409,
    RESP_ERROR_413, RESP_ERROR_429,
    RESP_REDIRECT,
    TLV_CONTENT as FX_TLV_CONTENT, TLV_SUBJECT as FX_TLV_SUBJECT,
    TLV_OPTIONS as FX_TLV_OPTIONS, TLV_TAGS as FX_TLV_TAGS,
    TLV_STICKY as FX_TLV_STICKY, TLV_CLOSED as FX_TLV_CLOSED,
    QUERY_VAL_INT, QUERY_VAL_STRING,
)


class TestOpcodeRegistry:
    """Verify the frozen opcode map matches the current COMMANDS dict."""

    @pytest.mark.parametrize("name,opcode", sorted(OPCODES.items(), key=lambda x: x[1]))
    def test_opcode_matches(self, name, opcode):
        assert name in COMMANDS, f"{name} missing from COMMANDS"
        assert COMMANDS[name] == opcode, f"{name}: expected 0x{opcode:02x}, got 0x{COMMANDS[name]:02x}"

    def test_opcode_count(self):
        assert len(REQUESTS) == len(OPCODES), "Every opcode should have a frozen request fixture"


class TestFrameLayer:
    """4-byte big-endian length prefix — the inner WebSocket framing."""

    def test_empty(self):
        assert encode_frame(b"") == FRAME_EMPTY
        assert struct.unpack(">I", FRAME_EMPTY[:4])[0] == 0

    def test_single_byte(self):
        assert encode_frame(b"\x00") == FRAME_SINGLE_BYTE

    def test_known(self):
        assert encode_frame(b"hello bonnet") == FRAME_KNOWN

    def test_decode_roundtrip(self):
        for payload in [b"", b"\x00", b"hello bonnet", b"\x01\x02\x03" * 100]:
            encoded = encode_frame(payload)
            length, decoded = decode_frame(encoded)
            assert length == len(payload)
            assert decoded == payload


class TestStringEncoding:
    """u8-length-prefixed UTF-8 strings (short) and u32 (long)."""

    def test_short_string(self):
        assert encode_string("alice") == bytes([5]) + b"alice"

    def test_long_string(self):
        assert encode_long_string("hello") == struct.pack(">I", 5) + b"hello"

    def test_bytes(self):
        assert encode_bytes(b"\x00" * 32) == bytes([32]) + b"\x00" * 32

    def test_empty_string(self):
        assert encode_string("") == bytes([0])

    def test_max_length_255(self):
        s = "x" * 255
        encoded = encode_string(s)
        assert len(encoded) == 256
        assert encoded[0] == 255


class TestRequestFixtures:
    """Each frozen request fixture must be reproducible by the corresponding build_* function."""

    def test_register(self):
        assert build_register("alice", "knolastna.me") == REQUESTS["REGISTER"]

    def test_get_user(self):
        assert build_get_user(TEST_PUBLIC_KEY) == REQUESTS["GET_USER"]

    def test_list_users(self):
        assert build_list_users(0, 100) == REQUESTS["LIST_USERS"]

    def test_list_peers(self):
        assert build_list_peers() == REQUESTS["LIST_PEERS"]

    def test_board_create(self):
        assert build_board_create("general") == REQUESTS["BOARD_CREATE"]

    def test_board_list(self):
        assert build_board_list() == REQUESTS["BOARD_LIST"]

    def test_post_create(self):
        assert build_post_create("general", 0, "Hello", "tag1,tag2", "", "Body text here") == REQUESTS["POST_CREATE"]

    def test_post_get(self):
        assert build_post_get("general", 1) == REQUESTS["POST_GET"]

    def test_post_list(self):
        assert build_post_list("general", 0, 50) == REQUESTS["POST_LIST"]

    def test_post_delete(self):
        assert build_post_delete("general", 1) == REQUESTS["POST_DELETE"]

    def test_board_close(self):
        assert build_board_close("general") == REQUESTS["BOARD_CLOSE"]

    def test_board_delete(self):
        assert build_board_delete("general") == REQUESTS["BOARD_DELETE"]

    def test_query_posts(self):
        assert build_query_posts("general", "", [], "", 100) == REQUESTS["QUERY_POSTS"]

    def test_post_content_search(self):
        assert build_post_content_search("general", "hello.*world", 100) == REQUESTS["POST_CONTENT_SEARCH"]

    def test_user_promote(self):
        assert build_user_promote("bob") == REQUESTS["USER_PROMOTE"]

    def test_user_demote(self):
        assert build_user_demote("bob") == REQUESTS["USER_DEMOTE"]

    def test_post_sign(self):
        assert build_post_sign("general", 1, "a" * 128) == REQUESTS["POST_SIGN"]

    def test_get_pubkey(self):
        assert build_get_pubkey() == REQUESTS["GET_PUBKEY"]

    def test_rule_create(self):
        assert build_rule_create("no-spam", "Don't spam") == REQUESTS["RULE_CREATE"]

    def test_rule_get(self):
        assert build_rule_get(1) == REQUESTS["RULE_GET"]

    def test_rule_get_by_name(self):
        assert build_rule_get_by_name("no-spam") == REQUESTS["RULE_GET_BY_NAME"]

    def test_rule_list(self):
        assert build_rule_list() == REQUESTS["RULE_LIST"]

    def test_report_create(self):
        assert build_report_create(1, TEST_PUBLIC_KEY, TEST2_PUBLIC_KEY, "spam reported", "general", 5, "", "") == REQUESTS["REPORT_CREATE"]

    def test_report_get(self):
        assert build_report_get("localhost", 1) == REQUESTS["REPORT_GET"]

    def test_report_list_by_culprit(self):
        assert build_report_list_by_culprit(TEST_PUBLIC_KEY) == REQUESTS["REPORT_LIST_BY_CULPRIT"]

    def test_report_sign(self):
        assert build_report_sign("localhost", 1, "b" * 128) == REQUESTS["REPORT_SIGN"]

    def test_report_list_since(self):
        assert build_report_list_since(0) == REQUESTS["REPORT_LIST_SINCE"]

    def test_punishment_create(self):
        assert build_punishment_create(TEST_PUBLIC_KEY, [1], 9999999999, "banned for spam") == REQUESTS["PUNISHMENT_CREATE"]

    def test_punishment_get(self):
        assert build_punishment_get("localhost", 1) == REQUESTS["PUNISHMENT_GET"]

    def test_punishment_list_active(self):
        assert build_punishment_list_active() == REQUESTS["PUNISHMENT_LIST_ACTIVE"]

    def test_punishment_list_by_pubkey(self):
        assert build_punishment_list_by_pubkey(TEST_PUBLIC_KEY) == REQUESTS["PUNISHMENT_LIST_BY_PUBKEY"]

    def test_is_banned(self):
        assert build_is_banned(TEST_PUBLIC_KEY) == REQUESTS["IS_BANNED"]

    def test_post_update(self):
        fields = [("subject", encode_tlv_str(TLV_SUBJECT, "New Subject"))]
        assert build_post_update("general", 1, fields) == REQUESTS["POST_UPDATE"]


class TestResponseParsing:
    """Frozen response fixtures must parse correctly with current parse_* functions."""

    def test_parse_success(self):
        status, payload = parse_response(RESP_SUCCESS_REGISTER)
        assert status == ResponseStatus.SUCCESS
        assert parse_register_resp(payload) == "alice"

    def test_parse_error_401(self):
        status, payload = parse_response(RESP_ERROR_401)
        assert status == ResponseStatus.ERROR
        msg = parse_error_response(payload)
        assert "0x0191" in msg
        assert "Authentication required" in msg

    def test_parse_error_403(self):
        status, payload = parse_response(RESP_ERROR_403)
        assert status == ResponseStatus.ERROR
        assert "0x0193" in parse_error_response(payload)

    def test_parse_error_404(self):
        status, payload = parse_response(RESP_ERROR_404)
        assert status == ResponseStatus.ERROR
        assert "not found" in parse_error_response(payload)

    def test_parse_error_409(self):
        status, payload = parse_response(RESP_ERROR_409)
        assert status == ResponseStatus.ERROR
        assert "already exists" in parse_error_response(payload)

    def test_parse_error_413(self):
        status, payload = parse_response(RESP_ERROR_413)
        assert status == ResponseStatus.ERROR
        assert "too large" in parse_error_response(payload)

    def test_parse_error_429(self):
        status, payload = parse_response(RESP_ERROR_429)
        assert status == ResponseStatus.ERROR
        assert "Too many" in parse_error_response(payload)

    def test_parse_redirect(self):
        status, payload = parse_response(RESP_REDIRECT)
        assert status == ResponseStatus.REDIRECT
        origin = decode_redirect(payload)
        assert origin == "remote.example.com"

    def test_parse_post_create_resp(self):
        status, payload = parse_response(RESP_SUCCESS_POST_CREATE)
        assert status == ResponseStatus.SUCCESS
        result = parse_post_create_resp(payload)
        assert result.post_num == 1
        assert result.author == "alice"
        assert result.subject == "Hello"

    def test_parse_post_get_resp(self):
        status, payload = parse_response(RESP_SUCCESS_POST_GET)
        assert status == ResponseStatus.SUCCESS
        post = parse_post_get_resp(payload)
        assert post.post_num == 1
        assert post.content == "Body text here"
        assert post.author == "alice"

    def test_parse_post_list_resp(self):
        status, payload = parse_response(RESP_SUCCESS_POST_LIST)
        assert status == ResponseStatus.SUCCESS
        posts = parse_post_list_resp(payload)
        assert len(posts) == 1
        assert posts[0].post_num == 1

    def test_parse_list_peers_empty(self):
        status, payload = parse_response(RESP_SUCCESS_LIST_PEERS)
        assert status == ResponseStatus.SUCCESS
        peers = parse_list_peers_resp(payload)
        assert peers == []

    def test_parse_board_list_empty(self):
        status, payload = parse_response(RESP_SUCCESS_BOARD_LIST)
        assert status == ResponseStatus.SUCCESS
        boards = parse_board_list_resp(payload)
        assert boards == []

    def test_parse_get_pubkey(self):
        status, payload = parse_response(RESP_SUCCESS_GET_PUBKEY)
        assert status == ResponseStatus.SUCCESS
        from client.protocol import parse_get_pubkey_resp
        pubkey_hex = parse_get_pubkey_resp(payload)
        assert bytes.fromhex(pubkey_hex) == TEST_PUBLIC_KEY


class TestErrorEnvelopeFormat:
    """Verify the exact byte layout of error responses: 0x01 || code:u16be || msg_len:u8 || msg"""

    def test_401_layout(self):
        raw = RESP_ERROR_401
        assert raw[0] == 0x01
        code = struct.unpack(">H", raw[1:3])[0]
        assert code == 401
        msg_len = raw[3]
        assert msg_len == len("Authentication required")
        msg = raw[4:4+msg_len].decode("utf-8")
        assert msg == "Authentication required"

    def test_429_layout(self):
        raw = RESP_ERROR_429
        assert raw[0] == 0x01
        code = struct.unpack(">H", raw[1:3])[0]
        assert code == 429


class TestRedirectEnvelopeFormat:
    """0x02 || origin_len:u8 || origin:utf8"""

    def test_layout(self):
        raw = RESP_REDIRECT
        assert raw[0] == 0x02
        origin_len = raw[1]
        origin = raw[2:2+origin_len].decode("utf-8")
        assert origin == "remote.example.com"


class TestTLVFieldTypes:
    """Post-update TLV field type constants must match."""

    def test_tlv_constants(self):
        assert TLV_CONTENT == FX_TLV_CONTENT == 0x01
        assert TLV_SUBJECT == FX_TLV_SUBJECT == 0x02
        assert TLV_OPTIONS == FX_TLV_OPTIONS == 0x03
        assert TLV_TAGS == FX_TLV_TAGS == 0x04
        assert TLV_STICKY == FX_TLV_STICKY == 0x05
        assert TLV_CLOSED == FX_TLV_CLOSED == 0x06


class TestErrorCodeConstants:
    """Error code constants must match frozen values."""

    def test_codes(self):
        assert ErrorCode.USER_NOT_FOUND == 0x0001
        assert ErrorCode.BOARD_NOT_FOUND == 0x0002
        assert ErrorCode.POST_NOT_FOUND == 0x0003
        assert ErrorCode.PERMISSION_DENIED == 0x0004
        assert ErrorCode.NOT_REGISTERED == 0x0009
