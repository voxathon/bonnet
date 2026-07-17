"""Protocol v1 frozen wire fixtures.

Deterministic byte sequences captured from the current v1 implementation.
These are NOT generated at runtime — they are hardcoded so that accidental
changes to the wire format are caught as test failures.

Key: RFC 8032 Ed25519 test vector 1 (seed 9d61b19d...)
     private: 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55
     public:  d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a

All fixture data uses struct.pack with big-endian byte order, matching
the current protocol codec in src/client/protocol.py.
"""

import struct

# ---------------------------------------------------------------------------
# Known keypair (RFC 8032 test vector 1)
# ---------------------------------------------------------------------------

TEST_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55"
)
TEST_PRIVATE_KEY = TEST_SEED
TEST_PUBLIC_KEY = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)

# A second keypair for handshake/multi-party fixtures (RFC 8032 test vector 2)
TEST2_SEED = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
)
TEST2_PUBLIC_KEY = bytes.fromhex(
    "3d4017c3e843895a92b70fe74e256d05ccc0b6565e8e28b5e2d3a30f1b3f7a36"
)

# ---------------------------------------------------------------------------
# Frame layer: 4-byte big-endian length prefix
# ---------------------------------------------------------------------------

def frame(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload

FRAME_EMPTY = frame(b"")
FRAME_SINGLE_BYTE = frame(b"\x00")
FRAME_KNOWN = frame(b"hello bonnet")

# ---------------------------------------------------------------------------
# Handshake wire format
# ---------------------------------------------------------------------------

# Server → Client: [32-byte pubkey][32-byte challenge]
# Using a fixed challenge for deterministic fixture
HANDSHAKE_CHALLENGE = bytes(32)  # 32 zero bytes as a fixed challenge
HANDSHAKE_SERVER_FRAME = frame(TEST_PUBLIC_KEY + HANDSHAKE_CHALLENGE)

# Client → Server: [32-byte pubkey][64-byte Ed25519 signature over challenge]
# Signature is deterministic (Ed25519 is deterministic)
from nacl.signing import SigningKey
_handshake_sk = SigningKey(TEST_SEED)
HANDSHAKE_CLIENT_SIG = _handshake_sk.sign(HANDSHAKE_CHALLENGE).signature
HANDSHAKE_CLIENT_FRAME = frame(TEST_PUBLIC_KEY + HANDSHAKE_CLIENT_SIG)

# ---------------------------------------------------------------------------
# Command opcodes (frozen registry)
# ---------------------------------------------------------------------------

OPCODES = {
    "REGISTER": 0x01,
    "GET_USER": 0x02,
    "LIST_USERS": 0x03,
    "LIST_PEERS": 0x04,
    "BOARD_CREATE": 0x10,
    "BOARD_LIST": 0x11,
    "POST_CREATE": 0x12,
    "POST_GET": 0x13,
    "POST_LIST": 0x14,
    "POST_UPDATE": 0x15,
    "POST_DELETE": 0x16,
    "BOARD_CLOSE": 0x17,
    "BOARD_DELETE": 0x18,
    "QUERY_POSTS": 0x19,
    "POST_CONTENT_SEARCH": 0x1A,
    "USER_PROMOTE": 0x20,
    "USER_DEMOTE": 0x21,
    "POST_SIGN": 0x22,
    "GET_PUBKEY": 0x30,
    "RULE_CREATE": 0x40,
    "RULE_GET": 0x41,
    "RULE_GET_BY_NAME": 0x42,
    "RULE_LIST": 0x43,
    "RULE_UPDATE": 0x44,
    "REPORT_CREATE": 0x50,
    "REPORT_GET": 0x51,
    "REPORT_LIST_BY_CULPRIT": 0x52,
    "REPORT_SIGN": 0x53,
    "REPORT_LIST_SINCE": 0x54,
    "PUNISHMENT_CREATE": 0x60,
    "PUNISHMENT_GET": 0x61,
    "PUNISHMENT_LIST_ACTIVE": 0x62,
    "IS_BANNED": 0x63,
}

# ---------------------------------------------------------------------------
# Request wire formats (opcode byte + payload)
# Each entry: (name, hex_bytes, human_description)
# ---------------------------------------------------------------------------

REQUESTS = {}


def _r(name, raw):
    REQUESTS[name] = raw
    return raw


# String encoding: u8-length || utf8
def _s(s):
    b = s.encode("utf-8")
    return struct.pack(">B", len(b)) + b

# Long string: u32-length || utf8
def _ls(s):
    b = s.encode("utf-8")
    return struct.pack(">I", len(b)) + b

# Bytes encoding: u8-length || raw
def _b(d):
    return struct.pack(">B", len(d)) + d


_r("REGISTER", bytes([0x01]) + _s("alice") + _s("knolastna.me"))
_r("GET_USER", bytes([0x02]) + TEST_PUBLIC_KEY)
_r("LIST_USERS", bytes([0x03]) + struct.pack(">II", 0, 100))
_r("LIST_PEERS", bytes([0x04]))
_r("BOARD_CREATE", bytes([0x10]) + _s("general"))
_r("BOARD_LIST", bytes([0x11]))
_r("POST_CREATE", bytes([0x12]) + _s("general") + struct.pack(">Q", 0) + _s("Hello") + _s("tag1,tag2") + _s("") + _ls("Body text here"))
_r("POST_GET", bytes([0x13]) + _s("general") + struct.pack(">Q", 1))
_r("POST_LIST", bytes([0x14]) + _s("general") + struct.pack(">II", 0, 50))
_r("POST_UPDATE", bytes([0x15]) + _s("general") + struct.pack(">Q", 1) + struct.pack(">B", 1) + bytes([0x02]) + _s("New Subject"))
_r("POST_DELETE", bytes([0x16]) + _s("general") + struct.pack(">Q", 1))
_r("BOARD_CLOSE", bytes([0x17]) + _s("general"))
_r("BOARD_DELETE", bytes([0x18]) + _s("general"))
_r("QUERY_POSTS", bytes([0x19]) + _s("general") + struct.pack(">H", 0) + struct.pack(">B", 0) + struct.pack(">H", 0) + struct.pack(">I", 100))
_r("POST_CONTENT_SEARCH", bytes([0x1A]) + _s("general") + _ls("hello.*world") + struct.pack(">I", 100))
_r("USER_PROMOTE", bytes([0x20]) + _s("bob"))
_r("USER_DEMOTE", bytes([0x21]) + _s("bob"))
_r("POST_SIGN", bytes([0x22]) + _s("general") + struct.pack(">Q", 1) + _s("a" * 128))  # hex sig placeholder
_r("GET_PUBKEY", bytes([0x30]))
_r("RULE_CREATE", bytes([0x40]) + _s("no-spam") + _s("Don't spam"))
_r("RULE_GET", bytes([0x41]) + struct.pack(">Q", 1))
_r("RULE_GET_BY_NAME", bytes([0x42]) + _s("no-spam"))
_r("RULE_LIST", bytes([0x43]))
_r("RULE_UPDATE", bytes([0x44]) + struct.pack(">Q", 1) + struct.pack(">B", 1) + bytes([0x02]) + _s("Updated desc"))
_r("REPORT_CREATE", bytes([0x50]) + struct.pack(">Q", 1) + _b(TEST_PUBLIC_KEY) + _b(TEST2_PUBLIC_KEY) + _s("spam reported") + _s("general") + struct.pack(">Q", 5) + _s("") + _s(""))
_r("REPORT_GET", bytes([0x51]) + _s("localhost") + struct.pack(">Q", 1))
_r("REPORT_LIST_BY_CULPRIT", bytes([0x52]) + _s(TEST_PUBLIC_KEY.hex()))
_r("REPORT_SIGN", bytes([0x53]) + _s("localhost") + struct.pack(">Q", 1) + _s("b" * 128))
_r("REPORT_LIST_SINCE", bytes([0x54]) + struct.pack(">q", 0))
_r("PUNISHMENT_CREATE", bytes([0x60]) + _b(TEST_PUBLIC_KEY) + struct.pack(">B", 1) + struct.pack(">Q", 1) + struct.pack(">q", 9999999999) + _s("banned for spam"))
_r("PUNISHMENT_GET", bytes([0x61]) + _b(TEST_PUBLIC_KEY))
_r("PUNISHMENT_LIST_ACTIVE", bytes([0x62]))
_r("IS_BANNED", bytes([0x63]) + _b(TEST_PUBLIC_KEY))

# ---------------------------------------------------------------------------
# Response wire formats
# ---------------------------------------------------------------------------

# Success envelope: 0x00 || payload
# Error envelope: 0x01 || code:u16be || msg_len:u8 || msg:utf8
# Redirect envelope: 0x02 || origin_len:u8 || origin:utf8

RESP_SUCCESS_REGISTER = bytes([0x00]) + _s("alice")
RESP_SUCCESS_GET_PUBKEY = bytes([0x00]) + TEST_PUBLIC_KEY
RESP_SUCCESS_LIST_PEERS = bytes([0x00]) + struct.pack(">H", 0)
RESP_SUCCESS_BOARD_LIST = bytes([0x00]) + struct.pack(">H", 0)

RESP_ERROR_401 = bytes([0x01]) + struct.pack(">H", 401) + _s("Authentication required")
RESP_ERROR_403 = bytes([0x01]) + struct.pack(">H", 403) + _s("Permission denied")
RESP_ERROR_404 = bytes([0x01]) + struct.pack(">H", 404) + _s("Board 'general' not found")
RESP_ERROR_409 = bytes([0x01]) + struct.pack(">H", 409) + _s("Board 'general' already exists")
RESP_ERROR_413 = bytes([0x01]) + struct.pack(">H", 413) + _s("Request too large")
RESP_ERROR_429 = bytes([0x01]) + struct.pack(">H", 429) + _s("Too many requests")

RESP_REDIRECT = bytes([0x02]) + _s("remote.example.com")

# Post create response: 0x00 || post_num:u64 || creation_date:i64 || last_modified:i64 || author || registrar || tags || subject || options
RESP_SUCCESS_POST_CREATE = (
    bytes([0x00])
    + struct.pack(">Q", 1)
    + struct.pack(">q", 1700000000)
    + struct.pack(">q", 1700000000)
    + _s("alice")
    + _s("knolastna.me")
    + _s("tag1,tag2")
    + _s("Hello")
    + _s("")
)

# Post get response: 0x00 || post_num:u64 || last_modified:i64 || creation_date:i64 || last_bumped:i64 || closed:u8 || sticky:i32 || tags || subject || options || root:u64 || author || registrar || signature || content:long_string
RESP_SUCCESS_POST_GET = (
    bytes([0x00])
    + struct.pack(">Q", 1)
    + struct.pack(">q", 1700000000)
    + struct.pack(">q", 1700000000)
    + struct.pack(">q", 1700000000)
    + bytes([0x00])
    + struct.pack(">i", 0)
    + _s("tag1,tag2")
    + _s("Hello")
    + _s("")
    + struct.pack(">Q", 0)
    + _s("alice")
    + _s("knolastna.me")
    + _s("")  # signature (empty = unsigned)
    + _ls("Body text here")
)

# Post list response: 0x00 || (post_num:u64 || creation_date:i64 || subject || author || root:u64)*
RESP_SUCCESS_POST_LIST = (
    bytes([0x00])
    + struct.pack(">Q", 1)
    + struct.pack(">q", 1700000000)
    + _s("Hello")
    + _s("alice")
    + struct.pack(">Q", 0)
)

# ---------------------------------------------------------------------------
# TLV field types for POST_UPDATE
# ---------------------------------------------------------------------------

TLV_CONTENT = 0x01
TLV_SUBJECT = 0x02
TLV_OPTIONS = 0x03
TLV_TAGS = 0x04
TLV_STICKY = 0x05
TLV_CLOSED = 0x06

# ---------------------------------------------------------------------------
# Query value types
# ---------------------------------------------------------------------------

QUERY_VAL_INT = 0x01
QUERY_VAL_STRING = 0x02
