"""Protocol v2 deterministic wire fixtures.

Known Ed25519 keypairs (RFC 8032 test vectors) with deterministic signature
outputs. These fixtures allow independent implementations to verify byte-level
compatibility with Bonnet's RFC 9421 profile.

RFC 8032 Section 7.1 Test Vector 1:
  seed:     9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55
  public:   d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
  private:  9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55

RFC 8032 Section 7.1 Test Vector 2:
  seed:     4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
  public:   3d4017c3e843895a92b70fe74e256d05ccc0b6565e8e28b5e2d3a30f1b3f7a36
  private:  4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb

All fixtures use the Bonnet v2 profile:
  - alg = ed25519
  - tag = bonnet-v2
  - label = bonnet
  - Content-Digest = sha-256
  - covered components: @method, @authority, @target-uri, content-type,
    content-digest, bonnet-version, bonnet-nonce (request)
    @status, content-type, content-digest, bonnet-version, bonnet-origin,
    bonnet-request-nonce (response)
"""

import os
import sys
import hashlib
import base64
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from nacl.signing import SigningKey

# ---------------------------------------------------------------------------
# Known keypairs (RFC 8032)
# ---------------------------------------------------------------------------

VECTOR1_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55"
)
_sk1_init = SigningKey(VECTOR1_SEED)
VECTOR1_PUBLIC = bytes(_sk1_init.verify_key)
VECTOR1_PRIVATE = VECTOR1_SEED

VECTOR2_SEED = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
)
_sk2_init = SigningKey(VECTOR2_SEED)
VECTOR2_PUBLIC = bytes(_sk2_init.verify_key)
VECTOR2_PRIVATE = VECTOR2_SEED

# ---------------------------------------------------------------------------
# Fixed test parameters
# ---------------------------------------------------------------------------

FIXED_CREATED = 1700000000
FIXED_EXPIRES = FIXED_CREATED + 60
FIXED_NONCE = base64.urlsafe_b64encode(b"\x01" * 32).rstrip(b"=").decode()
FIXED_NONCE_RAW = b"\x01" * 32

REQUEST_URL = "https://bbs.example.com/v2/command"
REQUEST_BODY = b"\x11"  # BOARD_LIST opcode
REQUEST_CONTENT_DIGEST = f"sha-256=:{base64.b64encode(hashlib.sha256(REQUEST_BODY).digest()).decode()}:"

RESPONSE_BODY = b"\x00\x00\x00"  # SUCCESS + 0 boards
RESPONSE_CONTENT_DIGEST = f"sha-256=:{base64.b64encode(hashlib.sha256(RESPONSE_BODY).digest()).decode()}:"

# ---------------------------------------------------------------------------
# Expected signature base strings
# ---------------------------------------------------------------------------

REQUEST_COMPONENTS = [
    "@method", "@authority", "@target-uri",
    "content-type", "content-digest",
    "bonnet-version", "bonnet-nonce",
]

REQUEST_PARAMS = {
    "created": FIXED_CREATED,
    "keyid": f"ed25519:{VECTOR1_PUBLIC.hex()}",
    "alg": "ed25519",
    "expires": FIXED_EXPIRES,
    "nonce": FIXED_NONCE,
    "tag": "bonnet-v2",
}

# Build the expected signature base for the request
# (same format as src/net/http_auth.py build_signature_base)
def _build_expected_request_sig_base():
    from net.http_auth import build_signature_base, HTTPMessage
    msg = HTTPMessage(
        method="POST",
        url=REQUEST_URL,
        headers={
            "Content-Type": "application/vnd.bonnet.command",
            "Content-Digest": REQUEST_CONTENT_DIGEST,
            "Bonnet-Version": "2",
            "Bonnet-Nonce": FIXED_NONCE,
        },
        body=REQUEST_BODY,
    )
    return build_signature_base(REQUEST_COMPONENTS, REQUEST_PARAMS, msg)


REQUEST_SIG_BASE = _build_expected_request_sig_base()

# Deterministic Ed25519 signature over the request sig base
_sk1 = SigningKey(VECTOR1_SEED)
REQUEST_SIGNATURE = _sk1.sign(REQUEST_SIG_BASE.encode()).signature
REQUEST_SIGNATURE_B64 = base64.b64encode(REQUEST_SIGNATURE).decode()

# Expected Signature-Input header
REQUEST_SIG_INPUT = (
    f'bonnet=("@method" "@authority" "@target-uri" "content-type" "content-digest" '
    f'"bonnet-version" "bonnet-nonce");created={FIXED_CREATED};'
    f'keyid="ed25519:{VECTOR1_PUBLIC.hex()}";alg="ed25519";'
    f'expires={FIXED_EXPIRES};nonce="{FIXED_NONCE}";tag="bonnet-v2"'
)

# Expected Signature header
REQUEST_SIG_HEADER = f"bonnet=:{REQUEST_SIGNATURE_B64}:"

# ---------------------------------------------------------------------------
# Response fixture
# ---------------------------------------------------------------------------

RESPONSE_COMPONENTS = [
    "@status", "content-type", "content-digest",
    "bonnet-version", "bonnet-origin",
    "bonnet-request-nonce",
]

RESPONSE_PARAMS = {
    "created": FIXED_CREATED,
    "keyid": "origin:bbs.example.com",
    "alg": "ed25519",
    "expires": FIXED_EXPIRES,
    "nonce": FIXED_NONCE,
    "tag": "bonnet-v2",
}

def _build_expected_response_sig_base():
    from net.http_auth import build_signature_base, HTTPMessage
    msg = HTTPMessage(
        method="POST",
        url=REQUEST_URL,
        headers={
            "Content-Type": "application/vnd.bonnet.command",
            "Content-Digest": RESPONSE_CONTENT_DIGEST,
            "Bonnet-Version": "2",
            "Bonnet-Origin": "bbs.example.com",
            "Bonnet-Request-Nonce": FIXED_NONCE,
        },
        status_code=200,
        body=RESPONSE_BODY,
    )
    return build_signature_base(RESPONSE_COMPONENTS, RESPONSE_PARAMS, msg)


RESPONSE_SIG_BASE = _build_expected_response_sig_base()

_sk2 = SigningKey(VECTOR2_SEED)
RESPONSE_SIGNATURE = _sk2.sign(RESPONSE_SIG_BASE.encode()).signature
RESPONSE_SIGNATURE_B64 = base64.b64encode(RESPONSE_SIGNATURE).decode()

RESPONSE_SIG_INPUT = (
    f'bonnet=("@status" "content-type" "content-digest" "bonnet-version" "bonnet-origin" '
    f'"bonnet-request-nonce");created={FIXED_CREATED};'
    f'keyid="origin:bbs.example.com";alg="ed25519";'
    f'expires={FIXED_EXPIRES};nonce="{FIXED_NONCE}";tag="bonnet-v2"'
)

RESPONSE_SIG_HEADER = f"bonnet=:{RESPONSE_SIGNATURE_B64}:"
