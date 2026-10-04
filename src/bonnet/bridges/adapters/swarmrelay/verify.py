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

"""Envelope verification: `swarmrelay-canonical-json-v1` and Ed25519.

An envelope is signed over `id|channel|sender|type|sequence|timestamp|checksum`
(UTF-8, pipes literal), where `checksum` is the SHA-256 of the payload in the
hub's canonical JSON: ECMAScript `JSON.stringify` output with object keys
sorted by UTF-16 code unit. Python's `json.dumps` differs on key order,
number formatting and lone surrogates, so the canon is written out here and
pinned to the hub's own vectors (`fixtures/canonical-json-v1.json`).

The sender id is `agent_` plus the first 16 hex digits of the SHA-256 of
the public key's lowercase hex string, so a key the hub serves for a sender
is checked against the id before it is trusted.
"""

from __future__ import annotations

import hashlib
import math
import re

import nacl.exceptions
import nacl.signing

# Verdicts, as the tag on a mirror reads them.
VERIFIED = "verified"
# The signature is good over the checksum the author claimed, but the payload
# doesn't hash to it: the author signed something, not provably this text.
CHECKSUM_MISMATCH = "checksum-mismatch"
INVALID = "invalid"  # bad signature, malformed envelope, or a key not the sender's
NO_KEY = "no-key"  # the hub has no key for the sender
VERDICTS = frozenset({VERIFIED, CHECKSUM_MISMATCH, INVALID, NO_KEY})

SENDER = re.compile(r"agent_[0-9a-f]{16}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX128 = re.compile(r"[0-9a-f]{128}")

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


def js_number(value: int | float) -> str:
    """A JSON number as ECMAScript's `Number.prototype.toString` writes it.

    Integers become binary64 first, as they would in JavaScript, so a large
    one prints rounded the same way.
    """
    f = float(value)
    if not math.isfinite(f):
        raise ValueError(f"not a JSON number: {value!r}")
    if f == 0:
        return "0"  # -0 too
    sign = "-" if f < 0 else ""
    # repr() is the shortest decimal that round-trips, the same digits
    # ECMAScript picks; only the layout differs.
    mantissa, _, exp = repr(abs(f)).partition("e")
    whole, _, frac = mantissa.partition(".")
    if frac == "0":
        frac = ""
    all_digits = whole + frac
    digits = all_digits.lstrip("0")
    point = len(whole) + (int(exp) if exp else 0) - (len(all_digits) - len(digits))
    digits = digits.rstrip("0")
    k, n = len(digits), point
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = f"{digits[:n]}.{digits[n:]}"
    elif -6 < n <= 0:
        out = "0." + "0" * -n + digits
    else:
        e = n - 1
        head = digits[0] + (f".{digits[1:]}" if k > 1 else "")
        out = f"{head}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + out


def _string(s: str) -> str:
    out = ['"']
    for c in s:
        o = ord(c)
        if c in _ESCAPES:
            out.append(_ESCAPES[c])
        elif o < 0x20 or 0xD800 <= o <= 0xDFFF:
            # Controls without a short escape, and lone surrogates (a valid
            # pair arrives from the JSON parser as one character).
            out.append(f"\\u{o:04x}")
        else:
            out.append(c)
    out.append('"')
    return "".join(out)


def _utf16(key: str) -> bytes:
    # Big-endian code units compare bytewise in code unit order.
    return key.encode("utf-16-be", "surrogatepass")


def canonical(value) -> str:
    """`value` (as `json.loads` gives it) in swarmrelay-canonical-json-v1."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (int, float)):
        return js_number(value)
    if isinstance(value, list):
        return "[" + ",".join(canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=_utf16)
        return "{" + ",".join(f"{_string(k)}:{canonical(value[k])}" for k in keys) + "}"
    raise TypeError(f"not a JSON value: {type(value).__name__}")


def checksum(payload) -> str:
    return hashlib.sha256(canonical(payload).encode("utf-8", "surrogatepass")).hexdigest()


def agent_id(public_key_hex: str) -> str:
    return "agent_" + hashlib.sha256(public_key_hex.lower().encode("ascii")).hexdigest()[:16]


def sign_string(envelope: dict) -> bytes:
    """The bytes an envelope's signature covers. Raises on missing fields."""
    parts = [envelope[k] for k in ("id", "channel", "sender", "type")]
    if not all(isinstance(p, str) for p in parts):
        raise TypeError("id, channel, sender and type must be strings")
    numbers = [envelope["sequence"], envelope["timestamp"]]
    if not all(isinstance(n, (int, float)) and not isinstance(n, bool) for n in numbers):
        raise TypeError("sequence and timestamp must be numbers")
    if not isinstance(envelope["checksum"], str):
        raise TypeError("checksum must be a string")
    fields = [*parts, *(js_number(n) for n in numbers), envelope["checksum"]]
    return "|".join(fields).encode("utf-8", "surrogatepass")


def verify(envelope: dict, public_key_hex: str | None) -> str:
    """The verdict on `envelope`, given the key the hub serves for its sender."""
    if public_key_hex is None:
        return NO_KEY
    sender = envelope.get("sender")
    signature = envelope.get("signature")
    if (
        not isinstance(public_key_hex, str)
        or not _HEX64.fullmatch(public_key_hex.lower())
        or not isinstance(sender, str)
        or agent_id(public_key_hex) != sender
        or not isinstance(signature, str)
        or not _HEX128.fullmatch(signature.lower())
    ):
        return INVALID
    try:
        signed = sign_string(envelope)
        nacl.signing.VerifyKey(bytes.fromhex(public_key_hex)).verify(
            signed, bytes.fromhex(signature)
        )
    except (KeyError, TypeError, ValueError, nacl.exceptions.BadSignatureError):
        return INVALID
    try:
        intact = checksum(envelope.get("payload")) == envelope["checksum"].lower()
    except (TypeError, ValueError):
        intact = False
    return VERIFIED if intact else CHECKSUM_MISMATCH
