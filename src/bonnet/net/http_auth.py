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

"""Firehose RFC 9421 HTTP Message Signatures profile — Ed25519 only, async-native.

Implements exactly what the firehose protocol requires:
  - Ed25519 sign/verify via pynacl (raw 32-byte keys, no PEM)
  - Content-Digest (RFC 9530, SHA-256)
  - Signature-Input / Signature header parsing and serialization
  - Signature base construction (RFC 9421 §2.5)
  - Mandatory covered-component enforcement
  - created / expires / clock-skew validation
  - nonce matching and base64url-32-byte validation
  - tag="untp-1" filtering
  - keyid format validation (ed25519:<hex> for requests, origin:<name> for responses)
  - All public sign/verify methods are async (crypto offloaded via asyncio.to_thread)
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import time
import urllib.parse
from collections.abc import Sequence
from dataclasses import dataclass, field

import nacl.exceptions
import nacl.signing

UNTP_TAG = "untp-1"
UNTP_LABEL = "untp"
ED25519_ALG = "ed25519"
DEFAULT_MAX_LIFETIME = 60
DEFAULT_CLOCK_SKEW = 30

REQUEST_REQUIRED_COMPONENTS = frozenset(
    {
        "@method",
        "@authority",
        "@target-uri",
        "content-type",
        "content-digest",
        "untp-version",
        "untp-nonce",
    }
)

RESPONSE_REQUIRED_COMPONENTS = frozenset(
    {
        "@status",
        "content-type",
        "content-digest",
        "untp-version",
        "untp-origin",
    }
)


class SignatureError(Exception):
    """Base for all signature verification failures."""


class MalformedSignature(SignatureError):
    """Header parsing or structural error."""


class InvalidSignature(SignatureError):
    """Cryptographic verification failure."""


class ExpiredSignature(SignatureError):
    """created too old or expires in the past."""


class FutureSignature(SignatureError):
    """created too far in the future."""


class MissingComponent(SignatureError):
    """A required covered component is absent."""


class InvalidParameter(SignatureError):
    """Bad keyid, alg, tag, nonce, or lifetime."""


class DigestMismatch(SignatureError):
    """Content-Digest does not match the body."""


# ---------------------------------------------------------------------------
# Content-Digest (RFC 9530)
# ---------------------------------------------------------------------------


def compute_content_digest(body: bytes) -> str:
    digest = hashlib.sha256(body).digest()
    return f"sha-256=:{base64.b64encode(digest).decode()}:"


def validate_content_digest(body: bytes, header_value: str) -> None:
    prefix = "sha-256=:"
    if not header_value.startswith(prefix) or not header_value.endswith(":"):
        raise DigestMismatch(f"Malformed Content-Digest: {header_value[:60]!r}")
    b64 = header_value[len(prefix) : -1]
    try:
        expected = base64.b64decode(b64, validate=True)
    except Exception:
        raise DigestMismatch("Content-Digest is not valid base64")
    actual = hashlib.sha256(body).digest()
    if actual != expected:
        raise DigestMismatch("Content-Digest does not match body")


# ---------------------------------------------------------------------------
# Message abstraction
# ---------------------------------------------------------------------------


@dataclass
class HTTPMessage:
    method: str = ""
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    status_code: int | None = None
    body: bytes = b""

    @property
    def is_response(self) -> bool:
        return self.status_code is not None

    def header(self, name: str) -> str:
        nl = name.lower()
        for k, v in self.headers.items():
            if k.lower() == nl:
                return v
        raise KeyError(name)

    def has_header(self, name: str) -> bool:
        nl = name.lower()
        return any(k.lower() == nl for k in self.headers)

    def set_header(self, name: str, value: str) -> None:
        self.headers[name] = value


# ---------------------------------------------------------------------------
# VerifyResult
# ---------------------------------------------------------------------------


@dataclass
class VerifyResult:
    label: str
    keyid: str
    covered_components: list[str]
    parameters: dict
    nonce: str | None = None


# ---------------------------------------------------------------------------
# Key resolver (sync — just a lookup)
# ---------------------------------------------------------------------------


class KeyResolver:
    def resolve_public_key(self, key_id: str) -> bytes:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Signature-Input parsing / serialization
# ---------------------------------------------------------------------------


@dataclass
class ParsedSigInput:
    label: str
    components: list[str]
    params: dict  # ordered: created, keyid, alg, expires, nonce, tag


def _parse_quoted(s: str, i: int) -> tuple[str, int]:
    """Parse a quoted string starting at s[i] == '"'. Return (value, next_index)."""
    assert s[i] == '"'
    i += 1
    out = []
    while i < len(s):
        c = s[i]
        if c == "\\":
            i += 1
            if i < len(s):
                out.append(s[i])
                i += 1
            continue
        if c == '"':
            return "".join(out), i + 1
        out.append(c)
        i += 1
    raise MalformedSignature("Unterminated quoted string in Signature-Input")


def _parse_params(s: str, i: int) -> tuple[dict, int]:
    """Parse semicolon-separated key=value parameters. Return (params, next_index)."""
    params: dict = {}
    while i < len(s):
        while i < len(s) and s[i] in "; ":
            i += 1
        if i >= len(s):
            break
        # read key
        ks = i
        while i < len(s) and s[i] != "=":
            i += 1
        key = s[ks:i].strip()
        if i >= len(s):
            break
        i += 1  # skip =
        # read value
        val: str | int
        if i < len(s) and s[i] == '"':
            val, i = _parse_quoted(s, i)
        else:
            vs = i
            while i < len(s) and s[i] != ";":
                i += 1
            raw = s[vs:i].strip()
            try:
                val = int(raw)
            except ValueError:
                val = raw
        params[key] = val
    return params, i


def parse_signature_input(header: str) -> ParsedSigInput:
    eq = header.find("=")
    if eq < 0:
        raise MalformedSignature("Signature-Input missing '='")
    label = header[:eq].strip()
    rest = header[eq + 1 :]
    lp = rest.find("(")
    if lp < 0:
        raise MalformedSignature("Signature-Input missing '('")
    rp = rest.find(")", lp)
    if rp < 0:
        raise MalformedSignature("Signature-Input missing ')'")
    inner = rest[lp + 1 : rp].strip()
    components: list[str] = []
    j = 0
    while j < len(inner):
        while j < len(inner) and inner[j] in " ":
            j += 1
        if j >= len(inner):
            break
        if inner[j] == '"':
            comp, j = _parse_quoted(inner, j)
            components.append(comp)
        else:
            ks = j
            while j < len(inner) and inner[j] != " ":
                j += 1
            components.append(inner[ks:j])
    params, _ = _parse_params(rest, rp + 1)
    return ParsedSigInput(label=label, components=components, params=params)


def serialize_signature_input(
    label: str,
    components: Sequence[str],
    params: dict,
) -> str:
    parts = []
    for c in components:
        escaped = c.replace("\\", "\\\\").replace('"', '\\"')
        parts.append(f'"{escaped}"')
    inner = f"({' '.join(parts)})"
    param_strs = []
    for k, v in params.items():
        if isinstance(v, int):
            param_strs.append(f"{k}={v}")
        else:
            escaped = str(v).replace("\\", "\\\\").replace('"', '\\"')
            param_strs.append(f'{k}="{escaped}"')
    suffix = ";".join(param_strs)
    return f"{label}={inner};{suffix}" if suffix else f"{label}={inner}"


# ---------------------------------------------------------------------------
# Signature header parsing / serialization
# ---------------------------------------------------------------------------


def parse_signature(header: str) -> tuple[str, bytes]:
    eq = header.find("=")
    if eq < 0:
        raise MalformedSignature("Signature header missing '='")
    label = header[:eq].strip()
    rest = header[eq + 1 :].strip()
    if not rest.startswith(":") or not rest.endswith(":"):
        raise MalformedSignature("Signature value not delimited by colons")
    b64 = rest[1:-1]
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception:
        raise MalformedSignature("Signature is not valid base64")
    return label, raw


def serialize_signature(label: str, raw: bytes) -> str:
    return f"{label}=:{base64.b64encode(raw).decode()}:"


# ---------------------------------------------------------------------------
# Component resolution
# ---------------------------------------------------------------------------

_DERIVED = {
    "@method",
    "@target-uri",
    "@authority",
    "@scheme",
    "@request-target",
    "@path",
    "@query",
    "@status",
}


def resolve_component(component_id: str, msg: HTTPMessage) -> str:
    if component_id.startswith("@"):
        if component_id not in _DERIVED:
            raise MalformedSignature(f"Unknown derived component: {component_id}")
        name = component_id[1:].replace("-", "_")
        fn = _DERIVED_RESOLVERS.get(name)
        if fn is None:
            raise MalformedSignature(f"Unsupported derived component: {component_id}")
        return fn(msg)
    if not msg.has_header(component_id):
        raise MalformedSignature(f'Covered header "{component_id}" not found')
    return msg.header(component_id)


def _get_method(msg: HTTPMessage) -> str:
    if msg.is_response:
        raise MalformedSignature("@method not valid for response signatures")
    return msg.method.upper()


def _get_target_uri(msg: HTTPMessage) -> str:
    return msg.url


def _get_authority(msg: HTTPMessage) -> str:
    return urllib.parse.urlsplit(msg.url).netloc.lower()


def _get_scheme(msg: HTTPMessage) -> str:
    return urllib.parse.urlsplit(msg.url).scheme.lower()


def _get_path(msg: HTTPMessage) -> str:
    return urllib.parse.urlsplit(msg.url).path


def _get_query(msg: HTTPMessage) -> str:
    q = urllib.parse.urlsplit(msg.url).query
    return "?" + q if q else ""


def _get_request_target(msg: HTTPMessage) -> str:
    return _get_path(msg) + _get_query(msg)


def _get_status(msg: HTTPMessage) -> str:
    if not msg.is_response:
        raise MalformedSignature("@status not valid for request signatures")
    return str(msg.status_code)


_DERIVED_RESOLVERS = {
    "method": _get_method,
    "target_uri": _get_target_uri,
    "authority": _get_authority,
    "scheme": _get_scheme,
    "path": _get_path,
    "query": _get_query,
    "request_target": _get_request_target,
    "status": _get_status,
}


# ---------------------------------------------------------------------------
# Signature base construction (RFC 9421 §2.5)
# ---------------------------------------------------------------------------


def build_signature_base(
    components: Sequence[str],
    params: dict,
    msg: HTTPMessage,
) -> str:
    lines: list[str] = []
    seen: set[str] = set()
    for comp in components:
        key = f'"{comp}"'
        if key in seen:
            raise MalformedSignature(f"Duplicate component: {comp}")
        if "\n" in comp:
            raise MalformedSignature(f"Component contains newline: {comp}")
        value = resolve_component(comp, msg)
        lines.append(f"{key}: {value}")
        seen.add(key)
    # @signature-params line — the inner list + parameters, no label prefix
    sig_params_value = _serialize_sig_params(components, params)
    lines.append(f'"@signature-params": {sig_params_value}')
    return "\n".join(lines)


def _serialize_sig_params(components: Sequence[str], params: dict) -> str:
    parts = []
    for c in components:
        escaped = c.replace("\\", "\\\\").replace('"', '\\"')
        parts.append(f'"{escaped}"')
    inner = f"({' '.join(parts)})"
    param_strs = []
    for k, v in params.items():
        if isinstance(v, int):
            param_strs.append(f"{k}={v}")
        else:
            escaped = str(v).replace("\\", "\\\\").replace('"', '\\"')
            param_strs.append(f'{k}="{escaped}"')
    suffix = ";".join(param_strs)
    return f"{inner};{suffix}" if suffix else inner


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _validate_keyid(keyid: str, is_response: bool) -> None:
    """Responses name an origin; requests carry a key.

    The asymmetry is deliberate and load-bearing. A response keyid must be
    `origin:<name>` so the verifier has to *look the key up* in what it pinned
    for that name — an `ed25519:<hex>` response keyid carries its own answer,
    so checking it proves only that the sender holds the key it just named,
    which is true of anyone who can answer the connection. That form was
    accepted here, and was what the server actually sent, which left response
    verification attributing to nobody.

    A request keyid is `ed25519:<hex>` because the client's key *is* its
    identity: the server resolves nothing, it reads the key off the request and
    then decides what that key is allowed to do.
    """
    if is_response:
        if keyid.startswith("origin:"):
            origin = keyid[7:]
            if not origin:
                raise InvalidParameter("Response keyid origin is empty")
        else:
            raise InvalidParameter(f"Response keyid must be origin:<name>, got: {keyid[:40]!r}")
    else:
        if not keyid.startswith("ed25519:"):
            raise InvalidParameter(f"Request keyid must be ed25519:<hex>, got: {keyid[:40]!r}")
        hex_part = keyid[8:]
        if len(hex_part) != 64:
            raise InvalidParameter(f"keyid hex must be 64 chars, got {len(hex_part)}")
        try:
            int(hex_part, 16)
        except ValueError:
            raise InvalidParameter("keyid hex is not valid hexadecimal")
        if hex_part != hex_part.lower():
            raise InvalidParameter("keyid hex must be lowercase")


def _validate_nonce(nonce: str) -> None:
    if "=" in nonce:
        raise InvalidParameter("nonce must not contain base64 padding")
    padded = nonce + "=" * (-len(nonce) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
    except Exception:
        raise InvalidParameter("nonce is not valid base64url")
    if len(raw) != 32:
        raise InvalidParameter(f"nonce must decode to 32 bytes, got {len(raw)}")


def _check_temporal(
    params: dict, max_lifetime: int, clock_skew: int, is_response: bool = False
) -> None:
    now = int(time.time())
    created = params.get("created")
    if created is None:
        raise InvalidParameter("Missing 'created' parameter")
    created = int(created)
    if created > now + clock_skew:
        raise FutureSignature(f"created {created} is too far in the future")
    expires = params.get("expires")
    if expires is None and not is_response:
        raise InvalidParameter("Missing 'expires' parameter")
    if expires is not None:
        expires = int(expires)
        if expires < now - clock_skew:
            raise ExpiredSignature(f"expires {expires} is in the past")
        if expires - created > max_lifetime:
            raise InvalidParameter(
                f"Signature lifetime {expires - created}s exceeds max {max_lifetime}s"
            )
    if created + max_lifetime < now - clock_skew:
        raise ExpiredSignature(f"created {created} exceeds max age {max_lifetime}s")


def _check_required_components(
    components: list[str],
    required: frozenset[str],
) -> None:
    for req in required:
        if req not in components:
            raise MissingComponent(f"Required component '{req}' not covered by signature")


# ---------------------------------------------------------------------------
# Ed25519 crypto (offloaded to thread pool)
# ---------------------------------------------------------------------------


def _ed25519_sign(private_key: bytes, message: bytes) -> bytes:
    sk = nacl.signing.SigningKey(private_key)
    return sk.sign(message).signature


def _ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> None:
    vk = nacl.signing.VerifyKey(public_key)
    try:
        vk.verify(message, signature)
    except (nacl.exceptions.BadSignatureError, nacl.exceptions.ValueError):
        raise InvalidSignature("Ed25519 signature verification failed")


# ---------------------------------------------------------------------------
# BonnetSigner (async)
# ---------------------------------------------------------------------------


class BonnetSigner:
    """Signs HTTP messages with the firehose RFC 9421 profile."""

    def __init__(
        self,
        private_key: bytes,
        key_id: str,
        tag: str = UNTP_TAG,
        label: str = UNTP_LABEL,
        request_components: list[str] = None,
        response_components: list[str] = None,
    ):
        if len(private_key) != 32:
            raise ValueError("Ed25519 private key must be 32 bytes")
        self._private_key = private_key
        self._key_id = key_id
        self._tag = tag
        self._label = label
        self._request_components = request_components or [
            "@method",
            "@authority",
            "@target-uri",
            "content-type",
            "content-digest",
            "untp-version",
            "untp-nonce",
        ]
        self._response_components = response_components or [
            "@status",
            "content-type",
            "content-digest",
            "untp-version",
            "untp-origin",
            "untp-request-nonce",
        ]

    async def sign_request(
        self,
        msg: HTTPMessage,
        *,
        nonce: str,
        created: int | None = None,
        expires: int | None = None,
        extra_components: Sequence[str] = (),
    ) -> None:
        components = list(self._request_components)
        components.extend(extra_components)
        await self._sign(msg, components, nonce, created, expires)

    async def sign_response(
        self,
        msg: HTTPMessage,
        *,
        request_nonce: str = "",
        created: int | None = None,
        expires: int | None = None,
    ) -> None:
        msg.set_header("Untp-Request-Nonce", request_nonce)
        components = list(self._response_components)
        await self._sign(msg, components, request_nonce, created, expires)

    async def _sign(
        self,
        msg: HTTPMessage,
        components: list[str],
        nonce: str,
        created: int | None,
        expires: int | None,
    ) -> None:
        if created is None:
            created = int(time.time())
        params: dict = {}
        params["created"] = created
        params["keyid"] = self._key_id
        params["alg"] = ED25519_ALG
        if expires is not None:
            params["expires"] = expires
        params["nonce"] = nonce
        params["tag"] = self._tag

        sig_base = build_signature_base(components, params, msg)
        signature = await asyncio.to_thread(_ed25519_sign, self._private_key, sig_base.encode())

        msg.set_header(
            "Signature-Input", serialize_signature_input(self._label, components, params)
        )
        msg.set_header("Signature", serialize_signature(self._label, signature))


# ---------------------------------------------------------------------------
# BonnetVerifier (async)
# ---------------------------------------------------------------------------


class BonnetVerifier:
    """Verifies HTTP messages signed with the firehose RFC 9421 profile."""

    def __init__(
        self,
        key_resolver: KeyResolver,
        tag: str = UNTP_TAG,
        max_lifetime: int = DEFAULT_MAX_LIFETIME,
        clock_skew: int = DEFAULT_CLOCK_SKEW,
        request_required_components: frozenset = None,
        response_required_components: frozenset = None,
    ):
        self._resolver = key_resolver
        self._tag = tag
        self._max_lifetime = max_lifetime
        self._clock_skew = clock_skew
        self._request_required = request_required_components or REQUEST_REQUIRED_COMPONENTS
        self._response_required = response_required_components or RESPONSE_REQUIRED_COMPONENTS

    async def verify_request(
        self,
        msg: HTTPMessage,
        *,
        require_components: bool = True,
    ) -> VerifyResult:
        return await self._verify(msg, is_response=False, require_components=require_components)

    async def verify_response(
        self,
        msg: HTTPMessage,
        *,
        expected_origin: str | None = None,
        expected_request_nonce: str | None = None,
        require_components: bool = True,
    ) -> VerifyResult:
        result = await self._verify(msg, is_response=True, require_components=require_components)
        # A caller passing expected_* is asking for a binding, so a missing or
        # unsigned header is a failure rather than a reason to skip the check.
        # Comparing an uncovered header would be worthless: it is not protected
        # by the signature, so anyone able to replay the response can set it.
        if expected_origin is not None:
            if not msg.has_header("untp-origin"):
                raise SignatureError("Response is missing Untp-Origin")
            if "untp-origin" not in result.covered_components:
                raise SignatureError("Response signature does not cover Untp-Origin")
            actual = msg.header("untp-origin")
            if actual != expected_origin:
                raise SignatureError(
                    f"Response Untp-Origin {actual!r} != expected {expected_origin!r}"
                )
        if expected_request_nonce is not None:
            if not msg.has_header("untp-request-nonce"):
                raise SignatureError("Response is missing Untp-Request-Nonce")
            if "untp-request-nonce" not in result.covered_components:
                raise SignatureError("Response signature does not cover Untp-Request-Nonce")
            actual = msg.header("untp-request-nonce")
            if actual != expected_request_nonce:
                raise SignatureError(
                    f"Response request-nonce {actual!r} != expected {expected_request_nonce!r}"
                )
        return result

    async def _verify(
        self,
        msg: HTTPMessage,
        *,
        is_response: bool,
        require_components: bool,
    ) -> VerifyResult:
        if not msg.has_header("Signature-Input"):
            raise MalformedSignature('Missing "Signature-Input" header')
        if not msg.has_header("Signature"):
            raise MalformedSignature('Missing "Signature" header')

        si = parse_signature_input(msg.header("Signature-Input"))
        sig_label, sig_raw = parse_signature(msg.header("Signature"))

        if si.label != sig_label:
            raise MalformedSignature(
                f"Signature-Input label {si.label!r} != Signature label {sig_label!r}"
            )

        tag = si.params.get("tag")
        if tag != self._tag:
            raise InvalidParameter(f"tag={tag!r} != expected {self._tag!r}")

        alg = si.params.get("alg")
        if alg != ED25519_ALG:
            raise InvalidParameter(f"alg={alg!r} != expected {ED25519_ALG!r}")

        keyid = si.params.get("keyid")
        if keyid is None:
            raise InvalidParameter("Missing 'keyid' parameter")
        _validate_keyid(keyid, is_response)

        _check_temporal(si.params, self._max_lifetime, self._clock_skew, is_response=is_response)

        nonce = si.params.get("nonce")
        if nonce is None:
            raise InvalidParameter("Missing 'nonce' parameter")

        if not is_response:
            _validate_nonce(nonce)
            if msg.has_header("untp-nonce"):
                header_nonce = msg.header("untp-nonce")
                if header_nonce != nonce:
                    raise InvalidParameter(
                        f"nonce param {nonce!r} != Untp-Nonce header {header_nonce!r}"
                    )

        if require_components:
            required = self._response_required if is_response else self._request_required
            _check_required_components(si.components, required)

        # Validate Content-Digest if covered
        if "content-digest" in si.components and msg.body is not None:
            validate_content_digest(msg.body, msg.header("content-digest"))

        # Build signature base and verify
        sig_base = build_signature_base(si.components, si.params, msg)
        public_key = self._resolver.resolve_public_key(keyid)
        if len(public_key) != 32:
            raise InvalidParameter(f"Public key must be 32 bytes, got {len(public_key)}")
        await asyncio.to_thread(_ed25519_verify, public_key, sig_base.encode(), sig_raw)

        return VerifyResult(
            label=si.label,
            keyid=keyid,
            covered_components=si.components,
            parameters=si.params,
            nonce=nonce,
        )
