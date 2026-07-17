"""Tests for protocol v2 wire fixtures — deterministic RFC 9421 vectors.

These tests verify that the frozen fixtures in tests/fixtures/protocol_v2/
are byte-for-byte reproducible from the same inputs. Any change to the
signature base construction, component ordering, or parameter format will
cause a test failure.

Independent implementations can use these fixtures to verify interoperability:
if they produce the same signature base and signature from the same Ed25519
seed, their RFC 9421 implementation is compatible with Bonnet v2.
"""

import os
import sys
import base64
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nacl.signing import SigningKey

from net.http_auth import (
    BonnetSigner, BonnetVerifier, KeyResolver, HTTPMessage,
    compute_content_digest, build_signature_base,
    parse_signature_input, parse_signature,
    BONNET_TAG, ED25519_ALG,
)

from tests.fixtures.protocol_v2.wire_fixtures import (
    VECTOR1_SEED, VECTOR1_PUBLIC, VECTOR1_PRIVATE,
    VECTOR2_SEED, VECTOR2_PUBLIC, VECTOR2_PRIVATE,
    FIXED_CREATED, FIXED_EXPIRES, FIXED_NONCE,
    REQUEST_URL, REQUEST_BODY, REQUEST_CONTENT_DIGEST,
    RESPONSE_BODY, RESPONSE_CONTENT_DIGEST,
    REQUEST_COMPONENTS, REQUEST_PARAMS,
    REQUEST_SIG_BASE, REQUEST_SIGNATURE, REQUEST_SIGNATURE_B64,
    REQUEST_SIG_INPUT, REQUEST_SIG_HEADER,
    RESPONSE_COMPONENTS, RESPONSE_PARAMS,
    RESPONSE_SIG_BASE, RESPONSE_SIGNATURE, RESPONSE_SIGNATURE_B64,
    RESPONSE_SIG_INPUT, RESPONSE_SIG_HEADER,
)


class TestKnownKeypairs:
    """RFC 8032 test vector keypairs must match known values."""

    def test_vector1_public_key(self):
        sk = SigningKey(VECTOR1_SEED)
        assert bytes(sk.verify_key) == VECTOR1_PUBLIC

    def test_vector2_public_key(self):
        sk = SigningKey(VECTOR2_SEED)
        assert bytes(sk.verify_key) == VECTOR2_PUBLIC

    def test_keys_are_32_bytes(self):
        assert len(VECTOR1_PRIVATE) == 32
        assert len(VECTOR1_PUBLIC) == 32
        assert len(VECTOR2_PRIVATE) == 32
        assert len(VECTOR2_PUBLIC) == 32


class TestRequestFixture:
    """The request fixture must be deterministic and verifiable."""

    def test_content_digest_matches_body(self):
        assert REQUEST_CONTENT_DIGEST == compute_content_digest(REQUEST_BODY)

    def test_signature_base_is_deterministic(self):
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
        base = build_signature_base(REQUEST_COMPONENTS, REQUEST_PARAMS, msg)
        assert base == REQUEST_SIG_BASE

    def test_signature_is_deterministic(self):
        sk = SigningKey(VECTOR1_SEED)
        sig = sk.sign(REQUEST_SIG_BASE.encode()).signature
        assert sig == REQUEST_SIGNATURE

    def test_signature_base64_matches(self):
        assert base64.b64encode(REQUEST_SIGNATURE).decode() == REQUEST_SIGNATURE_B64

    def test_signature_input_format(self):
        parsed = parse_signature_input(REQUEST_SIG_INPUT)
        assert parsed.label == "bonnet"
        assert parsed.components == REQUEST_COMPONENTS
        assert parsed.params["created"] == FIXED_CREATED
        assert parsed.params["keyid"] == f"ed25519:{VECTOR1_PUBLIC.hex()}"
        assert parsed.params["alg"] == "ed25519"
        assert parsed.params["tag"] == "bonnet-v2"
        assert parsed.params["nonce"] == FIXED_NONCE

    def test_signature_header_format(self):
        label, raw = parse_signature(REQUEST_SIG_HEADER)
        assert label == "bonnet"
        assert raw == REQUEST_SIGNATURE

    @pytest.mark.asyncio
    async def test_request_roundtrip_with_bonnet_signer(self):
        """Sign with BonnetSigner using the fixed key, verify the output matches
        the frozen fixture, then verify with BonnetVerifier."""
        msg = HTTPMessage(
            method="POST",
            url=REQUEST_URL,
            headers={
                "Content-Type": "application/vnd.bonnet.command",
                "Bonnet-Version": "2",
                "Bonnet-Nonce": FIXED_NONCE,
            },
            body=REQUEST_BODY,
        )
        msg.set_header("Content-Digest", compute_content_digest(REQUEST_BODY))

        signer = BonnetSigner(
            private_key=VECTOR1_PRIVATE,
            key_id=f"ed25519:{VECTOR1_PUBLIC.hex()}",
        )
        await signer.sign_request(
            msg,
            nonce=FIXED_NONCE,
            created=FIXED_CREATED,
            expires=FIXED_EXPIRES,
        )

        # The Signature-Input must match the frozen fixture
        assert msg.header("Signature-Input") == REQUEST_SIG_INPUT
        # The Signature must match the frozen fixture
        assert msg.header("Signature") == REQUEST_SIG_HEADER

        # Verify with BonnetVerifier
        class Resolver(KeyResolver):
            def resolve_public_key(self, key_id):
                return VECTOR1_PUBLIC

        verifier = BonnetVerifier(key_resolver=Resolver(), max_lifetime=10**9, clock_skew=10**9)
        result = await verifier.verify_request(msg)
        assert result.label == "bonnet"
        assert result.nonce == FIXED_NONCE
        assert result.keyid == f"ed25519:{VECTOR1_PUBLIC.hex()}"


class TestResponseFixture:
    """The response fixture must be deterministic and verifiable."""

    def test_content_digest_matches_body(self):
        assert RESPONSE_CONTENT_DIGEST == compute_content_digest(RESPONSE_BODY)

    def test_signature_base_is_deterministic(self):
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
        base = build_signature_base(RESPONSE_COMPONENTS, RESPONSE_PARAMS, msg)
        assert base == RESPONSE_SIG_BASE

    def test_signature_is_deterministic(self):
        sk = SigningKey(VECTOR2_SEED)
        sig = sk.sign(RESPONSE_SIG_BASE.encode()).signature
        assert sig == RESPONSE_SIGNATURE

    @pytest.mark.asyncio
    async def test_response_roundtrip_with_bonnet_signer(self):
        msg = HTTPMessage(
            method="POST",
            url=REQUEST_URL,
            headers={
                "Content-Type": "application/vnd.bonnet.command",
                "Bonnet-Version": "2",
                "Bonnet-Origin": "bbs.example.com",
            },
            status_code=200,
            body=RESPONSE_BODY,
        )
        msg.set_header("Content-Digest", compute_content_digest(RESPONSE_BODY))

        signer = BonnetSigner(
            private_key=VECTOR2_PRIVATE,
            key_id="origin:bbs.example.com",
        )
        await signer.sign_response(
            msg,
            request_nonce=FIXED_NONCE,
            created=FIXED_CREATED,
            expires=FIXED_EXPIRES,
        )

        assert msg.header("Signature-Input") == RESPONSE_SIG_INPUT
        assert msg.header("Signature") == RESPONSE_SIG_HEADER

        class Resolver(KeyResolver):
            def resolve_public_key(self, key_id):
                return VECTOR2_PUBLIC

        verifier = BonnetVerifier(key_resolver=Resolver(), max_lifetime=10**9, clock_skew=10**9)
        result = await verifier.verify_response(
            msg,
            expected_origin="bbs.example.com",
            expected_request_nonce=FIXED_NONCE,
        )
        assert result.label == "bonnet"
        assert "@status" in result.covered_components


class TestTamperEveryComponent:
    """Tampering with every mandatory covered component must fail verification."""

    @pytest.mark.asyncio
    async def test_tamper_method(self):
        await self._tamper_and_check(lambda msg: setattr(msg, "method", "GET"))

    @pytest.mark.asyncio
    async def test_tamper_authority(self):
        await self._tamper_and_check(lambda msg: setattr(msg, "url", "https://evil.com/v2/command"))

    @pytest.mark.asyncio
    async def test_tamper_target_uri(self):
        await self._tamper_and_check(lambda msg: setattr(msg, "url", "https://bbs.example.com/evil"))

    @pytest.mark.asyncio
    async def test_tamper_content_type(self):
        await self._tamper_and_check(lambda msg: msg.set_header("Content-Type", "text/plain"))

    @pytest.mark.asyncio
    async def test_tamper_content_digest(self):
        await self._tamper_and_check(lambda msg: msg.set_header("Content-Digest", "sha-256=:AAAA="))

    @pytest.mark.asyncio
    async def test_tamper_bonnet_version(self):
        await self._tamper_and_check(lambda msg: msg.set_header("Bonnet-Version", "1"))

    @pytest.mark.asyncio
    async def test_tamper_bonnet_nonce(self):
        import base64 as b64
        await self._tamper_and_check(lambda msg: msg.set_header(
            "Bonnet-Nonce", b64.urlsafe_b64encode(b"\x02" * 32).rstrip(b"=").decode()
        ))

    async def _tamper_and_check(self, tamper_fn):
        """Sign a request, tamper with one component, verify it fails."""
        from net.http_auth import SignatureError

        msg = HTTPMessage(
            method="POST",
            url=REQUEST_URL,
            headers={
                "Content-Type": "application/vnd.bonnet.command",
                "Bonnet-Version": "2",
                "Bonnet-Nonce": FIXED_NONCE,
            },
            body=REQUEST_BODY,
        )
        msg.set_header("Content-Digest", compute_content_digest(REQUEST_BODY))

        signer = BonnetSigner(
            private_key=VECTOR1_PRIVATE,
            key_id=f"ed25519:{VECTOR1_PUBLIC.hex()}",
        )
        await signer.sign_request(msg, nonce=FIXED_NONCE, created=FIXED_CREATED, expires=FIXED_EXPIRES)

        # Tamper
        tamper_fn(msg)

        class Resolver(KeyResolver):
            def resolve_public_key(self, key_id):
                return VECTOR1_PUBLIC

        verifier = BonnetVerifier(key_resolver=Resolver())
        with pytest.raises(SignatureError):
            await verifier.verify_request(msg)
