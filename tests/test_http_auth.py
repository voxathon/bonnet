"""Tests for src/bonnet/net/http_auth.py — Bonnet RFC 9421 Ed25519 profile."""

import asyncio
import base64
import hashlib
import os
import time

import pytest
from nacl.signing import SigningKey

from bonnet.net.http_auth import (
    BONNET_TAG,
    ED25519_ALG,
    BonnetSigner,
    BonnetVerifier,
    DigestMismatch,
    ExpiredSignature,
    FutureSignature,
    HTTPMessage,
    InvalidParameter,
    InvalidSignature,
    KeyResolver,
    MalformedSignature,
    MissingComponent,
    VerifyResult,
    _validate_keyid,
    _validate_nonce,
    build_signature_base,
    compute_content_digest,
    parse_signature,
    parse_signature_input,
    resolve_component,
    serialize_signature,
    serialize_signature_input,
    validate_content_digest,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def keypair():
    sk = SigningKey.generate()
    return bytes(sk), bytes(sk.verify_key)


@pytest.fixture
def key_resolver(keypair):
    priv, pub = keypair

    class Resolver(KeyResolver):
        def resolve_private_key(self, key_id):
            return priv

        def resolve_public_key(self, key_id):
            return pub

    return Resolver()


@pytest.fixture
def valid_nonce():
    raw = os.urandom(32)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@pytest.fixture
def request_msg(valid_nonce):
    body = b"\x11"
    return HTTPMessage(
        method="POST",
        url="https://bonnet.example.com/v2/command",
        headers={
            "Content-Type": "application/vnd.bonnet.command",
            "Content-Digest": compute_content_digest(body),
            "Bonnet-Protocol": "bonnet-firehose-1",
            "Bonnet-Nonce": valid_nonce,
        },
        body=body,
    )


@pytest.fixture
def response_msg(valid_nonce):
    body = b"\x00\x01\x02"
    return HTTPMessage(
        method="POST",
        url="https://bonnet.example.com/v2/command",
        headers={
            "Content-Type": "application/vnd.bonnet.command",
            "Content-Digest": compute_content_digest(body),
            "Bonnet-Protocol": "bonnet-firehose-1",
            "Bonnet-Origin": "bonnet.example.com",
        },
        status_code=200,
        body=body,
    )


# ---------------------------------------------------------------------------
# Content-Digest tests
# ---------------------------------------------------------------------------


class TestContentDigest:
    def test_compute_roundtrip(self):
        body = b"hello world"
        cd = compute_content_digest(body)
        assert cd.startswith("sha-256=:")
        assert cd.endswith(":")
        validate_content_digest(body, cd)

    def test_empty_body(self):
        cd = compute_content_digest(b"")
        validate_content_digest(b"", cd)

    def test_mismatch_raises(self):
        cd = compute_content_digest(b"correct")
        with pytest.raises(DigestMismatch):
            validate_content_digest(b"tampered", cd)

    def test_malformed_raises(self):
        with pytest.raises(DigestMismatch):
            validate_content_digest(b"x", "not-a-digest")
        with pytest.raises(DigestMismatch):
            validate_content_digest(b"x", "sha-256=:!!!:")

    def test_known_vector(self):
        body = b"hello world"
        expected = hashlib.sha256(body).digest()
        expected_cd = f"sha-256=:{base64.b64encode(expected).decode()}:"
        assert compute_content_digest(body) == expected_cd


# ---------------------------------------------------------------------------
# Signature-Input parsing / serialization
# ---------------------------------------------------------------------------


class TestSignatureInput:
    def test_parse_roundtrip(self):
        header = (
            'bonnet=("@method" "@authority" "content-digest" "bonnet-protocol" "bonnet-nonce");'
            'created=1234;keyid="ed25519:abc";alg="ed25519";tag="bonnet-firehose-1";nonce="xyz"'
        )
        parsed = parse_signature_input(header)
        assert parsed.label == "bonnet"
        assert parsed.components == [
            "@method",
            "@authority",
            "content-digest",
            "bonnet-protocol",
            "bonnet-nonce",
        ]
        assert parsed.params["created"] == 1234
        assert parsed.params["keyid"] == "ed25519:abc"
        assert parsed.params["alg"] == "ed25519"
        assert parsed.params["tag"] == "bonnet-firehose-1"
        assert parsed.params["nonce"] == "xyz"

    def test_serialize_roundtrip(self):
        components = ["@method", "@authority", "content-digest"]
        params = {
            "created": 1234,
            "keyid": "ed25519:abc",
            "alg": "ed25519",
            "tag": "bonnet-firehose-1",
        }
        header = serialize_signature_input("bonnet", components, params)
        parsed = parse_signature_input(header)
        assert parsed.label == "bonnet"
        assert parsed.components == components
        assert parsed.params["created"] == 1234

    def test_parse_empty_components(self):
        header = 'sig=();created=1234;keyid="k"'
        parsed = parse_signature_input(header)
        assert parsed.components == []
        assert parsed.params["created"] == 1234

    def test_parse_with_expires(self):
        header = (
            'bonnet=("@method");created=100;keyid="ed25519:k";'
            'alg="ed25519";expires=160;nonce="n";tag="bonnet-v2"'
        )
        parsed = parse_signature_input(header)
        assert parsed.params["expires"] == 160

    def test_parse_missing_equals(self):
        with pytest.raises(MalformedSignature):
            parse_signature_input("noquals")

    def test_parse_missing_paren(self):
        with pytest.raises(MalformedSignature):
            parse_signature_input('bonnet="@method"')


# ---------------------------------------------------------------------------
# Signature header parsing / serialization
# ---------------------------------------------------------------------------


class TestSignatureHeader:
    def test_roundtrip(self):
        raw = os.urandom(64)
        header = serialize_signature("bonnet", raw)
        label, decoded = parse_signature(header)
        assert label == "bonnet"
        assert decoded == raw

    def test_parse_missing_equals(self):
        with pytest.raises(MalformedSignature):
            parse_signature("nolabel")

    def test_parse_missing_colons(self):
        with pytest.raises(MalformedSignature):
            parse_signature("bonnet=notcolons")


# ---------------------------------------------------------------------------
# Component resolution
# ---------------------------------------------------------------------------


class TestComponentResolution:
    def test_method(self, request_msg):
        assert resolve_component("@method", request_msg) == "POST"

    def test_authority(self, request_msg):
        assert resolve_component("@authority", request_msg) == "bonnet.example.com"

    def test_target_uri(self, request_msg):
        assert (
            resolve_component("@target-uri", request_msg) == "https://bonnet.example.com/v2/command"
        )

    def test_header_field(self, request_msg):
        assert resolve_component("content-type", request_msg) == "application/vnd.bonnet.command"

    def test_missing_header(self, request_msg):
        with pytest.raises(MalformedSignature):
            resolve_component("x-missing", request_msg)

    def test_status_response(self, response_msg):
        assert resolve_component("@status", response_msg) == "200"

    def test_status_request_rejected(self, request_msg):
        with pytest.raises(MalformedSignature):
            resolve_component("@status", request_msg)


# ---------------------------------------------------------------------------
# Signature base construction
# ---------------------------------------------------------------------------


class TestSignatureBase:
    def test_structure(self, request_msg):
        components = ["@method", "@authority", "content-digest"]
        params = {
            "created": 1234,
            "keyid": "ed25519:abc",
            "alg": "ed25519",
            "tag": "bonnet-v2",
            "nonce": "n",
        }
        base = build_signature_base(components, params, request_msg)
        lines = base.split("\n")
        assert lines[0] == '"@method": POST'
        assert lines[1] == '"@authority": bonnet.example.com'
        assert lines[2] == '"content-digest": ' + request_msg.header("content-digest")
        assert lines[3].startswith('"@signature-params": ')
        assert '("@method" "@authority" "content-digest")' in lines[3]

    def test_duplicate_component(self, request_msg):
        with pytest.raises(MalformedSignature):
            build_signature_base(["@method", "@method"], {}, request_msg)


# ---------------------------------------------------------------------------
# Sign / verify roundtrip
# ---------------------------------------------------------------------------


class TestSignVerifyRoundtrip:
    @pytest.mark.asyncio
    async def test_request_roundtrip(self, keypair, key_resolver, request_msg, valid_nonce):
        priv, pub = keypair
        signer = BonnetSigner(private_key=priv, key_id="ed25519:" + pub.hex())
        now = int(time.time())
        await signer.sign_request(request_msg, nonce=valid_nonce, created=now, expires=now + 60)

        assert request_msg.has_header("Signature-Input")
        assert request_msg.has_header("Signature")

        verifier = BonnetVerifier(key_resolver=key_resolver)
        result = await verifier.verify_request(request_msg)
        assert result.label == "bonnet"
        assert result.keyid == "ed25519:" + pub.hex()
        assert result.nonce == valid_nonce
        assert result.parameters["tag"] == BONNET_TAG
        assert result.parameters["alg"] == ED25519_ALG
        assert "@method" in result.covered_components
        assert "bonnet-nonce" in result.covered_components

    @pytest.mark.asyncio
    async def test_response_roundtrip(self, keypair, key_resolver, response_msg, valid_nonce):
        priv, pub = keypair
        signer = BonnetSigner(private_key=priv, key_id="origin:bonnet.example.com")
        await signer.sign_response(response_msg, request_nonce=valid_nonce)

        verifier = BonnetVerifier(key_resolver=key_resolver)
        result = await verifier.verify_response(
            response_msg,
            expected_origin="bonnet.example.com",
            expected_request_nonce=valid_nonce,
        )
        assert "@status" in result.covered_components
        assert "bonnet-origin" in result.covered_components
        assert "bonnet-request-nonce" in result.covered_components

    @pytest.mark.asyncio
    async def test_request_with_username(self, keypair, key_resolver, request_msg, valid_nonce):
        priv, pub = keypair
        request_msg.set_header("Bonnet-Username", "alice")
        signer = BonnetSigner(private_key=priv, key_id="ed25519:" + pub.hex())
        now = int(time.time())
        await signer.sign_request(
            request_msg, nonce=valid_nonce, created=now, expires=now + 60, include_username=True
        )

        verifier = BonnetVerifier(key_resolver=key_resolver)
        result = await verifier.verify_request(request_msg)
        assert "bonnet-username" in result.covered_components


# ---------------------------------------------------------------------------
# Rejection tests
# ---------------------------------------------------------------------------


class TestRejections:
    @pytest.mark.asyncio
    async def test_wrong_tag_rejected(self, keypair, key_resolver, request_msg, valid_nonce):
        priv, pub = keypair
        signer = BonnetSigner(private_key=priv, key_id="ed25519:" + pub.hex(), tag="wrong-tag")
        now = int(time.time())
        await signer.sign_request(request_msg, nonce=valid_nonce, created=now, expires=now + 60)
        verifier = BonnetVerifier(key_resolver=key_resolver, tag="bonnet-v2")
        with pytest.raises(InvalidParameter, match="tag"):
            await verifier.verify_request(request_msg)

    @pytest.mark.asyncio
    async def test_tampered_body_rejected(self, keypair, key_resolver, request_msg, valid_nonce):
        priv, pub = keypair
        signer = BonnetSigner(private_key=priv, key_id="ed25519:" + pub.hex())
        now = int(time.time())
        await signer.sign_request(request_msg, nonce=valid_nonce, created=now, expires=now + 60)
        # Tamper body but NOT the Content-Digest header — the digest check should catch it
        request_msg.body = b"\x12"
        verifier = BonnetVerifier(key_resolver=key_resolver)
        with pytest.raises(DigestMismatch):
            await verifier.verify_request(request_msg)

    @pytest.mark.asyncio
    async def test_tampered_signature_rejected(
        self, keypair, key_resolver, request_msg, valid_nonce
    ):
        priv, pub = keypair
        signer = BonnetSigner(private_key=priv, key_id="ed25519:" + pub.hex())
        now = int(time.time())
        await signer.sign_request(request_msg, nonce=valid_nonce, created=now, expires=now + 60)
        # Flip a bit in the Signature header
        sig_header = request_msg.header("Signature")
        tampered = sig_header[:-3] + ("A" if sig_header[-3] != "A" else "B") + sig_header[-2:]
        request_msg.set_header("Signature", tampered)
        verifier = BonnetVerifier(key_resolver=key_resolver)
        with pytest.raises((InvalidSignature, MalformedSignature)):
            await verifier.verify_request(request_msg)

    @pytest.mark.asyncio
    async def test_missing_required_component(
        self, keypair, key_resolver, request_msg, valid_nonce
    ):
        priv, pub = keypair
        # Sign with a minimal set missing required components
        signer = BonnetSigner(private_key=priv, key_id="ed25519:" + pub.hex())
        # Manually sign with incomplete components
        components = [
            "@method",
            "@authority",
        ]  # missing content-digest, bonnet-protocol, bonnet-nonce
        now = int(time.time())
        params = {
            "created": now,
            "expires": now + 60,
            "keyid": "ed25519:" + pub.hex(),
            "alg": ED25519_ALG,
            "nonce": valid_nonce,
            "tag": BONNET_TAG,
        }
        sig_base = build_signature_base(components, params, request_msg)
        sig = (
            signer._ed25519_sign_helper(sig_base)
            if hasattr(signer, "_ed25519_sign_helper")
            else None
        )
        # Use the internal function directly
        from bonnet.net.http_auth import _ed25519_sign

        sig = _ed25519_sign(priv, sig_base.encode())
        request_msg.set_header(
            "Signature-Input", serialize_signature_input("bonnet", components, params)
        )
        request_msg.set_header("Signature", serialize_signature("bonnet", sig))

        verifier = BonnetVerifier(key_resolver=key_resolver)
        with pytest.raises(MissingComponent):
            await verifier.verify_request(request_msg)

    @pytest.mark.asyncio
    async def test_expired_signature(self, keypair, key_resolver, request_msg, valid_nonce):
        priv, pub = keypair
        signer = BonnetSigner(private_key=priv, key_id="ed25519:" + pub.hex())
        old = int(time.time()) - 120
        await signer.sign_request(request_msg, nonce=valid_nonce, created=old, expires=old + 1)
        verifier = BonnetVerifier(key_resolver=key_resolver)
        with pytest.raises(ExpiredSignature):
            await verifier.verify_request(request_msg)

    @pytest.mark.asyncio
    async def test_future_signature(self, keypair, key_resolver, request_msg, valid_nonce):
        priv, pub = keypair
        signer = BonnetSigner(private_key=priv, key_id="ed25519:" + pub.hex())
        future = int(time.time()) + 120
        await signer.sign_request(request_msg, nonce=valid_nonce, created=future)
        verifier = BonnetVerifier(key_resolver=key_resolver)
        with pytest.raises(FutureSignature):
            await verifier.verify_request(request_msg)

    @pytest.mark.asyncio
    async def test_excessive_lifetime(self, keypair, key_resolver, request_msg, valid_nonce):
        priv, pub = keypair
        signer = BonnetSigner(private_key=priv, key_id="ed25519:" + pub.hex())
        now = int(time.time())
        await signer.sign_request(request_msg, nonce=valid_nonce, created=now, expires=now + 120)
        verifier = BonnetVerifier(key_resolver=key_resolver, max_lifetime=60)
        with pytest.raises(InvalidParameter, match="lifetime"):
            await verifier.verify_request(request_msg)

    @pytest.mark.asyncio
    async def test_wrong_nonce_param(self, keypair, key_resolver, request_msg, valid_nonce):
        priv, pub = keypair
        signer = BonnetSigner(private_key=priv, key_id="ed25519:" + pub.hex())
        different_nonce = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        now = int(time.time())
        await signer.sign_request(request_msg, nonce=different_nonce, created=now, expires=now + 60)
        # The Bonnet-Nonce header still has the old nonce
        verifier = BonnetVerifier(key_resolver=key_resolver)
        with pytest.raises(InvalidParameter, match="nonce param"):
            await verifier.verify_request(request_msg)

    @pytest.mark.asyncio
    async def test_missing_signature_input(self, key_resolver, request_msg):
        verifier = BonnetVerifier(key_resolver=key_resolver)
        with pytest.raises(MalformedSignature, match="Signature-Input"):
            await verifier.verify_request(request_msg)

    @pytest.mark.asyncio
    async def test_missing_signature(self, key_resolver, request_msg):
        request_msg.set_header("Signature-Input", 'bonnet=("@method");created=1')
        verifier = BonnetVerifier(key_resolver=key_resolver)
        with pytest.raises(MalformedSignature, match="Signature"):
            await verifier.verify_request(request_msg)

    @pytest.mark.asyncio
    async def test_wrong_key(self, keypair, request_msg, valid_nonce):
        priv, pub = keypair
        other_priv = bytes(SigningKey.generate())
        other_pub = bytes(SigningKey(other_priv).verify_key)

        class WrongResolver(KeyResolver):
            def resolve_public_key(self, key_id):
                return other_pub

        signer = BonnetSigner(private_key=priv, key_id="ed25519:" + pub.hex())
        now = int(time.time())
        await signer.sign_request(request_msg, nonce=valid_nonce, created=now, expires=now + 60)
        verifier = BonnetVerifier(key_resolver=WrongResolver())
        with pytest.raises(InvalidSignature):
            await verifier.verify_request(request_msg)


# ---------------------------------------------------------------------------
# keyid and nonce validation
# ---------------------------------------------------------------------------


class TestKeyidValidation:
    def test_valid_request_keyid(self):
        _validate_keyid("ed25519:" + "a" * 64, is_response=False)

    def test_request_keyid_wrong_prefix(self):
        with pytest.raises(InvalidParameter):
            _validate_keyid("rsa:abc", is_response=False)

    def test_request_keyid_wrong_length(self):
        with pytest.raises(InvalidParameter):
            _validate_keyid("ed25519:abc", is_response=False)

    def test_request_keyid_uppercase_hex(self):
        with pytest.raises(InvalidParameter):
            _validate_keyid("ed25519:" + "A" * 64, is_response=False)

    def test_valid_response_keyid(self):
        _validate_keyid("origin:bonnet.example.com", is_response=True)

    def test_response_keyid_wrong_prefix(self):
        with pytest.raises(InvalidParameter):
            _validate_keyid("ed25519:abc", is_response=True)


class TestNonceValidation:
    def test_valid_nonce(self):
        raw = os.urandom(32)
        nonce = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        _validate_nonce(nonce)

    def test_padded_nonce_rejected(self):
        raw = os.urandom(32)
        nonce = base64.urlsafe_b64encode(raw).decode()  # has padding
        with pytest.raises(InvalidParameter, match="padding"):
            _validate_nonce(nonce)

    def test_short_nonce_rejected(self):
        raw = os.urandom(16)
        nonce = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        with pytest.raises(InvalidParameter, match="32 bytes"):
            _validate_nonce(nonce)

    def test_invalid_base64_rejected(self):
        with pytest.raises(InvalidParameter):
            _validate_nonce("!!!notbase64!!!")


# ---------------------------------------------------------------------------
# pynacl raw key compatibility
# ---------------------------------------------------------------------------


class TestPynaclCompat:
    def test_raw_keys_work(self):
        sk = SigningKey.generate()
        priv = bytes(sk)
        pub = bytes(sk.verify_key)
        assert len(priv) == 32
        assert len(pub) == 32

        msg = b"test message"
        from bonnet.net.http_auth import _ed25519_sign, _ed25519_verify

        sig = _ed25519_sign(priv, msg)
        assert len(sig) == 64
        _ed25519_verify(pub, msg, sig)  # no exception = pass

    def test_wrong_key_verify_fails(self):
        sk1 = SigningKey.generate()
        sk2 = SigningKey.generate()
        from bonnet.net.http_auth import _ed25519_sign, _ed25519_verify

        sig = _ed25519_sign(bytes(sk1), b"msg")
        with pytest.raises(InvalidSignature):
            _ed25519_verify(bytes(sk2.verify_key), b"msg", sig)


# ---------------------------------------------------------------------------
# Async interface tests
# ---------------------------------------------------------------------------


class TestAsyncInterface:
    @pytest.mark.asyncio
    async def test_sign_returns_awaitable(self, keypair, request_msg, valid_nonce):
        priv, pub = keypair
        signer = BonnetSigner(private_key=priv, key_id="ed25519:" + pub.hex())
        now = int(time.time())
        coro = signer.sign_request(request_msg, nonce=valid_nonce, created=now, expires=now + 60)
        assert asyncio.iscoroutine(coro)
        await coro

    @pytest.mark.asyncio
    async def test_verify_returns_awaitable(self, keypair, key_resolver, request_msg, valid_nonce):
        priv, pub = keypair
        signer = BonnetSigner(private_key=priv, key_id="ed25519:" + pub.hex())
        now = int(time.time())
        await signer.sign_request(request_msg, nonce=valid_nonce, created=now, expires=now + 60)
        verifier = BonnetVerifier(key_resolver=key_resolver)
        coro = verifier.verify_request(request_msg)
        assert asyncio.iscoroutine(coro)
        result = await coro
        assert isinstance(result, VerifyResult)


# ---------------------------------------------------------------------------
# Serialize / parse interop with upstream library format
# ---------------------------------------------------------------------------


class TestFormatCompatibility:
    def test_signature_input_format_matches_upstream(self, keypair, request_msg, valid_nonce):
        """Verify our Signature-Input format is structurally compatible with RFC 9421."""
        priv, pub = keypair
        signer = BonnetSigner(private_key=priv, key_id="ed25519:" + pub.hex())
        now = int(time.time())
        asyncio.run(
            signer.sign_request(request_msg, nonce=valid_nonce, created=now, expires=now + 60)
        )

        si = request_msg.header("Signature-Input")
        # Must start with label=
        assert si.startswith("bonnet=(")
        # Must contain quoted component IDs
        assert '"@method"' in si
        assert '"@authority"' in si
        assert '"content-digest"' in si
        # Must have parameters
        assert "created=" in si
        assert 'keyid="ed25519:' in si
        assert 'alg="ed25519"' in si
        assert f'tag="{BONNET_TAG}"' in si

    def test_signature_format(self, keypair, request_msg, valid_nonce):
        priv, pub = keypair
        signer = BonnetSigner(private_key=priv, key_id="ed25519:" + pub.hex())
        now = int(time.time())
        asyncio.run(
            signer.sign_request(request_msg, nonce=valid_nonce, created=now, expires=now + 60)
        )

        sig = request_msg.header("Signature")
        assert sig.startswith("bonnet=:")
        assert sig.endswith(":")
        # The base64 part should decode to 64 bytes (Ed25519 signature)
        b64_part = sig[len("bonnet=:") : -1]
        raw = base64.b64decode(b64_part)
        assert len(raw) == 64
