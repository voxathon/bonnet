"""A response has to be attributable to the origin, not merely signed.

The keyid asymmetry is the whole mechanism. A request is keyed
`ed25519:<hex>` because the client's key *is* its identity and the server
resolves nothing. A response is keyed `origin:<name>` so the client must look
the key up in what it pinned for that name.

Getting this backwards is not a small thing: an `ed25519:` response keyid
carries the key it is checked against, so verifying it establishes only that
whoever wrote the header holds the matching private key — true of anyone who
can answer the connection. That was the form the server sent, so the pin
decided whether *discovery* succeeded and nothing after it.
"""

import pytest

from bonnet.core.crypto import Identity
from bonnet.net.firehose_transport import FirehoseTransport, _ServerKeyResolver
from bonnet.net.http_auth import (
    UNTP_LABEL,
    UNTP_TAG,
    BonnetSigner,
    BonnetVerifier,
    HTTPMessage,
    InvalidParameter,
    SignatureError,
    _validate_keyid,
    compute_content_digest,
)

ORIGIN = "relay.example"

RESPONSE_COMPONENTS = [
    "@status",
    "content-type",
    "content-digest",
    "untp-version",
    "untp-origin",
    "untp-request-nonce",
]


def _verifier(pinned_key: bytes, origin: str = ORIGIN) -> BonnetVerifier:
    """A verifier wired exactly as `FirehoseTransport.discover` wires one."""
    return BonnetVerifier(
        key_resolver=_ServerKeyResolver(pinned_key, origin),
        tag=UNTP_TAG,
        max_lifetime=60,
        clock_skew=30,
    )


async def _signed_response(identity: Identity, key_id: str, origin: str = ORIGIN) -> HTTPMessage:
    body = b"\x00payload"
    msg = HTTPMessage(
        method="POST",
        url=f"https://{origin}/command",
        status_code=200,
        headers={
            "content-type": "application/octet-stream",
            "content-digest": compute_content_digest(body),
            "untp-version": "1",
            "untp-origin": origin,
        },
        body=body,
    )
    signer = BonnetSigner(
        private_key=identity.private_key,
        key_id=key_id,
        tag=UNTP_TAG,
        label=UNTP_LABEL,
        response_components=RESPONSE_COMPONENTS,
    )
    await signer.sign_response(msg, request_nonce="n0nce")
    return msg


# ---------------------------------------------------------------------------
# the hole, closed
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_a_key_the_client_never_pinned_is_refused():
    """The original demonstration, inverted. An attacker signs a response with
    a key of their choosing and names it in the keyid; that used to verify
    clean, because the resolver returned the key out of the keyid itself."""
    pinned = Identity.generate()
    attacker = Identity.generate()

    msg = await _signed_response(attacker, f"ed25519:{attacker.public_key.hex()}")

    with pytest.raises(SignatureError):
        await _verifier(pinned.public_key).verify_response(
            msg, expected_origin=ORIGIN, expected_request_nonce="n0nce"
        )


@pytest.mark.anyio
async def test_the_ed25519_response_form_is_refused_outright():
    """Even signed by the pinned key. The form is the problem: it invites a
    verifier to take the key from the message it is checking."""
    pinned = Identity.generate()

    msg = await _signed_response(pinned, f"ed25519:{pinned.public_key.hex()}")

    with pytest.raises(InvalidParameter, match="origin:<name>"):
        await _verifier(pinned.public_key).verify_response(
            msg, expected_origin=ORIGIN, expected_request_nonce="n0nce"
        )


@pytest.mark.anyio
async def test_the_pinned_key_under_the_expected_origin_verifies():
    pinned = Identity.generate()

    msg = await _signed_response(pinned, f"origin:{ORIGIN}")

    result = await _verifier(pinned.public_key).verify_response(
        msg, expected_origin=ORIGIN, expected_request_nonce="n0nce"
    )
    assert result.keyid == f"origin:{ORIGIN}"


@pytest.mark.anyio
async def test_a_key_pinned_for_a_different_origin_does_not_answer_for_this_one():
    """`untp-origin` alone cannot carry this: the header is covered by the same
    signature, so the party being checked writes both."""
    pinned = Identity.generate()

    msg = await _signed_response(pinned, "origin:somewhere-else.example")

    with pytest.raises(SignatureError, match="names origin"):
        await _verifier(pinned.public_key).verify_response(
            msg, expected_origin=ORIGIN, expected_request_nonce="n0nce"
        )


def test_the_resolver_never_returns_a_key_from_the_keyid():
    pinned = Identity.generate()
    attacker = Identity.generate()
    resolver = _ServerKeyResolver(pinned.public_key, ORIGIN)

    assert resolver.resolve_public_key(f"origin:{ORIGIN}") == pinned.public_key
    # InvalidParameter subclasses SignatureError, so a resolution failure is
    # caught by the same handler as any other verification failure.
    with pytest.raises(SignatureError):
        resolver.resolve_public_key(f"ed25519:{attacker.public_key.hex()}")


def test_keyid_forms_are_asymmetric_by_direction():
    _validate_keyid("origin:bonnet.example", is_response=True)
    _validate_keyid("ed25519:" + "ab" * 32, is_response=False)

    # a request may not name an origin: the server resolves nothing, so a name
    # would be a key it has no way to look up
    with pytest.raises(InvalidParameter):
        _validate_keyid("origin:bonnet.example", is_response=False)
    # and a response may not carry its own key
    with pytest.raises(InvalidParameter):
        _validate_keyid("ed25519:" + "ab" * 32, is_response=True)


# ---------------------------------------------------------------------------
# origin vs the address actually dialed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "origin", "expected"),
    [
        ("https://bbs.example:2272", "bbs.example", True),
        ("https://bbs.example", "BBS.Example", True),
        ("https://bbs.example", "bbs.example.", True),
        ("https://cdn-edge-7.example", "bbs.example", False),
        ("https://bbs.example", "", False),
    ],
)
def test_origin_is_compared_to_the_dialed_host(url, origin, expected):
    """Nothing compared these before: `discover` pinned under whatever name the
    body claimed, and the only other check compared that claim to a header the
    same party wrote."""
    t = FirehoseTransport(url)
    t._server_origin = origin
    assert t._origin_matches_dialed_host() is expected
