"""Signed-HTTP command transport for the firehose protocol.

Handles discovery, origin-key pinning, RFC 9421 request signing, response
verification, and the binary command round-trip. Shared by the server's
federation sync (bonnet.net.firehose_sync) and the client library
(bonnet.gateway.firehose_client), which layers typed methods on top.

Pinning has two modes, and the split is deliberate: this module *reports* what
kind of key event happened and never decides what to do about it. Under
PIN_MODE_AUTO — the default, and what federation sync uses — a key is adopted
on first contact and rolled forward when a rotation chain connects it, which
is the historical behaviour. Under PIN_MODE_CONFIRM nothing is adopted at all;
the presented key is recorded as pending and PinConfirmationRequired is
raised for the caller to resolve. The gateway chooses the mode; see
`bonnet.gateway.tools._pin_mode_for`.
"""

from __future__ import annotations

import base64
import os
import time
from urllib.parse import urlparse

import httpx

from bonnet.core.crypto import Identity
from bonnet.core.kinds import KIND_ORIGIN_KEY_ROTATE
from bonnet.core.record import (
    encode_unsigned_record,
    normalize_origin,
    verify_key_rotation_proof,
    verify_record_signature,
)
from bonnet.core.trust import TrustStore
from bonnet.net.firehose_models import DiscoveryInfo
from bonnet.net.firehose_wire import (
    build_event_range,
    build_key_epochs,
    parse_event_range_response,
    parse_key_epochs_response,
)
from bonnet.net.http_auth import (
    UNTP_LABEL,
    UNTP_TAG,
    BonnetSigner,
    BonnetVerifier,
    HTTPMessage,
    InvalidParameter,
    KeyResolver,
    SignatureError,
    compute_content_digest,
)


class FirehoseClientError(Exception):
    pass


#: Adopt any key on first contact, and any change a rotation chain connects.
#: The historical behaviour, and what every non-gateway caller wants.
PIN_MODE_AUTO = "auto"

#: Adopt nothing without an explicit decision. Records the presented key as
#: pending and raises PinConfirmationRequired.
PIN_MODE_CONFIRM = "confirm"


class PinConfirmationRequired(FirehoseClientError):
    """A key was presented that this client has not agreed to trust.

    Subclasses FirehoseClientError deliberately: a caller that catches the
    broad type and treats this as a failed connection is *right* to, because
    the connection did fail — nothing was pinned and nothing is trusted.
    Handling it specially is an improvement, not a correctness requirement.

    `evidence` describes what the origin offered in support of a changed key.
    It is the origin's own account, signed by the key being replaced, and is
    carried for the caller to weigh — it does not decide anything here.
    """

    def __init__(
        self,
        origin: str,
        presented_key: bytes,
        kind: str,
        evidence: str = "",
        host_match: bool = True,
    ):
        self.origin = origin
        self.presented_key = presented_key
        self.fingerprint = presented_key.hex()
        self.kind = kind  # "new" | "changed"
        self.evidence = evidence
        #: Whether the origin this server claims is the host that was dialed.
        #: An origin legitimately served from an unrelated address is a normal
        #: deployment, so this is reported for the caller to weigh rather than
        #: enforced — but it is the difference between "bbs.example answered at
        #: bbs.example" and "something at unrelated.host says it is bbs.example",
        #: and only the first is checkable against a TLS certificate.
        self.host_match = host_match
        super().__init__(
            f"origin '{origin}' presented a key this client has not accepted "
            f"({kind}); fingerprint {self.fingerprint}"
        )


class _ServerKeyResolver(KeyResolver):
    """Resolves a response's keyid to the key this client pinned for that origin.

    Only `origin:<name>` resolves, and only to the pinned key. There used to be
    an `ed25519:<hex>` branch that returned `bytes.fromhex(key_id[8:])` — the
    key named *in the keyid being checked* — and since the server signed its
    responses with exactly that form, it was the branch every real response
    took. Verification then established only that whoever wrote the header held
    the matching private key, which any party answering the connection does. It
    proved a signature existed, not whose it was, so the pin decided whether
    *discovery* succeeded and nothing after it.

    The origin in the keyid must also be the one this client connected to. A
    response signed by a key we pinned for some other origin is not this
    origin's answer, and saying so here keeps `untp-origin` from being the only
    thing tying a response to a name.
    """

    def __init__(self, server_pubkey: bytes, server_origin: str):
        self._server_pubkey = server_pubkey
        self._server_origin = server_origin

    def resolve_public_key(self, key_id: str) -> bytes:
        # InvalidParameter, not ValueError: it subclasses SignatureError, which
        # is what `_verify_response` catches and turns into a FirehoseClientError.
        # A bare ValueError escapes that handler and surfaces as an unhandled
        # error from a *verification failure*, which is the one case that must
        # always read as one. Matches FirehoseKeyResolver on the server side.
        if not key_id.startswith("origin:"):
            raise InvalidParameter(f"Response keyid must be origin:<name>, got: {key_id[:40]!r}")
        named = key_id[7:]
        if named != self._server_origin:
            raise InvalidParameter(
                f"Response keyid names origin {named!r}, expected {self._server_origin!r}"
            )
        return self._server_pubkey


class FirehoseTransport:
    """HTTP transport for the firehose protocol."""

    def __init__(
        self,
        base_url: str,
        timeout: float = 30.0,
        verify: bool | str = True,
        trust_store_path: str = None,
        pin_mode: str = PIN_MODE_AUTO,
    ):
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._verify = verify
        self._http = httpx.AsyncClient(timeout=timeout, verify=verify)
        self._identity: Identity | None = None
        self._server_pubkey: bytes | None = None
        self._server_origin: str | None = None
        self._anonymous_key: bytes | None = None
        self._anonymous_private_key: bytes | None = None
        self._discovery: DiscoveryInfo | None = None
        self._signer: BonnetSigner | None = None
        self._verifier: BonnetVerifier | None = None
        self._trust_store_path = trust_store_path
        self._pin_mode = pin_mode
        self._trust_store: TrustStore | None = None
        if trust_store_path:
            self._trust_store = TrustStore(trust_store_path)
        self._username: str = ""

    async def close(self) -> None:
        await self._http.aclose()

    @property
    def server_origin(self) -> str | None:
        """The connected server's origin, or None before discovery."""
        return self._server_origin

    @property
    def discovery(self) -> DiscoveryInfo | None:
        """The parsed discovery document, or None before discovery."""
        return self._discovery

    # ------------------------------------------------------------------
    # Discovery and connection
    # ------------------------------------------------------------------

    async def discover(self) -> DiscoveryInfo:
        """Fetch and parse the discovery document.

        The discovery response is signed by the server's own key. We parse
        the key from the response body, construct a verifier, and verify
        the response signature before pinning. On first contact this is
        self-attesting (circular) — TLS provides the independent trust
        anchor when enabled. TOFU pinning persists the key for subsequent
        connections.
        """
        try:
            resp = await self._http.get(f"{self._base_url}/.well-known/untp")
        except httpx.HTTPError as e:
            raise FirehoseClientError(
                f"could not reach {self._base_url}: {e or type(e).__name__}"
            ) from e
        resp.raise_for_status()
        data = resp.json()
        info = DiscoveryInfo(
            protocol=data.get("protocol", ""),
            origin=data.get("origin", ""),
            hostname=data.get("hostname", ""),
            public_key=data.get("public_key", ""),
            anonymous_key=data.get("anonymous_key", ""),
            anonymous_private_key=data.get("anonymous_private_key", ""),
            command_endpoint=data.get("command_endpoint", "/command"),
            capabilities=data.get("capabilities", []),
            known_origins=data.get("known_origins", []),
        )
        self._server_pubkey = bytes.fromhex(info.public_key)
        self._server_origin = info.origin
        self._anonymous_key = bytes.fromhex(info.anonymous_key)
        self._anonymous_private_key = bytes.fromhex(info.anonymous_private_key)
        self._discovery = info

        self._verifier = BonnetVerifier(
            key_resolver=_ServerKeyResolver(self._server_pubkey, self._server_origin),
            tag=UNTP_TAG,
            max_lifetime=60,
            clock_skew=30,
            request_required_components=frozenset(
                {
                    "@method",
                    "@authority",
                    "@target-uri",
                    "content-type",
                    "content-digest",
                    "untp-version",
                    "untp-nonce",
                }
            ),
            response_required_components=frozenset(
                {
                    "@status",
                    "content-type",
                    "content-digest",
                    "untp-version",
                    "untp-origin",
                    "untp-request-nonce",
                }
            ),
        )

        try:
            resp_msg = HTTPMessage(
                method="GET",
                url=str(resp.url),
                headers=dict(resp.headers),
                status_code=resp.status_code,
                body=resp.content,
            )
            await self._verifier.verify_response(
                resp_msg,
                expected_origin=info.origin,
                require_components=False,
            )
        except SignatureError as e:
            self._server_pubkey = None
            self._server_origin = None
            self._discovery = None
            self._verifier = None
            raise FirehoseClientError(f"Discovery response signature verification failed: {e}")

        await self._pin_server_key(info.origin, self._server_pubkey)

        return info

    async def _pin_server_key(self, origin: str, public_key: bytes) -> None:
        """Pin the server's key, or report that a decision is needed.

        Under PIN_MODE_AUTO this is the historical behaviour: adopt on first
        contact, and roll the pin forward when a chain of
        bonnet.origin.key.rotate records connects the pinned key to the one
        presented. A mismatch with no such chain fails.

        Under PIN_MODE_CONFIRM nothing is adopted here at all. Anything other
        than "already pinned to exactly this key" is recorded as pending and
        raised for the caller to decide — including a change whose rotation
        chain verifies, because that chain is the origin's own account of its
        key history signed by the key being replaced. It is testimony, not
        proof; a holder of the old key produces an identical one. The chain
        walk still runs, and its outcome rides along as `evidence`, but it
        does not decide.
        """
        if not self._trust_store:
            if self._server_pubkey and self._server_pubkey != public_key:
                raise FirehoseClientError("Server key changed without rotation")
            return

        pinned = self._trust_store.get_pin(origin)
        if pinned == public_key:
            return  # already trusted, nothing to decide

        host_match = self._origin_matches_dialed_host()

        if self._pin_mode == PIN_MODE_CONFIRM:
            if pinned is None:
                self._trust_store.record_pending(
                    origin,
                    public_key,
                    "new",
                    url=self._base_url,
                    verify_tls=str(self._verify),
                )
                raise PinConfirmationRequired(origin, public_key, "new", host_match=host_match)
            evidence = (
                "chain_verified"
                if await self._verify_rotation_chain(origin, pinned, public_key)
                else "no_chain"
            )
            self._trust_store.record_pending(
                origin,
                public_key,
                "changed",
                evidence,
                url=self._base_url,
                verify_tls=str(self._verify),
            )
            raise PinConfirmationRequired(
                origin, public_key, "changed", evidence, host_match=host_match
            )

        if self._trust_store.tofu_pin(origin, public_key):
            return
        old_pubkey = self._trust_store.get_pin(origin)
        if old_pubkey is not None and await self._verify_rotation_chain(
            origin, old_pubkey, public_key
        ):
            if self._trust_store.accept_rotation(origin, old_pubkey, public_key):
                return
        raise FirehoseClientError(f"Server key pin mismatch for origin '{origin}'")

    def _origin_matches_dialed_host(self) -> bool:
        """Whether the origin this server claims is the address we dialed.

        Nothing anywhere compared these before: `discover()` took `origin`
        straight out of the response body and pinned under it, and
        `verify_response(expected_origin=...)` compared that claim to the
        `untp-origin` header — the same party asserting the same thing twice.
        So a host could call itself any origin it liked, and the name a key got
        pinned under was entirely the server's choice.

        Reported, not enforced. An origin served from an unrelated address is
        an ordinary deployment (a relay behind a CDN, a service moved to new
        infrastructure), so refusing would break working setups to catch a case
        the pin already covers on every visit after the first. What it changes
        is the *first* visit, which is the one with no evidence behind it: when
        the names line up, TLS is checking the same string the key is being
        pinned under, and when they do not, the caller should know that before
        accepting.
        """
        host = (urlparse(self._base_url).hostname or "").lower()
        claimed = (self._server_origin or "").lower().rstrip(".")
        return bool(claimed) and host == claimed

    def advertised_address(self) -> str | None:
        """Where this origin says it can be reached, when that is not here.

        The discovery document has always carried `hostname`, and nothing read
        it — the server publishes it, the transport parses it into
        `DiscoveryInfo`, and no call site ever looked. This makes it legible
        without making it authoritative.

        Reported, never followed. Auto-redirecting on it would hand the party
        being identified the ability to choose where the next connection goes,
        which is the shape of the body-redirect hop that needed an SSRF guard
        and a TLS-policy fix. And the value would be small even then: you can
        only read this hint from a server you already reached, so it covers a
        planned move announced while the old address still answers, and not the
        case anyone actually wants — a peer that went dark and came back
        elsewhere. That case is out-of-band by nature.

        What it is good for is telling an operator their configured address is
        stale, which is a thing to surface and let them act on.
        """
        if self._discovery is None:
            return None
        advertised = normalize_origin(self._discovery.hostname)
        if not advertised:
            return None
        dialed = (urlparse(self._base_url).hostname or "").lower()
        return advertised if advertised != dialed else None

    async def refresh_epoch_cache(self, origin: str | None = None) -> bool:
        """Fetch, verify and cache an origin's key history. True if cached.

        Anchored on the pin. The advertised table's final epoch must be the key
        this client actually pinned, and every internal boundary is re-fetched
        as a full record and checked — actor equal to the preceding epoch's
        key, origin signature under that key, rotation proof chaining it to the
        successor. KEY_EPOCHS is a hint about *where to look*, never evidence:
        the same stance `firehose_sync._verify_epoch_hints` takes server-side,
        and `_verify_rotation_chain` takes for pin changes.

        Best-effort by design. A peer that does not implement KEY_EPOCHS, or an
        origin that is unreachable, leaves whatever was cached before intact —
        the point of caching is that verification keeps working when the origin
        does not, so a failed refresh must never invalidate a good table.
        """
        target = origin or self._server_origin
        if not self._trust_store or not target:
            return False
        pinned = self._trust_store.get_pin(target)
        if pinned is None:
            return False

        try:
            resp = await self.send_command(build_key_epochs(target))
            epochs = sorted(parse_key_epochs_response(resp), key=lambda e: e[0])
        except Exception:
            return False
        if not epochs or epochs[0][0] != 1 or epochs[-1][1] is not None:
            return False
        if epochs[-1][2] != pinned:
            # The history does not end at the key we trust, so it is not this
            # origin's history as far as we are concerned.
            return False

        for prev, nxt in zip(epochs, epochs[1:]):
            boundary, _, pk_prev = prev[1], prev[2], prev[2]
            start_i, _, pk_next = nxt
            if boundary is None or boundary != start_i - 1:
                return False
            try:
                records = parse_event_range_response(
                    await self.send_command(build_event_range(target, boundary, 1))
                )
            except Exception:
                return False
            if len(records) != 1:
                return False
            rec = records[0][0]
            if rec.kind != KIND_ORIGIN_KEY_ROTATE or rec.actor_pubkey != pk_prev:
                return False
            claimed = rec.metadata.get_bytes(1)
            proof = rec.metadata.get_bytes(2)
            if claimed != pk_next or proof is None:
                return False
            if not verify_record_signature(
                pk_prev, encode_unsigned_record(rec), rec.origin_signature
            ):
                return False
            if not verify_key_rotation_proof(pk_next, target, pk_prev, proof):
                return False

        self._trust_store.cache_epochs(target, epochs)
        return True

    def origin_key_for_seq(self, origin: str, seq: int) -> bytes | None:
        """The key that countersigned `seq`, from the cache. None if unknown."""
        if not self._trust_store:
            return None
        return self._trust_store.key_for_seq(origin, seq)

    async def _verify_rotation_chain(
        self, origin: str, old_pubkey: bytes, new_pubkey: bytes
    ) -> bool:
        """Check whether a chain of verified rotation records connects
        old_pubkey (the currently pinned key) to new_pubkey (the key just
        presented at discovery), possibly through several intermediate
        rotations.

        Mirrors firehose_sync._verify_epoch_hints: KEY_EPOCHS is only ever a
        hint for which sequences to fetch, never trusted as data. Each
        candidate boundary is re-fetched as a full record, and both its
        origin signature (under the previous key) and its rotation proof
        (under the claimed next key) are independently verified before the
        chain advances. Uses the anonymous identity, since this runs during
        discover() before any real identity has connected — anonymous reads
        of KEY_EPOCHS/EVENT_RANGE are the same substrate-level access
        federation sync already relies on.
        """
        try:
            await self.connect_anonymous()
            epochs_resp = await self.send_command(build_key_epochs(origin))
            epochs = sorted(parse_key_epochs_response(epochs_resp), key=lambda e: e[0])
        except Exception:
            return False

        current = old_pubkey
        for _start_seq, end_seq, pubkey in epochs:
            if pubkey != current:
                continue
            if end_seq is None:
                break

            try:
                range_resp = await self.send_command(build_event_range(origin, end_seq, 1))
                records = parse_event_range_response(range_resp)
            except Exception:
                return False
            if len(records) != 1:
                return False
            rec, _witness = records[0]

            if rec.kind != KIND_ORIGIN_KEY_ROTATE or rec.actor_pubkey != current:
                return False
            claimed_new = rec.metadata.get_bytes(1)
            proof = rec.metadata.get_bytes(2)
            if claimed_new is None or proof is None:
                return False
            if not verify_record_signature(
                current, encode_unsigned_record(rec), rec.origin_signature
            ):
                return False
            if not verify_key_rotation_proof(claimed_new, origin, current, proof):
                return False

            current = claimed_new
            if current == new_pubkey:
                return True

        return current == new_pubkey

    async def connect(self, identity: Identity, username: str = "") -> None:
        """Connect with an authenticated identity."""
        self._identity = identity
        self._username = username
        if self._discovery is None:
            await self.discover()

        self._signer = BonnetSigner(
            private_key=identity.private_key,
            key_id=f"ed25519:{identity.public_key.hex()}",
            tag=UNTP_TAG,
            label=UNTP_LABEL,
            request_components=[
                "@method",
                "@authority",
                "@target-uri",
                "content-type",
                "content-digest",
                "untp-version",
                "untp-nonce",
            ],
            response_components=[
                "@status",
                "content-type",
                "content-digest",
                "untp-version",
                "untp-origin",
                "untp-request-nonce",
            ],
        )

    async def connect_anonymous(self) -> None:
        """Connect using the server's anonymous key."""
        if self._discovery is None:
            await self.discover()
        if self._anonymous_private_key is None:
            raise FirehoseClientError("server does not publish anonymous private key")
        self._identity = Identity.from_private_key(self._anonymous_private_key)
        self._username = ""

        self._signer = BonnetSigner(
            private_key=self._identity.private_key,
            key_id=f"ed25519:{self._identity.public_key.hex()}",
            tag=UNTP_TAG,
            label=UNTP_LABEL,
            request_components=[
                "@method",
                "@authority",
                "@target-uri",
                "content-type",
                "content-digest",
                "untp-version",
                "untp-nonce",
            ],
            response_components=[
                "@status",
                "content-type",
                "content-digest",
                "untp-version",
                "untp-origin",
                "untp-request-nonce",
            ],
        )

    # ------------------------------------------------------------------
    # Core request/response
    # ------------------------------------------------------------------

    async def send_command(self, cmd_bytes: bytes) -> bytes:
        """Sign and send a command, verify the response, return the payload."""
        if self._signer is None:
            raise FirehoseClientError("not connected — call connect() or connect_anonymous() first")

        nonce = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        now = int(time.time())
        expires = now + 60

        msg = HTTPMessage(
            method="POST",
            url=f"{self._base_url}/command",
            headers={
                "Content-Type": "application/vnd.bonnet.command",
                "Content-Digest": compute_content_digest(cmd_bytes),
                "Untp-Version": "1",
                "Untp-Nonce": nonce,
            },
            body=cmd_bytes,
        )

        await self._signer.sign_request(
            msg,
            nonce=nonce,
            created=now,
            expires=expires,
        )

        headers = dict(msg.headers)
        try:
            resp = await self._http.post(
                f"{self._base_url}/command",
                content=cmd_bytes,
                headers=headers,
            )
        except httpx.HTTPError as e:
            raise FirehoseClientError(
                f"could not reach {self._base_url}: {e or type(e).__name__}"
            ) from e

        if resp.status_code != 200:
            raise FirehoseClientError(f"HTTP {resp.status_code}: {resp.text[:200]}")

        await self._verify_response(resp, nonce)

        return resp.content

    # Compat alias: existing callers historically used the private name.
    _send_command = send_command

    async def _verify_response(self, resp: httpx.Response, request_nonce: str) -> None:
        """Verify the response signature, origin, and request nonce."""
        if self._verifier is None or self._server_origin is None:
            return

        resp_msg = HTTPMessage(
            method="POST",
            url=str(resp.url),
            headers=dict(resp.headers),
            status_code=resp.status_code,
            body=resp.content,
        )

        try:
            await self._verifier.verify_response(
                resp_msg,
                expected_origin=self._server_origin,
                expected_request_nonce=request_nonce,
            )
        except SignatureError as e:
            raise FirehoseClientError(f"Response signature verification failed: {e}")
