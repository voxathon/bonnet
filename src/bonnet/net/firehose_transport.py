"""Signed-HTTP command transport for the firehose protocol.

Handles discovery, TOFU key pinning, RFC 9421 request signing, response
verification, and the binary command round-trip. Shared by the server's
federation sync (bonnet.net.firehose_sync) and the client library
(bonnet.gateway.firehose_client), which layers typed methods on top.
"""

from __future__ import annotations

import base64
import os
import time

import httpx

from bonnet.core.crypto import Identity
from bonnet.core.kinds import KIND_ORIGIN_KEY_ROTATE
from bonnet.core.record import (
    encode_unsigned_record,
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
    KeyResolver,
    SignatureError,
    compute_content_digest,
)


class FirehoseClientError(Exception):
    pass


class _ServerKeyResolver(KeyResolver):
    """Resolves the server's key for response verification."""

    def __init__(self, server_pubkey: bytes):
        self._server_pubkey = server_pubkey

    def resolve_public_key(self, key_id: str) -> bytes:
        if key_id.startswith("ed25519:"):
            return bytes.fromhex(key_id[8:])
        if key_id.startswith("origin:"):
            return self._server_pubkey
        raise ValueError(f"Unknown keyid format: {key_id}")


class FirehoseTransport:
    """HTTP transport for the firehose protocol."""

    def __init__(
        self,
        base_url: str,
        timeout: float = 30.0,
        verify: bool | str = True,
        trust_store_path: str = None,
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
        resp = await self._http.get(f"{self._base_url}/.well-known/untp")
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
            key_resolver=_ServerKeyResolver(self._server_pubkey),
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
        """TOFU pin, or accept a verified key rotation, for the server's key.

        A key mismatch against the existing pin is only ever a mismatch, not
        automatically an attack: the origin may have legitimately rotated.
        Before rejecting, ask whether a verified chain of
        bonnet.origin.key.rotate records connects the pinned key to the one
        just presented, and if so, roll the pin forward instead of failing.
        """
        if self._trust_store:
            if self._trust_store.tofu_pin(origin, public_key):
                return
            old_pubkey = self._trust_store.get_pin(origin)
            if old_pubkey is not None and await self._verify_rotation_chain(
                origin, old_pubkey, public_key
            ):
                if self._trust_store.accept_rotation(origin, old_pubkey, public_key):
                    return
            raise FirehoseClientError(f"Server key pin mismatch for origin '{origin}'")
        else:
            if self._server_pubkey and self._server_pubkey != public_key:
                raise FirehoseClientError("Server key changed without rotation")

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
        resp = await self._http.post(
            f"{self._base_url}/command",
            content=cmd_bytes,
            headers=headers,
        )

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
