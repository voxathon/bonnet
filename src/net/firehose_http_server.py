"""Firehose HTTP server for the Bonnet Firehose Protocol (PROTOCOL.md §18-19).

ASGI application serving:
  GET  /.well-known/bonnet  — firehose discovery document
  POST /command             — signed firehose command dispatch

Reuses the existing http_auth.py RFC 9421 signature infrastructure with
updated tag/headers for bonnet-firehose-1.
"""

from __future__ import annotations

import asyncio
import json
import struct
import time

from core.crypto import Identity
from core.logging import log_msg
from net.http_auth import (
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
    SignatureError,
    compute_content_digest,
    validate_content_digest,
)
from net.rate_limiter import RateLimiter
from net.replay import ReplayLedger

FIREHOSE_TAG = "bonnet-firehose-1"
FIREHOSE_LABEL = "bonnet"


class _BodyTooLarge(Exception):
    pass

REQUEST_REQUIRED_COMPONENTS = frozenset({
    "@method", "@authority", "@target-uri",
    "content-type", "content-digest",
    "bonnet-protocol", "bonnet-nonce",
})

RESPONSE_REQUIRED_COMPONENTS = frozenset({
    "@status", "content-type", "content-digest",
    "bonnet-protocol", "bonnet-origin", "bonnet-request-nonce",
})


class FirehoseKeyResolver(KeyResolver):
    """Resolves keyid → raw Ed25519 public key for verification."""

    def __init__(self, anonymous_public_key: bytes):
        self._anonymous_pubkey = anonymous_public_key

    def resolve_public_key(self, key_id: str) -> bytes:
        if key_id.startswith("ed25519:"):
            return bytes.fromhex(key_id[8:])
        raise InvalidParameter(f"Unknown keyid format: {key_id}")


class FirehoseHTTPServer:
    """ASGI application for the Bonnet Firehose Protocol."""

    def __init__(
        self,
        command_handler,
        server_identity: Identity,
        config,
        anonymous_identity: Identity | None = None,
        replay_ledger: ReplayLedger | None = None,
        rate_limiter: RateLimiter | None = None,
        users_projection=None,
        firehose_store=None,
    ):
        self._handler = command_handler
        self._server_identity = server_identity
        self._config = config
        self._users = users_projection
        self._firehose = firehose_store

        if anonymous_identity is None:
            anonymous_identity = Identity.generate()
        self._anonymous_identity = anonymous_identity
        self._anonymous_public_key = anonymous_identity.public_key

        self._replay_ledger = replay_ledger or ReplayLedger(
            config.replay_db_path,
            clock_skew_seconds=getattr(config, 'clock_skew_seconds', 30),
        )

        self._rate_limiter = rate_limiter or RateLimiter(
            max_requests=getattr(config, 'rate_limit_requests', 100),
            window_seconds=getattr(config, 'rate_limit_window', 1),
        )

        self._signer = BonnetSigner(
            private_key=server_identity.private_key,
            key_id=f"ed25519:{server_identity.public_key.hex()}",
            tag=FIREHOSE_TAG,
            label=FIREHOSE_LABEL,
            request_components=[
                "@method", "@authority", "@target-uri",
                "content-type", "content-digest",
                "bonnet-protocol", "bonnet-nonce",
            ],
            response_components=[
                "@status", "content-type", "content-digest",
                "bonnet-protocol", "bonnet-origin",
                "bonnet-request-nonce",
            ],
        )

        self._verifier = BonnetVerifier(
            key_resolver=FirehoseKeyResolver(self._anonymous_public_key),
            tag=FIREHOSE_TAG,
            max_lifetime=getattr(config, 'signature_lifetime_seconds', 60),
            clock_skew=getattr(config, 'clock_skew_seconds', 30),
            request_required_components=REQUEST_REQUIRED_COMPONENTS,
            response_required_components=RESPONSE_REQUIRED_COMPONENTS,
        )

        self._max_request_size = getattr(config, 'max_request_size', 10 * 1024 * 1024)
        self._cleanup_counter = 0

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            path = scope.get("path", "")
            method = scope.get("method", "")

            if path == "/.well-known/bonnet" and method == "GET":
                await self._handle_discovery(scope, receive, send)
            elif path == "/command" and method == "POST":
                await self._handle_command(scope, receive, send)
            else:
                await self._send_error_response(send, 404, b"Not Found")
        elif scope["type"] == "lifespan":
            await self._handle_lifespan(scope, receive, send)
        else:
            await send({"type": "http.response.start", "status": 404, "headers": []})
            await send({"type": "http.response.body", "body": b"Not Found"})

    async def _handle_lifespan(self, scope, receive, send):
        while True:
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif msg["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    # ------------------------------------------------------------------
    # Discovery (§18)
    # ------------------------------------------------------------------

    async def _handle_discovery(self, scope, receive, send):
        known_origins = [self._config.origin]
        for peer in getattr(self._config, 'peers', []):
            known_origins.append(peer.origin)
        known_origins = sorted(set(known_origins))

        body = json.dumps({
            "protocol": "bonnet-firehose-1",
            "origin": self._config.origin,
            "hostname": self._config.hostname,
            "public_key": self._server_identity.public_key.hex(),
            "anonymous_key": self._anonymous_public_key.hex(),
            "anonymous_private_key": self._anonymous_identity.private_key.hex(),
            "command_endpoint": "/command",
            "known_origins": known_origins,
            "capabilities": [
                "global-firehose",
                "generic-record-kinds",
                "relay-hop-witness",
                "per-board-body-search",
                "origin-directory-v1",
            ],
        }).encode("utf-8")

        msg = HTTPMessage(
            method="GET",
            url=f"https://{self._config.origin}/.well-known/bonnet",
            headers={
                "Content-Type": "application/json",
                "Content-Digest": compute_content_digest(body),
                "Bonnet-Protocol": "bonnet-firehose-1",
                "Bonnet-Origin": self._config.origin,
            },
            status_code=200,
            body=body,
        )

        try:
            await self._signer.sign_response(msg, request_nonce="")
        except Exception as e:
            log_msg(f"DISCOVERY: failed to sign: {e}")
            await self._send_raw(send, 500, [], b"")
            return

        headers = self._msg_to_headers(msg)
        await self._send_raw(send, 200, headers, body)

    # ------------------------------------------------------------------
    # Command dispatch (§19)
    # ------------------------------------------------------------------

    async def _handle_command(self, scope, receive, send):
        remote_addr = self._get_remote_addr(scope)

        body = None
        try:
            body = await self._read_body(receive, self._max_request_size)
        except _BodyTooLarge:
            await self._send_protocol_error(send, 413, "Request too large", remote_addr, "")
            return
        if body is None:
            await self._send_protocol_error(send, 400, "Failed to read body", remote_addr, "")
            return

        if len(body) == 0:
            await self._send_protocol_error(send, 400, "Empty command body", remote_addr, "")
            return

        headers = self._extract_headers(scope)
        content_type = headers.get("content-type", "")
        bonnet_protocol = headers.get("bonnet-protocol", "")
        content_digest = headers.get("content-digest", "")
        sig_input = headers.get("signature-input", "")
        sig = headers.get("signature", "")
        bonnet_nonce = headers.get("bonnet-nonce", "")

        if bonnet_protocol != "bonnet-firehose-1":
            await self._send_protocol_error(send, 426, "Unsupported protocol", remote_addr, "")
            return

        if content_type != "application/vnd.bonnet.command":
            await self._send_protocol_error(send, 415, "Unsupported content type", remote_addr, "")
            return

        if not content_digest:
            await self._send_protocol_error(send, 400, "Missing Content-Digest", remote_addr, "")
            return

        try:
            validate_content_digest(body, content_digest)
        except DigestMismatch:
            await self._send_protocol_error(send, 400, "Content-Digest mismatch", remote_addr, "")
            return

        if not sig_input or not sig:
            await self._send_protocol_error(send, 401, "Missing signature", remote_addr, "")
            return

        authority = self._get_authority(scope)
        url = f"https://{authority}/command"

        req_msg = HTTPMessage(
            method="POST",
            url=url,
            headers=headers,
            body=body,
        )

        try:
            verify_result = await self._verifier.verify_request(req_msg, require_components=True)
        except SignatureError as e:
            error_desc = self._signature_error_desc(e)
            await self._send_protocol_error(send, 401, error_desc, remote_addr, "")
            return

        peer_public_key = bytes.fromhex(verify_result.keyid[8:])
        nonce = verify_result.nonce or bonnet_nonce
        request_nonce = nonce

        is_anonymous = peer_public_key == self._anonymous_public_key

        if not is_anonymous and self._replay_ledger:
            expires = verify_result.parameters.get("expires")
            if expires is None:
                expires = int(time.time()) + 60
            if not self._replay_ledger.check_and_insert(peer_public_key, nonce, int(expires)):
                await self._send_protocol_error(send, 409, "Replay detected", remote_addr, request_nonce)
                return

        if is_anonymous:
            rl_key = self._rate_limiter.address_key(remote_addr)
        else:
            rl_key = self._rate_limiter.identity_key(peer_public_key)

        if not self._rate_limiter.check(rl_key):
            await self._send_protocol_error(send, 429, "Too many requests", remote_addr, request_nonce)
            return

        if not is_anonymous:
            addr_key = self._rate_limiter.address_key(remote_addr)
            if not self._rate_limiter.check(addr_key):
                await self._send_protocol_error(send, 429, "Too many requests", remote_addr, request_nonce)
                return

        if self._cleanup_counter % 64 == 0:
            self._rate_limiter.cleanup()
        self._cleanup_counter += 1

        from net.firehose_commands import FirehoseContext

        role = ""
        is_registered = False
        is_unknown = False

        if is_anonymous:
            is_unknown = False
        else:
            if self._users is not None:
                user = self._users.get_user_by_pubkey(self._config.origin, peer_public_key)
                if user is not None and not user.get("revoked", False):
                    is_registered = True
                    flags = user.get("flags", 0)
                    if flags & 0x01:
                        role = "administrator"
                    elif flags & 0x02:
                        role = "moderator"
                else:
                    is_unknown = True
            else:
                is_unknown = True

        ctx = FirehoseContext(
            peer_pubkey=peer_public_key,
            is_anonymous=is_anonymous,
            is_unknown=is_unknown,
            is_registered=is_registered,
            role=role,
            origin=self._config.origin,
            remote_addr=remote_addr,
        )

        try:
            response_body = await asyncio.to_thread(self._handler.handle, body, ctx)
        except Exception as e:
            log_msg(f"HTTP_COMMAND: dispatch error: {type(e).__name__}: {e}")
            msg = b"Internal error"
            response_body = b"\x01" + struct.pack(">H", 0) + struct.pack(">H", len(msg)) + msg

        await self._send_signed_response(send, response_body, request_nonce)

    # ------------------------------------------------------------------
    # Response helpers
    # ------------------------------------------------------------------

    async def _send_signed_response(self, send, response_body: bytes, request_nonce: str):
        msg = HTTPMessage(
            method="POST",
            url=f"https://{self._config.origin}/command",
            headers={
                "Content-Type": "application/vnd.bonnet.command",
                "Bonnet-Protocol": "bonnet-firehose-1",
                "Bonnet-Origin": self._config.origin,
            },
            status_code=200,
            body=response_body,
        )
        msg.set_header("Content-Digest", compute_content_digest(response_body))

        try:
            await self._signer.sign_response(msg, request_nonce=request_nonce)
        except Exception as e:
            log_msg(f"HTTP_RESPONSE: failed to sign: {e}")
            await self._send_raw(send, 500, [], b"")
            return

        headers = self._msg_to_headers(msg)
        await self._send_raw(send, 200, headers, response_body)

    async def _send_protocol_error(self, send, status_code: int, message: str,
                                   remote_addr: str, request_nonce: str = ""):
        body = message.encode("utf-8")

        msg = HTTPMessage(
            method="POST",
            url=f"https://{self._config.origin}/command",
            headers={
                "Content-Type": "text/plain",
                "Bonnet-Protocol": "bonnet-firehose-1",
                "Bonnet-Origin": self._config.origin,
            },
            status_code=status_code,
            body=body,
        )
        msg.set_header("Content-Digest", compute_content_digest(body))

        try:
            await self._signer.sign_response(msg, request_nonce=request_nonce)
        except Exception:
            await self._send_raw(send, status_code, [(b"content-type", b"text/plain")], body)
            return

        headers = self._msg_to_headers(msg)
        await self._send_raw(send, status_code, headers, body)

    async def _send_error_response(self, send, status_code: int, body: bytes):
        await self._send_raw(send, status_code, [(b"content-type", b"text/plain")], body)

    async def _send_raw(self, send, status_code: int, headers: list, body: bytes):
        raw_headers = []
        for item in headers:
            if isinstance(item, tuple):
                k, v = item
                if isinstance(k, bytes):
                    raw_headers.append((k, v if isinstance(v, bytes) else v.encode("utf-8")))
                else:
                    raw_headers.append((k.encode("utf-8"), v.encode("utf-8") if isinstance(v, str) else v))
            else:
                raw_headers.append(item)
        await send({"type": "http.response.start", "status": status_code, "headers": raw_headers})
        await send({"type": "http.response.body", "body": body})

    # ------------------------------------------------------------------
    # ASGI helpers
    # ------------------------------------------------------------------

    async def _read_body(self, receive, max_size: int) -> bytes | None:
        """Read the request body, aborting if it exceeds max_size.

        Returns the body bytes, or None if the client disconnected.
        Raises _BodyTooLarge if the cumulative size exceeds max_size.
        """
        chunks = []
        total = 0
        while True:
            msg = await receive()
            if msg["type"] == "http.request":
                chunk = msg.get("body", b"")
                total += len(chunk)
                if total > max_size:
                    raise _BodyTooLarge()
                chunks.append(chunk)
                if not msg.get("more_body", False):
                    return b"".join(chunks)
            elif msg["type"] == "http.disconnect":
                return None

    def _extract_headers(self, scope) -> dict:
        headers = {}
        for k, v in scope.get("headers", []):
            key = k.decode("utf-8").lower()
            val = v.decode("utf-8")
            headers[key] = val
        return headers

    def _get_remote_addr(self, scope) -> str:
        client = scope.get("client")
        if client and isinstance(client, tuple) and len(client) > 0:
            return str(client[0])
        return "unknown"

    def _get_authority(self, scope) -> str:
        for k, v in scope.get("headers", []):
            if k == b"host":
                return v.decode("utf-8").lower()
        return self._config.origin

    def _msg_to_headers(self, msg: HTTPMessage) -> list:
        result = []
        for k, v in msg.headers.items():
            result.append((k, v))
        return result

    def _signature_error_desc(self, e: SignatureError) -> str:
        if isinstance(e, ExpiredSignature):
            return "Signature expired"
        if isinstance(e, FutureSignature):
            return "Signature created in the future"
        if isinstance(e, MissingComponent):
            return f"Missing required component: {e}"
        if isinstance(e, InvalidParameter):
            return f"Invalid parameter: {e}"
        if isinstance(e, DigestMismatch):
            return "Content-Digest mismatch"
        if isinstance(e, InvalidSignature):
            return "Signature verification failed"
        if isinstance(e, MalformedSignature):
            return f"Malformed signature: {e}"
        return f"Signature error: {e}"

    @property
    def anonymous_public_key(self) -> bytes:
        return self._anonymous_public_key

    @property
    def anonymous_private_key(self) -> bytes:
        return self._anonymous_identity.private_key
