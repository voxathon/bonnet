"""Bonnet protocol v2 ASGI HTTP server.

Implements the HTTP transport layer per PROTOCOL_RENOVATION_PLAN §6:
  GET /.well-known/bonnet  — signed discovery document
  POST /v2/command          — signed command endpoint

Request flow (§7, §9, §10):
  1. Read body, enforce max_request_size
  2. Verify Bonnet-Version header
  3. Check Content-Type
  4. Verify Content-Digest against body
  5. Verify Signature via BonnetVerifier (or detect anonymous via shared key)
  6. Check replay ledger (authenticated only)
  7. Rate limit (identity key for authenticated, address for anonymous)
  8. Resolve UME user(s) for the public key
  9. Handle Bonnet-Username selection
  10. Build CommandContext
  11. Dispatch through CommandHandler.handle()
  12. Sign response with server_identity

Response flow (§8):
  Every response includes Bonnet-Version, Bonnet-Origin, Bonnet-Request-Nonce,
  Content-Digest, Signature-Input, Signature headers.

Anonymous shared-key design:
  The server generates an anonymous Ed25519 keypair at init.
  Requests signed with the anonymous key are is_anonymous=True — no UME lookup.
  The anonymous private key is published via discovery for clients to use.
"""

from __future__ import annotations

import asyncio
import json
import os
import struct
import time
import base64
from typing import Optional, Callable

from net.context import CommandContext
from net.http_auth import (
    BonnetSigner, BonnetVerifier, KeyResolver, HTTPMessage,
    compute_content_digest, validate_content_digest,
    SignatureError, MalformedSignature, InvalidSignature,
    ExpiredSignature, FutureSignature, MissingComponent,
    InvalidParameter, DigestMismatch,
    BONNET_TAG, ED25519_ALG,
)
from net.rate_limiter import RateLimiter
from net.replay import ReplayLedger
from core.crypto import Identity
from core.logging import log_msg


class BonnetKeyResolver(KeyResolver):
    """Resolves keyid → raw Ed25519 public key for verification.

    For request keyids (ed25519:<hex>), the hex IS the public key.
    For the anonymous key, the keyid matches the server's anonymous public key.
    """

    def __init__(self, anonymous_public_key: bytes):
        self._anonymous_pub = anonymous_public_key

    def resolve_public_key(self, key_id: str) -> bytes:
        if key_id.startswith("ed25519:"):
            hex_part = key_id[8:]
            return bytes.fromhex(hex_part)
        if key_id.startswith("origin:"):
            raise InvalidParameter(f"Request keyid must not be origin: type")
        raise InvalidParameter(f"Unrecognized keyid format: {key_id[:40]!r}")


class BonnetHTTPServer:
    """ASGI application for Bonnet protocol v2."""

    def __init__(
        self,
        command_handler,
        server_identity: Identity,
        config,
        ume,
        anonymous_identity: Optional[Identity] = None,
        replay_ledger: Optional[ReplayLedger] = None,
        rate_limiter: Optional[RateLimiter] = None,
    ):
        self._handler = command_handler
        self._server_identity = server_identity
        self._config = config
        self._ume = ume

        if anonymous_identity is None:
            anonymous_identity = Identity.generate()
        self._anonymous_identity = anonymous_identity
        self._anonymous_public_key = anonymous_identity.public_key

        self._replay_ledger = replay_ledger or ReplayLedger(
            os.path.join(config.data_dir, "replay.db") if hasattr(config, 'data_dir') else "replay.db",
            clock_skew_seconds=getattr(config, 'clock_skew_seconds', 30),
        )

        self._rate_limiter = rate_limiter or RateLimiter(
            max_requests=getattr(config, 'rate_limit_requests', 100),
            window_seconds=getattr(config, 'rate_limit_window', 1),
        )

        self._signer = BonnetSigner(
            private_key=server_identity.private_key,
            key_id=f"origin:{config.origin}",
        )

        self._verifier = BonnetVerifier(
            key_resolver=BonnetKeyResolver(self._anonymous_public_key),
            max_lifetime=getattr(config, 'signature_lifetime_seconds', 60),
            clock_skew=getattr(config, 'clock_skew_seconds', 30),
        )

        self._max_request_size = getattr(config, 'max_request_size', 10 * 1024 * 1024)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            path = scope.get("path", "")
            method = scope.get("method", "")

            if path == "/.well-known/bonnet" and method == "GET":
                await self._handle_discovery(scope, receive, send)
            elif path == "/v2/command" and method == "POST":
                await self._handle_command(scope, receive, send)
            else:
                await self._send_error_response(send, 404, b"Not Found", scope)
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
                self._replay_ledger.close()
                await send({"type": "lifespan.shutdown.complete"})
                return

    # ------------------------------------------------------------------
    # Discovery endpoint
    # ------------------------------------------------------------------

    async def _handle_discovery(self, scope, receive, send):
        body = json.dumps({
            "protocol_versions": [2],
            "origin": self._config.origin,
            "public_key": self._server_identity.public_key.hex(),
            "anonymous_key": self._anonymous_public_key.hex(),
            "anonymous_private_key": self._anonymous_identity.private_key.hex(),
            "command_endpoint": "/v2/command",
            "capabilities": ["user-registry-merkle-v1"],
        }).encode("utf-8")

        msg = HTTPMessage(
            method="GET",
            url=f"https://{self._config.origin}/.well-known/bonnet",
            headers={
                "Content-Type": "application/json",
                "Content-Digest": compute_content_digest(body),
                "Bonnet-Version": "2",
                "Bonnet-Origin": self._config.origin,
            },
            status_code=200,
            body=body,
        )

        try:
            await self._signer.sign_response(msg, request_nonce="")
        except Exception as e:
            log_msg(f"DISCOVERY: failed to sign response: {e}")

        headers = self._msg_to_headers(msg)
        await self._send_raw(send, 200, headers, body)

    # ------------------------------------------------------------------
    # Command endpoint
    # ------------------------------------------------------------------

    async def _handle_command(self, scope, receive, send):
        remote_addr = self._get_remote_addr(scope)

        # 1. Read body
        body = await self._read_body(receive)
        if body is None:
            await self._send_protocol_error(send, 400, "Failed to read body", remote_addr, scope)
            return

        if len(body) > self._max_request_size:
            await self._send_protocol_error(send, 413, "Request too large", remote_addr, scope)
            return

        if len(body) == 0:
            await self._send_protocol_error(send, 400, "Empty command body", remote_addr, scope)
            return

        # 2. Extract headers
        headers = self._extract_headers(scope)
        content_type = headers.get("content-type", "")
        bonnet_version = headers.get("bonnet-version", "")
        content_digest = headers.get("content-digest", "")
        sig_input = headers.get("signature-input", "")
        sig = headers.get("signature", "")
        bonnet_nonce = headers.get("bonnet-nonce", "")
        bonnet_username = headers.get("bonnet-username", "")

        # 3. Check Bonnet-Version
        if bonnet_version != "2":
            await self._send_protocol_error(send, 426, "Unsupported protocol version", remote_addr, scope)
            return

        # 4. Check Content-Type
        if content_type != "application/vnd.bonnet.command":
            await self._send_protocol_error(send, 415, "Unsupported content type", remote_addr, scope)
            return

        # 5. Check Content-Digest
        if not content_digest:
            await self._send_protocol_error(send, 400, "Missing Content-Digest", remote_addr, scope)
            return

        try:
            validate_content_digest(body, content_digest)
        except DigestMismatch:
            await self._send_protocol_error(send, 400, "Content-Digest mismatch", remote_addr, scope)
            return

        # 6. Determine if anonymous or authenticated
        is_anonymous = False
        peer_public_key = None
        verify_result = None
        nonce = bonnet_nonce
        request_nonce_for_response = ""

        if not sig_input or not sig:
            # No signature — but in our shared-key design, all requests should be signed.
            # If no signature, treat as malformed (not anonymous).
            await self._send_protocol_error(send, 401, "Missing signature", remote_addr, scope)
            return

        # 7. Verify signature
        authority = self._get_authority(scope)
        url = f"https://{authority}/v2/command"

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
            await self._send_protocol_error(send, 401, error_desc, remote_addr, scope)
            return

        peer_public_key = bytes.fromhex(verify_result.keyid[8:])  # ed25519:<hex>
        nonce = verify_result.nonce or bonnet_nonce
        request_nonce_for_response = nonce

        # 8. Anonymous shortcut: O(1) key comparison
        if peer_public_key == self._anonymous_public_key:
            is_anonymous = True
        else:
            # 9. Replay check (authenticated only)
            if self._replay_ledger and not is_anonymous:
                expires = verify_result.parameters.get("expires")
                if expires is None:
                    expires = int(time.time()) + 60
                if not self._replay_ledger.check_and_insert(peer_public_key, nonce, int(expires)):
                    await self._send_protocol_error(send, 409, "Replay detected", remote_addr, scope,
                                                    request_nonce=request_nonce_for_response)
                    return

        # 10. Rate limit
        if is_anonymous:
            rl_key = self._rate_limiter.address_key(remote_addr)
        else:
            rl_key = self._rate_limiter.identity_key(peer_public_key)

        if not self._rate_limiter.check(rl_key):
            await self._send_protocol_error(send, 429, "Too many requests", remote_addr, scope,
                                            request_nonce=request_nonce_for_response)
            return

        # 11. Resolve user
        user = None
        username = None

        if not is_anonymous:
            users = self._ume.get_all_by_publickey(peer_public_key)
            if users:
                if len(users) == 1:
                    user = users[0]
                    username = users[0].username
                elif len(users) > 1:
                    if not bonnet_username:
                        await self._send_protocol_error(send, 403, "Multiple users for key; Bonnet-Username required",
                                                        remote_addr, scope, request_nonce=request_nonce_for_response)
                        return
                    user = None
                    for u in users:
                        if u.username == bonnet_username:
                            user = u
                            username = bonnet_username
                            break
                    if user is None:
                        await self._send_protocol_error(send, 403, "Username not associated with key",
                                                        remote_addr, scope, request_nonce=request_nonce_for_response)
                        return
            else:
                # Unknown key — not anonymous, not in UME.
                # Allow REGISTER (0x01) to proceed for unregistered keys.
                # Allow public commands to proceed as an unregistered principal.
                if body[0] != 0x01 and body[0] not in self._config.public_commands:
                    await self._send_protocol_error(send, 403, "Unknown key; register first",
                                                    remote_addr, scope, request_nonce=request_nonce_for_response)
                    return

        # 12. Build CommandContext
        ctx = CommandContext(
            peer_public_key=peer_public_key,
            user=user,
            username=username,
            remote_addr=remote_addr,
            request_id=str(id(scope)),
            is_anonymous=is_anonymous,
            origin=self._config.origin,
        )

        # 13. Dispatch
        try:
            response_body = self._handler.handle(body, ctx)
        except Exception as e:
            import traceback
            log_msg(f"HTTP_COMMAND: dispatch error: {type(e).__name__}: {e}")
            traceback.print_exc()
            response_body = bytes([0x01]) + struct.pack(">BHB", 0x01, 500, len(str(e))) + str(e).encode("utf-8")

        # 14. Sign and send response
        await self._send_signed_response(send, response_body, remote_addr, request_nonce_for_response)

    # ------------------------------------------------------------------
    # Response helpers
    # ------------------------------------------------------------------

    async def _send_signed_response(self, send, response_body: bytes, remote_addr: str, request_nonce: str):
        msg = HTTPMessage(
            method="POST",
            url=f"https://{self._config.origin}/v2/command",
            headers={
                "Content-Type": "application/vnd.bonnet.command",
                "Bonnet-Version": "2",
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
            # If we can't sign, we must not send an unsigned response as authoritative
            await self._send_raw(send, 500, [], b"")
            return

        headers = self._msg_to_headers(msg)
        await self._send_raw(send, 200, headers, response_body)

    async def _send_protocol_error(self, send, status_code: int, message: str,
                                   remote_addr: str, scope, request_nonce: str = ""):
        """Send a signed protocol error response."""
        body = message.encode("utf-8")

        msg = HTTPMessage(
            method="POST",
            url=f"https://{self._config.origin}/v2/command",
            headers={
                "Content-Type": "text/plain",
                "Bonnet-Version": "2",
                "Bonnet-Origin": self._config.origin,
            },
            status_code=status_code,
            body=body,
        )
        msg.set_header("Content-Digest", compute_content_digest(body))

        try:
            await self._signer.sign_response(msg, request_nonce=request_nonce)
        except Exception as e:
            log_msg(f"HTTP_ERROR: failed to sign error response: {e}")
            await self._send_raw(send, status_code, [(b"content-type", b"text/plain")], body)
            return

        headers = self._msg_to_headers(msg)
        await self._send_raw(send, status_code, headers, body)

    async def _send_error_response(self, send, status_code: int, body: bytes, scope):
        """Send an unsigned error (for non-command routes)."""
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

    async def _read_body(self, receive) -> Optional[bytes]:
        chunks = []
        while True:
            msg = await receive()
            if msg["type"] == "http.request":
                chunks.append(msg.get("body", b""))
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

    # ------------------------------------------------------------------
    # Public accessors for testing
    # ------------------------------------------------------------------

    @property
    def anonymous_public_key(self) -> bytes:
        return self._anonymous_public_key

    @property
    def anonymous_private_key(self) -> bytes:
        return self._anonymous_identity.private_key
