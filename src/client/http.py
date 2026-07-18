"""Bonnet protocol v2 async HTTP client.

Replaces src/client/connection.py BonnetClient (WebSocket) with an httpx-based
client that signs every request with RFC 9421 Ed25519 and verifies every
response signature + origin pin.

PROTOCOL_RENOVATION_PLAN §5 (Phase 5):
  - Replace WebSocket lifecycle with async HTTP client
  - Sign authenticated requests with the unlocked local Ed25519 key
  - Verify all response signatures and origin pins before parsing bodies
  - First-contact TOFU and configured-pin flows
  - Send signed username selection when needed
  - Reuse HTTP connections through a bounded client pool
  - Preserve existing high-level client method signatures where practical

Anonymous mode:
  The client fetches the server's anonymous shared key from discovery,
  then signs anonymous requests with that key.
"""

from __future__ import annotations

import asyncio
import base64
import os
import time
from typing import Optional

import httpx
from nacl.signing import SigningKey

from core.crypto import Identity
from core.trust import TrustStore, TRUST_MODE_TOFU, TRUST_MODE_CONFIGURED
from net.http_auth import (
    BonnetSigner, BonnetVerifier, KeyResolver, HTTPMessage,
    compute_content_digest, validate_content_digest,
    SignatureError, MalformedSignature, InvalidSignature,
)
from .protocol import (
    build_register, build_get_user, build_list_users, build_list_peers,
    build_board_create, build_board_list, build_board_close, build_board_delete,
    build_post_create, build_post_get, build_post_list, build_post_update,
    build_post_delete, build_query_posts, build_post_content_search,
    build_post_sign, build_user_promote, build_user_demote, build_get_pubkey,
    build_rule_create, build_rule_get, build_rule_get_by_name, build_rule_list,
    build_rule_update, build_report_create, build_report_get,
    build_report_list_by_culprit, build_report_sign, build_report_list_since,
    build_punishment_create, build_punishment_get, build_punishment_list_active,
    build_is_banned,
    parse_response, parse_error_response, decode_redirect,
    parse_register_resp, parse_list_users_resp, parse_list_peers_resp,
    parse_board_list_resp, parse_post_create_resp, parse_post_get_resp,
    parse_post_list_resp, parse_query_posts_resp, parse_post_content_search_resp,
    parse_get_pubkey_resp, parse_rule_resp, parse_rule_list_resp,
    parse_report_resp, parse_report_list_resp, parse_punishment_resp,
    parse_punishment_list_resp, parse_is_banned_resp,
    encode_tlv_str, encode_tlv_long_str, encode_tlv_i32, encode_tlv_u8,
    TLV_CONTENT, TLV_SUBJECT, TLV_OPTIONS, TLV_TAGS, TLV_STICKY, TLV_CLOSED,
    ResponseStatus,
)
from .models import User, Board, Post, PostSummary, PostCreateResult, Rule, Report, Punishment, BannedStatus, Peer


class BonnetHTTPError(Exception):
    """Raised when the server returns a command-level error."""
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(f"Error {code:#06x}: {message}")


class BonnetHTTPClient:
    """Async HTTP client for Bonnet protocol v2.

    Usage:
        async with BonnetHTTPClient(base_url="https://bbs.example.com") as client:
            await client.connect(identity)
            boards = await client.board_list()

    For anonymous access:
        async with BonnetHTTPClient(base_url="https://bbs.example.com") as client:
            await client.connect_anonymous()
            boards = await client.board_list()
    """

    def __init__(
        self,
        base_url: str = "https://localhost:2272",
        trust_store_path: Optional[str] = None,
        max_connections: int = 10,
        timeout: float = 30.0,
        verify: bool | str = True,
    ):
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_connections = max_connections
        self._verify = verify

        self._identity: Optional[Identity] = None
        self._private_key: Optional[bytes] = None
        self._public_key: Optional[bytes] = None
        self._username: Optional[str] = None

        self._anonymous_private_key: Optional[bytes] = None
        self._anonymous_public_key: Optional[bytes] = None
        self._is_anonymous: bool = False

        self._server_public_key: Optional[bytes] = None
        self._server_origin: Optional[str] = None

        self._trust_store: Optional[TrustStore] = None
        if trust_store_path:
            self._trust_store = TrustStore(trust_store_path)

        self._http_client: Optional[httpx.AsyncClient] = None
        self._signer: Optional[BonnetSigner] = None
        self._verifier: Optional[BonnetVerifier] = None

    async def __aenter__(self) -> "BonnetHTTPClient":
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def close(self):
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
        if self._trust_store:
            self._trust_store.close()

    def _ensure_client(self):
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                base_url=self._base_url,
                timeout=httpx.Timeout(self._timeout),
                limits=httpx.Limits(max_connections=self._max_connections),
                verify=self._verify,
            )

    # ------------------------------------------------------------------
    # Connection / discovery
    # ------------------------------------------------------------------

    async def discover(self) -> dict:
        """Fetch the discovery document from /.well-known/bonnet."""
        self._ensure_client()
        resp = await self._http_client.get("/.well-known/bonnet")
        resp.raise_for_status()
        return resp.json()

    async def connect(self, identity: Identity, username: Optional[str] = None) -> None:
        """Connect with an authenticated identity. Fetches discovery, TOFUs the server key."""
        self._identity = identity
        self._private_key = identity.private_key
        self._public_key = identity.public_key
        self._username = username
        self._is_anonymous = False

        info = await self.discover()
        self._server_public_key = bytes.fromhex(info["public_key"])
        self._server_origin = info["origin"]
        self._anonymous_public_key = bytes.fromhex(info.get("anonymous_key", ""))

        self._pin_server_key(info["origin"], self._server_public_key)

        self._signer = BonnetSigner(
            private_key=self._private_key,
            key_id=f"ed25519:{self._public_key.hex()}",
        )
        self._verifier = BonnetVerifier(
            key_resolver=_ServerKeyResolver(self._server_public_key),
            max_lifetime=60,
            clock_skew=30,
        )

    async def connect_anonymous(self, anonymous_private_key: Optional[bytes] = None) -> None:
        """Connect anonymously using the server's shared anonymous key.

        The anonymous private key is published by the server in its discovery
        document. If not provided explicitly, it is fetched automatically.
        """
        info = await self.discover()
        self._server_public_key = bytes.fromhex(info["public_key"])
        self._server_origin = info["origin"]
        self._anonymous_public_key = bytes.fromhex(info["anonymous_key"])

        if anonymous_private_key is None:
            anon_priv_hex = info.get("anonymous_private_key")
            if anon_priv_hex:
                anonymous_private_key = bytes.fromhex(anon_priv_hex)
            else:
                raise BonnetHTTPError(500, "Server does not publish anonymous private key")

        self._anonymous_private_key = anonymous_private_key

        self._is_anonymous = True

        self._pin_server_key(info["origin"], self._server_public_key)

        self._signer = BonnetSigner(
            private_key=self._anonymous_private_key,
            key_id=f"ed25519:{self._anonymous_public_key.hex()}",
        )
        self._verifier = BonnetVerifier(
            key_resolver=_ServerKeyResolver(self._server_public_key),
            max_lifetime=60,
            clock_skew=30,
        )

    def _pin_server_key(self, origin: str, public_key: bytes) -> None:
        """TOFU or verify the server's origin key pin."""
        if self._trust_store:
            if not self._trust_store.tofu_pin(origin, public_key):
                raise BonnetHTTPError(403, f"Server key pin mismatch for origin '{origin}'")
        else:
            # No trust store — accept first contact (pure TOFU in memory)
            if self._server_public_key and self._server_public_key != public_key:
                raise BonnetHTTPError(403, "Server key changed without rotation")

    def set_configured_pin(self, origin: str, public_key: bytes) -> None:
        """Set a pre-configured origin pin (out-of-band trust)."""
        if self._trust_store:
            self._trust_store.configured_pin(origin, public_key)

    # ------------------------------------------------------------------
    # Core request/response
    # ------------------------------------------------------------------

    async def _send_command(self, cmd_bytes: bytes) -> bytes:
        """Send a signed command and return the verified response payload."""
        if self._signer is None:
            raise BonnetHTTPError(500, "Not connected — call connect() or connect_anonymous() first")

        self._ensure_client()
        nonce = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        now = int(time.time())
        expires = now + 60

        msg = HTTPMessage(
            method="POST",
            url=f"{self._base_url}/v2/command",
            headers={
                "Content-Type": "application/vnd.bonnet.command",
                "Content-Digest": compute_content_digest(cmd_bytes),
                "Bonnet-Version": "2",
                "Bonnet-Nonce": nonce,
            },
            body=cmd_bytes,
        )

        await self._signer.sign_request(
            msg, nonce=nonce, created=now, expires=expires,
            include_username=self._username is not None,
        )

        headers = dict(msg.headers)
        resp = await self._http_client.post("/v2/command", content=cmd_bytes, headers=headers)

        if resp.status_code != 200:
            raise BonnetHTTPError(resp.status_code, f"HTTP error: {resp.text[:200]}")

        # Verify response signature
        await self._verify_response(resp, nonce)

        # Parse binary response
        status, payload = parse_response(resp.content)
        if status == ResponseStatus.ERROR:
            raise BonnetHTTPError(*self._parse_error(payload))
        if status == ResponseStatus.REDIRECT:
            origin = decode_redirect(payload)
            raise BonnetHTTPError(302, f"Redirect to origin: {origin}")

        return payload

    async def _verify_response(self, resp: httpx.Response, request_nonce: str) -> None:
        """Verify the response signature, origin, and request nonce."""
        if self._verifier is None or self._server_origin is None:
            return  # not enough info to verify

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
            raise BonnetHTTPError(403, f"Response signature verification failed: {e}")

    def _parse_error(self, payload: bytes) -> tuple[int, str]:
        import struct
        if len(payload) < 3:
            return (0, "Unknown error")
        code = struct.unpack(">H", payload[:2])[0]
        msg_len = payload[2]
        msg = payload[3:3+msg_len].decode("utf-8", errors="replace")
        return (code, msg)

    # ------------------------------------------------------------------
    # High-level command methods — mirror BonnetClient API
    # ------------------------------------------------------------------

    async def register(self, username: str, registrar: str) -> str:
        cmd = build_register(username, registrar)
        payload = await self._send_command(cmd)
        return parse_register_resp(payload)

    async def get_user(self, pubkey: bytes) -> User | None:
        cmd = build_get_user(pubkey)
        try:
            payload = await self._send_command(cmd)
        except BonnetHTTPError as e:
            if e.code == 0x0404 or "not found" in e.message.lower():
                return None
            raise
        users = parse_list_users_resp(payload)
        return users[0] if users else None

    async def list_users(self, offset: int = 0, limit: int = 100) -> list[User]:
        cmd = build_list_users(offset, limit)
        payload = await self._send_command(cmd)
        return parse_list_users_resp(payload)

    async def list_peers(self) -> list[Peer]:
        cmd = build_list_peers()
        payload = await self._send_command(cmd)
        return parse_list_peers_resp(payload)

    async def board_create(self, name: str) -> Board:
        cmd = build_board_create(name)
        await self._send_command(cmd)
        boards = await self.board_list()
        for b in boards:
            if b.name == name:
                return b
        raise BonnetHTTPError(500, f"Board {name} not found after creation")

    async def board_list(self) -> list[Board]:
        cmd = build_board_list()
        payload = await self._send_command(cmd)
        return parse_board_list_resp(payload)

    async def board_close(self, name: str) -> None:
        cmd = build_board_close(name)
        await self._send_command(cmd)

    async def board_delete(self, name: str) -> None:
        cmd = build_board_delete(name)
        await self._send_command(cmd)

    async def post_create(self, board: str, subject: str, content: str,
                          tags: str = "", options: str = "", root: int = 0) -> PostCreateResult:
        cmd = build_post_create(board, root, subject, tags, options, content)
        payload = await self._send_command(cmd)
        return parse_post_create_resp(payload)

    async def post_get(self, board: str, post_num: int) -> Post:
        cmd = build_post_get(board, post_num)
        payload = await self._send_command(cmd)
        return parse_post_get_resp(payload)

    async def post_list(self, board: str, offset: int = 0, limit: int = 50) -> list[PostSummary]:
        cmd = build_post_list(board, offset, limit)
        payload = await self._send_command(cmd)
        return parse_post_list_resp(payload)

    async def post_update(self, board: str, post_num: int, content: str | None = None,
                          subject: str | None = None, tags: str | None = None,
                          options: str | None = None, sticky: int | None = None,
                          closed: bool | None = None) -> None:
        fields = []
        if content is not None:
            fields.append(("content", encode_tlv_long_str(TLV_CONTENT, content)))
        if subject is not None:
            fields.append(("subject", encode_tlv_str(TLV_SUBJECT, subject)))
        if tags is not None:
            fields.append(("tags", encode_tlv_str(TLV_TAGS, tags)))
        if options is not None:
            fields.append(("options", encode_tlv_str(TLV_OPTIONS, options)))
        if sticky is not None:
            fields.append(("sticky", encode_tlv_i32(TLV_STICKY, sticky)))
        if closed is not None:
            fields.append(("closed", encode_tlv_u8(TLV_CLOSED, 1 if closed else 0)))
        if not fields:
            return
        cmd = build_post_update(board, post_num, fields)
        await self._send_command(cmd)

    async def post_delete(self, board: str, post_num: int) -> None:
        cmd = build_post_delete(board, post_num)
        await self._send_command(cmd)

    async def query_posts(self, board: str, where: str = "",
                          values: list[tuple[int, bytes]] | None = None,
                          orderby: str = "last_bumped DESC", limit: int = 100) -> list[PostSummary]:
        cmd = build_query_posts(board, where, values or [], orderby, limit)
        payload = await self._send_command(cmd)
        return parse_query_posts_resp(payload)

    async def post_content_search(self, board: str, pattern: str, limit: int = 100) -> list[PostSummary]:
        cmd = build_post_content_search(board, pattern, limit)
        payload = await self._send_command(cmd)
        return parse_post_content_search_resp(payload)

    async def post_sign(self, board: str, post_num: int, creation_date: int,
                        last_modified: int, author: str, author_registrar: str,
                        tags: str, subject: str, options: str, content: str) -> str:
        if self._private_key is None:
            raise BonnetHTTPError(500, "No identity loaded")
        signing_key = SigningKey(self._private_key)
        import struct as _struct
        from .protocol import encode_string, encode_long_string
        payload = _struct.pack(">Q", post_num)
        payload += _struct.pack(">q", creation_date)
        payload += _struct.pack(">q", last_modified)
        payload += encode_string(author)
        payload += encode_string(author_registrar)
        payload += encode_string(tags)
        payload += encode_string(subject)
        payload += encode_string(options)
        payload += encode_long_string(content)
        signature = signing_key.sign(payload).signature.hex()
        cmd = build_post_sign(board, post_num, signature)
        await self._send_command(cmd)
        return signature

    async def user_promote(self, username: str) -> None:
        cmd = build_user_promote(username)
        await self._send_command(cmd)

    async def user_demote(self, username: str) -> None:
        cmd = build_user_demote(username)
        await self._send_command(cmd)

    async def get_server_pubkey(self) -> str:
        cmd = build_get_pubkey()
        payload = await self._send_command(cmd)
        return parse_get_pubkey_resp(payload)

    async def rule_create(self, name: str, description: str) -> Rule:
        cmd = build_rule_create(name, description)
        payload = await self._send_command(cmd)
        return parse_rule_resp(payload)

    async def rule_get(self, rule_num: int) -> Rule:
        cmd = build_rule_get(rule_num)
        payload = await self._send_command(cmd)
        return parse_rule_resp(payload)

    async def rule_get_by_name(self, name: str) -> Rule:
        cmd = build_rule_get_by_name(name)
        payload = await self._send_command(cmd)
        return parse_rule_resp(payload)

    async def rule_list(self) -> list[Rule]:
        cmd = build_rule_list()
        payload = await self._send_command(cmd)
        return parse_rule_list_resp(payload)

    async def rule_update(self, rule_num: int, name: str | None = None,
                          description: str | None = None) -> Rule:
        from .protocol import encode_string
        fields = []
        if name is not None:
            fields.append(("name", encode_string(name)))
        if description is not None:
            fields.append(("description", encode_string(description)))
        cmd = build_rule_update(rule_num, fields)
        payload = await self._send_command(cmd)
        return parse_rule_resp(payload)

    async def report_create(self, rule_num: int, culprit_pubkey: str, description: str,
                            board: str | None = None, post_num: int | None = None,
                            origin: str | None = None, relay: str | None = None) -> Report:
        if self._public_key is None:
            raise BonnetHTTPError(500, "No identity loaded")
        culprit = bytes.fromhex(culprit_pubkey)
        cmd = build_report_create(rule_num, culprit, self._public_key, description,
                                  board, post_num, origin, relay)
        payload = await self._send_command(cmd)
        return parse_report_resp(payload)

    async def report_get(self, origin: str, report_num: int) -> Report:
        cmd = build_report_get(origin, report_num)
        payload = await self._send_command(cmd)
        return parse_report_resp(payload)

    async def report_list_by_culprit(self, pubkey: str) -> list[Report]:
        cmd = build_report_list_by_culprit(bytes.fromhex(pubkey))
        payload = await self._send_command(cmd)
        return parse_report_list_resp(payload)

    async def report_sign(self, origin: str, report_num: int) -> Report:
        report = await self.report_get(origin, report_num)
        if self._private_key is None:
            raise BonnetHTTPError(500, "No identity loaded")
        signing_key = SigningKey(self._private_key)
        import struct as _struct
        from .protocol import encode_string, encode_bytes
        payload = _struct.pack(">Q", report.report_num)
        payload += _struct.pack(">Q", report.rule_num)
        payload += encode_bytes(bytes.fromhex(report.culprit_pubkey))
        payload += encode_string(report.board or "")
        payload += _struct.pack(">Q", report.post_num or 0)
        payload += encode_bytes(bytes.fromhex(report.reporter_pubkey))
        payload += _struct.pack(">q", report.report_time)
        payload += encode_string(report.origin)
        payload += encode_string(report.description)
        signature = signing_key.sign(payload).signature.hex()
        cmd = build_report_sign(origin, report_num, signature)
        await self._send_command(cmd)
        return await self.report_get(origin, report_num)

    async def report_list_since(self, since: int) -> list[Report]:
        cmd = build_report_list_since(since)
        payload = await self._send_command(cmd)
        return parse_report_list_resp(payload)

    async def punishment_create(self, pubkey: str, report_ids: list[int],
                                expires_at: int, notes: str = "") -> Punishment:
        cmd = build_punishment_create(bytes.fromhex(pubkey), report_ids, expires_at, notes)
        payload = await self._send_command(cmd)
        return parse_punishment_resp(payload)

    async def punishment_get(self, pubkey: str) -> Punishment | None:
        cmd = build_punishment_get(bytes.fromhex(pubkey))
        try:
            payload = await self._send_command(cmd)
        except BonnetHTTPError:
            return None
        return parse_punishment_resp(payload)

    async def punishment_list_active(self) -> list[Punishment]:
        cmd = build_punishment_list_active()
        payload = await self._send_command(cmd)
        return parse_punishment_list_resp(payload)

    async def is_banned(self, pubkey: str) -> BannedStatus:
        cmd = build_is_banned(bytes.fromhex(pubkey))
        payload = await self._send_command(cmd)
        return parse_is_banned_resp(payload)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_connected(self) -> bool:
        return self._signer is not None

    @property
    def is_anonymous(self) -> bool:
        return self._is_anonymous

    @property
    def server_public_key(self) -> Optional[bytes]:
        return self._server_public_key


class _ServerKeyResolver(KeyResolver):
    """Resolves the server's origin key for response verification."""

    def __init__(self, server_public_key: bytes):
        self._key = server_public_key

    def resolve_public_key(self, key_id: str) -> bytes:
        return self._key


class BonnetMCPClient:
    """IdentityStore-aware wrapper around BonnetHTTPClient for MCP tool servers.

    Provides the v1-compatible connect API that the MCP tools (tools.py,
    simple.py) expect:

        client = BonnetMCPClient(identity_store, bonnet_url)
        async with client:
            await client.connect(username, password, require_auth=True)
            await client.board_create("test")

    When require_auth=True, the wrapper unlocks the local Ed25519 key from the
    IdentityStore using username+password and delegates to
    BonnetHTTPClient.connect(identity, username).

    When require_auth=False, it connects anonymously (the server publishes its
    shared anonymous private key via discovery) so read-only public commands
    work without a password.
    """

    def __init__(self, identity_store, base_url: str = "https://localhost:2272",
                 trust_store_path: Optional[str] = None, verify: bool | str = True,
                 **kwargs):
        self.identity_store = identity_store
        self._http = BonnetHTTPClient(
            base_url=base_url,
            trust_store_path=trust_store_path,
            verify=verify,
            **kwargs,
        )
        self._public_key: Optional[bytes] = None
        self._connected_username: Optional[str] = None

    async def __aenter__(self) -> "BonnetMCPClient":
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def close(self):
        await self._http.close()

    async def connect(self, username: str, password: Optional[str] = None,
                      require_auth: bool = False) -> None:
        """Connect to the server.

        require_auth=True: unlock the local Ed25519 key with username+password
        and connect as an authenticated user.
        require_auth=False: connect anonymously for public read commands.
        """
        self._connected_username = username
        if require_auth:
            if password is None:
                raise BonnetHTTPError(500, "Password required for authenticated connection")
            private_key = self.identity_store.get_private_key(username, password)
            identity = Identity.from_private_key(private_key)
            self._public_key = identity.public_key
            await self._http.connect(identity, username)
        else:
            self._public_key = self.identity_store.get_pubkey(username)
            await self._http.connect_anonymous()

    async def _register(self, username: str) -> str:
        """Register the user on the Bonnet server.

        Uses the registrar from the server's discovery origin.
        """
        if self._http._server_origin is None:
            raise BonnetHTTPError(500, "Not connected — call connect() first")
        registrar = self._http._server_origin
        result = await self._http.register(username, registrar)
        self.identity_store.mark_registered(username)
        return result

    @property
    def _identity(self) -> Optional[Identity]:
        return self._http._identity

    @property
    def is_connected(self) -> bool:
        return self._http.is_connected

    @property
    def is_anonymous(self) -> bool:
        return self._http.is_anonymous

    @property
    def server_public_key(self) -> Optional[bytes]:
        return self._http.server_public_key

    def __getattr__(self, name: str):
        """Delegate all other methods/attributes to the underlying BonnetHTTPClient."""
        return getattr(self._http, name)
