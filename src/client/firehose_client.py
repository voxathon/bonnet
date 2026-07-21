"""Firehose HTTP client for the Bonnet Firehose Protocol (PROTOCOL.md §18-19).

High-level client that connects to a Bonnet server, fetches discovery,
handles TOFU pinning, signs requests with RFC 9421 HTTP Message Signatures,
verifies response signatures, and provides typed methods for all firehose
commands.
"""

from __future__ import annotations

import base64
import os
import struct
import time
from typing import Optional

import httpx

from core.crypto import Identity
from core.record import (
    Intent, MetadataMap, ZERO_ID,
    encode_intent, sign_intent, compute_body_hash,
    metadata_text, metadata_text_list, metadata_bytes, metadata_u64, metadata_i64,
)
from core.trust import TrustStore
from net.http_auth import (
    BonnetSigner, BonnetVerifier, KeyResolver, HTTPMessage,
    compute_content_digest, validate_content_digest,
    SignatureError,
)
from client.firehose_models import (
    PublishResult, EventInfo, HeadInfo, ArticleView, ArticleListItem,
    SearchResult, SearchResponse, BoardInfo, UserInfo, BanStatus, DiscoveryInfo,
)
from client.firehose_protocol import (
    build_publish_record, parse_publish_response, parse_publish_response_raw,
    build_event_head, parse_event_head_response, parse_event_head_response_raw,
    build_event_range, parse_event_range_response,
    build_event_get, parse_event_get_response,
    build_board_list, parse_board_list_response,
    build_article_get, parse_article_get_response,
    build_article_list, parse_article_list_response,
    build_article_search, parse_article_search_response,
    build_article_query, parse_article_query_response,
    build_article_body, parse_article_body_response,
    build_user_get, parse_user_get_response,
    build_user_list, parse_user_list_response,
    build_ban_status, parse_ban_status_response,
    build_event_body, parse_event_body_response,
    SELECTOR_BY_NUM, SELECTOR_BY_ID,
    ProtocolError,
)


FIREHOSE_TAG = "bonnet-firehose-1"
FIREHOSE_LABEL = "bonnet"


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


class FirehoseHTTPClient:
    """HTTP client for the Bonnet firehose protocol."""

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
        self._identity: Optional[Identity] = None
        self._server_pubkey: Optional[bytes] = None
        self._server_origin: Optional[str] = None
        self._anonymous_key: Optional[bytes] = None
        self._anonymous_private_key: Optional[bytes] = None
        self._discovery: Optional[DiscoveryInfo] = None
        self._signer: Optional[BonnetSigner] = None
        self._verifier: Optional[BonnetVerifier] = None
        self._trust_store: Optional[TrustStore] = None
        if trust_store_path:
            self._trust_store = TrustStore(trust_store_path)
        self._username: str = ""

    async def close(self) -> None:
        await self._http.aclose()

    # ------------------------------------------------------------------
    # Discovery and connection
    # ------------------------------------------------------------------

    async def discover(self) -> DiscoveryInfo:
        """Fetch and parse the discovery document."""
        resp = await self._http.get(f"{self._base_url}/.well-known/bonnet")
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
        )
        self._server_pubkey = bytes.fromhex(info.public_key)
        self._server_origin = info.origin
        self._anonymous_key = bytes.fromhex(info.anonymous_key)
        self._anonymous_private_key = bytes.fromhex(info.anonymous_private_key)
        self._discovery = info

        self._pin_server_key(info.origin, self._server_pubkey)

        self._verifier = BonnetVerifier(
            key_resolver=_ServerKeyResolver(self._server_pubkey),
            tag=FIREHOSE_TAG,
            max_lifetime=60,
            clock_skew=30,
        )

        return info

    def _pin_server_key(self, origin: str, public_key: bytes) -> None:
        """TOFU pin or verify the server's origin key."""
        if self._trust_store:
            if not self._trust_store.tofu_pin(origin, public_key):
                raise FirehoseClientError(f"Server key pin mismatch for origin '{origin}'")
        else:
            if self._server_pubkey and self._server_pubkey != public_key:
                raise FirehoseClientError("Server key changed without rotation")

    async def connect(self, identity: Identity, username: str = "") -> None:
        """Connect with an authenticated identity."""
        self._identity = identity
        self._username = username
        if self._discovery is None:
            await self.discover()

        self._signer = BonnetSigner(
            private_key=identity.private_key,
            key_id=f"ed25519:{identity.public_key.hex()}",
            tag=FIREHOSE_TAG,
            label=FIREHOSE_LABEL,
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
            tag=FIREHOSE_TAG,
            label=FIREHOSE_LABEL,
        )

    # ------------------------------------------------------------------
    # Core request/response
    # ------------------------------------------------------------------

    async def _send_command(self, cmd_bytes: bytes) -> bytes:
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
                "Bonnet-Protocol": "bonnet-firehose-1",
                "Bonnet-Nonce": nonce,
            },
            body=cmd_bytes,
        )

        await self._signer.sign_request(
            msg, nonce=nonce, created=now, expires=expires,
            extra_components=["bonnet-protocol"],
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

    # ------------------------------------------------------------------
    # Publication
    # ------------------------------------------------------------------

    async def publish_article(
        self, board: str, article_id: bytes, body: bytes,
        subject: str, content_type: str = "text/plain",
        tags: list[str] = None, event_id: bytes = None,
        actor_username: str = "", actor_registrar: str = "",
    ) -> PublishResult:
        """Publish an article to the connected server."""
        if self._identity is None or self._server_origin is None:
            raise FirehoseClientError("not connected")
        eid = event_id or os.urandom(32)

        m = MetadataMap([metadata_text(1, subject)])
        if tags:
            m.fields.append(metadata_text_list(2, tags))
        m.fields.append(metadata_text(4, content_type))

        intent = Intent(
            event_id=eid,
            kind="bonnet.article",
            origin=self._server_origin,
            actor_pubkey=self._identity.public_key,
            actor_username=actor_username or self._username,
            actor_registrar=actor_registrar or self._server_origin,
            board=board,
            article_id=article_id,
            metadata=m,
            body_hash=compute_body_hash(body),
            body_size=len(body),
        )
        actor_sig = sign_intent(self._identity, encode_intent(intent))
        cmd = build_publish_record(intent, actor_sig, body)
        resp = await self._send_command(cmd)
        return parse_publish_response(resp)

    async def publish_record(
        self, intent: Intent, actor_sig: bytes, body: bytes = b"",
    ) -> tuple:
        """Publish an arbitrary signed record. Returns (Record, Witness)."""
        cmd = build_publish_record(intent, actor_sig, body)
        resp = await self._send_command(cmd)
        return parse_publish_response_raw(resp)

    async def publish_board_create(
        self, board: str, owner_pubkey: bytes, display_name: str = "",
    ) -> PublishResult:
        """Create a board."""
        if self._identity is None or self._server_origin is None:
            raise FirehoseClientError("not connected")
        eid = os.urandom(32)
        m = MetadataMap([metadata_bytes(1, owner_pubkey)])
        if display_name:
            m.fields.append(metadata_text(2, display_name))

        intent = Intent(
            event_id=eid, kind="bonnet.board.create", origin=self._server_origin,
            actor_pubkey=self._identity.public_key,
            actor_username=self._username, actor_registrar=self._server_origin,
            board=board, metadata=m,
        )
        actor_sig = sign_intent(self._identity, encode_intent(intent))
        cmd = build_publish_record(intent, actor_sig, b"")
        resp = await self._send_command(cmd)
        return parse_publish_response(resp)

    async def publish_user_register(
        self, username: str, user_pubkey: bytes, flags: int = 0,
    ) -> PublishResult:
        """Register a user identity."""
        if self._identity is None or self._server_origin is None:
            raise FirehoseClientError("not connected")
        eid = os.urandom(32)
        m = MetadataMap([
            metadata_text(1, username),
            metadata_bytes(2, user_pubkey),
            metadata_u64(3, flags),
        ])

        intent = Intent(
            event_id=eid, kind="bonnet.user.register", origin=self._server_origin,
            actor_pubkey=self._identity.public_key,
            actor_username=self._username, actor_registrar=self._server_origin,
            metadata=m,
        )
        actor_sig = sign_intent(self._identity, encode_intent(intent))
        cmd = build_publish_record(intent, actor_sig, b"")
        resp = await self._send_command(cmd)
        return parse_publish_response(resp)

    async def publish_cancel(
        self, board: str, target_origin: str, target_board: str,
        target_article_id: bytes, reason: str = "",
    ) -> PublishResult:
        """Cancel an article."""
        return await self._publish_control(
            "bonnet.article.cancel", board, target_origin, target_board,
            target_article_id, reason,
        )

    async def publish_restore(
        self, board: str, target_origin: str, target_board: str,
        target_article_id: bytes, reason: str = "",
    ) -> PublishResult:
        """Restore a cancelled article."""
        return await self._publish_control(
            "bonnet.article.restore", board, target_origin, target_board,
            target_article_id, reason,
        )

    async def publish_purge(
        self, board: str, target_origin: str, target_board: str,
        target_article_id: bytes, reason: str = "",
    ) -> PublishResult:
        """Purge an article's body."""
        return await self._publish_control(
            "bonnet.article.purge", board, target_origin, target_board,
            target_article_id, reason,
        )

    async def publish_pin(
        self, board: str, target_origin: str, target_board: str,
        target_article_id: bytes, priority: int,
    ) -> PublishResult:
        """Pin an article."""
        if self._identity is None or self._server_origin is None:
            raise FirehoseClientError("not connected")
        eid = os.urandom(32)
        m = MetadataMap([metadata_i64(1, priority)])
        intent = Intent(
            event_id=eid, kind="bonnet.article.pin", origin=self._server_origin,
            actor_pubkey=self._identity.public_key,
            actor_username=self._username, actor_registrar=self._server_origin,
            board=board, target_origin=target_origin, target_board=target_board,
            target_article_id=target_article_id, metadata=m,
        )
        actor_sig = sign_intent(self._identity, encode_intent(intent))
        cmd = build_publish_record(intent, actor_sig, b"")
        resp = await self._send_command(cmd)
        return parse_publish_response(resp)

    async def publish_unpin(
        self, board: str, target_origin: str, target_board: str,
        target_article_id: bytes,
    ) -> PublishResult:
        """Unpin an article."""
        return await self._publish_control(
            "bonnet.article.unpin", board, target_origin, target_board,
            target_article_id, "",
        )

    async def _publish_control(
        self, kind: str, board: str, target_origin: str, target_board: str,
        target_article_id: bytes, reason: str,
    ) -> PublishResult:
        """Publish a control event targeting an article."""
        if self._identity is None or self._server_origin is None:
            raise FirehoseClientError("not connected")
        eid = os.urandom(32)
        body = reason.encode("utf-8") if reason else b""
        intent = Intent(
            event_id=eid, kind=kind, origin=self._server_origin,
            actor_pubkey=self._identity.public_key,
            actor_username=self._username, actor_registrar=self._server_origin,
            board=board, target_origin=target_origin, target_board=target_board,
            target_article_id=target_article_id,
            body_hash=compute_body_hash(body) if body else ZERO_ID,
            body_size=len(body),
        )
        actor_sig = sign_intent(self._identity, encode_intent(intent))
        cmd = build_publish_record(intent, actor_sig, body)
        resp = await self._send_command(cmd)
        return parse_publish_response(resp)

    # ------------------------------------------------------------------
    # Firehose reads
    # ------------------------------------------------------------------

    async def get_head(self, origin: str) -> HeadInfo:
        cmd = build_event_head(origin)
        resp = await self._send_command(cmd)
        return parse_event_head_response(resp)

    async def get_event_range(self, origin: str, start_seq: int, max_count: int = 100) -> list:
        cmd = build_event_range(origin, start_seq, max_count)
        resp = await self._send_command(cmd)
        return parse_event_range_response(resp)

    async def get_event(self, origin: str, event_id: bytes) -> tuple:
        """Get a single event by ID. Used for relay tracing."""
        cmd = build_event_get(origin, event_id)
        resp = await self._send_command(cmd)
        return parse_event_get_response(resp)

    # ------------------------------------------------------------------
    # Projection reads
    # ------------------------------------------------------------------

    async def list_boards(self, origin: str) -> list[BoardInfo]:
        cmd = build_board_list(origin)
        resp = await self._send_command(cmd)
        return parse_board_list_response(resp)

    async def get_article(self, origin: str, board: str, article_num: int, include_body: bool = False) -> ArticleView:
        cmd = build_article_get(origin, board, SELECTOR_BY_NUM, article_num, include_body)
        resp = await self._send_command(cmd)
        return parse_article_get_response(resp)

    async def get_article_by_id(self, origin: str, board: str, article_id: bytes, include_body: bool = False) -> ArticleView:
        cmd = build_article_get(origin, board, SELECTOR_BY_ID, article_id, include_body)
        resp = await self._send_command(cmd)
        return parse_article_get_response(resp)

    async def list_articles(self, origin: str, board: str, offset: int = 0, limit: int = 100,
                            include_cancelled: bool = False, include_superseded: bool = False) -> list[ArticleListItem]:
        cmd = build_article_list(origin, board, offset, limit, include_cancelled, include_superseded)
        resp = await self._send_command(cmd)
        return parse_article_list_response(resp)

    async def search_articles(self, origin: str, board: str, meta_query: str = "", body_query: str = "",
                              offset: int = 0, limit: int = 100,
                              include_cancelled: bool = False, include_superseded: bool = False) -> SearchResponse:
        cmd = build_article_search(origin, board, meta_query, body_query, offset, limit,
                                   include_cancelled, include_superseded)
        resp = await self._send_command(cmd)
        return parse_article_search_response(resp)

    async def query_articles(self, origin: str, board: str, filters: list,
                             offset: int = 0, limit: int = 100) -> list[ArticleListItem]:
        """Query articles with structured filters.

        filters: list of (field_id, operator, value_type, value_bytes) tuples.
        """
        cmd = build_article_query(origin, board, filters, offset, limit)
        resp = await self._send_command(cmd)
        return parse_article_query_response(resp)

    async def get_article_body(self, origin: str, board: str, article_num: int) -> bytes:
        cmd = build_article_body(origin, board, article_num)
        resp = await self._send_command(cmd)
        return parse_article_body_response(resp)

    async def get_user(self, origin: str, pubkey: bytes) -> UserInfo:
        cmd = build_user_get(origin, pubkey)
        resp = await self._send_command(cmd)
        return parse_user_get_response(resp)

    async def list_users(self, origin: str, include_revoked: bool = False) -> list[UserInfo]:
        cmd = build_user_list(origin, include_revoked)
        resp = await self._send_command(cmd)
        return parse_user_list_response(resp)

    async def get_ban_status(self, pubkey: bytes) -> BanStatus:
        cmd = build_ban_status(pubkey)
        resp = await self._send_command(cmd)
        return parse_ban_status_response(resp)

    async def get_event_body(self, origin: str, event_id: bytes) -> bytes:
        cmd = build_event_body(origin, event_id)
        resp = await self._send_command(cmd)
        return parse_event_body_response(resp)

    # ------------------------------------------------------------------
    # Relay tracing
    # ------------------------------------------------------------------

    async def trace_event(self, origin: str, event_id: bytes, max_hops: int = 10) -> list[dict]:
        """Trace an event back to its origin through relay witnesses.

        Follows the witness chain by dialing each upstream server,
        verifying its discovery key, and requesting the event.

        Returns a list of hop dictionaries:
            {relay_pubkey, relay_hostname, received_from_pubkey,
             received_from_hostname, seen_at, record_hash}
        """
        hops = []
        current_origin = origin
        current_event_id = event_id
        current_base_url = self._base_url

        for _ in range(max_hops):
            try:
                if current_base_url == self._base_url:
                    rec, witness = await self.get_event(current_origin, current_event_id)
                else:
                    sub_client = FirehoseHTTPClient(current_base_url, verify=self._verify)
                    await sub_client.connect_anonymous()
                    try:
                        rec, witness = await sub_client.get_event(current_origin, current_event_id)
                    finally:
                        await sub_client.close()
            except Exception:
                break

            encoded = encode_record(rec) if hasattr(rec, 'origin_seq') else b""
            from core.record import compute_event_hash
            event_hash = compute_event_hash(encoded).hex() if encoded else ""

            hop = {
                "relay_pubkey": witness.relay_pubkey.hex(),
                "relay_hostname": witness.relay_hostname,
                "received_from_pubkey": witness.received_from_pubkey.hex(),
                "received_from_hostname": witness.received_from_hostname,
                "seen_at": witness.seen_at,
                "record_hash": event_hash,
            }
            hops.append(hop)

            zero_key = b"\x00" * 32
            if witness.received_from_pubkey == zero_key and not witness.received_from_hostname:
                break

            upstream_hostname = witness.received_from_hostname
            if not upstream_hostname:
                break

            current_base_url = f"https://{upstream_hostname}"

        return hops
