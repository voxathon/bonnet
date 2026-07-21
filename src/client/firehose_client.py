"""Firehose HTTP client for the Bonnet Firehose Protocol (PROTOCOL.md §18-19).

High-level client that connects to a Bonnet server, fetches discovery,
handles TOFU pinning, and provides typed methods for all firehose commands.
"""

from __future__ import annotations

import os
import struct
from typing import Optional

import httpx

from core.crypto import Identity
from core.record import (
    Intent, MetadataMap, ZERO_ID,
    encode_intent, sign_intent, compute_body_hash,
    metadata_text, metadata_text_list, metadata_bytes, metadata_u64, metadata_i64,
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
    build_article_body, parse_article_body_response,
    build_user_get, parse_user_get_response,
    build_user_list, parse_user_list_response,
    build_ban_status, parse_ban_status_response,
    build_event_body, parse_event_body_response,
    SELECTOR_BY_NUM, SELECTOR_BY_ID,
    ProtocolError,
)


class FirehoseClientError(Exception):
    pass


class FirehoseHTTPClient:
    """HTTP client for the Bonnet firehose protocol."""

    def __init__(self, base_url: str, timeout: float = 30.0, verify: bool | str = True):
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

    async def close(self) -> None:
        await self._http.aclose()

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
        return info

    async def connect(self, identity: Identity) -> None:
        """Connect with an authenticated identity."""
        self._identity = identity
        if self._discovery is None:
            await self.discover()

    async def connect_anonymous(self) -> None:
        """Connect using the server's anonymous key."""
        if self._discovery is None:
            await self.discover()
        if self._anonymous_private_key is None:
            raise FirehoseClientError("server does not publish anonymous private key")
        self._identity = Identity.from_private_key(self._anonymous_private_key)

    async def _send_command(self, cmd_bytes: bytes) -> bytes:
        """Send a command and return the raw response body."""
        if self._identity is None:
            raise FirehoseClientError("not connected — call connect() or connect_anonymous() first")
        resp = await self._http.post(
            f"{self._base_url}/command",
            content=cmd_bytes,
            headers={
                "Content-Type": "application/vnd.bonnet.command",
                "Bonnet-Protocol": "bonnet-firehose-1",
            },
        )
        resp.raise_for_status()
        return resp.content

    # ------------------------------------------------------------------
    # Publication
    # ------------------------------------------------------------------

    async def publish_article(
        self, board: str, article_id: bytes, body: bytes,
        subject: str, content_type: str = "text/plain",
        tags: list[str] = None, event_id: bytes = None,
    ) -> PublishResult:
        """Publish an article to the connected server."""
        if self._identity is None or self._server_origin is None:
            raise FirehoseClientError("not connected")
        eid = event_id or os.urandom(32)
        m = MetadataMap([
            metadata_text(1, subject),
            metadata_text(4, content_type),
        ])
        if tags:
            m.fields.append(metadata_text_list(2, tags))

        intent = Intent(
            event_id=eid,
            kind="bonnet.article",
            origin=self._server_origin,
            actor_pubkey=self._identity.public_key,
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

        Returns a list of hop dictionaries: {relay_pubkey, relay_hostname,
        received_from_pubkey, received_from_hostname, seen_at}.
        """
        hops = []
        current_origin = origin
        current_event_id = event_id
        current_hostname = self._base_url.split("//")[-1].split("/")[0]

        for _ in range(max_hops):
            try:
                rec, witness = await self.get_event(current_origin, current_event_id)
            except Exception:
                break

            hop = {
                "relay_pubkey": witness.relay_pubkey.hex(),
                "relay_hostname": witness.relay_hostname,
                "received_from_pubkey": witness.received_from_pubkey.hex(),
                "received_from_hostname": witness.received_from_hostname,
                "seen_at": witness.seen_at,
            }
            hops.append(hop)

            if witness.received_from_pubkey == b"\x00" * 32 and not witness.received_from_hostname:
                break

            current_hostname = witness.received_from_hostname
            if not current_hostname:
                break

        return hops
