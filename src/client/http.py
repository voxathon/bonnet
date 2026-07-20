"""Bonnet protocol v3 async HTTP client.

Signs every request with RFC 9421 Ed25519 and verifies every response
signature + origin pin. All commands are routed through /v3/command.

Anonymous mode:
    The client fetches the server's anonymous shared key from discovery,
    then signs anonymous requests with that key.
"""

from __future__ import annotations

import base64
import os
import time
from typing import Optional

import httpx
from nacl.signing import SigningKey

from core.crypto import Identity
from core.trust import TrustStore
from core.article_feed import (
    Submission,
    ArticleHeaders,
    RuleHeaders,
    ReportHeaders,
    PunishmentHeaders,
    PinHeaders,
    encode_submission,
    compute_body_hash,
    author_signature_payload,
    EVENT_ARTICLE,
    EVENT_CANCEL,
    EVENT_RESTORE,
    EVENT_PURGE,
    EVENT_RULE,
    EVENT_RULE_REVOKE,
    EVENT_REPORT,
    EVENT_PUNISHMENT,
    EVENT_PUNISHMENT_REVOKE,
    EVENT_BOARD_CLOSE,
    EVENT_BOARD_REOPEN,
    EVENT_ARTICLE_PIN,
    EVENT_ARTICLE_UNPIN,
    EVENT_THREAD_CLOSE,
    EVENT_THREAD_REOPEN,
    SCHEME_V3,
    ZERO_HASH,
    ZERO_MESSAGE_ID,
    STATE_ACTIVE,
    STATE_CANCELLED,
    STATE_SUPERSEDED,
    STATE_PURGED,
    FLAG_INCLUDE_CANCELLED,
    FLAG_INCLUDE_SUPERSEDED,
    FLAG_INCLUDE_PURGED,
    FLAG_INCLUDE_CONTROLS,
    FLAG_INCLUDE_BODIES,
    SELECTOR_ARTICLE_NUM,
    SELECTOR_MESSAGE_ID,
)
from net.http_auth import (
    BonnetSigner, BonnetVerifier, KeyResolver, HTTPMessage,
    compute_content_digest,
    SignatureError,
)
from .protocol import (
    build_register, build_get_user, build_list_users, build_list_peers,
    build_board_create, build_board_list,
    build_user_promote, build_user_demote, build_get_pubkey,
    build_article_publish, build_article_get, build_article_list,
    build_feed_head, build_feed_events, build_article_body,
    build_feed_heads, build_article_search, build_ban_status,
    build_board_set_state,
    build_peer_key_rotate, build_peer_key_list,
    build_submission, sign_submission, make_message_id,
    encode_and_sign_submission,
    parse_response, parse_error_response, decode_redirect,
    parse_register_resp, parse_list_users_resp, parse_get_user_resp,
    parse_list_peers_resp, parse_board_list_resp, parse_get_pubkey_resp,
    parse_article_publish_resp, parse_article_get_resp, parse_article_list_resp,
    parse_feed_head_resp, parse_feed_events_resp, parse_article_body_resp,
    parse_feed_heads_resp, parse_article_search_resp, parse_ban_status_resp,
    parse_board_set_state_resp,
    parse_peer_key_list_resp,
    decode_v3_event, decode_v3_head,
    EVENT_TYPE_NAMES,
    ResponseStatus, ProtocolError,
)
from .models import (
    User, Board, Peer, BanStatus,
    Article, ArticleEvent, FeedHeadInfo, ArticlePublishResult,
)


_STATE_NAMES = {
    STATE_ACTIVE: "active", STATE_CANCELLED: "cancelled",
    STATE_SUPERSEDED: "superseded", STATE_PURGED: "purged",
}


class BonnetHTTPError(Exception):
    """Raised when the server returns a command-level error."""
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(f"Error {code:#06x}: {message}")


class BonnetHTTPClient:
    """Async HTTP client for Bonnet protocol v3.

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
        """Connect anonymously using the server's shared anonymous key."""
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
            if self._server_public_key and self._server_public_key != public_key:
                raise BonnetHTTPError(403, "Server key changed without rotation")

    def set_configured_pin(self, origin: str, public_key: bytes) -> None:
        """Set a pre-configured origin pin (out-of-band trust)."""
        if self._trust_store:
            self._trust_store.configured_pin(origin, public_key)

    # ------------------------------------------------------------------
    # Core request/response (single v3 transport path)
    # ------------------------------------------------------------------

    async def _send_command(self, cmd_bytes: bytes) -> bytes:
        """Send a signed v3 command and return the verified response payload."""
        if self._signer is None:
            raise BonnetHTTPError(500, "Not connected — call connect() or connect_anonymous() first")

        self._ensure_client()
        nonce = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        now = int(time.time())
        expires = now + 60

        msg = HTTPMessage(
            method="POST",
            url=f"{self._base_url}/v3/command",
            headers={
                "Content-Type": "application/vnd.bonnet.command",
                "Content-Digest": compute_content_digest(cmd_bytes),
                "Bonnet-Version": "3",
                "Bonnet-Nonce": nonce,
            },
            body=cmd_bytes,
        )

        await self._signer.sign_request(
            msg, nonce=nonce, created=now, expires=expires,
            include_username=self._username is not None,
        )

        headers = dict(msg.headers)
        resp = await self._http_client.post("/v3/command", content=cmd_bytes, headers=headers)

        if resp.status_code != 200:
            raise BonnetHTTPError(resp.status_code, f"HTTP error: {resp.text[:200]}")

        await self._verify_response(resp, nonce)

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
    # Internal: submission publish helper
    # ------------------------------------------------------------------

    def _require_auth(self) -> None:
        if self._private_key is None or self._public_key is None:
            raise BonnetHTTPError(403, "Authenticated connection required for write operations")
        if self._server_origin is None:
            raise BonnetHTTPError(500, "Not connected — call connect() first")

    def _actor_info(self) -> tuple[bytes, str, str, str]:
        """Return (actor_pubkey, actor_username, actor_registrar, origin)."""
        self._require_auth()
        return (
            self._public_key,
            self._username or "",
            self._server_origin or "",
            self._server_origin or "",
        )

    async def _publish_event(
        self,
        event_type: int,
        board: str,
        body: bytes = b"",
        headers=None,
        root_message_id: Optional[bytes] = None,
        reply_to_message_id: Optional[bytes] = None,
        supersedes_message_id: Optional[bytes] = None,
        target_message_id: Optional[bytes] = None,
        use_board_set_state: bool = False,
    ) -> ArticlePublishResult:
        """Build, sign, and publish a v3 event via ARTICLE_PUBLISH or BOARD_SET_STATE."""
        actor_pubkey, actor_username, actor_registrar, origin = self._actor_info()
        sub, raw_body = build_submission(
            event_type=event_type,
            origin=origin,
            board=board,
            actor_pubkey=actor_pubkey,
            actor_username=actor_username,
            actor_registrar=actor_registrar,
            body=body,
            headers=headers,
            root_message_id=root_message_id,
            reply_to_message_id=reply_to_message_id,
            supersedes_message_id=supersedes_message_id,
            target_message_id=target_message_id,
        )
        encoded_sub = encode_submission(sub)
        author_sig = sign_submission(sub, self._private_key)
        if use_board_set_state:
            cmd = build_board_set_state(encoded_sub, raw_body, SCHEME_V3, author_sig)
        else:
            cmd = build_article_publish(encoded_sub, raw_body, SCHEME_V3, author_sig)
        payload = await self._send_command(cmd)
        resp = parse_article_publish_resp(payload)
        ev = decode_v3_event(resp["event_bytes"])
        return ArticlePublishResult(
            article_num=ev.get("article_num", 0),
            message_id=ev.get("message_id", sub.message_id.hex()),
            feed_seq=ev.get("feed_seq", 0),
            event_type=ev.get("event_type", event_type),
            event_type_name=EVENT_TYPE_NAMES.get(ev.get("event_type", event_type), "UNKNOWN"),
            projected_state=_STATE_NAMES.get(
                ev.get("projected_state", STATE_ACTIVE), "active"
            ) if "projected_state" in ev else "active",
            board=board,
            origin=origin,
        )

    # ------------------------------------------------------------------
    # High-level command methods — identity / board / user admin
    # ------------------------------------------------------------------

    async def register(self, username: str, registrar: str) -> str:
        cmd = build_register(username, registrar)
        payload = await self._send_command(cmd)
        return parse_register_resp(payload)

    async def get_user(self, username: str) -> User | None:
        """Look up a user by username. Returns None if not found."""
        cmd = build_get_user(username)
        try:
            payload = await self._send_command(cmd)
        except BonnetHTTPError as e:
            if e.code == 0x0404 or "not found" in e.message.lower():
                return None
            raise
        user = parse_get_user_resp(payload)
        user.username = username
        return user

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

    async def peer_key_list(self) -> list[dict]:
        """List pinned peer keys via PEER_KEY_LIST."""
        cmd = build_peer_key_list()
        payload = await self._send_command(cmd)
        return parse_peer_key_list_resp(payload)

    # ------------------------------------------------------------------
    # High-level v3 article / control event methods
    # ------------------------------------------------------------------

    async def publish_article(
        self,
        board: str,
        subject: str,
        content: str,
        tags: str = "",
        options: str = "",
        root_message_id: Optional[bytes] = None,
        reply_to_message_id: Optional[bytes] = None,
    ) -> ArticlePublishResult:
        """Publish a new article (EVENT_ARTICLE). Requires registered user.

        root_message_id: 32-byte message ID of the root article (for replies).
        reply_to_message_id: 32-byte message ID of the article being replied to.
        """
        body = content.encode("utf-8")
        headers = ArticleHeaders(subject=subject, tags=tags, options=options)
        return await self._publish_event(
            EVENT_ARTICLE, board, body=body, headers=headers,
            root_message_id=root_message_id,
            reply_to_message_id=reply_to_message_id,
        )

    async def supersede_article(
        self,
        board: str,
        target_message_id: bytes,
        subject: str,
        content: str,
        tags: str = "",
        options: str = "",
        root_message_id: Optional[bytes] = None,
    ) -> ArticlePublishResult:
        """Publish a new article that supersedes an existing one (EVENT_ARTICLE
        with supersedes_message_id set). Only the original author may supersede.

        target_message_id: 32-byte message ID of the article being superseded.
        """
        body = content.encode("utf-8")
        headers = ArticleHeaders(subject=subject, tags=tags, options=options)
        return await self._publish_event(
            EVENT_ARTICLE, board, body=body, headers=headers,
            root_message_id=root_message_id,
            supersedes_message_id=target_message_id,
        )

    async def cancel_article(
        self, board: str, target_message_id: bytes, reason: str = "",
    ) -> ArticlePublishResult:
        """Cancel an article (EVENT_CANCEL). Author or moderator may cancel.

        target_message_id: 32-byte message ID of the article to cancel.
        reason: optional human-readable cancellation reason (stored as the
            event body in the feed).
        """
        body = reason.encode("utf-8") if reason else b""
        return await self._publish_event(
            EVENT_CANCEL, board, body=body, target_message_id=target_message_id,
        )

    async def restore_article(
        self, board: str, target_message_id: bytes, reason: str = "",
    ) -> ArticlePublishResult:
        """Restore a cancelled article (EVENT_RESTORE). Author or moderator.

        target_message_id: 32-byte message ID of the article to restore.
        reason: optional restore reason (stored as the event body).
        """
        body = reason.encode("utf-8") if reason else b""
        return await self._publish_event(
            EVENT_RESTORE, board, body=body, target_message_id=target_message_id,
        )

    async def purge_article(
        self, board: str, target_message_id: bytes, reason: str,
    ) -> ArticlePublishResult:
        """Purge an article (EVENT_PURGE). Moderator/admin only.

        target_message_id: 32-byte message ID of the article to purge.
        reason: human-readable purge reason (stored as the event body).
        """
        body = reason.encode("utf-8") if reason else b""
        return await self._publish_event(
            EVENT_PURGE, board, body=body, target_message_id=target_message_id,
        )

    async def close_board(self, board: str, reason: str = "") -> ArticlePublishResult:
        """Close a board (BOARD_SET_STATE with EVENT_BOARD_CLOSE). Admin only.

        A closed board rejects new articles and most control events.
        """
        body = reason.encode("utf-8") if reason else b""
        return await self._publish_event(
            EVENT_BOARD_CLOSE, board, body=body, use_board_set_state=True,
        )

    async def reopen_board(self, board: str, reason: str = "") -> ArticlePublishResult:
        """Reopen a closed board (BOARD_SET_STATE with EVENT_BOARD_REOPEN). Admin only."""
        body = reason.encode("utf-8") if reason else b""
        return await self._publish_event(
            EVENT_BOARD_REOPEN, board, body=body, use_board_set_state=True,
        )

    async def publish_rule(
        self, board: str, rule_name: str, description: str,
    ) -> ArticlePublishResult:
        """Publish a rule (EVENT_RULE with RuleHeaders). Admin only.

        rule_name: short name for the rule.
        description: full rule text (stored as body).
        """
        body = description.encode("utf-8")
        headers = RuleHeaders(rule_name=rule_name)
        return await self._publish_event(
            EVENT_RULE, board, body=body, headers=headers,
        )

    async def revoke_rule(
        self, board: str, target_message_id: bytes, reason: str,
    ) -> ArticlePublishResult:
        """Revoke a rule (EVENT_RULE_REVOKE). Admin only.

        target_message_id: 32-byte message ID of the RULE event to revoke.
        """
        body = reason.encode("utf-8")
        return await self._publish_event(
            EVENT_RULE_REVOKE, board, body=body, target_message_id=target_message_id,
        )

    async def publish_report(
        self,
        board: str,
        culprit_pubkey: bytes,
        description: str,
        target_origin: str = "",
        target_board: str = "",
        target_message_id: Optional[bytes] = None,
        rule_message_ids: Optional[list[bytes]] = None,
        evidence_hashes: Optional[list[bytes]] = None,
    ) -> ArticlePublishResult:
        """File a report (EVENT_REPORT with ReportHeaders). Any registered user.

        culprit_pubkey: 32-byte public key of the user being reported.
        description: report text (stored as body).
        target_origin/target_board/target_message_id: identify the offending article.
        rule_message_ids: message IDs of RULE events the report cites.
        evidence_hashes: 32-byte hashes of evidence bodies.
        """
        body = description.encode("utf-8")
        headers = ReportHeaders(
            culprit_pubkey=culprit_pubkey,
            target_origin=target_origin,
            target_board=target_board,
            target_article_id=target_message_id or ZERO_MESSAGE_ID,
            rule_message_ids=rule_message_ids or [],
            evidence_hashes=evidence_hashes or [],
        )
        return await self._publish_event(
            EVENT_REPORT, board, body=body, headers=headers,
        )

    async def publish_punishment(
        self,
        board: str,
        punished_pubkey: bytes,
        expires_at: int,
        report_ids: Optional[list[bytes]] = None,
        rule_ids: Optional[list[bytes]] = None,
        notes: str = "",
    ) -> ArticlePublishResult:
        """Issue a punishment/ban (EVENT_PUNISHMENT with PunishmentHeaders). Mod/admin.

        punished_pubkey: 32-byte public key of the user being punished.
        expires_at: 0=warning, -1=permanent, >0=unix timestamp.
        report_ids: message IDs of REPORT events justifying the punishment.
        rule_ids: message IDs of RULE events violated.
        notes: moderator notes (stored as body).
        """
        body = notes.encode("utf-8") if notes else b""
        headers = PunishmentHeaders(
            punished_pubkey=punished_pubkey,
            expires_at=expires_at,
            report_ids=report_ids or [],
            rule_ids=rule_ids or [],
        )
        return await self._publish_event(
            EVENT_PUNISHMENT, board, body=body, headers=headers,
        )

    async def revoke_punishment(
        self, board: str, target_message_id: bytes, reason: str,
    ) -> ArticlePublishResult:
        """Revoke a punishment (EVENT_PUNISHMENT_REVOKE). Mod/admin.

        target_message_id: 32-byte message ID of the PUNISHMENT event to revoke.
        """
        body = reason.encode("utf-8")
        return await self._publish_event(
            EVENT_PUNISHMENT_REVOKE, board, body=body, target_message_id=target_message_id,
        )

    async def pin_article(
        self, board: str, target_message_id: bytes, priority: int = 0,
    ) -> ArticlePublishResult:
        """Pin an article (EVENT_ARTICLE_PIN with PinHeaders). Moderator/admin.

        target_message_id: 32-byte message ID of the article to pin.
        priority: higher = more prominent (signed 32-bit).
        """
        headers = PinHeaders(priority=priority)
        return await self._publish_event(
            EVENT_ARTICLE_PIN, board, body=b"", headers=headers,
            target_message_id=target_message_id,
        )

    async def unpin_article(
        self, board: str, target_message_id: bytes,
    ) -> ArticlePublishResult:
        """Unpin an article (EVENT_ARTICLE_UNPIN). Moderator/admin.

        target_message_id: 32-byte message ID of the ARTICLE_PIN event to reverse.
        """
        return await self._publish_event(
            EVENT_ARTICLE_UNPIN, board, body=b"",
            target_message_id=target_message_id,
        )

    async def close_thread(
        self, board: str, target_message_id: bytes,
    ) -> ArticlePublishResult:
        """Close a thread (EVENT_THREAD_CLOSE). Moderator/admin.

        target_message_id: 32-byte message ID of the thread root article.
        """
        return await self._publish_event(
            EVENT_THREAD_CLOSE, board, body=b"",
            target_message_id=target_message_id,
        )

    async def reopen_thread(
        self, board: str, target_message_id: bytes,
    ) -> ArticlePublishResult:
        """Reopen a closed thread (EVENT_THREAD_REOPEN). Moderator/admin.

        target_message_id: 32-byte message ID of the thread root article.
        """
        return await self._publish_event(
            EVENT_THREAD_REOPEN, board, body=b"",
            target_message_id=target_message_id,
        )

    # ------------------------------------------------------------------
    # v3 read methods (return typed models)
    # ------------------------------------------------------------------

    async def article_publish_raw(
        self, encoded_submission: bytes, body: bytes,
        author_signature_scheme: int, author_signature: bytes,
    ) -> dict:
        """Raw ARTICLE_PUBLISH for power users who build their own submissions."""
        cmd = build_article_publish(encoded_submission, body,
                                    author_signature_scheme, author_signature)
        payload = await self._send_command(cmd)
        return parse_article_publish_resp(payload)

    async def article_get(
        self, board: str, selector_type: int, selector, include_body: bool = True,
    ) -> Optional[Article]:
        """Get a single article via ARTICLE_GET. Returns None if not found.

        selector_type: SELECTOR_ARTICLE_NUM (0x01, selector is int) or
                       SELECTOR_MESSAGE_ID (0x02, selector is 32-byte bytes).
        """
        cmd = build_article_get(board, selector_type, selector, include_body)
        try:
            payload = await self._send_command(cmd)
        except BonnetHTTPError as e:
            if "not found" in e.message.lower() or e.code == 0x0404:
                return None
            raise
        resp = parse_article_get_resp(payload)
        return self._to_article(resp)

    async def article_list(
        self, board: str, offset: int = 0, limit: int = 50, flags: int = 0,
    ) -> list[Article]:
        """List articles via ARTICLE_LIST.

        flags: bitmask of FLAG_INCLUDE_CANCELLED, FLAG_INCLUDE_SUPERSEDED,
               FLAG_INCLUDE_PURGED, FLAG_INCLUDE_CONTROLS, FLAG_INCLUDE_BODIES.
        """
        cmd = build_article_list(board, offset, limit, flags)
        payload = await self._send_command(cmd)
        entries = parse_article_list_resp(payload)
        return [self._to_article(e) for e in entries]

    async def article_search(
        self, board: str, text_query: str = "", offset: int = 0, limit: int = 50,
        flags: int = 0, event_type_mask: int = 0,
        actor_pubkey: Optional[bytes] = None,
        subject_pubkey: Optional[bytes] = None,
        target_message_id: Optional[bytes] = None,
        created_after: int = 0, created_before: int = 0,
    ) -> list[Article]:
        """Search articles via ARTICLE_SEARCH with structured filters.

        event_type_mask: bitmask selecting event types (bit (type-1) set; 0 = all).
        actor_pubkey: filter by author/actor public key.
        subject_pubkey: filter by typed subject (culprit/punished key).
        target_message_id: filter by target_message_id field.
        created_after/created_before: time window (0 = unbounded).
        flags: same bitmask as article_list.
        """
        cmd = build_article_search(
            board, text_query, offset, limit, flags, event_type_mask,
            actor_pubkey, subject_pubkey, target_message_id,
            created_after, created_before,
        )
        payload = await self._send_command(cmd)
        resp = parse_article_search_resp(payload)
        return [self._to_article(e) for e in resp["entries"]]

    async def feed_head(self, board: str) -> Optional[FeedHeadInfo]:
        """Get the signed feed head via FEED_HEAD. Returns None if no feed."""
        cmd = build_feed_head(board)
        try:
            payload = await self._send_command(cmd)
        except BonnetHTTPError as e:
            if "not found" in e.message.lower():
                return None
            raise
        resp = parse_feed_head_resp(payload)
        info = decode_v3_head(resp["head_bytes"])
        return FeedHeadInfo(
            origin=info["origin"],
            board=info["board"],
            latest_feed_seq=info["latest_feed_seq"],
            latest_event_hash=info["latest_event_hash"],
            article_count=info["article_count"],
            event_count=info["event_count"],
            snapshot_timestamp=info["snapshot_timestamp"],
            signature=info["signature"],
            accepted_at=resp["accepted_at"],
            source_relay=resp["source_relay"],
        )

    async def feed_events(
        self, board: str, start_seq: int = 1, max_count: int = 100,
    ) -> list[ArticleEvent]:
        """Fetch feed events via FEED_EVENTS. Returns ArticleEvent models."""
        cmd = build_feed_events(board, start_seq, max_count)
        payload = await self._send_command(cmd)
        events = parse_feed_events_resp(payload)
        results = []
        for e in events:
            ev = decode_v3_event(e["event_bytes"])
            results.append(ArticleEvent(
                feed_seq=ev["feed_seq"],
                article_num=ev["article_num"],
                message_id=ev["message_id"],
                event_type=ev["event_type"],
                event_type_name=ev["event_type_name"],
                origin=ev["origin"],
                board=ev["board"],
                created_at=ev["created_at"],
                actor_pubkey=ev["actor_pubkey"],
                actor_username=ev["actor_username"],
                actor_registrar=ev["actor_registrar"],
                root_message_id=ev["root_message_id"],
                reply_to_message_id=ev["reply_to_message_id"],
                supersedes_message_id=ev["supersedes_message_id"],
                target_message_id=ev["target_message_id"],
                subject=ev.get("subject", ""),
                tags=ev.get("tags", ""),
                options=ev.get("options", ""),
                body_hash=ev["body_hash"],
                body_size=ev["body_size"],
                projected_state="active",
                body_available=True,
                control_event_ids=[],
            ))
        return results

    async def article_body(
        self, board: str, message_id: bytes, body_hash: bytes,
    ) -> bytes:
        """Fetch a body blob via ARTICLE_BODY. Returns raw body bytes."""
        cmd = build_article_body(board, message_id, body_hash)
        payload = await self._send_command(cmd)
        return parse_article_body_resp(payload)

    async def feed_heads(
        self, offset: int = 0, limit: int = 100,
    ) -> list[FeedHeadInfo]:
        """List feed heads via FEED_HEADS."""
        cmd = build_feed_heads(offset, limit)
        payload = await self._send_command(cmd)
        entries = parse_feed_heads_resp(payload)
        results = []
        for e in entries:
            info = decode_v3_head(e["head_bytes"])
            results.append(FeedHeadInfo(
                origin=info["origin"],
                board=info["board"],
                latest_feed_seq=info["latest_feed_seq"],
                latest_event_hash=info["latest_event_hash"],
                article_count=info["article_count"],
                event_count=info["event_count"],
                snapshot_timestamp=info["snapshot_timestamp"],
                signature=info["signature"],
                accepted_at=e["accepted_at"],
                source_relay=e["source_relay"],
            ))
        return results

    async def ban_status(self, pubkey: bytes) -> BanStatus:
        """Check ban status via v3 BAN_STATUS."""
        cmd = build_ban_status(pubkey)
        payload = await self._send_command(cmd)
        info = parse_ban_status_resp(payload)
        return BanStatus(
            banned=info["banned"],
            reason=info["reason"],
            punishment_message_id=info["punishment_message_id"],
            source_origin=info["source_origin"],
            source_board=info["source_board"],
            expires_at=info["expires_at"],
        )

    # ------------------------------------------------------------------
    # Conversion helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _to_article(entry: dict) -> Article:
        """Convert a raw ARTICLE_GET/LIST/SEARCH entry dict to an Article model."""
        ev = decode_v3_event(entry["event_bytes"])
        body = entry.get("body", b"")
        body_str = body.decode("utf-8", errors="replace") if body else None
        return Article(
            article_num=ev["article_num"],
            message_id=ev["message_id"],
            origin=ev["origin"],
            board=ev["board"],
            created_at=ev["created_at"],
            actor_pubkey=ev["actor_pubkey"],
            actor_username=ev["actor_username"],
            actor_registrar=ev["actor_registrar"],
            subject=ev.get("subject", ""),
            tags=ev.get("tags", ""),
            options=ev.get("options", ""),
            body=body_str,
            body_available=entry.get("body_status", 0) != 3,  # BODY_UNAVAILABLE=3
            projected_state=_STATE_NAMES.get(entry.get("projected_state", STATE_ACTIVE), "active"),
            feed_seq=ev["feed_seq"],
            root_message_id=ev["root_message_id"] or None,
            reply_to_message_id=ev["reply_to_message_id"] or None,
            supersedes_message_id=ev["supersedes_message_id"] or None,
            control_event_ids=entry.get("control_event_ids", []),
        )

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

    Provides the connect API that the MCP tools (tools.py, simple.py) expect:

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
