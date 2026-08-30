"""HTTP client for the firehose protocol.

High-level typed client. Connection, discovery, TOFU pinning, request
signing, and response verification live in the shared transport
(bonnet.net.firehose_transport); this module layers typed methods for all
firehose commands on top.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

from bonnet.core.record import (
    ZERO_ID,
    Intent,
    MetadataMap,
    compute_body_hash,
    compute_event_hash,
    encode_intent,
    encode_record,
    metadata_bytes,
    metadata_i64,
    metadata_text,
    metadata_text_list,
    metadata_u64,
    sign_intent,
)
from bonnet.net.firehose_models import (
    ArticleView,
    BanStatus,
    BoardInfo,
    HeadInfo,
    Permissions,
    PublishResult,
    QueryResponse,
    ReportInfo,
    SearchResponse,
    UserInfo,
)
from bonnet.net.firehose_transport import (
    FirehoseClientError,  # noqa: F401 — re-export
    FirehoseTransport,
)
from bonnet.net.firehose_wire import (
    SELECTOR_BY_ID,
    SELECTOR_BY_NUM,
    BodyRedirectError,
    build_article_body,
    build_article_get,
    build_article_list,
    build_article_query,
    build_article_search,
    build_ban_status,
    build_board_list,
    build_event_body,
    build_event_get,
    build_event_head,
    build_event_range,
    build_permissions,
    build_publish_record,
    build_report_list,
    build_user_get,
    build_user_list,
    parse_article_body_response,
    parse_article_get_response,
    parse_article_list_response,
    parse_article_query_response,
    parse_article_search_response,
    parse_ban_status_response,
    parse_board_list_response,
    parse_event_body_response,
    parse_event_get_response,
    parse_event_head_response,
    parse_event_range_response,
    parse_permissions_response,
    parse_publish_response,
    parse_publish_response_raw,
    parse_report_list_response,
    parse_user_get_response,
    parse_user_list_response,
)

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def default_verify_tls(url: str) -> bool:
    """TLS verification default: on, except for loopback URLs.

    A freshly `--init`'d server only has a self-signed cert it just
    generated for itself; verifying that against a CA trust store fails by
    construction and buys nothing, since there's no attacker positioned on
    loopback in that scenario. Any other host still defaults to verified
    TLS — this only relaxes the case where BONNET_URL points at the same
    machine.
    """
    host = (urlparse(url).hostname or "").lower()
    return host not in _LOOPBACK_HOSTS


class FirehoseHTTPClient(FirehoseTransport):
    """Typed client API over the shared signed-HTTP transport."""

    # ------------------------------------------------------------------
    # Publication
    # ------------------------------------------------------------------

    async def publish_article(
        self,
        board: str,
        article_id: bytes,
        body: bytes,
        subject: str,
        content_type: str = "text/plain",
        tags: list[str] = None,
        event_id: bytes = None,
        actor_username: str = "",
        actor_registrar: str = "",
        root_article_id: bytes = None,
        reply_to_article_id: bytes = None,
        supersedes_article_id: bytes = None,
    ) -> PublishResult:
        """Publish an article to the connected server."""
        if self._identity is None or self._server_origin is None:
            raise FirehoseClientError("not connected")
        eid = event_id or os.urandom(32)

        m = MetadataMap([metadata_text(1, subject)])
        if tags:
            m.fields.append(metadata_text_list(2, tags))
        m.fields.append(metadata_text(4, content_type))
        if root_article_id:
            m.fields.append(metadata_bytes(5, root_article_id))
        if reply_to_article_id:
            m.fields.append(metadata_bytes(6, reply_to_article_id))
        if supersedes_article_id:
            m.fields.append(metadata_bytes(7, supersedes_article_id))

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

    async def publish_supersede(
        self,
        board: str,
        article_id: bytes,
        body: bytes,
        subject: str,
        supersedes_article_id: bytes,
        content_type: str = "text/plain",
        tags: list[str] = None,
        event_id: bytes = None,
    ) -> PublishResult:
        """Publish a new article that supersedes an existing one."""
        return await self.publish_article(
            board,
            article_id,
            body,
            subject,
            content_type=content_type,
            tags=tags,
            event_id=event_id,
            supersedes_article_id=supersedes_article_id,
        )

    async def publish_record(
        self,
        intent: Intent,
        actor_sig: bytes,
        body: bytes = b"",
    ) -> tuple:
        """Publish an arbitrary signed record. Returns (Record, Witness)."""
        cmd = build_publish_record(intent, actor_sig, body)
        resp = await self._send_command(cmd)
        return parse_publish_response_raw(resp)

    async def publish_board_create(
        self,
        board: str,
        owner_pubkey: bytes,
        display_name: str = "",
    ) -> PublishResult:
        """Create a board."""
        if self._identity is None or self._server_origin is None:
            raise FirehoseClientError("not connected")
        eid = os.urandom(32)
        m = MetadataMap([metadata_bytes(1, owner_pubkey)])
        if display_name:
            m.fields.append(metadata_text(2, display_name))

        intent = Intent(
            event_id=eid,
            kind="bonnet.board.create",
            origin=self._server_origin,
            actor_pubkey=self._identity.public_key,
            actor_username=self._username,
            actor_registrar=self._server_origin,
            board=board,
            metadata=m,
        )
        actor_sig = sign_intent(self._identity, encode_intent(intent))
        cmd = build_publish_record(intent, actor_sig, b"")
        resp = await self._send_command(cmd)
        return parse_publish_response(resp)

    async def publish_user_register(
        self,
        username: str,
        user_pubkey: bytes,
        flags: int = 0,
    ) -> PublishResult:
        """Register a user identity."""
        if self._identity is None or self._server_origin is None:
            raise FirehoseClientError("not connected")
        eid = os.urandom(32)
        m = MetadataMap(
            [
                metadata_text(1, username),
                metadata_bytes(2, user_pubkey),
                metadata_u64(3, flags),
            ]
        )

        intent = Intent(
            event_id=eid,
            kind="bonnet.user.register",
            origin=self._server_origin,
            actor_pubkey=self._identity.public_key,
            actor_username=self._username,
            actor_registrar=self._server_origin,
            metadata=m,
        )
        actor_sig = sign_intent(self._identity, encode_intent(intent))
        cmd = build_publish_record(intent, actor_sig, b"")
        resp = await self._send_command(cmd)
        return parse_publish_response(resp)

    async def publish_cancel(
        self,
        board: str,
        target_origin: str,
        target_board: str,
        target_article_id: bytes,
        reason: str = "",
    ) -> PublishResult:
        """Cancel an article."""
        return await self._publish_control(
            "bonnet.article.cancel",
            board,
            target_origin,
            target_board,
            target_article_id,
            reason,
        )

    async def publish_restore(
        self,
        board: str,
        target_origin: str,
        target_board: str,
        target_article_id: bytes,
        reason: str = "",
    ) -> PublishResult:
        """Restore a cancelled article."""
        return await self._publish_control(
            "bonnet.article.restore",
            board,
            target_origin,
            target_board,
            target_article_id,
            reason,
        )

    async def publish_purge(
        self,
        board: str,
        target_origin: str,
        target_board: str,
        target_article_id: bytes,
        reason: str = "",
    ) -> PublishResult:
        """Purge an article's body."""
        return await self._publish_control(
            "bonnet.article.purge",
            board,
            target_origin,
            target_board,
            target_article_id,
            reason,
        )

    async def publish_report(
        self,
        culprit_pubkey: bytes,
        reason: str,
        target_origin: str = "",
        target_board: str = "",
        target_article_id: bytes = ZERO_ID,
        target_event_id: bytes = ZERO_ID,
        board: str = "",
    ) -> PublishResult:
        """File a report naming a culprit, optionally pointing at evidence.

        An accusation, not a verdict — any user who may publish can file one,
        and it grants the filer no authority. Punishment is a separate kind
        issued by whoever the ACL grants that power to.

        The validator accepts exactly three target shapes and rejects any
        mixture: a complete article tuple (origin + board + article_id), an
        event (origin + event_id), or no target at all. Passing a partial
        tuple is a validation error rather than a silently weaker report, so
        callers should send a whole shape or none.

        The reason is the record body, which the validator does not require —
        but a report nobody can read the grounds for is not worth filing.
        """
        if self._identity is None or self._server_origin is None:
            raise FirehoseClientError("not connected")

        body = reason.encode("utf-8")
        m = MetadataMap([metadata_bytes(1, culprit_pubkey)])
        intent = Intent(
            event_id=os.urandom(32),
            kind="bonnet.report",
            origin=self._server_origin,
            actor_pubkey=self._identity.public_key,
            actor_username=self._username,
            actor_registrar=self._server_origin,
            board=board,
            target_origin=target_origin,
            target_board=target_board,
            target_article_id=target_article_id,
            target_event_id=target_event_id,
            metadata=m,
            body_hash=compute_body_hash(body),
            body_size=len(body),
        )
        actor_sig = sign_intent(self._identity, encode_intent(intent))
        cmd = build_publish_record(intent, actor_sig, body)
        resp = await self._send_command(cmd)
        return parse_publish_response(resp)

    async def publish_pin(
        self,
        board: str,
        target_origin: str,
        target_board: str,
        target_article_id: bytes,
        priority: int,
    ) -> PublishResult:
        """Pin an article."""
        if self._identity is None or self._server_origin is None:
            raise FirehoseClientError("not connected")
        eid = os.urandom(32)
        m = MetadataMap([metadata_i64(1, priority)])
        intent = Intent(
            event_id=eid,
            kind="bonnet.article.pin",
            origin=self._server_origin,
            actor_pubkey=self._identity.public_key,
            actor_username=self._username,
            actor_registrar=self._server_origin,
            board="",
            target_origin=target_origin,
            target_board=target_board,
            target_article_id=target_article_id,
            metadata=m,
        )
        actor_sig = sign_intent(self._identity, encode_intent(intent))
        cmd = build_publish_record(intent, actor_sig, b"")
        resp = await self._send_command(cmd)
        return parse_publish_response(resp)

    async def publish_unpin(
        self,
        board: str,
        target_origin: str,
        target_board: str,
        target_article_id: bytes,
    ) -> PublishResult:
        """Unpin an article."""
        return await self._publish_control(
            "bonnet.article.unpin",
            board,
            target_origin,
            target_board,
            target_article_id,
            "",
        )

    async def _publish_control(
        self,
        kind: str,
        board: str,
        target_origin: str,
        target_board: str,
        target_article_id: bytes,
        reason: str,
    ) -> PublishResult:
        """Publish a control event targeting an article."""
        if self._identity is None or self._server_origin is None:
            raise FirehoseClientError("not connected")
        eid = os.urandom(32)
        body = reason.encode("utf-8") if reason else b""
        intent = Intent(
            event_id=eid,
            kind=kind,
            origin=self._server_origin,
            actor_pubkey=self._identity.public_key,
            actor_username=self._username,
            actor_registrar=self._server_origin,
            board="",
            target_origin=target_origin,
            target_board=target_board,
            target_article_id=target_article_id,
            body_hash=compute_body_hash(body) if body else ZERO_ID,
            body_size=len(body),
        )
        actor_sig = sign_intent(self._identity, encode_intent(intent))
        cmd = build_publish_record(intent, actor_sig, body)
        resp = await self._send_command(cmd)
        return parse_publish_response(resp)

    # ------------------------------------------------------------------
    # Punishments
    # ------------------------------------------------------------------

    async def _publish_punishment_issue(
        self,
        kind: str,
        board: str,
        punished_pubkey: bytes,
        reason: str,
        expires_at: int | None = None,
    ) -> PublishResult:
        if self._identity is None or self._server_origin is None:
            raise FirehoseClientError("not connected")
        eid = os.urandom(32)
        body = reason.encode("utf-8")
        m = MetadataMap([metadata_bytes(1, punished_pubkey)])
        if expires_at is not None:
            m.fields.append(metadata_i64(2, expires_at))
        intent = Intent(
            event_id=eid,
            kind=kind,
            origin=self._server_origin,
            actor_pubkey=self._identity.public_key,
            actor_username=self._username,
            actor_registrar=self._server_origin,
            board=board,
            metadata=m,
            body_hash=compute_body_hash(body),
            body_size=len(body),
        )
        actor_sig = sign_intent(self._identity, encode_intent(intent))
        cmd = build_publish_record(intent, actor_sig, body)
        resp = await self._send_command(cmd)
        return parse_publish_response(resp)

    async def publish_punishment_warn(
        self, punished_pubkey: bytes, reason: str, board: str = "moderation.actions"
    ) -> PublishResult:
        """Issue a warning. Stays pending until the user acknowledges it."""
        return await self._publish_punishment_issue(
            "bonnet.punishment.warn", board, punished_pubkey, reason
        )

    async def publish_punishment_ban(
        self,
        punished_pubkey: bytes,
        reason: str,
        expires_at: int,
        board: str = "moderation.actions",
    ) -> PublishResult:
        """Issue a temporary ban expiring at a unix timestamp."""
        return await self._publish_punishment_issue(
            "bonnet.punishment.ban", board, punished_pubkey, reason, expires_at=expires_at
        )

    async def publish_punishment_permaban(
        self, punished_pubkey: bytes, reason: str, board: str = "moderation.actions"
    ) -> PublishResult:
        """Issue a permanent ban."""
        return await self._publish_punishment_issue(
            "bonnet.punishment.permaban", board, punished_pubkey, reason
        )

    async def publish_punishment_revoke(
        self, punishment_event_id: bytes, reason: str = ""
    ) -> PublishResult:
        """Revoke any punishment by its event ID."""
        if self._identity is None or self._server_origin is None:
            raise FirehoseClientError("not connected")
        eid = os.urandom(32)
        body = reason.encode("utf-8") if reason else b""
        intent = Intent(
            event_id=eid,
            kind="bonnet.punishment.revoke",
            origin=self._server_origin,
            actor_pubkey=self._identity.public_key,
            actor_username=self._username,
            actor_registrar=self._server_origin,
            target_origin=self._server_origin,
            target_event_id=punishment_event_id,
            body_hash=compute_body_hash(body) if body else ZERO_ID,
            body_size=len(body),
        )
        actor_sig = sign_intent(self._identity, encode_intent(intent))
        cmd = build_publish_record(intent, actor_sig, body)
        resp = await self._send_command(cmd)
        return parse_publish_response(resp)

    async def publish_punishment_ack(self, punishment_event_id: bytes) -> PublishResult:
        """Acknowledge a punishment as the punished user."""
        if self._identity is None or self._server_origin is None:
            raise FirehoseClientError("not connected")
        eid = os.urandom(32)
        intent = Intent(
            event_id=eid,
            kind="bonnet.punishment.ack",
            origin=self._server_origin,
            actor_pubkey=self._identity.public_key,
            actor_username=self._username,
            actor_registrar=self._server_origin,
            metadata=MetadataMap([metadata_bytes(1, punishment_event_id)]),
        )
        actor_sig = sign_intent(self._identity, encode_intent(intent))
        cmd = build_publish_record(intent, actor_sig, b"")
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

    async def get_permissions(self, board: str = "") -> Permissions:
        """Ask the relay what this connection's principal is allowed to do."""
        resp = await self._send_command(build_permissions(board))
        return parse_permissions_response(resp)

    async def list_reports(
        self, culprit_pubkey: bytes = b"", limit: int = 100, offset: int = 0
    ) -> list[ReportInfo]:
        """Fetch the moderation queue from the relay's own index.

        Server-side because that is where it can be enforced: REPORT_LIST is
        an ACL command in its own right, and reports carrying an article
        target are filtered per board by the relay. Assembling this client
        side from EVENT_RANGE would answer the same question with neither
        check applied.
        """
        resp = await self._send_command(build_report_list(culprit_pubkey, limit, offset))
        return parse_report_list_response(resp)

    async def list_boards(self, origin: str) -> list[BoardInfo]:
        cmd = build_board_list(origin)
        resp = await self._send_command(cmd)
        return parse_board_list_response(resp, aggregate=(origin == ""))

    async def get_article(
        self, origin: str, board: str, article_num: int, include_body: bool = False
    ) -> ArticleView:
        cmd = build_article_get(origin, board, SELECTOR_BY_NUM, article_num, include_body)
        resp = await self._send_command(cmd)
        view = parse_article_get_response(resp)
        if view.body_state == "unavailable" and origin and origin != self._server_origin:
            view.body_state = "remote"
        return view

    async def get_article_by_id(
        self, origin: str, board: str, article_id: bytes, include_body: bool = False
    ) -> ArticleView:
        cmd = build_article_get(origin, board, SELECTOR_BY_ID, article_id, include_body)
        resp = await self._send_command(cmd)
        view = parse_article_get_response(resp)
        if view.body_state == "unavailable" and origin and origin != self._server_origin:
            view.body_state = "remote"
        return view

    async def list_articles(
        self,
        origin: str,
        board: str,
        offset: int = 0,
        limit: int = 100,
        include_cancelled: bool = False,
        include_superseded: bool = False,
        include_purged: bool = False,
    ) -> QueryResponse:
        cmd = build_article_list(
            origin, board, offset, limit, include_cancelled, include_superseded, include_purged
        )
        resp = await self._send_command(cmd)
        result = parse_article_list_response(resp, aggregate=(origin == ""))
        if origin and origin != self._server_origin:
            for item in result.results:
                if item.body_state == "unavailable":
                    item.body_state = "remote"
        elif origin == "":
            for item in result.results:
                if (
                    item.body_state == "unavailable"
                    and item.origin
                    and item.origin != self._server_origin
                ):
                    item.body_state = "remote"
        return result

    async def search_articles(
        self,
        origin: str,
        board: str,
        meta_query: str = "",
        body_query: str = "",
        offset: int = 0,
        limit: int = 100,
        include_cancelled: bool = False,
        include_superseded: bool = False,
    ) -> SearchResponse:
        cmd = build_article_search(
            origin,
            board,
            meta_query,
            body_query,
            offset,
            limit,
            include_cancelled,
            include_superseded,
        )
        resp = await self._send_command(cmd)
        return parse_article_search_response(resp, aggregate=(origin == ""))

    async def query_articles(
        self, origin: str, board: str, filters: list, offset: int = 0, limit: int = 100
    ) -> QueryResponse:
        """Query articles with structured filters.

        filters: list of (field_id, operator, value_type, value_bytes) tuples.
        """
        cmd = build_article_query(origin, board, filters, offset, limit)
        resp = await self._send_command(cmd)
        return parse_article_query_response(resp)

    async def get_article_body(self, origin: str, board: str, article_num: int) -> bytes:
        try:
            cmd = build_article_body(origin, board, article_num)
            resp = await self._send_command(cmd)
            return parse_article_body_response(resp)
        except BodyRedirectError as redirect:
            origin_client = FirehoseHTTPClient(
                f"https://{redirect.hostname}:{redirect.port}",
                verify=redirect.verify_tls,
                # A redirect hop is a connection to a different origin, and
                # therefore exactly a case worth pinning: pass the store down
                # rather than letting cross-origin fetches skip TOFU.
                trust_store_path=self._trust_store_path,
            )
            try:
                await origin_client.connect_anonymous()
                return await origin_client.get_article_body(origin, board, article_num)
            finally:
                await origin_client.close()

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
                    sub_client = FirehoseHTTPClient(
                        current_base_url,
                        verify=self._verify,
                        trust_store_path=self._trust_store_path,
                    )
                    await sub_client.connect_anonymous()
                    try:
                        rec, witness = await sub_client.get_event(current_origin, current_event_id)
                    finally:
                        await sub_client.close()
            except Exception:
                break

            encoded = encode_record(rec) if hasattr(rec, "origin_seq") else b""
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
