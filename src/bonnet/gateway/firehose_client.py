# Copyright 2026 The Bonnet Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""HTTP client for the firehose protocol.

High-level typed client. Connection, discovery, TOFU pinning, request
signing, and response verification live in the shared transport
(bonnet.net.firehose_transport); this module layers typed methods for all
firehose commands on top.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

from bonnet.core.crypto import Identity
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
    sign_key_rotation_proof,
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
from bonnet.net.firehose_sync import is_safe_dial_target
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
    parse_report_list_response,
    parse_user_get_response,
    parse_user_list_response,
)

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def is_loopback(url: str) -> bool:
    """Whether `url` points at this machine.

    One definition, two callers: TLS verification and pin confirmation both
    relax on loopback, for the same underlying reason — there is no
    independent anchor to check against and no attacker positioned between
    a process and itself. Keeping it in one place stops the two drifting.
    """
    return (urlparse(url).hostname or "").lower() in _LOOPBACK_HOSTS


def default_verify_tls(url: str) -> bool:
    """TLS verification default: on, except for loopback URLs.

    A freshly `--init`'d server only has a self-signed cert it just
    generated for itself; verifying that against a CA trust store fails by
    construction and buys nothing, since there's no attacker positioned on
    loopback in that scenario. Any other host still defaults to verified
    TLS — this only relaxes the case where BONNET_URL points at the same
    machine.
    """
    return not is_loopback(url)


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
        user_pubkey: bytes | None = None,
        flags: int = 0,
    ) -> PublishResult:
        """Register a user identity.

        `user_pubkey` defaults to this client's own connected identity - the
        only key this client can actually sign a registration for - so a
        caller registering itself doesn't need to hand back a key it already
        gave `connect()`. Pass it explicitly only when registering some other
        key (an admin registering a user on their behalf, say).

        On success, this client's own actor_username updates to `username` so
        every later publish from this connection (publish_article included)
        attributes to it automatically - a caller that registered but never
        passed `username=` to `connect()` would otherwise keep publishing
        with an empty actor_username indefinitely.
        """
        if self._identity is None or self._server_origin is None:
            raise FirehoseClientError("not connected")
        if user_pubkey is None:
            user_pubkey = self._identity.public_key
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
        result = parse_publish_response(resp)
        if user_pubkey == self._identity.public_key:
            self._username = username
        return result

    async def publish_user_key_rotate(self, new_identity: Identity) -> PublishResult:
        """Succeed this connection's actor key with `new_identity`.

        Mutual consent, mirroring the origin scheme: the record is signed by
        the outgoing key (it is the actor, and the server requires the actor to
        be the authenticated caller), while the proof in field 2 is signed by
        the incoming key attesting it accepts the succession. Neither key alone
        moves the identity.

        The connection keeps signing with the old key after this returns —
        rotating the live transport is the caller's business, as is swapping
        the stored key, which must happen only once this has succeeded.
        """
        if self._identity is None or self._server_origin is None:
            raise FirehoseClientError("not connected")

        proof = sign_key_rotation_proof(
            new_identity,
            self._server_origin,
            self._identity.public_key,
            new_identity.public_key,
        )
        intent = Intent(
            event_id=os.urandom(32),
            kind="bonnet.user.key.rotate",
            origin=self._server_origin,
            actor_pubkey=self._identity.public_key,
            actor_username=self._username,
            actor_registrar=self._server_origin,
            metadata=MetadataMap(
                [
                    metadata_bytes(1, new_identity.public_key),
                    metadata_bytes(2, proof),
                ]
            ),
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
        boards = parse_board_list_response(resp, aggregate=(origin == ""))
        if origin:
            # Explicit-origin queries omit the per-row origin prefix on the
            # wire (it would repeat the request value); fill it back in so
            # callers see the same BoardInfo.shape as aggregate reads.
            for b in boards:
                if not b.origin:
                    b.origin = origin
        return boards

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
            # The hostname here was chosen by the relay, so it gets the same
            # treatment as any other dial target named by someone else.
            #
            # Without this check a relay could point the client at loopback,
            # a private range, or a link-local metadata address — and this
            # client runs on the user's machine, next to their identity store.
            # `is_safe_dial_target` already guarded federation sync's dials and
            # simply was never applied on this path.
            # Private targets are allowed only when this client is itself
            # talking to one — a local test federation legitimately redirects
            # between loopback ports, and a public relay has no business
            # sending anyone there. Same reasoning, and same seam, as
            # is_loopback's other two callers.
            if not is_safe_dial_target(
                redirect.hostname,
                redirect.port,
                allow_private=is_loopback(self._base_url),
            ):
                raise FirehoseClientError(
                    f"refusing redirect to unsafe target {redirect.hostname}:{redirect.port}"
                ) from None
            scheme = urlparse(self._base_url).scheme
            origin_client = FirehoseHTTPClient(
                f"{scheme}://{redirect.hostname}:{redirect.port}",
                # This client's own TLS policy, not the relay's suggestion.
                verify=self._verify,
                # A redirect hop is a connection to a different origin, and
                # therefore exactly a case worth pinning: pass the store down
                # rather than letting cross-origin fetches skip TOFU. The pin
                # mode goes with it, or declining one origin's key would not
                # stop a redirect quietly adopting another's.
                trust_store_path=self._trust_store_path,
                pin_mode=self._pin_mode,
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

    def verify_record(self, rec) -> dict:
        """Check a record's two signatures here, rather than trusting the relay.

        Until now nothing on the reading side verified anything. `core.record`
        exported the verifiers, the wire delivered both signatures, and no
        client called them — while `get_article`'s docstring told callers to
        use the event tools "when you need the signed artifact", which those
        tools then dropped from their output.

        The two checks are independent and answer different questions.

        `author` verifies `actor_signature` over the intent reconstructed from
        the record, under `actor_pubkey`. That needs no key lookup — the key is
        in the record — so it always has an answer, and a valid one means this
        content is what that key signed and cannot be repudiated. It says
        nothing about who holds that key or whether the name beside it is
        theirs; that is `author_check`'s question.

        `origin` verifies `origin_signature` over the unsigned record, under
        the key that was authoritative *at that sequence*. That needs the epoch
        cache, because after a rotation the current pin is not the key that
        countersigned seq 400. With no epoch covering the sequence the answer
        is 'unverifiable', never 'invalid': a signature checked against the
        wrong key fails exactly like a forgery does, and reporting the two the
        same way would turn this client's own missing state into an accusation.
        """
        from bonnet.core.record import (
            encode_intent,
            encode_unsigned_record,
            reconstruct_intent_from_record,
            verify_intent_signature,
            verify_record_signature,
        )

        author_ok = verify_intent_signature(
            rec.actor_pubkey,
            encode_intent(reconstruct_intent_from_record(rec)),
            rec.actor_signature,
        )

        key = self.origin_key_for_seq(rec.origin, rec.origin_seq)
        if key is None:
            origin_state = "unverifiable"
        elif verify_record_signature(key, encode_unsigned_record(rec), rec.origin_signature):
            origin_state = "valid"
        else:
            origin_state = "invalid"

        return {
            "author": "valid" if author_ok else "invalid",
            "origin": origin_state,
            "origin_key_known_for_seq": key is not None,
        }

    # ------------------------------------------------------------------
    # Relay tracing
    # ------------------------------------------------------------------

    async def trace_event(self, origin: str, event_id: bytes) -> list[dict]:
        """Reassemble an event's provenance chain from the witnesses it carries.

        One request. This used to dial each upstream hostname in turn, asking
        every relay in the chain to confirm its own link - which made tracing
        depend on all of them still being reachable *and* still willing to
        answer, and by the protocol's own reasoning those two failures are
        indistinguishable from outside. A relay that had gone quiet erased the
        trail through it.

        Now the chain travels with the record, so it is read rather than
        chased. Every entry is a signed statement by the relay it names, and
        the signature is checked here against `relay_pubkey`: a link only
        counts if that relay really made it, and one that fails is reported
        rather than dropped, because a forged link is itself the finding.

        Ordered from the origin outward where the edges connect, with any
        witness that does not join the chain listed after - a break or a fork
        is what a reader most needs to see, so it is not smoothed away.

        Returns hop dicts: {relay_pubkey, relay_hostname, received_from_pubkey,
        received_from_hostname, seen_at, record_hash, signature_valid,
        is_origin, linked}.
        """
        from bonnet.core.record import (
            encode_unsigned_witness,
            is_origin_witness,
            verify_witness_signature,
        )

        rec, witnesses = await self.get_event(origin, event_id)
        event_hash = compute_event_hash(encode_record(rec))

        def describe(w, linked: bool) -> dict:
            return {
                "relay_pubkey": w.relay_pubkey.hex(),
                "relay_hostname": w.relay_hostname,
                "received_from_pubkey": w.received_from_pubkey.hex(),
                "received_from_hostname": w.received_from_hostname,
                "seen_at": w.seen_at,
                "record_hash": event_hash.hex(),
                # A witness naming a different hash is a statement about some
                # other record and cannot be part of this chain.
                "signature_valid": (
                    w.event_hash == event_hash
                    and verify_witness_signature(
                        w.relay_pubkey, encode_unsigned_witness(w), w.relay_signature
                    )
                ),
                "is_origin": is_origin_witness(w),
                "linked": linked,
            }

        by_upstream: dict[bytes, list] = {}
        for w in witnesses:
            by_upstream.setdefault(w.received_from_pubkey, []).append(w)

        hops: list[dict] = []
        seen: set[bytes] = set()
        frontier = [w for w in witnesses if is_origin_witness(w)]
        while frontier:
            w = frontier.pop(0)
            if w.relay_pubkey in seen:
                continue
            seen.add(w.relay_pubkey)
            hops.append(describe(w, linked=True))
            frontier.extend(by_upstream.get(w.relay_pubkey, []))

        hops.extend(describe(w, linked=False) for w in witnesses if w.relay_pubkey not in seen)
        return hops
