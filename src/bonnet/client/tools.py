"""MCP tools for the Bonnet Firehose Protocol.

Exposes firehose client operations as FastMCP tools for AI agents.
Uses IdentityStore for local key management (username:password → Ed25519).
"""

import contextvars
import os
import time

from fastmcp import FastMCP

from bonnet.client.firehose_client import FirehoseHTTPClient
from bonnet.client.firehose_models import (
    ArticleView,
    BanStatus,
    BoardInfo,
    HeadInfo,
    QueryResponse,
    SearchResponse,
    UserInfo,
)
from bonnet.client.identity import IdentityStore
from bonnet.core.crypto import Identity
from bonnet.core.record import ZERO_ID

mcp = FastMCP("Bonnet BBS")

current_username: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "username", default=None
)
current_password: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "password", default=""
)

identity_store: IdentityStore | None = None
bonnet_url: str = os.environ.get("BONNET_URL", "https://localhost:2272")
bonnet_verify: bool | str = os.environ.get("BONNET_VERIFY_TLS", "true").lower() not in (
    "false",
    "0",
    "no",
)

auth_tokens: dict[str, dict] = {}
TOKEN_EXPIRY_SECONDS = 24 * 60 * 60


def _get_identity_store() -> IdentityStore:
    global identity_store
    if identity_store is None:
        identity_store = IdentityStore(os.environ.get("BONNET_IDENTITIES_DB") or None)
    return identity_store


def _make_client() -> FirehoseHTTPClient:
    return FirehoseHTTPClient(bonnet_url, verify=bonnet_verify)


def _resolve_auth(auth: str | None) -> tuple[str, str]:
    if auth is None:
        username = current_username.get()
        password = current_password.get() or ""
        if not username:
            raise ValueError("No username in context - check Authorization header")
        return username, password

    if ":" in auth:
        parts = auth.split(":", 1)
        if len(parts) == 2:
            return parts[0], parts[1]

    token_data = auth_tokens.get(auth)
    if token_data is None:
        raise ValueError("Invalid or expired auth token")

    if time.time() > token_data["expires_at"]:
        del auth_tokens[auth]
        raise ValueError("Auth token has expired")

    return token_data["username"], token_data["password"]


async def _connect_authenticated(client: FirehoseHTTPClient, auth: str | None) -> None:
    """Connect with authenticated identity from IdentityStore."""
    username, password = _resolve_auth(auth)
    store = _get_identity_store()
    private_key = store.get_private_key(username, password)
    identity = Identity.from_private_key(private_key)
    await client.connect(identity, username=username)


async def _connect_anonymous(client: FirehoseHTTPClient) -> None:
    """Connect using the server's anonymous key."""
    await client.connect_anonymous()


def _validate_pubkey(pubkey_hex: str) -> bytes:
    try:
        pk = bytes.fromhex(pubkey_hex)
        if len(pk) != 32:
            raise ValueError(f"Public key must be 32 bytes (64 hex chars), got {len(pk)} bytes")
        return pk
    except ValueError as e:
        raise ValueError(f"Invalid public key: {pubkey_hex}") from e


def _validate_article_id(aid_hex: str) -> bytes:
    try:
        aid = bytes.fromhex(aid_hex)
        if len(aid) != 32:
            raise ValueError(f"Article ID must be 32 bytes (64 hex chars), got {len(aid)} bytes")
        return aid
    except ValueError as e:
        raise ValueError(f"Invalid article ID: {aid_hex}") from e


def _validate_event_id(eid_hex: str) -> bytes:
    try:
        eid = bytes.fromhex(eid_hex)
        if len(eid) != 32:
            raise ValueError(f"Event ID must be 32 bytes (64 hex chars), got {len(eid)} bytes")
        return eid
    except ValueError as e:
        raise ValueError(f"Invalid event ID: {eid_hex}") from e


# ---------------------------------------------------------------------------
# Auth / identity tools
# ---------------------------------------------------------------------------


@mcp.tool
async def login(username: str, password: str) -> str:
    """Authenticate and receive a temporary auth token valid for 24 hours.

    Returns a hex token string to pass as the 'auth' parameter to other tools.
    You can also pass 'username:password' directly as the auth parameter
    without calling login first.
    """
    store = _get_identity_store()
    if not store.verify_password(username, password):
        raise ValueError(f"Authentication failed: invalid credentials for '{username}'")

    token = os.urandom(32).hex()
    auth_tokens[token] = {
        "username": username,
        "password": password,
        "expires_at": time.time() + TOKEN_EXPIRY_SECONDS,
    }
    return token


@mcp.tool
async def register_user(username: str, password: str) -> str:
    """Register a new user identity locally and on the Bonnet server.

    Creates a local Ed25519 identity and publishes a bonnet.user.register
    record to the server. Returns the registered username.
    """
    store = _get_identity_store()
    try:
        store.register(username, password)
    except ValueError as e:
        if "already exists" in str(e).lower():
            if not store.verify_password(username, password):
                raise ValueError("User already exists and password does not match") from e
        else:
            raise

    identity = Identity.from_private_key(store.get_private_key(username, password))

    client = _make_client()
    try:
        await _connect_authenticated(client, f"{username}:{password}")
        result = await client.publish_user_register(username, identity.public_key, flags=0)
        return f"Registered '{username}' — event seq {result.origin_seq}"
    finally:
        await client.close()


@mcp.tool
async def get_user(pubkey_hex: str, origin: str = "", auth: str | None = None) -> UserInfo | None:
    """Look up a registered user by their Ed25519 public key.

    pubkey_hex: hex-encoded 32-byte Ed25519 public key.
    origin: origin to query (defaults to server's origin).
    """
    pubkey = _validate_pubkey(pubkey_hex)
    client = _make_client()
    try:
        if auth:
            await _connect_authenticated(client, auth)
        else:
            await _connect_anonymous(client)
        origin = origin or client._server_origin or ""
        return await client.get_user(origin, pubkey)
    finally:
        await client.close()


@mcp.tool
async def list_users(origin: str = "", auth: str | None = None) -> list[UserInfo]:
    """List registered users on an origin.

    origin: origin to query (defaults to server's origin).
    """
    client = _make_client()
    try:
        if auth:
            await _connect_authenticated(client, auth)
        else:
            await _connect_anonymous(client)
        origin = origin or client._server_origin or ""
        return await client.list_users(origin)
    finally:
        await client.close()


# ---------------------------------------------------------------------------
# Board tools
# ---------------------------------------------------------------------------


@mcp.tool
async def create_board(
    name: str,
    display_name: str = "",
    auth: str | None = None,
) -> str:
    """Create a new board. Requires admin privileges.

    name: board name (alphanumeric, hyphens, underscores).
    display_name: optional human-readable board title.
    """
    client = _make_client()
    try:
        await _connect_authenticated(client, auth)
        result = await client.publish_board_create(
            name,
            client._identity.public_key,
            display_name,
        )
        return f"Board '{name}' created — event seq {result.origin_seq}"
    finally:
        await client.close()


@mcp.tool
async def list_boards(origin: str = "", auth: str | None = None) -> list[BoardInfo]:
    """List all boards with metadata (name, closed state, owner, display name).

    origin: origin to query (empty = aggregate across all known origins).
    """
    client = _make_client()
    try:
        if auth:
            await _connect_authenticated(client, auth)
        else:
            await _connect_anonymous(client)
        if origin:
            return await client.list_boards(origin)
        return await client.list_boards("")
    finally:
        await client.close()


# ---------------------------------------------------------------------------
# Article tools (read)
# ---------------------------------------------------------------------------


@mcp.tool
async def get_article(
    board: str,
    article_num: int,
    include_body: bool = True,
    origin: str = "",
    auth: str | None = None,
) -> ArticleView | None:
    """Get a single article by board and article number.

    Returns the full article including subject, tags, body (if available),
    author info, projected state (active/cancelled/superseded), and lifecycle
    metadata. Returns None if not found.

    board: board name.
    article_num: article number (starts at 1).
    include_body: whether to fetch the article body content.
    origin: origin to query (defaults to server's origin).
    """
    client = _make_client()
    try:
        if auth:
            await _connect_authenticated(client, auth)
        else:
            await _connect_anonymous(client)
        origin = origin or client._server_origin or ""
        view = await client.get_article(origin, board, article_num, include_body)
        if view and include_body and view.body is None and view.body_size > 0:
            try:
                body = await client.get_article_body(origin, board, article_num)
                view.body = body
                if view.body_hash and view.body_size:
                    from bonnet.core.record import compute_body_hash

                    actual_hash = compute_body_hash(body).hex()
                    view.body_verified = (
                        len(body) == view.body_size and actual_hash == view.body_hash
                    )
            except Exception:
                pass
        return view
    finally:
        await client.close()


@mcp.tool
async def list_articles(
    board: str,
    offset: int = 0,
    limit: int = 50,
    include_cancelled: bool = False,
    include_superseded: bool = False,
    origin: str = "",
    auth: str | None = None,
) -> QueryResponse:
    """List articles on a board, sorted by created_at descending.

    By default only active articles are returned. Set include_cancelled or
    include_superseded to also include those states.

    board: board name.
    offset: pagination offset.
    limit: max articles to return.
    origin: origin to query (empty = aggregate across all known origins).
    """
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if limit < 1:
        raise ValueError("limit must be at least 1")
    client = _make_client()
    try:
        if auth:
            await _connect_authenticated(client, auth)
        else:
            await _connect_anonymous(client)
        if origin:
            return await client.list_articles(
                origin,
                board,
                offset,
                limit,
                include_cancelled,
                include_superseded,
            )
        return await client.list_articles(
            "",
            board,
            offset,
            limit,
            include_cancelled,
            include_superseded,
        )
    finally:
        await client.close()


@mcp.tool
async def search_articles(
    board: str,
    query: str,
    offset: int = 0,
    limit: int = 50,
    origin: str = "",
    auth: str | None = None,
) -> SearchResponse:
    """Search article metadata (subject, tags) on a board. Results sorted by created_at descending.

    query: substring to search for in subject and tags.
    board: board name.
    origin: origin to query (empty = aggregate across all known origins).
    """
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if limit < 1:
        raise ValueError("limit must be at least 1")
    client = _make_client()
    try:
        if auth:
            await _connect_authenticated(client, auth)
        else:
            await _connect_anonymous(client)
        if origin:
            return await client.search_articles(origin, board, query, "", offset, limit)
        return await client.search_articles("", board, query, "", offset, limit)
    finally:
        await client.close()


@mcp.tool
async def query_articles(
    board: str,
    author_pubkey: str = "",
    username: str = "",
    tag: str = "",
    state: str = "",
    root_only: bool = False,
    pinned_only: bool = False,
    offset: int = 0,
    limit: int = 50,
    origin: str = "",
    auth: str | None = None,
) -> QueryResponse:
    """Query articles with structured field filters. All filters are AND'd.

    author_pubkey: hex Ed25519 public key to filter by author.
    username: filter by author username.
    tag: filter by tag (substring match).
    state: filter by visibility (active, cancelled, superseded).
    root_only: only show root articles (not replies).
    pinned_only: only show pinned articles.
    origin: origin to query (defaults to server's origin).
    """
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if limit < 1:
        raise ValueError("limit must be at least 1")
    filters = []
    if author_pubkey:
        pk = _validate_pubkey(author_pubkey)
        filters.append((0x01, 0x01, 0x01, pk))
    if username:
        filters.append((0x02, 0x01, 0x02, username.encode("utf-8")))
    if tag:
        filters.append((0x04, 0x05, 0x02, tag.encode("utf-8")))
    if state:
        filters.append((0x06, 0x01, 0x02, state.encode("utf-8")))
    if root_only:
        filters.append((0x07, 0x01, 0x04, b"\x01"))
    if pinned_only:
        filters.append((0x09, 0x01, 0x04, b"\x01"))

    client = _make_client()
    try:
        if auth:
            await _connect_authenticated(client, auth)
        else:
            await _connect_anonymous(client)
        origin = origin or client._server_origin or ""
        return await client.query_articles(origin, board, filters, offset, limit)
    finally:
        await client.close()


# ---------------------------------------------------------------------------
# Article tools (write)
# ---------------------------------------------------------------------------


@mcp.tool
async def publish_article(
    board: str,
    subject: str,
    content: str,
    tags: str = "",
    reply_to_article_id: str = "",
    auth: str | None = None,
) -> str:
    """Publish a new article to a board. Requires a registered user.

    Articles are immutable once published; to remove use cancel_article,
    to hard-delete use purge_article, to replace use supersede_article.
    The article is signed with your Ed25519 key.

    board: board name.
    subject: article subject line.
    content: article body text.
    tags: comma-separated tags (optional).
    reply_to_article_id: hex article ID of the article being replied to (optional).
    """
    import os as _os

    article_id = _os.urandom(32)
    tags_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
    body = content.encode("utf-8")

    root_id = None
    reply_id = None
    if reply_to_article_id:
        reply_id = _validate_article_id(reply_to_article_id)
        client = _make_client()
        try:
            if auth:
                await _connect_authenticated(client, auth)
            else:
                await _connect_anonymous(client)
            srv_origin = client._server_origin or ""
            target = await client.get_article_by_id(srv_origin, board, reply_id, include_body=False)
            if target is None:
                return f"Error: Article {reply_to_article_id} not found in /{board}"
            if target.root_article_id:
                root_id = bytes.fromhex(target.root_article_id)
            else:
                root_id = reply_id
        finally:
            await client.close()

    client = _make_client()
    try:
        await _connect_authenticated(client, auth)
        result = await client.publish_article(
            board,
            article_id,
            body,
            subject,
            tags=tags_list or None,
            root_article_id=root_id,
            reply_to_article_id=reply_id,
        )
        return f"Article #{result.article_num} published — event seq {result.origin_seq}"
    finally:
        await client.close()


@mcp.tool
async def supersede_article(
    board: str,
    target_article_id: str,
    subject: str,
    content: str,
    tags: str = "",
    auth: str | None = None,
) -> str:
    """Publish a replacement article that supersedes an existing one.

    Only the original author may supersede. The superseded article's
    visibility becomes 'superseded' and this article carries the link.

    board: board where the target article lives.
    target_article_id: hex article ID of the article being superseded.
    subject: subject line for the replacement article.
    content: body text for the replacement article.
    tags: comma-separated tags (optional).
    """
    import os as _os

    supersedes_id = _validate_article_id(target_article_id)
    article_id = _os.urandom(32)
    tags_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
    body = content.encode("utf-8")

    client = _make_client()
    try:
        await _connect_authenticated(client, auth)
        result = await client.publish_supersede(
            board,
            article_id,
            body,
            subject,
            supersedes_article_id=supersedes_id,
            tags=tags_list or None,
        )
        return f"Article #{result.article_num} supersedes {target_article_id[:16]}... — event seq {result.origin_seq}"
    finally:
        await client.close()


@mcp.tool
async def cancel_article(
    board: str,
    target_article_id: str,
    reason: str = "",
    origin: str = "",
    auth: str | None = None,
) -> str:
    """Cancel an article (soft delete). Author or moderator may cancel.

    board: board where the target article lives.
    target_article_id: hex article ID of the article to cancel.
    origin: origin to query (defaults to server's origin).
    reason: optional human-readable cancellation reason.
    """
    aid = _validate_article_id(target_article_id)
    client = _make_client()
    try:
        await _connect_authenticated(client, auth)
        srv_origin = origin or client._server_origin or ""
        result = await client.publish_cancel(board, srv_origin, board, aid, reason)
        return f"Cancel event published — seq {result.origin_seq}"
    finally:
        await client.close()


@mcp.tool
async def restore_article(
    board: str,
    target_article_id: str,
    reason: str = "",
    origin: str = "",
    auth: str | None = None,
) -> str:
    """Restore a previously cancelled article. Author or moderator.

    board: board where the target article lives.
    target_article_id: hex article ID of the cancelled article to restore.
    """
    aid = _validate_article_id(target_article_id)
    client = _make_client()
    try:
        await _connect_authenticated(client, auth)
        srv_origin = origin or client._server_origin or ""
        result = await client.publish_restore(board, srv_origin, board, aid, reason)
        return f"Restore event published — seq {result.origin_seq}"
    finally:
        await client.close()


@mcp.tool
async def purge_article(
    board: str,
    target_article_id: str,
    reason: str,
    origin: str = "",
    auth: str | None = None,
) -> str:
    """Purge an article's body (hard delete). The author or a moderator/admin may purge.
    Irreversible — the body is deleted but the event metadata is retained in the firehose.

    board: board where the target article lives.
    target_article_id: hex article ID of the article to purge.
    reason: human-readable purge reason (required).
    """
    aid = _validate_article_id(target_article_id)
    client = _make_client()
    try:
        await _connect_authenticated(client, auth)
        srv_origin = origin or client._server_origin or ""
        result = await client.publish_purge(board, srv_origin, board, aid, reason)
        return f"Purge event published — seq {result.origin_seq}"
    finally:
        await client.close()


@mcp.tool
async def pin_article(
    board: str,
    target_article_id: str,
    priority: int = 0,
    origin: str = "",
    auth: str | None = None,
) -> str:
    """Pin an article to the top of the board. Moderator/admin only.

    board: board where the target article lives.
    target_article_id: hex article ID of the article to pin.
    priority: higher values appear more prominent.
    """
    aid = _validate_article_id(target_article_id)
    client = _make_client()
    try:
        await _connect_authenticated(client, auth)
        srv_origin = origin or client._server_origin or ""
        result = await client.publish_pin(board, srv_origin, board, aid, priority)
        return f"Pin event published — seq {result.origin_seq}"
    finally:
        await client.close()


@mcp.tool
async def unpin_article(
    board: str,
    target_article_id: str,
    origin: str = "",
    auth: str | None = None,
) -> str:
    """Remove a pin from an article. Moderator/admin only.

    board: board where the target article lives.
    target_article_id: hex article ID of the article to unpin.
    """
    aid = _validate_article_id(target_article_id)
    client = _make_client()
    try:
        await _connect_authenticated(client, auth)
        srv_origin = origin or client._server_origin or ""
        result = await client.publish_unpin(board, srv_origin, board, aid)
        return f"Unpin event published — seq {result.origin_seq}"
    finally:
        await client.close()


# ---------------------------------------------------------------------------
# Punishments (Gate D)
# ---------------------------------------------------------------------------


@mcp.tool
async def ban_status(pubkey_hex: str, auth: str | None = None) -> BanStatus:
    """List all punishments currently pending against a user.

    pubkey_hex: hex Ed25519 public key of the user to check.
    Returns each pending punishment with its type, event ID, issuing
    origin, expiry, and body reference. Pending warnings and bans gate
    the user's writes until acknowledged/expired/revoked.
    """
    pubkey = _validate_pubkey(pubkey_hex)
    client = _make_client()
    try:
        if auth:
            await _connect_authenticated(client, auth)
        else:
            await _connect_anonymous(client)
        return await client.get_ban_status(pubkey)
    finally:
        await client.close()


@mcp.tool
async def punish_warn(
    punished_pubkey_hex: str,
    reason: str,
    board: str = "moderation.actions",
    auth: str | None = None,
) -> str:
    """Issue a formal warning to a user. Requires moderator or administrator.

    The warning stays pending until the user acknowledges it with
    acknowledge_punishment; while pending it blocks their writes.
    """
    pubkey = _validate_pubkey(punished_pubkey_hex)
    client = _make_client()
    try:
        await _connect_authenticated(client, auth)
        result = await client.publish_punishment_warn(pubkey, reason, board=board)
        return f"Warning issued — event seq {result.origin_seq}, event {result.event_id}"
    finally:
        await client.close()


@mcp.tool
async def punish_ban(
    punished_pubkey_hex: str,
    reason: str,
    expires_at: int,
    board: str = "moderation.actions",
    auth: str | None = None,
) -> str:
    """Temporarily ban a user until a unix timestamp. Requires moderator or administrator.

    expires_at: positive unix timestamp when the ban lapses.
    """
    pubkey = _validate_pubkey(punished_pubkey_hex)
    if expires_at <= int(time.time()):
        raise ValueError("expires_at must be a future unix timestamp")
    client = _make_client()
    try:
        await _connect_authenticated(client, auth)
        result = await client.publish_punishment_ban(pubkey, reason, expires_at, board=board)
        return f"Ban issued until {expires_at} — event seq {result.origin_seq}"
    finally:
        await client.close()


@mcp.tool
async def punish_permaban(
    punished_pubkey_hex: str,
    reason: str,
    board: str = "moderation.actions",
    auth: str | None = None,
) -> str:
    """Permanently ban a user. Requires administrator authority via ACL.

    Permabans never expire; only punish_revoke can lift them.
    """
    pubkey = _validate_pubkey(punished_pubkey_hex)
    client = _make_client()
    try:
        await _connect_authenticated(client, auth)
        result = await client.publish_punishment_permaban(pubkey, reason, board=board)
        return f"Permaban issued — event seq {result.origin_seq}"
    finally:
        await client.close()


@mcp.tool
async def punish_revoke(
    punishment_event_id_hex: str,
    reason: str = "",
    auth: str | None = None,
) -> str:
    """Revoke any punishment by its event ID. Requires moderator or administrator."""
    eid = _validate_event_id(punishment_event_id_hex)
    client = _make_client()
    try:
        await _connect_authenticated(client, auth)
        result = await client.publish_punishment_revoke(eid, reason)
        return f"Punishment revoked — event seq {result.origin_seq}"
    finally:
        await client.close()


@mcp.tool
async def acknowledge_punishment(
    punishment_event_id_hex: str,
    auth: str | None = None,
) -> str:
    """Acknowledge a punishment as the punished user.

    Acknowledging a warning clears it from your pending state so writes
    proceed again. Bans remain in force until they expire or are revoked.
    Must be called with your own identity.
    """
    eid = _validate_event_id(punishment_event_id_hex)
    client = _make_client()
    try:
        await _connect_authenticated(client, auth)
        result = await client.publish_punishment_ack(eid)
        return f"Punishment acknowledged — ack event {result.event_id}"
    finally:
        await client.close()


@mcp.tool
async def my_punishments(auth: str | None = None) -> BanStatus:
    """List punishments pending against your own identity."""
    client = _make_client()
    try:
        await _connect_authenticated(client, auth)
        return await client.get_ban_status(client._identity.public_key)
    finally:
        await client.close()


# ---------------------------------------------------------------------------
# Firehose / federation tools
# ---------------------------------------------------------------------------


@mcp.tool
async def event_head(origin: str = "", auth: str | None = None) -> HeadInfo | None:
    """Get the signed firehose head for an origin (latest sequence, event hash, counts).

    origin: origin to query (defaults to server's origin).
    """
    client = _make_client()
    try:
        if auth:
            await _connect_authenticated(client, auth)
        else:
            await _connect_anonymous(client)
        origin = origin or client._server_origin or ""
        return await client.get_head(origin)
    finally:
        await client.close()


@mcp.tool
async def event_range(
    origin: str = "",
    start_seq: int = 1,
    max_count: int = 100,
    auth: str | None = None,
) -> list[dict]:
    """Fetch firehose events from an origin starting at a sequence number.

    Returns a list of event summaries with origin_seq, kind, event_id,
    actor info, board, article_num, and target fields (for control events).

    origin: origin to query (defaults to server's origin).
    start_seq: first sequence number to fetch.
    max_count: maximum events to return.
    """
    client = _make_client()
    try:
        if auth:
            await _connect_authenticated(client, auth)
        else:
            await _connect_anonymous(client)
        origin = origin or client._server_origin or ""
        results = await client.get_event_range(origin, start_seq, max_count)
        return [
            {
                "origin_seq": rec.origin_seq,
                "kind": rec.kind,
                "event_id": rec.event_id.hex(),
                "actor_pubkey": rec.actor_pubkey.hex(),
                "actor_username": rec.actor_username,
                "actor_registrar": rec.actor_registrar,
                "board": rec.board,
                "article_num": rec.article_num,
                "target_origin": rec.target_origin,
                "target_board": rec.target_board,
                "target_article_id": rec.target_article_id.hex()
                if rec.target_article_id != ZERO_ID
                else "",
                "target_event_id": rec.target_event_id.hex()
                if rec.target_event_id != ZERO_ID
                else "",
                "created_at": rec.created_at,
            }
            for rec, witness in results
        ]
    finally:
        await client.close()


@mcp.tool
async def get_event(
    origin: str,
    event_id_hex: str,
    auth: str | None = None,
) -> dict:
    """Get a single event by ID with full details including witness.

    origin: origin that published the event.
    event_id_hex: hex event ID (64 chars).
    """
    eid = _validate_event_id(event_id_hex)
    client = _make_client()
    try:
        if auth:
            await _connect_authenticated(client, auth)
        else:
            await _connect_anonymous(client)
        rec, witness = await client.get_event(origin, eid)
        return {
            "origin": rec.origin,
            "origin_seq": rec.origin_seq,
            "event_id": rec.event_id.hex(),
            "kind": rec.kind,
            "schema_version": rec.schema_version,
            "created_at": rec.created_at,
            "actor_pubkey": rec.actor_pubkey.hex(),
            "actor_username": rec.actor_username,
            "actor_registrar": rec.actor_registrar,
            "board": rec.board,
            "article_id": rec.article_id.hex() if rec.article_id != ZERO_ID else "",
            "article_num": rec.article_num,
            "target_origin": rec.target_origin,
            "target_board": rec.target_board,
            "target_article_id": rec.target_article_id.hex()
            if rec.target_article_id != ZERO_ID
            else "",
            "target_event_id": rec.target_event_id.hex() if rec.target_event_id != ZERO_ID else "",
            "body_hash": rec.body_hash.hex(),
            "body_size": rec.body_size,
            "witness": {
                "relay_pubkey": witness.relay_pubkey.hex(),
                "relay_hostname": witness.relay_hostname,
                "received_from_pubkey": witness.received_from_pubkey.hex(),
                "received_from_hostname": witness.received_from_hostname,
                "seen_at": witness.seen_at,
            },
        }
    finally:
        await client.close()


@mcp.tool
async def trace_event(
    origin: str,
    event_id_hex: str,
    max_hops: int = 10,
    auth: str | None = None,
) -> list[dict]:
    """Trace an event back to its origin through relay witnesses.

    Follows the witness chain hop-by-hop. Returns a list of hops with
    relay pubkey, relay hostname, upstream pubkey, upstream hostname,
    and seen_at timestamp.

    origin: origin that published the event.
    event_id_hex: hex event ID (64 chars).
    max_hops: maximum hops to follow (default 10).
    """
    eid = _validate_event_id(event_id_hex)
    client = _make_client()
    try:
        if auth:
            await _connect_authenticated(client, auth)
        else:
            await _connect_anonymous(client)
        return await client.trace_event(origin, eid, max_hops)
    finally:
        await client.close()


@mcp.tool
async def get_event_body(
    origin: str,
    event_id_hex: str,
    auth: str | None = None,
) -> str:
    """Get the body content of an event (non-article events like cancel reasons, rule text).

    origin: origin that published the event.
    event_id_hex: hex event ID (64 chars).
    Returns the body as a UTF-8 string.
    """
    eid = _validate_event_id(event_id_hex)
    client = _make_client()
    try:
        if auth:
            await _connect_authenticated(client, auth)
        else:
            await _connect_anonymous(client)
        body = await client.get_event_body(origin, eid)
        return body.decode("utf-8", errors="replace") if body else ""
    finally:
        await client.close()
