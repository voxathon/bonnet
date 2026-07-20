import contextvars
import os
import time
from typing import Optional

from fastmcp import FastMCP

from .http import BonnetMCPClient as BonnetClient
from .identity import IdentityStore
from .models import (
    User,
    Board,
    Peer,
    BanStatus,
    Article,
    ArticleEvent,
    FeedHeadInfo,
    ArticlePublishResult,
)

mcp = FastMCP("Bonnet BBS")

current_username: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "username", default=None
)
current_password: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "password", default=""
)
identity_store: IdentityStore | None = None
bonnet_url: str = os.environ.get("BONNET_URL", "https://localhost:2272")
bonnet_verify: bool | str = os.environ.get("BONNET_VERIFY_TLS", "true").lower() not in ("false", "0", "no")

auth_tokens: dict[str, dict] = {}
TOKEN_EXPIRY_SECONDS = 24 * 60 * 60


def get_client() -> BonnetClient:
    global identity_store
    if identity_store is None:
        identity_store = IdentityStore()
    return BonnetClient(identity_store, bonnet_url, verify=bonnet_verify)


def get_username() -> str:
    username = current_username.get()
    if not username:
        raise ValueError("No username in context - check Authorization header")
    return username


def get_password() -> str:
    return current_password.get() or ""


def resolve_auth(auth: str | None) -> tuple[str, str]:
    if auth is None:
        return get_username(), get_password()

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


def resolve_username(auth: str | None) -> str:
    if auth is None:
        return get_username()

    if ":" in auth:
        return auth.split(":", 1)[0]

    token_data = auth_tokens.get(auth)
    if token_data is None:
        raise ValueError("Invalid or expired auth token")

    if time.time() > token_data["expires_at"]:
        del auth_tokens[auth]
        raise ValueError("Auth token has expired")

    return token_data["username"]


async def _connect(client: BonnetClient, auth: str | None) -> None:
    """Connect the client, authenticating if auth is provided, anonymous otherwise."""
    if auth is not None:
        username, password = resolve_auth(auth)
        await client.connect(username, password, require_auth=True)
    else:
        username = resolve_username(auth)
        await client.connect(username, require_auth=False)


def validate_pubkey(pubkey: str) -> bytes:
    try:
        pubkey_bytes = bytes.fromhex(pubkey)
        if len(pubkey_bytes) != 32:
            raise ValueError(
                f"Public key must be 32 bytes (64 hex characters), got {len(pubkey_bytes)} bytes."
            )
        return pubkey_bytes
    except ValueError as e:
        raise ValueError(f"Invalid public key format: {pubkey}") from e


def validate_message_id(mid: str) -> bytes:
    try:
        mid_bytes = bytes.fromhex(mid)
        if len(mid_bytes) != 32:
            raise ValueError(
                f"Message ID must be 32 bytes (64 hex characters), got {len(mid_bytes)} bytes."
            )
        return mid_bytes
    except ValueError as e:
        raise ValueError(f"Invalid message ID format: {mid}") from e


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
    client = get_client()

    try:
        async with client:
            await client.connect(username, password, require_auth=True)
    except Exception as e:
        raise ValueError(f"Authentication failed: {e}") from e

    token = os.urandom(32).hex()
    auth_tokens[token] = {
        "username": username,
        "password": password,
        "expires_at": time.time() + TOKEN_EXPIRY_SECONDS,
    }

    return token


@mcp.tool
async def register(username: str, password: str) -> str:
    """Register a new user locally and on the Bonnet server.

    Creates a local Ed25519 identity and registers the username on the server.
    Returns the registered username. If the user already exists locally and
    the password matches, the backend registration is retried idempotently.
    """
    client = get_client()
    is_existing = False
    try:
        client.identity_store.register(username, password)
    except ValueError as e:
        if str(e) == "User already exists locally":
            if not client.identity_store.verify_password(username, password):
                raise ValueError(
                    "User already exists locally and password does not match."
                ) from e
            is_existing = True
        else:
            raise

    async with client:
        await client.connect(username, password, require_auth=True)
        try:
            await client._register(username)
        except Exception as backend_err:
            if is_existing and "already exists" in str(backend_err).lower():
                user = await client.get_user(username)
                if user and user.username == username:
                    return username
            raise backend_err
        return username


@mcp.tool
async def get_user(username: str, auth: str | None = None) -> User | None:
    """Look up a registered user by their username.

    Returns the user's public key, registrar, record origin, and relay,
    or None if not found.
    """
    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.get_user(username)


@mcp.tool
async def get_users_by_pubkey(pubkey: str, auth: str | None = None) -> list[User]:
    """Look up all users associated with an Ed25519 public key.

    A single public key may be associated with multiple users across
    different origins. Returns a list of matching user records.

    pubkey: hex-encoded 32-byte Ed25519 public key.
    """
    pubkey_bytes = validate_pubkey(pubkey)
    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.get_users_by_pubkey(pubkey_bytes)


@mcp.tool
async def list_users(
    offset: int = 0, limit: int = 100, auth: str | None = None
) -> list[User]:
    """List registered users with pagination. Each entry includes username,
    registrar origin, public key, and relay information."""
    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.list_users(offset, limit)


@mcp.tool
async def list_peers(auth: str | None = None) -> list[Peer]:
    """List known peer server hostnames for federation."""
    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.list_peers()


@mcp.tool
async def get_server_pubkey(auth: str | None = None) -> str:
    """Get the server's Ed25519 public key (hex string)."""
    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.get_server_pubkey()


# ---------------------------------------------------------------------------
# Board tools
# ---------------------------------------------------------------------------

@mcp.tool
async def create_board(name: str, auth: str | None = None) -> Board:
    """Create a new board. Requires admin privileges.

    Boards are immutable signed entries in the navigation database; once
    created they can be closed (read-only) or reopened but not deleted.
    """
    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.board_create(name)


@mcp.tool
async def list_boards(auth: str | None = None) -> list[Board]:
    """List all available boards with metadata (name, origin, closed state, signature)."""
    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.board_list()


@mcp.tool
async def close_board(name: str, reason: str = "", auth: str | None = None) -> ArticlePublishResult:
    """Close a board so it rejects new articles. Requires admin privileges.

    A closed board still allows reads and certain moderator control events
    (purge, rule revoke, punishment revoke). Records a BOARD_CLOSE feed event.
    Returns the published event metadata.
    """
    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.close_board(name, reason)


@mcp.tool
async def reopen_board(name: str, reason: str = "", auth: str | None = None) -> ArticlePublishResult:
    """Reopen a previously closed board. Requires admin privileges.

    Records a BOARD_REOPEN feed event. Returns the published event metadata.
    """
    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.reopen_board(name, reason)


# ---------------------------------------------------------------------------
# Article tools (read)
# ---------------------------------------------------------------------------

@mcp.tool
async def get_article(
    board: str,
    article_num: int | None = None,
    message_id: str | None = None,
    include_body: bool = True,
    auth: str | None = None,
) -> Article | None:
    """Get a single article by board and either article_num (int) or message_id (hex string).

    Returns the full article including subject, tags, body (if available),
    author info, projected state (active/cancelled/superseded/purged), and
    any control event IDs targeting it. Returns None if not found.
    """
    client = get_client()
    async with client:
        await _connect(client, auth)
        if message_id is not None:
            mid = validate_message_id(message_id)
            from client.protocol import SELECTOR_MESSAGE_ID
            return await client.article_get(board, SELECTOR_MESSAGE_ID, mid, include_body)
        if article_num is None:
            raise ValueError("Either article_num or message_id must be provided")
        from client.protocol import SELECTOR_ARTICLE_NUM
        return await client.article_get(board, SELECTOR_ARTICLE_NUM, article_num, include_body)


@mcp.tool
async def list_articles(
    board: str,
    offset: int = 0,
    limit: int = 50,
    include_cancelled: bool = False,
    include_superseded: bool = False,
    include_purged: bool = False,
    include_bodies: bool = False,
    auth: str | None = None,
) -> list[Article]:
    """List articles on a board with pagination and state filtering.

    By default only active articles are returned. Set include_cancelled,
    include_superseded, or include_purged to also include those states.
    Set include_bodies to fetch article content along with metadata.
    """
    from core.article_feed import (
        FLAG_INCLUDE_CANCELLED, FLAG_INCLUDE_SUPERSEDED,
        FLAG_INCLUDE_PURGED, FLAG_INCLUDE_BODIES,
    )
    flags = 0
    if include_cancelled:
        flags |= FLAG_INCLUDE_CANCELLED
    if include_superseded:
        flags |= FLAG_INCLUDE_SUPERSEDED
    if include_purged:
        flags |= FLAG_INCLUDE_PURGED
    if include_bodies:
        flags |= FLAG_INCLUDE_BODIES

    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.article_list(board, offset, limit, flags)


@mcp.tool
async def search_articles(
    board: str,
    text_query: str = "",
    offset: int = 0,
    limit: int = 50,
    actor_pubkey: str | None = None,
    created_after: int = 0,
    created_before: int = 0,
    include_cancelled: bool = False,
    include_superseded: bool = False,
    include_purged: bool = False,
    auth: str | None = None,
) -> list[Article]:
    """Search articles on a board with structured filters.

    text_query: substring search over subject and tags.
    actor_pubkey: hex public key to filter by author.
    created_after/created_before: optional unix timestamp time window.
    State filters default to active-only; set flags to include other states.
    """
    from core.article_feed import (
        FLAG_INCLUDE_CANCELLED, FLAG_INCLUDE_SUPERSEDED, FLAG_INCLUDE_PURGED,
    )
    flags = 0
    if include_cancelled:
        flags |= FLAG_INCLUDE_CANCELLED
    if include_superseded:
        flags |= FLAG_INCLUDE_SUPERSEDED
    if include_purged:
        flags |= FLAG_INCLUDE_PURGED

    actor = validate_pubkey(actor_pubkey) if actor_pubkey else None

    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.article_search(
            board, text_query, offset, limit, flags,
            actor_pubkey=actor,
            created_after=created_after,
            created_before=created_before,
        )


# ---------------------------------------------------------------------------
# Article tools (write)
# ---------------------------------------------------------------------------

@mcp.tool
async def publish_article(
    board: str,
    subject: str,
    content: str,
    tags: str = "",
    options: str = "",
    root_message_id: str | None = None,
    reply_to_message_id: str | None = None,
    auth: str | None = None,
) -> ArticlePublishResult:
    """Publish a new article to a board. Requires a registered user.

    Articles are immutable once published; to revise content use supersede_article,
    to remove use cancel_article. The article is signed with your Ed25519 key
    and recorded as a feed event.

    root_message_id: hex message ID of the root article (for thread replies).
    reply_to_message_id: hex message ID of the article being replied to.
    Omit both to start a new thread.
    """
    root_mid = validate_message_id(root_message_id) if root_message_id else None
    reply_mid = validate_message_id(reply_to_message_id) if reply_to_message_id else None

    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.publish_article(
            board, subject, content, tags, options, root_mid, reply_mid,
        )


@mcp.tool
async def supersede_article(
    board: str,
    target_message_id: str,
    subject: str,
    content: str,
    tags: str = "",
    options: str = "",
    auth: str | None = None,
) -> ArticlePublishResult:
    """Publish a new article that supersedes an existing one. Only the original
    author may supersede. The superseded article's projected state becomes
    'superseded' and the new article carries the supersedes link.

    target_message_id: hex message ID of the article being superseded.
    """
    target_mid = validate_message_id(target_message_id)

    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.supersede_article(
            board, target_mid, subject, content, tags, options,
        )


@mcp.tool
async def cancel_article(
    board: str,
    target_message_id: str,
    reason: str = "",
    auth: str | None = None,
) -> ArticlePublishResult:
    """Cancel an article (mark it as cancelled). The author or a moderator
    may cancel. A cancelled article is soft-deleted: its body is retained
    but its projected state becomes 'cancelled'.

    target_message_id: hex message ID of the article to cancel.
    reason: optional human-readable cancellation reason.
    """
    target_mid = validate_message_id(target_message_id)

    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.cancel_article(board, target_mid, reason)


@mcp.tool
async def restore_article(
    board: str,
    target_message_id: str,
    reason: str = "",
    auth: str | None = None,
) -> ArticlePublishResult:
    """Restore a previously cancelled article. Author or moderator.

    target_message_id: hex message ID of the cancelled article to restore.
    """
    target_mid = validate_message_id(target_message_id)

    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.restore_article(board, target_mid, reason)


# ---------------------------------------------------------------------------
# Moderation tools (write)
# ---------------------------------------------------------------------------

@mcp.tool
async def purge_article(
    board: str,
    target_message_id: str,
    reason: str,
    auth: str | None = None,
) -> ArticlePublishResult:
    """Purge an article (hard delete). Moderator/admin only.

    A purged article's body is removed and its projected state becomes 'purged'.
    Unlike cancel, purge is irreversible.

    target_message_id: hex message ID of the article to purge.
    reason: human-readable purge reason (required).
    """
    target_mid = validate_message_id(target_message_id)

    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.purge_article(board, target_mid, reason)


@mcp.tool
async def publish_rule(
    board: str,
    rule_name: str,
    description: str,
    auth: str | None = None,
) -> ArticlePublishResult:
    """Publish a community rule. Admin only.

    Rules are immutable feed events; to revoke a rule use revoke_rule.
    rule_name: short identifier for the rule.
    description: full rule text.
    """
    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.publish_rule(board, rule_name, description)


@mcp.tool
async def revoke_rule(
    board: str,
    target_message_id: str,
    reason: str,
    auth: str | None = None,
) -> ArticlePublishResult:
    """Revoke a previously published rule. Admin only.

    target_message_id: hex message ID of the RULE event to revoke.
    reason: human-readable revocation reason (required).
    """
    target_mid = validate_message_id(target_message_id)

    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.revoke_rule(board, target_mid, reason)


@mcp.tool
async def publish_report(
    board: str,
    culprit_pubkey: str,
    description: str,
    target_origin: str = "",
    target_board: str = "",
    target_message_id: str | None = None,
    auth: str | None = None,
) -> ArticlePublishResult:
    """File a report against a user for rule violation. Any registered user.

    culprit_pubkey: hex Ed25519 public key of the user being reported.
    description: report text explaining the violation.
    target_origin/target_board/target_message_id: identify the offending article
    (all optional but recommended when reporting a specific article).
    """
    culprit = validate_pubkey(culprit_pubkey)
    target_mid = validate_message_id(target_message_id) if target_message_id else None

    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.publish_report(
            board, culprit, description, target_origin, target_board, target_mid,
        )


@mcp.tool
async def publish_punishment(
    board: str,
    punished_pubkey: str,
    expires_at: int,
    notes: str = "",
    auth: str | None = None,
) -> ArticlePublishResult:
    """Issue a punishment (ban or warning) to a user. Moderator/admin only.

    punished_pubkey: hex Ed25519 public key of the user to punish.
    expires_at: 0 = warning (no ban), -1 = permanent ban, >0 = unix timestamp expiry.
    notes: moderator notes explaining the punishment.
    """
    punished = validate_pubkey(punished_pubkey)

    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.publish_punishment(
            board, punished, expires_at, notes=notes,
        )


@mcp.tool
async def revoke_punishment(
    board: str,
    target_message_id: str,
    reason: str,
    auth: str | None = None,
) -> ArticlePublishResult:
    """Revoke a previously issued punishment. Moderator/admin only.

    target_message_id: hex message ID of the PUNISHMENT event to revoke.
    reason: human-readable revocation reason (required).
    """
    target_mid = validate_message_id(target_message_id)

    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.revoke_punishment(board, target_mid, reason)


@mcp.tool
async def pin_article(
    board: str,
    target_message_id: str,
    priority: int = 0,
    auth: str | None = None,
) -> ArticlePublishResult:
    """Pin an article to the top of the board. Moderator/admin only.

    target_message_id: hex message ID of the article to pin.
    priority: higher values appear more prominent (signed 32-bit integer).
    """
    target_mid = validate_message_id(target_message_id)

    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.pin_article(board, target_mid, priority)


@mcp.tool
async def unpin_article(
    board: str,
    target_message_id: str,
    auth: str | None = None,
) -> ArticlePublishResult:
    """Remove a pin from an article. Moderator/admin only.

    target_message_id: hex message ID of the ARTICLE_PIN event to reverse.
    """
    target_mid = validate_message_id(target_message_id)

    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.unpin_article(board, target_mid)


@mcp.tool
async def close_thread(
    board: str,
    target_message_id: str,
    auth: str | None = None,
) -> ArticlePublishResult:
    """Close a thread so no new replies can be posted. Moderator/admin only.

    target_message_id: hex message ID of the thread root article.
    """
    target_mid = validate_message_id(target_message_id)

    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.close_thread(board, target_mid)


@mcp.tool
async def reopen_thread(
    board: str,
    target_message_id: str,
    auth: str | None = None,
) -> ArticlePublishResult:
    """Reopen a previously closed thread. Moderator/admin only.

    target_message_id: hex message ID of the thread root article.
    """
    target_mid = validate_message_id(target_message_id)

    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.reopen_thread(board, target_mid)


# ---------------------------------------------------------------------------
# Ban status / user admin
# ---------------------------------------------------------------------------

@mcp.tool
async def ban_status(pubkey: str, auth: str | None = None) -> BanStatus:
    """Check if a user is currently banned. Returns ban status, reason,
    source origin/board, and expiry timestamp.

    pubkey: hex Ed25519 public key of the user to check.
    """
    pubkey_bytes = validate_pubkey(pubkey)

    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.ban_status(pubkey_bytes)


@mcp.tool
async def promote_user(target_username: str, auth: str | None = None) -> None:
    """Promote a user to moderator. Requires admin privileges."""
    client = get_client()
    async with client:
        await _connect(client, auth)
        await client.user_promote(target_username)


@mcp.tool
async def demote_user(target_username: str, auth: str | None = None) -> None:
    """Remove moderator status from a user. Requires admin privileges."""
    client = get_client()
    async with client:
        await _connect(client, auth)
        await client.user_demote(target_username)


# ---------------------------------------------------------------------------
# Feed tools (federation / sync inspection)
# ---------------------------------------------------------------------------

@mcp.tool
async def feed_head(board: str, auth: str | None = None) -> FeedHeadInfo | None:
    """Get the signed feed head for a board (latest sequence, event hash, counts).

    The feed head is a signed summary of the board's article feed state,
    used for federation sync. Returns None if the board has no feed.
    """
    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.feed_head(board)


@mcp.tool
async def feed_heads(
    offset: int = 0, limit: int = 100, auth: str | None = None,
) -> list[FeedHeadInfo]:
    """List feed heads across all local-origin boards."""
    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.feed_heads(offset, limit)


@mcp.tool
async def feed_events(
    board: str, start_seq: int = 1, max_count: int = 100, auth: str | None = None,
) -> list[ArticleEvent]:
    """Fetch raw feed events from a board starting at a sequence number.

    Returns ArticleEvent models with full event metadata (type, actor, message
    IDs, body hash). Use this to inspect the feed chain for federation or audit.
    """
    client = get_client()
    async with client:
        await _connect(client, auth)
        return await client.feed_events(board, start_seq, max_count)
