import contextvars
import os
import time
from typing import Optional

from fastmcp import FastMCP

from .connection import BonnetClient
from .identity import IdentityStore
from .models import (
    User,
    Board,
    Post,
    PostSummary,
    PostCreateResult,
    Rule,
    Report,
    Punishment,
    BannedStatus,
    Peer,
)

mcp = FastMCP("Bonnet BBS")

current_username: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "username", default=None
)
current_password: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "password", default=""
)
identity_store: IdentityStore | None = None
bonnet_url: str = "ws://localhost:2272"

auth_tokens: dict[str, dict] = {}
TOKEN_EXPIRY_SECONDS = 24 * 60 * 60


def get_client() -> BonnetClient:
    global identity_store
    if identity_store is None:
        identity_store = IdentityStore()
    return BonnetClient(identity_store, bonnet_url)


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


@mcp.tool
async def login(username: str, password: str) -> str:
    """Authenticate and receive a temporary auth token valid for 24 hours."""
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
async def register_user(username: str, password: str) -> str:
    """Register a new user locally and on the Bonnet server. Returns the registered username."""
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
                user = await client.get_user(client._public_key)
                if user and user.username == username:
                    return username
            raise backend_err
        return username


@mcp.tool
async def get_user_by_pubkey(pubkey: str, auth: str | None = None) -> User | None:
    """Look up a user by their Ed25519 public key (hex string)."""
    pubkey_bytes = validate_pubkey(pubkey)

    client = get_client()
    username = resolve_username(auth)
    async with client:
        await client.connect(username, require_auth=False)
        return await client.get_user(pubkey_bytes)


@mcp.tool
async def list_users(
    offset: int = 0, limit: int = 100, auth: str | None = None
) -> list[User]:
    """List registered users with pagination."""
    client = get_client()
    username = resolve_username(auth)
    async with client:
        await client.connect(username, require_auth=False)
        return await client.list_users(offset, limit)


@mcp.tool
async def list_peers(auth: str | None = None) -> list[Peer]:
    """List known peer server hostnames for federation."""
    client = get_client()
    username = resolve_username(auth)
    async with client:
        await client.connect(username, require_auth=False)
        return await client.list_peers()


@mcp.tool
async def create_board(name: str, auth: str | None = None) -> Board:
    """Create a new board. Requires admin privileges."""
    client = get_client()
    username, password = resolve_auth(auth)
    async with client:
        await client.connect(username, password, require_auth=True)
        return await client.board_create(name)


@mcp.tool
async def list_boards(auth: str | None = None) -> list[Board]:
    """List all available boards with metadata."""
    client = get_client()
    username = resolve_username(auth)
    async with client:
        await client.connect(username, require_auth=False)
        return await client.board_list()


@mcp.tool
async def close_board(name: str, auth: str | None = None) -> None:
    """Mark a board as read-only. Requires admin privileges."""
    client = get_client()
    username, password = resolve_auth(auth)
    async with client:
        await client.connect(username, password, require_auth=True)
        await client.board_close(name)


@mcp.tool
async def delete_board(name: str, auth: str | None = None) -> None:
    """Delete a board from disk. Requires admin privileges. Must be closed first."""
    client = get_client()
    username, password = resolve_auth(auth)
    async with client:
        await client.connect(username, password, require_auth=True)
        await client.board_delete(name)


@mcp.tool
async def create_post(
    board: str,
    subject: str,
    content: str,
    tags: str = "",
    options: str = "",
    root: int = 0,
    auth: str | None = None,
) -> PostCreateResult:
    """Create a new post. root=0 starts a new thread, root>0 replies to that post."""
    client = get_client()
    username, password = resolve_auth(auth)
    async with client:
        await client.connect(username, password, require_auth=True)
        return await client.post_create(board, subject, content, tags, options, root)


@mcp.tool
async def get_post(board: str, post_num: int, auth: str | None = None) -> Post:
    """Get full post content by board and post number."""
    client = get_client()
    username = resolve_username(auth)
    async with client:
        await client.connect(username, require_auth=False)
        return await client.post_get(board, post_num)


@mcp.tool
async def list_posts(
    board: str, offset: int = 0, limit: int = 50, auth: str | None = None
) -> list[PostSummary]:
    """List posts on a board with pagination."""
    client = get_client()
    username = resolve_username(auth)
    async with client:
        await client.connect(username, require_auth=False)
        return await client.post_list(board, offset, limit)


@mcp.tool
async def update_post(
    board: str,
    post_num: int,
    content: str | None = None,
    subject: str | None = None,
    tags: str | None = None,
    options: str | None = None,
    sticky: int | None = None,
    closed: bool | None = None,
    auth: str | None = None,
) -> None:
    """Update post fields. Author can edit content/subject/tags/options. Mods can also edit sticky/closed."""
    client = get_client()
    username, password = resolve_auth(auth)
    async with client:
        await client.connect(username, password, require_auth=True)
        await client.post_update(
            board, post_num, content, subject, tags, options, sticky, closed
        )


@mcp.tool
async def delete_post(board: str, post_num: int, auth: str | None = None) -> None:
    """Delete a post."""
    client = get_client()
    username, password = resolve_auth(auth)
    async with client:
        await client.connect(username, password, require_auth=True)
        await client.post_delete(board, post_num)


@mcp.tool
async def query_posts(
    board: str,
    where: str = "",
    values: list[tuple[int, str | int]] | None = None,
    orderby: str = "last_bumped DESC",
    limit: int = 100,
    auth: str | None = None,
) -> list[PostSummary]:
    """Query posts with SQL WHERE clause. values is a list of [type, value] pairs (type: 1=int, 2=str)."""
    client = get_client()
    username = resolve_username(auth)

    parsed_values = []
    if values:
        from .protocol import encode_string
        import struct

        for vtype, vval in values:
            if vtype == 1:
                parsed_values.append((1, struct.pack(">q", vval)))
            else:
                parsed_values.append((2, encode_string(str(vval))))

    async with client:
        await client.connect(username, require_auth=False)
        return await client.query_posts(board, where, parsed_values, orderby, limit)


@mcp.tool
async def sign_post(board: str, post_num: int, auth: str | None = None) -> str:
    """Sign a post with your identity. Only the post author can sign. Returns the signature hex."""
    client = get_client()
    username, password = resolve_auth(auth)

    async with client:
        await client.connect(username, password, require_auth=False)
        post = await client.post_get(board, post_num)

    async with client:
        await client.connect(username, password, require_auth=True)
        return await client.post_sign(
            board,
            post_num,
            post.creation_date,
            post.last_modified,
            post.author,
            post.author_registrar,
            ",".join(post.tags),
            post.subject,
            post.options,
            post.content,
        )


@mcp.tool
async def promote_user(target_username: str, auth: str | None = None) -> None:
    """Promote a user to moderator. Requires admin privileges."""
    client = get_client()
    username, password = resolve_auth(auth)
    async with client:
        await client.connect(username, password, require_auth=True)
        await client.user_promote(target_username)


@mcp.tool
async def demote_user(target_username: str, auth: str | None = None) -> None:
    """Remove moderator status from a user. Requires admin privileges."""
    client = get_client()
    username, password = resolve_auth(auth)
    async with client:
        await client.connect(username, password, require_auth=True)
        await client.user_demote(target_username)


@mcp.tool
async def get_server_pubkey(auth: str | None = None) -> str:
    """Get the server's Ed25519 public key (hex string)."""
    client = get_client()
    username = resolve_username(auth)
    async with client:
        await client.connect(username, require_auth=False)
        return await client.get_server_pubkey()


@mcp.tool
async def create_rule(name: str, description: str, auth: str | None = None) -> Rule:
    """Create a new community rule. Requires moderator privileges."""
    client = get_client()
    username, password = resolve_auth(auth)
    async with client:
        await client.connect(username, password, require_auth=True)
        return await client.rule_create(name, description)


@mcp.tool
async def get_rule(rule_num: int, auth: str | None = None) -> Rule:
    """Get a rule by its number."""
    client = get_client()
    username = resolve_username(auth)
    async with client:
        await client.connect(username, require_auth=False)
        return await client.rule_get(rule_num)


@mcp.tool
async def get_rule_by_name(name: str, auth: str | None = None) -> Rule:
    """Get a rule by its name."""
    client = get_client()
    username = resolve_username(auth)
    async with client:
        await client.connect(username, require_auth=False)
        return await client.rule_get_by_name(name)


@mcp.tool
async def list_rules(auth: str | None = None) -> list[Rule]:
    """List all community rules."""
    client = get_client()
    username = resolve_username(auth)
    async with client:
        await client.connect(username, require_auth=False)
        return await client.rule_list()


@mcp.tool
async def update_rule(
    rule_num: int,
    name: str | None = None,
    description: str | None = None,
    auth: str | None = None,
) -> Rule:
    """Update a rule's name or description."""
    client = get_client()
    username, password = resolve_auth(auth)
    async with client:
        await client.connect(username, password, require_auth=True)
        return await client.rule_update(rule_num, name, description)


@mcp.tool
async def create_report(
    rule_num: int,
    culprit_pubkey: str,
    description: str,
    board: str | None = None,
    post_num: int | None = None,
    origin: str | None = None,
    relay: str | None = None,
    auth: str | None = None,
) -> Report:
    """Report a user for violating a rule."""
    validate_pubkey(culprit_pubkey)

    client = get_client()
    username, password = resolve_auth(auth)
    async with client:
        await client.connect(username, password, require_auth=True)
        return await client.report_create(
            rule_num, culprit_pubkey, description, board, post_num, origin, relay
        )


@mcp.tool
async def get_report(origin: str, report_num: int, auth: str | None = None) -> Report:
    """Get a report by origin server and report number."""
    client = get_client()
    username = resolve_username(auth)
    async with client:
        await client.connect(username, require_auth=False)
        return await client.report_get(origin, report_num)


@mcp.tool
async def list_reports_by_culprit(pubkey: str, auth: str | None = None) -> list[Report]:
    """List all reports against a user by their public key."""
    validate_pubkey(pubkey)

    client = get_client()
    username = resolve_username(auth)
    async with client:
        await client.connect(username, require_auth=False)
        return await client.report_list_by_culprit(pubkey)


@mcp.tool
async def sign_report(origin: str, report_num: int, auth: str | None = None) -> Report:
    """Sign a report as the reporter."""
    client = get_client()
    username, password = resolve_auth(auth)
    async with client:
        await client.connect(username, password, require_auth=True)
        return await client.report_sign(origin, report_num)


@mcp.tool
async def create_punishment(
    pubkey: str,
    report_ids: list[int],
    expires_at: int,
    notes: str = "",
    auth: str | None = None,
) -> Punishment:
    """Create a punishment (ban/warning). expires_at: 0=warning, -1=permanent, >0=unix timestamp. Requires mod privileges."""
    validate_pubkey(pubkey)

    client = get_client()
    username, password = resolve_auth(auth)
    async with client:
        await client.connect(username, password, require_auth=True)
        return await client.punishment_create(pubkey, report_ids, expires_at, notes)


@mcp.tool
async def get_punishment(pubkey: str, auth: str | None = None) -> Punishment | None:
    """Get active punishment for a user."""
    validate_pubkey(pubkey)

    client = get_client()
    username = resolve_username(auth)
    async with client:
        await client.connect(username, require_auth=False)
        return await client.punishment_get(pubkey)


@mcp.tool
async def list_active_punishments(auth: str | None = None) -> list[Punishment]:
    """List all active punishments."""
    client = get_client()
    username = resolve_username(auth)
    async with client:
        await client.connect(username, require_auth=False)
        return await client.punishment_list_active()


@mcp.tool
async def is_banned(pubkey: str, auth: str | None = None) -> BannedStatus:
    """Check if a user is banned. Returns (banned, reason)."""
    validate_pubkey(pubkey)

    client = get_client()
    username = resolve_username(auth)
    async with client:
        await client.connect(username, require_auth=False)
        return await client.is_banned(pubkey)
