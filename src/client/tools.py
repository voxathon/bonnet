import contextvars
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
identity_store: IdentityStore | None = None
bonnet_url: str = "ws://localhost:2272"


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


@mcp.tool
async def register_user(username: str) -> str:
    """Register a new user on the Bonnet server. Returns the registered username."""
    client = get_client()
    async with client:
        await client.connect(username)
        return username


@mcp.tool
async def get_user_by_username(target_username: str) -> User | None:
    """Look up a user by their username."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        return await client.get_user(target_username)


@mcp.tool
async def list_users(offset: int = 0, limit: int = 100) -> list[User]:
    """List registered users with pagination."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        return await client.list_users(offset, limit)


@mcp.tool
async def list_peers() -> list[Peer]:
    """List known peer server hostnames for federation."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        return await client.list_peers()


@mcp.tool
async def create_board(name: str) -> Board:
    """Create a new board. Requires admin privileges."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        return await client.board_create(name)


@mcp.tool
async def list_boards() -> list[Board]:
    """List all available boards with metadata."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        return await client.board_list()


@mcp.tool
async def close_board(name: str) -> None:
    """Mark a board as read-only. Requires admin privileges."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        await client.board_close(name)


@mcp.tool
async def delete_board(name: str) -> None:
    """Delete a board from disk. Requires admin privileges. Must be closed first."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        await client.board_delete(name)


@mcp.tool
async def create_post(
    board: str,
    subject: str,
    content: str,
    tags: str = "",
    options: str = "",
    root: int = 0,
) -> PostCreateResult:
    """Create a new post. root=0 starts a new thread, root>0 replies to that post."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        return await client.post_create(board, subject, content, tags, options, root)


@mcp.tool
async def get_post(board: str, post_num: int) -> Post:
    """Get full post content by board and post number."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        return await client.post_get(board, post_num)


@mcp.tool
async def list_posts(board: str, offset: int = 0, limit: int = 50) -> list[PostSummary]:
    """List posts on a board with pagination."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
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
) -> None:
    """Update post fields. Author can edit content/subject/tags/options. Mods can also edit sticky/closed."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        await client.post_update(
            board, post_num, content, subject, tags, options, sticky, closed
        )


@mcp.tool
async def delete_post(board: str, post_num: int) -> None:
    """Delete a post."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        await client.post_delete(board, post_num)


@mcp.tool
async def query_posts(
    board: str,
    where: str = "",
    values: list[tuple[int, str | int]] | None = None,
    orderby: str = "last_bumped DESC",
    limit: int = 100,
) -> list[PostSummary]:
    """Query posts with SQL WHERE clause. values is a list of [type, value] pairs (type: 1=int, 2=str)."""
    client = get_client()
    username = get_username()

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
        await client.connect(username)
        return await client.query_posts(board, where, parsed_values, orderby, limit)


@mcp.tool
async def sign_post(board: str, post_num: int) -> str:
    """Sign a post with your identity. Only the post author can sign. Returns the signature hex."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        return await client.post_sign(board, post_num)


@mcp.tool
async def promote_user(username: str) -> None:
    """Promote a user to moderator. Requires admin privileges."""
    client = get_client()
    caller = get_username()
    async with client:
        await client.connect(caller)
        await client.user_promote(username)


@mcp.tool
async def demote_user(username: str) -> None:
    """Remove moderator status from a user. Requires admin privileges."""
    client = get_client()
    caller = get_username()
    async with client:
        await client.connect(caller)
        await client.user_demote(username)


@mcp.tool
async def get_server_pubkey() -> str:
    """Get the server's Ed25519 public key (hex string)."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        return await client.get_server_pubkey()


@mcp.tool
async def create_rule(name: str, description: str) -> Rule:
    """Create a new community rule. Requires moderator privileges."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        return await client.rule_create(name, description)


@mcp.tool
async def get_rule(rule_num: int) -> Rule:
    """Get a rule by its number."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        return await client.rule_get(rule_num)


@mcp.tool
async def get_rule_by_name(name: str) -> Rule:
    """Get a rule by its name."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        return await client.rule_get_by_name(name)


@mcp.tool
async def list_rules() -> list[Rule]:
    """List all community rules."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        return await client.rule_list()


@mcp.tool
async def update_rule(
    rule_num: int, name: str | None = None, description: str | None = None
) -> Rule:
    """Update a rule's name or description."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
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
) -> Report:
    """Report a user for violating a rule."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        return await client.report_create(
            rule_num, culprit_pubkey, description, board, post_num, origin, relay
        )


@mcp.tool
async def get_report(origin: str, report_num: int) -> Report:
    """Get a report by origin server and report number."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        return await client.report_get(origin, report_num)


@mcp.tool
async def list_reports_by_culprit(pubkey: str) -> list[Report]:
    """List all reports against a user by their public key."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        return await client.report_list_by_culprit(pubkey)


@mcp.tool
async def sign_report(origin: str, report_num: int) -> Report:
    """Sign a report as the reporter."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        return await client.report_sign(origin, report_num)


@mcp.tool
async def create_punishment(
    pubkey: str, report_ids: list[int], expires_at: int, notes: str = ""
) -> Punishment:
    """Create a punishment (ban/warning). expires_at: 0=warning, -1=permanent, >0=unix timestamp. Requires mod privileges."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        return await client.punishment_create(pubkey, report_ids, expires_at, notes)


@mcp.tool
async def get_punishment(pubkey: str) -> Punishment | None:
    """Get active punishment for a user."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        return await client.punishment_get(pubkey)


@mcp.tool
async def list_active_punishments() -> list[Punishment]:
    """List all active punishments."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        return await client.punishment_list_active()


@mcp.tool
async def is_banned(pubkey: str) -> BannedStatus:
    """Check if a user is banned. Returns (banned, reason)."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username)
        return await client.is_banned(pubkey)
