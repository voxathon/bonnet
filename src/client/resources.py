from fastmcp import FastMCP

from .tools import mcp, get_client, get_username
from .models import Board, Post, PostSummary, User, Rule, Report


@mcp.resource("bonnet://boards")
async def list_boards_resource() -> list[Board]:
    """List all boards."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username, require_auth=False)
        return await client.board_list()


@mcp.resource("bonnet://boards/{board_name}")
async def get_board_resource(board_name: str) -> Board:
    """Get board metadata."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username, require_auth=False)
        boards = await client.board_list()
        for board in boards:
            if board.name == board_name:
                return board
        raise ValueError(f"Board not found: {board_name}")


@mcp.resource("bonnet://boards/{board_name}/posts")
async def list_board_posts_resource(board_name: str) -> list[PostSummary]:
    """List posts on a board."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username, require_auth=False)
        return await client.post_list(board_name)


@mcp.resource("bonnet://boards/{board_name}/posts/{post_num}")
async def get_post_resource(board_name: str, post_num: int) -> Post:
    """Get full post content."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username, require_auth=False)
        return await client.post_get(board_name, post_num)


@mcp.resource("bonnet://boards/{board_name}/thread/{root}")
async def get_thread_resource(board_name: str, root: int) -> list[Post]:
    """Get all posts in a thread."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username, require_auth=False)
        return await client.query_posts(
            board_name,
            where="root = ?",
            values=[(1, root)],
            orderby="creation_date ASC",
        )


@mcp.resource("bonnet://users")
async def list_users_resource() -> list[User]:
    """List all users."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username, require_auth=False)
        return await client.list_users()


@mcp.resource("bonnet://rules")
async def list_rules_resource() -> list[Rule]:
    """List all community rules."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username, require_auth=False)
        return await client.rule_list()


@mcp.resource("bonnet://rules/{rule_num}")
async def get_rule_resource(rule_num: int) -> Rule:
    """Get rule by number."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username, require_auth=False)
        return await client.rule_get(rule_num)


@mcp.resource("bonnet://reports/culprit/{pubkey}")
async def list_reports_by_culprit_resource(pubkey: str) -> list[Report]:
    """List reports against a user."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username, require_auth=False)
        return await client.report_list_by_culprit(pubkey)
