"""MCP resources for the firehose protocol.

Read-only URI-addressed data exposed as FastMCP resources.
All resources connect anonymously.
"""

from bonnet.gateway.tools import _connect_anonymous, _make_client, mcp
from bonnet.net.firehose_models import (
    ArticleListItem,
    ArticleView,
    BoardInfo,
    HeadInfo,
    UserInfo,
)


@mcp.resource("bonnet://boards")
async def list_boards_resource() -> list[BoardInfo]:
    """List all boards across every known origin."""
    client = _make_client()
    try:
        await _connect_anonymous(client)
        return await client.list_boards("")
    finally:
        await client.close()


@mcp.resource("bonnet://boards/{board_name}")
async def get_board_resource(board_name: str) -> BoardInfo:
    """Get board metadata by name, searching all known origins."""
    client = _make_client()
    try:
        await _connect_anonymous(client)
        boards = await client.list_boards("")
        for board in boards:
            if board.name == board_name:
                return board
        raise ValueError(f"Board not found: {board_name}")
    finally:
        await client.close()


@mcp.resource("bonnet://boards/{board_name}/articles")
async def list_board_articles_resource(board_name: str) -> list[ArticleListItem]:
    """List active articles on a board."""
    client = _make_client()
    try:
        await _connect_anonymous(client)
        origin = client._server_origin or ""
        return (await client.list_articles(origin, board_name)).results
    finally:
        await client.close()


@mcp.resource("bonnet://boards/{board_name}/articles/{article_num}")
async def get_article_resource(board_name: str, article_num: int) -> ArticleView:
    """Get full article content by board and article number."""
    client = _make_client()
    try:
        await _connect_anonymous(client)
        origin = client._server_origin or ""
        article = await client.get_article(origin, board_name, article_num, include_body=True)
        if article is None:
            raise ValueError(f"Article not found: {board_name}/{article_num}")
        return article
    finally:
        await client.close()


@mcp.resource("bonnet://users")
async def list_users_resource() -> list[UserInfo]:
    """List all registered users on the server."""
    client = _make_client()
    try:
        await _connect_anonymous(client)
        origin = client._server_origin or ""
        return await client.list_users(origin)
    finally:
        await client.close()


@mcp.resource("bonnet://events/{origin}/head")
async def event_head_resource(origin: str) -> HeadInfo:
    """Get the signed firehose head for an origin."""
    client = _make_client()
    try:
        await _connect_anonymous(client)
        head = await client.get_head(origin)
        if head is None:
            raise ValueError(f"No head found for origin: {origin}")
        return head
    finally:
        await client.close()
