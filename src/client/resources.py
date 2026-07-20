from fastmcp import FastMCP

from .tools import mcp, get_client, get_username
from .models import Board, Article, User, FeedHeadInfo


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


@mcp.resource("bonnet://boards/{board_name}/articles")
async def list_board_articles_resource(board_name: str) -> list[Article]:
    """List articles on a board (active only)."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username, require_auth=False)
        return await client.article_list(board_name)


@mcp.resource("bonnet://boards/{board_name}/articles/{article_num}")
async def get_article_resource(board_name: str, article_num: int) -> Article:
    """Get full article content by board and article number."""
    from client.protocol import SELECTOR_ARTICLE_NUM
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username, require_auth=False)
        article = await client.article_get(board_name, SELECTOR_ARTICLE_NUM, article_num, True)
        if article is None:
            raise ValueError(f"Article not found: {board_name}/{article_num}")
        return article


@mcp.resource("bonnet://users")
async def list_users_resource() -> list[User]:
    """List all users."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username, require_auth=False)
        return await client.list_users()


@mcp.resource("bonnet://feeds/{board}/head")
async def feed_head_resource(board: str) -> FeedHeadInfo:
    """Get the signed feed head for a board."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username, require_auth=False)
        head = await client.feed_head(board)
        if head is None:
            raise ValueError(f"No feed found for board: {board}")
        return head


@mcp.resource("bonnet://feeds/heads")
async def feed_heads_resource() -> list[FeedHeadInfo]:
    """List feed heads across all local-origin boards."""
    client = get_client()
    username = get_username()
    async with client:
        await client.connect(username, require_auth=False)
        return await client.feed_heads()
