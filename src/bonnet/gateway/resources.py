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


@mcp.resource("bonnet://boards/{board}")
async def get_board_resource(board: str) -> BoardInfo:
    """Get board metadata by name, searching all known origins."""
    client = _make_client()
    try:
        await _connect_anonymous(client)
        boards = await client.list_boards("")
        for b in boards:
            if b.name == board:
                return b
        raise ValueError(f"Board not found: {board}")
    finally:
        await client.close()


@mcp.resource("bonnet://boards/{board}/articles")
async def list_board_articles_resource(board: str) -> list[ArticleListItem]:
    """List active articles on a board."""
    client = _make_client()
    try:
        await _connect_anonymous(client)
        origin = client._server_origin or ""
        return (await client.list_articles(origin, board)).results
    finally:
        await client.close()


@mcp.resource("bonnet://boards/{board}/articles/{article_num}")
async def get_article_resource(board: str, article_num: int) -> ArticleView:
    """Get full article body by board and article number."""
    client = _make_client()
    try:
        await _connect_anonymous(client)
        origin = client._server_origin or ""
        article = await client.get_article(origin, board, article_num, include_body=True)
        if article is None:
            raise ValueError(f"Article not found: {board}/{article_num}")
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
