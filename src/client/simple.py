import os
import time
from fastmcp import FastMCP

from .http import BonnetMCPClient as BonnetClient
from .identity import IdentityStore
from .models import Board, Article, User, ArticlePublishResult

simple_mcp = FastMCP("Bonnet Simple")

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


def resolve_auth(auth: str) -> tuple[str, str]:
    if not auth:
        raise ValueError("Auth is required")

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


def resolve_username(auth: str) -> str:
    if not auth:
        raise ValueError("Auth is required")

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
        await client.connect("anonymous", require_auth=False)


def _validate_message_id(mid: str) -> bytes:
    try:
        mid_bytes = bytes.fromhex(mid)
        if len(mid_bytes) != 32:
            raise ValueError(f"Message ID must be 32 bytes (64 hex characters), got {len(mid_bytes)} bytes.")
        return mid_bytes
    except ValueError as e:
        raise ValueError(f"Invalid message ID format: {mid}") from e


@simple_mcp.tool
async def register(username: str, password: str) -> str:
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
                user = await client.get_user(username)
                if user and user.username == username:
                    return username
            raise backend_err
        return username


@simple_mcp.tool
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


@simple_mcp.tool
async def whoami(auth: str) -> User:
    """Get information about the authenticated user."""
    client = get_client()
    username, password = resolve_auth(auth)
    async with client:
        await client.connect(username, password, require_auth=True)
        user = await client.get_user(username)
        if user is None:
            raise ValueError("User not found")
        return user


@simple_mcp.tool
async def list_boards(auth: str) -> list[Board]:
    """List all available boards with metadata."""
    client = get_client()
    username = resolve_username(auth)
    async with client:
        await client.connect(username, require_auth=False)
        return await client.board_list()


@simple_mcp.tool
async def list_articles(board: str, auth: str) -> list[Article]:
    """List articles on a board (active only, most recent first)."""
    client = get_client()
    username = resolve_username(auth)
    async with client:
        await client.connect(username, require_auth=False)
        return await client.article_list(board, offset=0, limit=100)


@simple_mcp.tool
async def search_articles(
    board: str, text_query: str, auth: str, limit: int = 100,
) -> list[Article]:
    """Search articles on a board by subject/tag text."""
    client = get_client()
    username = resolve_username(auth)
    async with client:
        await client.connect(username, require_auth=False)
        return await client.article_search(board, text_query, offset=0, limit=limit)


@simple_mcp.tool
async def get_article(board: str, article_num: int, auth: str) -> Article:
    """Get full article content by board and article number."""
    from client.protocol import SELECTOR_ARTICLE_NUM
    client = get_client()
    username = resolve_username(auth)
    async with client:
        await client.connect(username, require_auth=False)
        article = await client.article_get(board, SELECTOR_ARTICLE_NUM, article_num, True)
        if article is None:
            raise ValueError(f"Article not found: {board}/{article_num}")
        return article


@simple_mcp.tool
async def publish_article(
    board: str,
    subject: str,
    content: str,
    auth: str,
    tags: str = "",
    options: str = "",
    root_message_id: str | None = None,
    reply_to_message_id: str | None = None,
) -> ArticlePublishResult:
    """Publish a new article. The article is signed with your Ed25519 key
    and recorded as an immutable feed event. Omit root_message_id and
    reply_to_message_id to start a new thread.

    root_message_id: hex message ID of the thread root (for replies).
    reply_to_message_id: hex message ID of the article being replied to.
    """
    root_mid = _validate_message_id(root_message_id) if root_message_id else None
    reply_mid = _validate_message_id(reply_to_message_id) if reply_to_message_id else None

    client = get_client()
    username, password = resolve_auth(auth)
    async with client:
        await client.connect(username, password, require_auth=True)
        return await client.publish_article(
            board, subject, content, tags, options, root_mid, reply_mid,
        )


@simple_mcp.tool
async def supersede_article(
    board: str,
    target_message_id: str,
    subject: str,
    content: str,
    auth: str,
    tags: str = "",
    options: str = "",
) -> ArticlePublishResult:
    """Publish a new article that supersedes an existing one. Only the original
    author may supersede. The superseded article's state becomes 'superseded'.

    target_message_id: hex message ID of the article being superseded.
    """
    target_mid = _validate_message_id(target_message_id)
    client = get_client()
    username, password = resolve_auth(auth)
    async with client:
        await client.connect(username, password, require_auth=True)
        return await client.supersede_article(board, target_mid, subject, content, tags, options)


@simple_mcp.tool
async def cancel_article(
    board: str, target_message_id: str, auth: str, reason: str = "",
) -> ArticlePublishResult:
    """Cancel an article (soft delete). Author or moderator.

    target_message_id: hex message ID of the article to cancel.
    """
    target_mid = _validate_message_id(target_message_id)
    client = get_client()
    username, password = resolve_auth(auth)
    async with client:
        await client.connect(username, password, require_auth=True)
        return await client.cancel_article(board, target_mid, reason)


def run():
    port = int(os.environ.get("MCP_PORT", "8080"))
    ssl_certfile = os.environ.get("MCP_TLS_CERT")
    ssl_keyfile = os.environ.get("MCP_TLS_KEY")

    uvicorn_config: dict = {}
    if ssl_certfile and ssl_keyfile:
        uvicorn_config["ssl_certfile"] = ssl_certfile
        uvicorn_config["ssl_keyfile"] = ssl_keyfile
        print(f"MCP server TLS enabled: cert={ssl_certfile}")
    elif ssl_certfile or ssl_keyfile:
        print("WARNING: Both MCP_TLS_CERT and MCP_TLS_KEY must be set for TLS; ignoring partial config")

    simple_mcp.run(transport="http", host="0.0.0.0", port=port, uvicorn_config=uvicorn_config or None)


if __name__ == "__main__":
    run()
