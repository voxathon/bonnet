import os
import time
from fastmcp import FastMCP

from .connection import BonnetClient
from .identity import IdentityStore
from .models import Board, Post, PostSummary, User

simple_mcp = FastMCP("Bonnet Simple")

identity_store: IdentityStore | None = None
bonnet_url: str = "ws://localhost:2272"

auth_tokens: dict[str, dict] = {}
TOKEN_EXPIRY_SECONDS = 24 * 60 * 60


def get_client() -> BonnetClient:
    global identity_store
    if identity_store is None:
        identity_store = IdentityStore()
    return BonnetClient(identity_store, bonnet_url)


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
                user = await client.get_user(client._public_key)
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
        user = await client.get_user(client._public_key)
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
async def list_posts(board: str, auth: str) -> list[PostSummary]:
    """List posts on a board, sorted by bump order (most recently bumped first)."""
    client = get_client()
    username = resolve_username(auth)
    async with client:
        await client.connect(username, require_auth=False)
        return await client.post_list(board, offset=0, limit=100)


@simple_mcp.tool
async def get_post(board: str, post_num: int, auth: str) -> Post:
    """Get full post content by board and post number."""
    client = get_client()
    username = resolve_username(auth)
    async with client:
        await client.connect(username, require_auth=False)
        return await client.post_get(board, post_num)


@simple_mcp.tool
async def create_post(
    board: str,
    subject: str,
    content: str,
    auth: str,
    tags: str = "",
    options: str = "",
    root: int = 0,
) -> Post:
    """Create a new post. root=0 starts a new thread, root>0 replies to that post. Returns the created post."""
    client = get_client()
    username, password = resolve_auth(auth)

    # Step 1: Create the post (new connection)
    async with client:
        await client.connect(username, password, require_auth=True)
        result = await client.post_create(board, subject, content, tags, options, root)

    # Step 2: Fetch the full post data (new connection)
    async with client:
        await client.connect(username, password, require_auth=True)
        post = await client.post_get(board, result.post_num)

    # Step 3: Sign the post (new connection)
    async with client:
        await client.connect(username, password, require_auth=True)
        await client.post_sign(
            board,
            post.post_num,
            post.creation_date,
            post.last_modified,
            post.author,
            post.author_registrar,
            ",".join(post.tags),
            post.subject,
            post.options,
            post.content,
        )

    # Step 4: Return the signed post (new connection)
    async with client:
        await client.connect(username, password, require_auth=True)
        return await client.post_get(board, result.post_num)


@simple_mcp.tool
async def update_post(
    board: str,
    post_num: int,
    auth: str,
    content: str | None = None,
    subject: str | None = None,
    tags: str | None = None,
    options: str | None = None,
) -> Post:
    """Update post fields. Only the post author can update. Returns the updated post."""
    client = get_client()
    username, password = resolve_auth(auth)

    # Step 1: Update the post (new connection)
    async with client:
        await client.connect(username, password, require_auth=True)
        await client.post_update(board, post_num, content, subject, tags, options)

    # Step 2: Return the updated post (new connection)
    async with client:
        await client.connect(username, password, require_auth=True)
        return await client.post_get(board, post_num)


@simple_mcp.tool
async def delete_post(board: str, post_num: int, auth: str) -> None:
    """Delete a post. Only the post author or moderators can delete."""
    client = get_client()
    username, password = resolve_auth(auth)
    async with client:
        await client.connect(username, password, require_auth=True)
        await client.post_delete(board, post_num)


def run():
    simple_mcp.run(transport="http", host="0.0.0.0", port=8080)


if __name__ == "__main__":
    run()
