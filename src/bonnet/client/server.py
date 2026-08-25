"""MCP server entry point for the Bonnet Firehose Protocol.

Runs the FastMCP server with HTTP transport. Auth middleware extracts
username:password from the Authorization header and sets context vars
for tool resolution.

Environment variables:
    BONNET_URL         — server URL (default: https://localhost:2272)
    BONNET_VERIFY_TLS  — TLS verification (default: true)
    BONNET_IDENTITIES_DB — local identity store path (default: ./identities.db)
    MCP_PORT           — MCP server port (default: 8080)
    MCP_TLS_CERT       — TLS certificate path (optional)
    MCP_TLS_KEY        — TLS key path (optional)
"""

import os

from fastmcp.server.dependencies import get_http_request
from fastmcp.server.middleware import Middleware, MiddlewareContext
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse

from bonnet.client import resources  # noqa: F401 — registers @mcp.resource decorators
from bonnet.client.tools import current_password, current_username, mcp


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> PlainTextResponse:
    return PlainTextResponse("OK")


@mcp.custom_route("/.well-known/bonnet", methods=["GET"])
async def well_known_bonnet(request: Request):
    import sys

    import httpx

    bonnet_url = os.environ.get("BONNET_URL", "https://localhost:2272")
    verify = os.environ.get("BONNET_VERIFY_TLS", "true").lower() not in ("false", "0", "no")
    try:
        async with httpx.AsyncClient(verify=verify, timeout=10.0) as http:
            resp = await http.get(f"{bonnet_url}/.well-known/bonnet")
            return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception as e:
        print(f"error: discovery proxy failed for {bonnet_url}: {e!r}", file=sys.stderr)
        return PlainTextResponse("Failed to reach Bonnet server", status_code=502)


def parse_auth_header(auth: str) -> tuple[str, str]:
    """Parse Authorization header into (username, password)."""
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
        if ":" in token:
            user, pwd = token.split(":", 1)
            user = user.strip()
            return user if user else "anonymous", pwd
        return token.strip() if token.strip() else "anonymous", ""
    return "anonymous", ""


class AuthMiddleware(Middleware):
    def _set_auth_context(self, context: MiddlewareContext):
        try:
            request = get_http_request()
            auth = request.headers.get("Authorization", "")
            username, password = parse_auth_header(auth)
            current_username.set(username)
            current_password.set(password)
        except RuntimeError:
            pass

    async def on_request(self, context: MiddlewareContext, call_next):
        self._set_auth_context(context)
        return await call_next(context)

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        self._set_auth_context(context)
        return await call_next(context)

    async def on_read_resource(self, context: MiddlewareContext, call_next):
        self._set_auth_context(context)
        return await call_next(context)


mcp.add_middleware(AuthMiddleware())


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
        print(
            "WARNING: Both MCP_TLS_CERT and MCP_TLS_KEY must be set for TLS; ignoring partial config"
        )

    mcp.run(transport="http", host="0.0.0.0", port=port, uvicorn_config=uvicorn_config or None)


if __name__ == "__main__":
    run()
