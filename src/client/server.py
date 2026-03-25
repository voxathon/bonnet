from fastmcp import FastMCP
from fastmcp.server.middleware import Middleware, MiddlewareContext
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from .tools import mcp, current_username, identity_store, bonnet_url
from . import resources


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> PlainTextResponse:
    return PlainTextResponse("OK")


class AuthMiddleware(Middleware):
    async def on_request(self, context: MiddlewareContext, call_next):
        request = context.fastmcp_request
        if request:
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                username = auth[7:].strip()
            else:
                username = "anonymous"
            current_username.set(username)
        return await call_next(context)

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        request = context.fastmcp_request
        if request:
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                username = auth[7:].strip()
            else:
                username = "anonymous"
            current_username.set(username)
        return await call_next(context)

    async def on_read_resource(self, context: MiddlewareContext, call_next):
        request = context.fastmcp_request
        if request:
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                username = auth[7:].strip()
            else:
                username = "anonymous"
            current_username.set(username)
        return await call_next(context)


mcp.add_middleware(AuthMiddleware())


def run():
    mcp.run(transport="http", host="0.0.0.0", port=8080)


if __name__ == "__main__":
    run()
