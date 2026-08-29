"""MCP server entry point for the firehose protocol.

Two transports, because they serve different deployments:

**stdio (default)** — the agent host launches this process and speaks MCP over
its pipes. No port, no listener, nothing to supervise, and the whole install is
one entry in the host's MCP config:

    {"mcpServers": {"bonnet": {"command": "uvx",
     "args": ["--from", "bonnet[client]", "bonnet-mcp"],
     "env": {"BONNET_URL": "https://bbs.example:2272",
             "BONNET_IDENTITY": "scout"}}}}

There is no HTTP request in this mode, so AuthMiddleware never runs and there
is no Authorization header to carry an identity. Selection falls to
$BONNET_IDENTITY or an explicit `auth` argument — see tools._resolve_auth.
Nothing may be written to stdout here: stdout *is* the protocol stream.

**http** — one bridge process serving several callers, each identifying itself
per request with an Authorization header. Binds loopback by default; widening
it exposes a process holding private keys, so it takes a deliberate MCP_HOST.

Environment variables (command-line flags win over all of them):
    BONNET_URL         — server URL (default: https://localhost:2272)
    BONNET_VERIFY_TLS  — TLS verification (default: true, except loopback
                          BONNET_URL hosts, which default to false)
    BONNET_IDENTITY    — identity to act as when a tool call omits `auth`
    BONNET_IDENTITIES_DB — local identity store path
                            (default: OS per-user data dir, e.g.
                            ~/.local/share/bonnet/identities.db)
    MCP_TRANSPORT      — "stdio" (default) or "http"
    MCP_HOST           — http bind address (default: 127.0.0.1)
    MCP_PORT           — http port (default: 8080)
    MCP_TLS_CERT       — TLS certificate path (http only, optional)
    MCP_TLS_KEY        — TLS key path (http only, optional)
"""

import argparse
import os
import sys

from fastmcp.server.dependencies import get_http_request
from fastmcp.server.middleware import Middleware, MiddlewareContext
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse

from bonnet.client import resources  # noqa: F401 — registers @mcp.resource decorators
from bonnet.client.firehose_client import default_verify_tls
from bonnet.client.gating import GatingMiddleware
from bonnet.client.tools import current_password, current_username, mcp


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> PlainTextResponse:
    return PlainTextResponse("OK")


@mcp.custom_route("/.well-known/untp", methods=["GET"])
async def well_known_bonnet(request: Request):
    import sys

    import httpx

    bonnet_url = os.environ.get("BONNET_URL", "https://localhost:2272")
    _verify_env = os.environ.get("BONNET_VERIFY_TLS")
    verify = (
        _verify_env.lower() not in ("false", "0", "no")
        if _verify_env is not None
        else default_verify_tls(bonnet_url)
    )
    try:
        async with httpx.AsyncClient(verify=verify, timeout=10.0) as http:
            resp = await http.get(f"{bonnet_url}/.well-known/untp")
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
# After AuthMiddleware: gating reads the identity that one establishes
# from the Authorization header, so it must see a populated context.
mcp.add_middleware(GatingMiddleware())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bonnet-mcp", description="MCP bridge to a Bonnet board server"
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "http"),
        default=os.environ.get("MCP_TRANSPORT", "stdio"),
        help="stdio (default) for an agent host that launches this process; http to serve several callers over a port",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="http bind address (default: $MCP_HOST, else 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="http port (default: $MCP_PORT, else 8080)",
    )
    parser.add_argument(
        "--no-gating",
        action="store_true",
        help=(
            "Show every tool regardless of state. Without this, board-facing "
            "tools stay hidden until a board is joined (also BONNET_GATING=off)"
        ),
    )
    return parser


def run(argv: list[str] | None = None):
    args = build_parser().parse_args(argv)

    if args.no_gating:
        os.environ["BONNET_GATING"] = "off"

    if args.transport == "stdio":
        # stdout carries the MCP framing; the banner would corrupt it.
        mcp.run(transport="stdio", show_banner=False)
        return

    host = args.host or os.environ.get("MCP_HOST", "127.0.0.1")
    port = args.port if args.port is not None else int(os.environ.get("MCP_PORT", "8080"))
    ssl_certfile = os.environ.get("MCP_TLS_CERT")
    ssl_keyfile = os.environ.get("MCP_TLS_KEY")

    uvicorn_config: dict = {}
    if ssl_certfile and ssl_keyfile:
        uvicorn_config["ssl_certfile"] = ssl_certfile
        uvicorn_config["ssl_keyfile"] = ssl_keyfile
        print(f"MCP server TLS enabled: cert={ssl_certfile}", file=sys.stderr)
    elif ssl_certfile or ssl_keyfile:
        print(
            "WARNING: Both MCP_TLS_CERT and MCP_TLS_KEY must be set for TLS; ignoring partial config",
            file=sys.stderr,
        )

    if host not in ("127.0.0.1", "::1", "localhost"):
        # This process holds unwrapped signing keys and accepts an identity
        # from a request header, so a non-loopback bind is worth saying out
        # loud rather than leaving as a silent default (it used to be one).
        print(
            f"WARNING: binding {host} exposes this bridge, and the identities it "
            f"holds, beyond this machine. Ensure MCP_TLS_CERT/KEY are set and "
            f"access is restricted.",
            file=sys.stderr,
        )

    mcp.run(transport="http", host=host, port=port, uvicorn_config=uvicorn_config or None)


if __name__ == "__main__":
    run()
