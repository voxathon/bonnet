"""Gateway entry point: transports, tenant auth, and the admin CLI.

Two deployments, and the difference between them is tenancy:

**stdio (default)** — the agent host launches this process and speaks MCP over
its pipes. No port, no listener, nothing to supervise, and the whole install is
one entry in the host's MCP config:

    {"mcpServers": {"bonnet": {"command": "uvx",
     "args": ["bonnet", "gateway"],
     "env": {"BONNET_URL": "https://bbs.example:2272",
             "BONNET_IDENTITY": "scout"}}}}

One caller, one tenant (`default`), full capability. There is no HTTP request
here, so AuthMiddleware resolves nothing and there is nothing to authenticate:
a process the host started over its own pipes has already established who it
belongs to. Identity selection falls to $BONNET_IDENTITY or an explicit `auth`
argument — see tools._resolve_auth. Nothing may be written to stdout in this
mode: stdout *is* the protocol stream.

**http / sse** — one process serving several tenants, each presenting an API
key per request as either `Authorization: Bearer <key>` or `X-API-Key: <key>`.
A key that names no usable tenant degrades to the read-only anonymous tenant
rather than returning a non-200 (see AuthMiddleware). Binds loopback by
default; widening it exposes a process holding every tenant's private keys, so
it takes a deliberate MCP_HOST. `sse` is the legacy MCP transport, kept for
clients that cannot speak Streamable HTTP; prefer `--http`.

Tenants are administered from this same entry point — `bonnet gateway tenant
add`, `key revoke`, and so on — wrapping `gateway.tenants`, which is also the
programmatic path for an external script. Deliberately not MCP tools: see that
module for why.

http mode only, `gateway.toml` (see `gateway_config`) can also set transport,
host, port, TLS cert/key and gating — a lower-precedence layer under
everything below, so a fresh install with no file behaves identically to
before this file existed.

Environment variables (command-line flags win over all of them):
    BONNET_GATEWAY_HOME — all durable state (default: OS per-user data dir);
                          --dir sets this for future runs too, see core.home
    BONNET_URL         — server URL (default: https://localhost:2272)
    BONNET_VERIFY_TLS  — TLS verification (default: true, except loopback
                          BONNET_URL hosts, which default to false)
    BONNET_IDENTITY    — identity to act as when a tool call omits `auth`
    BONNET_IDENTITIES_DB — identity store path, default tenant only
    MCP_TRANSPORT      — "stdio" (default), "http" or "sse"
    MCP_HOST           — http bind address (default: 127.0.0.1)
    MCP_PORT           — http port (default: 8080)
    MCP_TLS_CERT       — TLS certificate path (http only, optional)
    MCP_TLS_KEY        — TLS key path (http only, optional)
"""

import argparse
import json
import os
import sys
from typing import Literal, cast

from fastmcp.server.dependencies import get_http_request
from fastmcp.server.middleware import Middleware, MiddlewareContext
from starlette.middleware import Middleware as ASGIMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response

from bonnet.core import home
from bonnet.gateway import (
    gateway_config,
    paths,
    resources,  # noqa: F401 — registers @mcp.resource decorators
    tenancy,
    tenants,
)
from bonnet.gateway.firehose_client import default_verify_tls
from bonnet.gateway.gating import GatingMiddleware
from bonnet.gateway.registry import TenantError
from bonnet.gateway.session import SessionStateMiddleware
from bonnet.gateway.tools import current_password, current_username, mcp


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


def presented_key(headers) -> str:
    """The API key a request presents, from either header form.

    Two spellings of the same thing because agent harnesses differ in which
    they can set: some expose an arbitrary header, others only an
    Authorization bearer token.
    """
    auth = headers.get("Authorization", "")
    # The scheme token is case-insensitive per RFC 7235 - "bearer" is a
    # reasonable, easy mistake for integrators used to lowercase HTTP header
    # conventions, and it used to silently degrade to anonymous instead of
    # being recognized.
    scheme, _, rest = auth.partition(" ")
    if scheme.lower() == "bearer":
        token = rest.strip()
        if token:
            return token
    return (headers.get("X-API-Key", "") or "").strip()


def presented_key_candidates(headers) -> list[str]:
    """Every API key candidate this request presents, Bearer first.

    A harness that defensively sets both headers must not have a garbage or
    stale Bearer token silently discard a working X-API-Key - `presented_key`
    picks one deterministically for simple call sites, but auth resolution
    (`AuthMiddleware`) needs to try each candidate against the tenant store
    in turn, since only the store knows which one (if either) actually names
    a usable tenant.
    """
    candidates = []
    auth = headers.get("Authorization", "")
    scheme, _, rest = auth.partition(" ")
    if scheme.lower() == "bearer":
        token = rest.strip()
        if token:
            candidates.append(token)
    api_key = (headers.get("X-API-Key", "") or "").strip()
    if api_key:
        candidates.append(api_key)
    return candidates


class AuthMiddleware(Middleware):
    """Resolve which tenant a request belongs to, before gating reads it.

    A key that names no usable tenant — absent, unknown, revoked, or its
    tenant disabled — lands on the anonymous tenant rather than a 401. A
    non-200 on the MCP transport strands a lot of harnesses in ways neither
    the agent nor its operator can diagnose; a session that works but is
    visibly reduced is legible, and `gating` reports the reduction through
    the tool list where the agent will actually read it.

    In stdio there is no HTTP request at all, so nothing here runs and the
    context keeps its default: the full-capability `default` tenant. Auth is
    an http-mode concept — a process the agent host launched over its own
    pipes has nothing to authenticate.
    """

    def _set_auth_context(self, context: MiddlewareContext):
        try:
            request = get_http_request()
        except RuntimeError:
            return  # stdio: no request, no header, default tenant

        candidates = presented_key_candidates(request.headers)
        tenant = None
        for candidate in candidates:
            tenant = tenancy.resolve_key(candidate)
            if tenant is not None:
                break
        if tenant is not None:
            tenancy.current_tenant.set(tenant)
            tenancy.current_auth_status.set(tenancy.AUTH_OK)
        else:
            tenancy.current_tenant.set(tenancy.ANONYMOUS_TENANT)
            tenancy.current_auth_status.set(
                tenancy.AUTH_REJECTED if candidates else tenancy.AUTH_ABSENT
            )
            # An anonymous session signs as nobody, so it must not inherit a
            # username from whatever ran in this context before it.
            current_username.set(None)
            current_password.set("")

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
# Between the two, and the order is load-bearing in both directions: the
# session key is scoped by the tenant AuthMiddleware resolves, and gating
# reads the cursor this restores — `_missing_for` consults board-scoped
# PERMISSIONS, so an unhydrated cursor would answer for the wrong board.
mcp.add_middleware(SessionStateMiddleware())
# After AuthMiddleware: gating reads the tenant that one resolves from the
# request's API key, so it must see a populated context.
mcp.add_middleware(GatingMiddleware())


class CleanTransportErrorMiddleware(BaseHTTPMiddleware):
    """Reword the SDK's raw pydantic dump for a malformed JSON-RPC body.

    A body that fails JSONRPCMessage validation (missing `jsonrpc`, a batch
    array, wrong types, ...) is rejected before it ever reaches our own MCP
    tool/middleware layer above - the mcp SDK's transport code catches it and
    writes a JSON-RPC error envelope itself, but stuffs `error.message` with
    the full multi-error pydantic dump, including a live errors.pydantic.dev
    link and internal model names (JSONRPCRequest, JSONRPCNotification, ...).
    That leaks implementation details a caller can't act on. Only that one
    shape is rewritten; a genuine tool-call error (also JSON, also possibly
    400) is left untouched, and nothing here reads or buffers a streaming
    (text/event-stream) response, so normal SSE traffic passes straight
    through call_next unmodified.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if response.status_code != 400 or not response.headers.get("content-type", "").startswith(
            "application/json"
        ):
            return response

        body = b"".join([chunk async for chunk in response.body_iterator])
        try:
            data = json.loads(body)
        except ValueError:
            data = None

        if isinstance(data, dict):
            error = data.get("error")
            if isinstance(error, dict):
                message = error.get("message")
                if isinstance(message, str) and "errors.pydantic.dev" in message:
                    error["message"] = "Malformed JSON-RPC request"
                    body = json.dumps(data).encode("utf-8")

        return Response(
            content=body, status_code=response.status_code, media_type="application/json"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bonnet gateway",
        description="MCP gateway to Bonnet board servers",
    )
    parser.add_argument(
        "--dir",
        default=None,
        help=(
            "This gateway's home directory (gateway.toml, registry.db, tenant "
            "state). Remembered for future runs — see BONNET_GATEWAY_HOME below."
        ),
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "http", "sse"),
        default=None,
        help=(
            "stdio (default) for an agent host that launches this process; http to "
            "serve several callers over a port; sse is legacy. Falls back to "
            "$MCP_TRANSPORT, then gateway.toml, then stdio."
        ),
    )
    # Sugar for --transport, because `bonnet gateway --http` is what an
    # operator reaches for. Mutually exclusive so `--stdio --http` is an
    # error rather than a silent last-one-wins.
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--stdio",
        dest="mode",
        action="store_const",
        const="stdio",
        help="shorthand for --transport stdio",
    )
    mode.add_argument(
        "--http",
        dest="mode",
        action="store_const",
        const="http",
        help="shorthand for --transport http (Streamable HTTP)",
    )
    mode.add_argument(
        "--sse",
        dest="mode",
        action="store_const",
        const="sse",
        help="shorthand for --transport sse; legacy, prefer --http",
    )
    parser.set_defaults(mode=None)
    parser.add_argument(
        "--host",
        default=None,
        help="http bind address (default: $MCP_HOST, else gateway.toml, else 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="http port (default: $MCP_PORT, else gateway.toml, else 8080)",
    )
    parser.add_argument(
        "--no-gating",
        action="store_true",
        help=(
            "Show every tool regardless of state. Without this, board-facing "
            "tools stay hidden until a board is joined (also BONNET_GATING=off)"
        ),
    )

    # Tenant administration. Deliberately here and not as MCP tools: every
    # tool is hidden until a caller has what it needs, and an account-creation
    # tool would have to be visible to callers who have nothing — an open
    # registration endpoint reachable by anything that speaks MCP.
    subs = parser.add_subparsers(dest="command")

    tenant = subs.add_parser("tenant", help="manage gateway tenants").add_subparsers(
        dest="action", required=True
    )
    add = tenant.add_parser("add", help="create a tenant and print its first API key")
    add.add_argument("tenant_id")
    add.add_argument("--note", default="", help="free-text note stored with the tenant")
    tenant.add_parser("list", help="list tenants")
    for name, helptext in (("enable", "re-enable a tenant"), ("disable", "disable a tenant")):
        sub = tenant.add_parser(name, help=helptext)
        sub.add_argument("tenant_id")
    remove = tenant.add_parser("remove", help="delete a tenant, its keys and its state")
    remove.add_argument("tenant_id")
    remove.add_argument(
        "--yes",
        action="store_true",
        help="required: this destroys the tenant's signing keys, which nothing else holds",
    )

    key = subs.add_parser("key", help="manage a tenant's API keys").add_subparsers(
        dest="action", required=True
    )
    key_add = key.add_parser("add", help="mint an additional key for a tenant")
    key_add.add_argument("tenant_id")
    key_add.add_argument("--label", default="", help="what this key is for")
    key_list = key.add_parser("list", help="list keys")
    key_list.add_argument("tenant_id", nargs="?", default=None)
    key_revoke = key.add_parser("revoke", help="revoke one key by id")
    key_revoke.add_argument("key_id")
    key_revoke.add_argument(
        "--yes", action="store_true", help="required to revoke a tenant's last live key"
    )

    return parser


def _run_admin(args) -> int:
    """Handle a `tenant`/`key` subcommand. Returns a process exit code."""
    try:
        if args.command == "tenant":
            if args.action == "add":
                api_key = tenants.add_tenant(args.tenant_id, args.note)
                print(f"tenant {args.tenant_id} created")
                print(f"api key: {api_key}")
                print("This is shown once and is not recoverable. Store it now.")
            elif args.action == "list":
                rows = tenants.list_tenants()
                if not rows:
                    print("no tenants")
                for row in rows:
                    state = "enabled" if row["enabled"] else "disabled"
                    note = f"  {row['note']}" if row["note"] else ""
                    print(f"{row['tenant_id']}\t{state}{note}")
            elif args.action in ("enable", "disable"):
                tenants.set_enabled(args.tenant_id, args.action == "enable")
                print(f"tenant {args.tenant_id} {args.action}d")
            elif args.action == "remove":
                if tenants.get_tenant(args.tenant_id) is None:
                    raise TenantError(f"no such tenant {args.tenant_id!r}")
                if not args.yes:
                    print(
                        f"refusing to remove {args.tenant_id} without --yes: this deletes "
                        f"its signing keys, and nothing else holds a copy",
                        file=sys.stderr,
                    )
                    return 1
                tenants.remove_tenant(args.tenant_id)
                print(f"tenant {args.tenant_id} removed")
        elif args.command == "key":
            if args.action == "add":
                api_key = tenants.add_key(args.tenant_id, args.label)
                print(f"api key: {api_key}")
                print("This is shown once and is not recoverable. Store it now.")
            elif args.action == "list":
                rows = tenants.list_keys(args.tenant_id)
                if not rows:
                    print("no keys")
                for row in rows:
                    state = "revoked" if row["revoked_at"] else "live"
                    label = f"  {row['label']}" if row["label"] else ""
                    print(f"{row['key_id']}\t{row['tenant_id']}\t{state}{label}")
            elif args.action == "revoke":
                all_keys = tenants.list_keys()
                target = next((k for k in all_keys if k["key_id"] == args.key_id), None)
                if target is None:
                    raise TenantError(f"no live key with id {args.key_id!r}")
                other_live = [
                    k
                    for k in all_keys
                    if k["tenant_id"] == target["tenant_id"]
                    and k["key_id"] != args.key_id
                    and k["revoked_at"] is None
                ]
                if not other_live and not args.yes:
                    print(
                        f"refusing to revoke {args.key_id} without --yes: it is the last "
                        f"live key for tenant {target['tenant_id']!r} - revoking it locks "
                        "that tenant out of the gateway until an operator runs `key add`",
                        file=sys.stderr,
                    )
                    return 1
                tenants.revoke_key(args.key_id)
                print(f"key {args.key_id} revoked")
    except TenantError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


def run(argv: list[str] | None = None):
    args = build_parser().parse_args(argv)
    if args.dir:
        args.dir = os.path.expanduser(args.dir)

    # Only remember --dir for future runs that omit it entirely - a process
    # with BONNET_GATEWAY_HOME set always resolves via that override anyway,
    # and writing here would leak this run's --dir into other processes that
    # rely on their own BONNET_GATEWAY_HOME for isolation (the pointer file
    # isn't scoped by that env var).
    if args.dir and not os.environ.get("BONNET_GATEWAY_HOME"):
        home.set_home("gateway", args.dir)

    if getattr(args, "command", None):
        raise SystemExit(_run_admin(args))

    # http mode only — see gateway_config's own docstring for why stdio never
    # touches this. Absent entirely on a fresh install; every field is then
    # None and every line below falls straight through to $MCP_*/built-ins,
    # unchanged from before this file existed.
    gw_config = gateway_config.load(paths.config_path())

    if args.no_gating or (gw_config and gw_config.gating is False):
        os.environ["BONNET_GATING"] = "off"

    transport = (
        args.mode
        or args.transport
        or os.environ.get("MCP_TRANSPORT")
        or (gw_config.transport if gw_config else None)
        or "stdio"
    )
    # args.transport/args.mode are already constrained by argparse (choices=,
    # store_const), but $MCP_TRANSPORT and gateway.toml are arbitrary
    # operator-supplied strings — validate here rather than let a typo reach
    # mcp.run with a confusing error from underneath it.
    if transport not in ("stdio", "http", "sse"):
        print(
            f"error: invalid transport {transport!r} (expected stdio, http, or sse)",
            file=sys.stderr,
        )
        raise SystemExit(1)
    transport = cast(Literal["stdio", "http", "sse"], transport)
    if transport == "stdio":
        # stdout carries the MCP framing; the banner would corrupt it.
        mcp.run(transport="stdio", show_banner=False)
        return

    host = (
        args.host
        or os.environ.get("MCP_HOST")
        or (gw_config.host if gw_config else None)
        or "127.0.0.1"
    )
    port = args.port
    if port is None:
        port_env = os.environ.get("MCP_PORT")
        port = int(port_env) if port_env else (gw_config.port if gw_config else None) or 8080
    ssl_certfile = os.environ.get("MCP_TLS_CERT") or (gw_config.tls_cert if gw_config else None)
    ssl_keyfile = os.environ.get("MCP_TLS_KEY") or (gw_config.tls_key if gw_config else None)

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
        # This process holds unwrapped signing keys for every tenant it
        # serves, so a non-loopback bind is worth saying out loud rather than
        # leaving as a silent default (it used to be one).
        print(
            f"WARNING: binding {host} exposes this gateway, and the identities it "
            f"holds for every tenant, beyond this machine. Ensure MCP_TLS_CERT/KEY "
            f"are set and access is restricted.",
            file=sys.stderr,
        )

    if not tenants.list_tenants():
        # Not fatal: a gateway with no tenants still serves anonymous reads,
        # which is a legitimate way to run one. But it is almost always a
        # forgotten setup step, and the failure it produces otherwise — every
        # session silently anonymous — is unpleasant to diagnose from the
        # agent's side.
        print(
            "WARNING: no tenants are registered, so every request will fall back to "
            "the anonymous tenant (read-only). Run: bonnet gateway tenant add <id>",
            file=sys.stderr,
        )

    mcp.run(
        transport=transport,
        host=host,
        port=port,
        uvicorn_config=uvicorn_config or None,
        middleware=[ASGIMiddleware(CleanTransportErrorMiddleware)],
    )


if __name__ == "__main__":
    run()
