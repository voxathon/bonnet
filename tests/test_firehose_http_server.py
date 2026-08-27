"""ASGI server integration tests: discovery, command dispatch, authentication,
replay, rate limiting, error handling, and lifecycle.

Uses httpx.ASGITransport for in-process testing with the real
FirehoseHTTPClient signing and verifying requests end-to-end.
"""

import os
import time

import httpx
import pytest

from bonnet.client.firehose_client import FirehoseHTTPClient
from bonnet.core.acl import ACLEvaluator, ACLRule, PrincipalMatcher, default_rules_for_admin
from bonnet.core.bodies import BodyStore
from bonnet.core.config import FirehoseConfig
from bonnet.core.crypto import Identity
from bonnet.core.dispatcher import Dispatcher
from bonnet.core.firehose import FirehoseStore
from bonnet.core.global_projections import NavProjection, PolicyProjection, UserProjection
from bonnet.core.kind_validator import KindValidator
from bonnet.core.search import SearchService
from bonnet.net.firehose_commands import (
    FirehoseCommandHandler,
)
from bonnet.net.firehose_http_server import FirehoseHTTPServer
from bonnet.net.firehose_wire import (
    build_board_list,
    build_event_head,
    parse_board_list_response,
)
from bonnet.net.http_auth import (
    compute_content_digest,
)
from bonnet.net.rate_limiter import RateLimiter
from bonnet.net.replay import ReplayLedger

ORIGIN = "bbs.test"
SERVER_IDENTITY = Identity.from_private_key(bytes(range(1, 33)))
ACTOR = Identity.from_private_key(bytes(range(10, 42)))
SERVER_PUB = SERVER_IDENTITY.public_key
ACTOR_PUB = ACTOR.public_key


def _rid(seed: int) -> bytes:
    return bytes([(seed + i) % 256 for i in range(32)])


@pytest.fixture
async def server_stack(tmp_path):
    """Full server stack with ASGI app and in-process client transport."""
    config = FirehoseConfig(
        origin=ORIGIN,
        hostname="bbs.test",
        data_dir=str(tmp_path / "data"),
        boards_dir=str(tmp_path / "boards"),
        events_bodies_dir=str(tmp_path / "event_bodies"),
        port=2272,
        tls_enabled=False,
        rate_limit_requests=100,
        rate_limit_window=1,
    )
    os.makedirs(config.data_dir, exist_ok=True)
    os.makedirs(config.boards_dir, exist_ok=True)
    os.makedirs(config.events_bodies_dir, exist_ok=True)

    firehose = FirehoseStore(config.events_db_path)
    firehose.init_origin_key(ORIGIN, SERVER_PUB)

    nav = NavProjection(config.nav_db_path)
    users = UserProjection(config.users_db_path)
    policy = PolicyProjection(config.policy_db_path)
    body_store = BodyStore(
        boards_dir=config.boards_dir,
        events_dir=config.events_bodies_dir,
    )

    allowed_origins = {ORIGIN}
    dispatcher = Dispatcher(
        firehose=firehose,
        nav=nav,
        users=users,
        policy=policy,
        boards_dir=config.boards_dir,
        body_store=body_store,
        allowed_origins=allowed_origins,
        local_origin=ORIGIN,
    )

    acl = ACLEvaluator(default_rules_for_admin(SERVER_PUB.hex()))
    acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(anonymous=True),
            actions=["read"],
            commands=[
                "EVENT_HEAD",
                "EVENT_RANGE",
                "EVENT_GET",
                "BOARD_LIST",
                "ARTICLE_GET",
                "ARTICLE_LIST",
                "ARTICLE_SEARCH",
                "ARTICLE_BODY",
                "USER_GET",
                "USER_LIST",
                "BAN_STATUS",
                "EVENT_BODY",
            ],
            boards=["*"],
        )
    )
    acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(unknown=True),
            actions=["write"],
            commands=["PUBLISH_RECORD"],
            kinds=["bonnet.user.register"],
        )
    )

    validator = KindValidator()
    search = SearchService(
        boards_dir=config.boards_dir,
        body_store=body_store,
        max_count=config.search_max_count,
        timeout_seconds=config.search_timeout_seconds,
        result_limit=config.search_result_limit,
    )

    command_handler = FirehoseCommandHandler(
        firehose=firehose,
        server_identity=SERVER_IDENTITY,
        config_origin=ORIGIN,
        nav=nav,
        users=users,
        policy=policy,
        body_store=body_store,
        boards_dir=config.boards_dir,
        acl=acl,
        validator=validator,
        search=search,
        hostname="bbs.test",
        dispatcher=dispatcher,
        allowed_origins=allowed_origins,
    )

    anonymous_identity = Identity.generate()

    replay_ledger = ReplayLedger(
        config.replay_db_path,
        clock_skew_seconds=config.clock_skew_seconds,
    )
    rate_limiter = RateLimiter(
        max_requests=config.rate_limit_requests,
        window_seconds=config.rate_limit_window,
    )

    http_server = FirehoseHTTPServer(
        command_handler=command_handler,
        server_identity=SERVER_IDENTITY,
        config=config,
        anonymous_identity=anonymous_identity,
        replay_ledger=replay_ledger,
        rate_limiter=rate_limiter,
        users_projection=users,
    )

    transport = httpx.ASGITransport(app=http_server)
    base_url = "https://bbs.test"

    client = FirehoseHTTPClient(base_url, verify=False)
    client._http = httpx.AsyncClient(
        transport=transport,
        base_url=base_url,
        timeout=30.0,
        verify=False,
    )

    yield {
        "server": http_server,
        "client": client,
        "config": config,
        "firehose": firehose,
        "nav": nav,
        "users": users,
        "policy": policy,
        "body_store": body_store,
        "dispatcher": dispatcher,
        "command_handler": command_handler,
        "replay_ledger": replay_ledger,
        "rate_limiter": rate_limiter,
        "anonymous_identity": anonymous_identity,
    }

    await client.close()
    command_handler.close()
    dispatcher.close()
    firehose.close()
    nav.close()
    users.close()
    policy.close()
    replay_ledger.close()


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


async def test_discovery_returns_signed_response(server_stack):
    """Discovery endpoint returns signed JSON with server key and origin."""
    c = server_stack["client"]
    resp = await c._http.get("/.well-known/bonnet")
    assert resp.status_code == 200

    data = resp.json()
    assert data["protocol"] == "bonnet-firehose-1"
    assert data["origin"] == ORIGIN
    assert data["public_key"] == SERVER_PUB.hex()
    assert "anonymous_key" in data
    assert "anonymous_private_key" in data
    assert data["command_endpoint"] == "/command"
    assert "global-firehose" in data["capabilities"]

    assert "signature-input" in resp.headers
    assert "signature" in resp.headers


async def test_discovery_anonymous_key_matches(server_stack):
    """The anonymous key in discovery matches the server's anonymous identity."""
    c = server_stack["client"]
    anon = server_stack["anonymous_identity"]

    resp = await c._http.get("/.well-known/bonnet")
    data = resp.json()

    assert data["anonymous_key"] == anon.public_key.hex()
    assert data["anonymous_private_key"] == anon.private_key.hex()


# ---------------------------------------------------------------------------
# Authenticated command roundtrip
# ---------------------------------------------------------------------------


async def test_authenticated_command_roundtrip(server_stack):
    """A signed command request gets a signed response."""
    c = server_stack["client"]
    await c.discover()
    await c.connect(SERVER_IDENTITY, username="admin")

    cmd = build_board_list(ORIGIN)
    resp = await c._send_command(cmd)
    boards = parse_board_list_response(resp)
    assert isinstance(boards, list)


# ---------------------------------------------------------------------------
# Missing and malformed authentication
# ---------------------------------------------------------------------------


async def test_missing_signature_rejected(server_stack):
    """A command without signature headers is rejected with 401."""
    c = server_stack["client"]
    cmd = build_event_head(ORIGIN)
    resp = await c._http.post(
        "/command",
        content=cmd,
        headers={
            "Content-Type": "application/vnd.bonnet.command",
            "Content-Digest": compute_content_digest(cmd),
            "Bonnet-Protocol": "bonnet-firehose-1",
            "Bonnet-Nonce": "test-nonce",
        },
    )
    assert resp.status_code == 401


async def test_missing_content_digest_rejected(server_stack):
    """A command without Content-Digest is rejected with 400."""
    c = server_stack["client"]
    cmd = build_event_head(ORIGIN)
    resp = await c._http.post(
        "/command",
        content=cmd,
        headers={
            "Content-Type": "application/vnd.bonnet.command",
            "Bonnet-Protocol": "bonnet-firehose-1",
        },
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Unsupported protocol and content type
# ---------------------------------------------------------------------------


async def test_unsupported_protocol_rejected(server_stack):
    """A command with wrong protocol header is rejected with 426."""
    c = server_stack["client"]
    cmd = build_event_head(ORIGIN)
    resp = await c._http.post(
        "/command",
        content=cmd,
        headers={
            "Content-Type": "application/vnd.bonnet.command",
            "Content-Digest": compute_content_digest(cmd),
            "Bonnet-Protocol": "bonnet-firehose-0",
        },
    )
    assert resp.status_code == 426


async def test_unsupported_content_type_rejected(server_stack):
    """A command with wrong content type is rejected with 415."""
    c = server_stack["client"]
    cmd = build_event_head(ORIGIN)
    resp = await c._http.post(
        "/command",
        content=cmd,
        headers={
            "Content-Type": "application/json",
            "Content-Digest": compute_content_digest(cmd),
            "Bonnet-Protocol": "bonnet-firehose-1",
        },
    )
    assert resp.status_code == 415


# ---------------------------------------------------------------------------
# Anonymous access
# ---------------------------------------------------------------------------


async def test_anonymous_command_roundtrip(server_stack):
    """Anonymous requests can read but the response is still signed."""
    c = server_stack["client"]
    await c.discover()
    await c.connect_anonymous()

    cmd = build_board_list(ORIGIN)
    resp = await c._send_command(cmd)
    boards = parse_board_list_response(resp)
    assert isinstance(boards, list)


# ---------------------------------------------------------------------------
# Replay protection
# ---------------------------------------------------------------------------


async def test_replay_detected(server_stack):
    """A replayed nonce is rejected with 409."""
    c = server_stack["client"]
    await c.discover()
    await c.connect(SERVER_IDENTITY, username="admin")

    import base64

    nonce = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    now = int(time.time())
    expires = now + 60

    cmd = build_event_head(ORIGIN)
    msg = __import__("bonnet.net.http_auth", fromlist=["HTTPMessage"]).HTTPMessage(
        method="POST",
        url="https://bbs.test/command",
        headers={
            "Content-Type": "application/vnd.bonnet.command",
            "Content-Digest": compute_content_digest(cmd),
            "Bonnet-Protocol": "bonnet-firehose-1",
            "Bonnet-Nonce": nonce,
        },
        body=cmd,
    )
    await c._signer.sign_request(msg, nonce=nonce, created=now, expires=expires)

    resp1 = await c._http.post(
        "/command",
        content=cmd,
        headers=dict(msg.headers),
    )
    assert resp1.status_code == 200

    resp2 = await c._http.post(
        "/command",
        content=cmd,
        headers=dict(msg.headers),
    )
    assert resp2.status_code == 409


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


async def test_rate_limit_enforced(server_stack):
    """Exceeding the rate limit returns 429."""
    stack = server_stack
    stack["rate_limiter"]._max_requests = 2
    stack["rate_limiter"]._window_seconds = 60

    c = stack["client"]
    await c.discover()
    await c.connect_anonymous()

    cmd = build_board_list(ORIGIN)
    r1 = await c._send_command(cmd)
    assert r1[0] == 0x00

    r2 = await c._send_command(cmd)
    assert r2[0] == 0x00

    import base64

    cmd3 = build_board_list(ORIGIN)
    nonce3 = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    msg3 = __import__("bonnet.net.http_auth", fromlist=["HTTPMessage"]).HTTPMessage(
        method="POST",
        url="https://bbs.test/command",
        headers={
            "Content-Type": "application/vnd.bonnet.command",
            "Content-Digest": compute_content_digest(cmd3),
            "Bonnet-Protocol": "bonnet-firehose-1",
            "Bonnet-Nonce": nonce3,
        },
        body=cmd3,
    )
    await c._signer.sign_request(
        msg3, nonce=nonce3, created=int(time.time()), expires=int(time.time()) + 60
    )
    resp3 = await c._http.post("/command", content=cmd3, headers=dict(msg3.headers))
    assert resp3.status_code == 429


# ---------------------------------------------------------------------------
# Oversized body rejection
# ---------------------------------------------------------------------------


async def test_oversized_body_rejected(server_stack):
    """An oversized body is rejected with 413."""
    c = server_stack["client"]
    big_body = b"\x00" * (11 * 1024 * 1024)

    resp = await c._http.post(
        "/command",
        content=big_body,
        headers={
            "Content-Type": "application/vnd.bonnet.command",
            "Content-Digest": compute_content_digest(big_body),
            "Bonnet-Protocol": "bonnet-firehose-1",
        },
    )
    assert resp.status_code == 413


# ---------------------------------------------------------------------------
# Sanitized error responses
# ---------------------------------------------------------------------------


async def test_internal_error_sanitized(server_stack):
    """Dispatch exceptions should not leak internal details to the client."""
    stack = server_stack
    c = stack["client"]
    await c.discover()
    await c.connect(SERVER_IDENTITY, username="admin")

    original_handle = stack["command_handler"].handle

    def exploding_handle(data, ctx):
        raise RuntimeError("internal secret: /path/to/secret.db")

    stack["command_handler"].handle = exploding_handle
    try:
        cmd = build_board_list(ORIGIN)
        resp = await c._send_command(cmd)
    finally:
        stack["command_handler"].handle = original_handle

    assert resp[0] == 0x01
    assert b"secret" not in resp
    assert b"Internal error" in resp


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


async def test_lifespan_startup_and_shutdown(server_stack):
    """ASGI lifespan startup and shutdown complete without error."""
    server = server_stack["server"]

    startup_received = []
    shutdown_received = []

    async def receive_startup():
        return {"type": "lifespan.startup"}

    async def receive_shutdown():
        return {"type": "lifespan.shutdown"}

    async def send_lifespan(msg):
        if msg["type"] == "lifespan.startup.complete":
            startup_received.append(True)
        elif msg["type"] == "lifespan.shutdown.complete":
            shutdown_received.append(True)

    receive_queue = [receive_startup, receive_shutdown]

    async def receive():
        if receive_queue:
            fn = receive_queue.pop(0)
            return await fn()
        return {"type": "lifespan.shutdown"}

    await server(
        {"type": "lifespan"},
        receive,
        send_lifespan,
    )

    assert startup_received
    assert shutdown_received


# ---------------------------------------------------------------------------
# 404 handling
# ---------------------------------------------------------------------------


async def test_unknown_path_returns_404(server_stack):
    """Unknown paths return 404."""
    c = server_stack["client"]
    resp = await c._http.get("/unknown")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Empty body rejection
# ---------------------------------------------------------------------------


async def test_empty_body_rejected(server_stack):
    """An empty command body is rejected with 400."""
    c = server_stack["client"]
    resp = await c._http.post(
        "/command",
        content=b"",
        headers={
            "Content-Type": "application/vnd.bonnet.command",
            "Content-Digest": compute_content_digest(b""),
            "Bonnet-Protocol": "bonnet-firehose-1",
        },
    )
    assert resp.status_code == 400
