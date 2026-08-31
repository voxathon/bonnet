"""The pin confirm/decline gate.

Pinning used to be the one step in the whole flow that happened *to* the
agent: first contact adopted a key silently, and a changed key died as a bare
error. These cover it becoming a decision the caller makes.

The transport's own auto mode is unchanged and still covered by
`test_firehose_http_server.py` — nothing here duplicates that. What is tested
here is the gateway's policy: when it asks, when it deliberately does not, and
what happens to the answer.
"""

import httpx
import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("cryptography")
pytest.importorskip("fastmcp")

from fastmcp import Client

from bonnet.core.acl import ACLRule, PrincipalMatcher
from bonnet.core.crypto import Identity
from bonnet.core.trust import TrustStore
from bonnet.gateway import tenancy, tools
from bonnet.gateway.firehose_client import FirehoseHTTPClient
from bonnet.gateway.gating import GatingMiddleware
from bonnet.net.firehose_transport import PIN_MODE_AUTO, PIN_MODE_CONFIRM
from tests.test_firehose_http_server import (  # noqa: F401
    ORIGIN,
    SERVER_IDENTITY,
    SERVER_PUB,
    _publish_rotation,
    _second_server,
    server_stack,
)

REMOTE = "https://bbs.test"


def _route_at(app, monkeypatch, base_url: str = REMOTE):
    """Point tools._make_client at `app`, keeping the real pin policy."""

    def make_client(url: str | None = None, verify=None) -> FirehoseHTTPClient:
        target = url if url is not None else tools._current_url()
        if target != base_url:
            raise httpx.ConnectError(f"no server at {target}")
        client = FirehoseHTTPClient(
            target,
            verify=False,
            trust_store_path=tenancy.tenant_trust_db_path(),
            pin_mode=tools._pin_mode_for(target),
        )
        client._http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=target,
            timeout=30.0,
            verify=False,
        )
        return client

    monkeypatch.setattr(tools, "_make_client", make_client)


@pytest.fixture
def wired(server_stack, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "gw"))
    for var in ("BONNET_IDENTITIES_DB", "BONNET_IDENTITY", "BONNET_URL", "BONNET_GATING"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.delenv("BONNET_PIN_PROMPT", raising=False)
    tenancy.reset_store_cache()
    tenancy.current_tenant.set(tenancy.DEFAULT_TENANT)
    tools.current_origin_url.set(None)
    tools.current_origin_verify.set(None)
    tools.current_origin.set(None)
    tools.current_username.set(None)
    tools._origin_loaded.set(False)

    server_stack["command_handler"]._acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(registered=True),
            actions=["read"],
            commands=["BOARD_LIST", "ARTICLE_LIST", "ARTICLE_GET", "EVENT_HEAD", "USER_GET"],
            boards=["*"],
        )
    )
    _route_at(server_stack["server"], monkeypatch)

    yield server_stack

    tenancy.reset_store_cache()
    tools.current_origin_url.set(None)
    tools.current_origin.set(None)
    tools._origin_loaded.set(False)
    tools.current_username.set(None)


def _pins() -> TrustStore:
    return TrustStore(tenancy.tenant_trust_db_path())


# --- first contact ---------------------------------------------------------


async def test_first_contact_asks_instead_of_adopting(wired):
    result = await tools.connect(REMOTE)

    assert result["pin_required"] is True
    assert result["kind"] == "new"
    assert result["fingerprint"] == SERVER_PUB.hex()
    assert "trust_origin_key" in result["next"]


async def test_nothing_is_pinned_while_the_decision_is_open(wired):
    await tools.connect(REMOTE)

    store = _pins()
    try:
        assert store.get_pin(ORIGIN) is None
        assert store.get_pending(ORIGIN)["publickey"] == SERVER_PUB
    finally:
        store.close()


async def test_the_origin_does_not_become_active(wired):
    """Nothing about the key has been accepted, so there is nothing to talk
    to — and gating hides every origin-facing tool off the back of that,
    without needing a rule of its own."""
    await tools.connect(REMOTE)

    assert tools.current_origin_url.get() is None
    assert (await tools.where_am_i())["state"] == "disconnected"


async def test_the_pending_decision_is_findable_later(wired):
    await tools.connect(REMOTE)

    waiting = (await tools.where_am_i())["pending_pin"]

    assert len(waiting) == 1
    assert waiting[0]["origin"] == ORIGIN
    assert waiting[0]["kind"] == "new"
    assert waiting[0]["fingerprint"] == SERVER_PUB.hex()


async def test_origin_tools_stay_hidden_until_a_key_is_accepted(wired):
    if not any(isinstance(m, GatingMiddleware) for m in tools.mcp.middleware):
        tools.mcp.add_middleware(GatingMiddleware())
    await tools.connect(REMOTE)

    async with Client(tools.mcp) as c:
        visible = {t.name for t in await c.list_tools()}

    assert "trust_origin_key" in visible
    assert "list_articles" not in visible
    assert "publish_article" not in visible


# --- answering -------------------------------------------------------------


async def test_accepting_pins_and_completes_the_connection(wired):
    offer = await tools.connect(REMOTE)

    result = await tools.trust_origin_key(offer["fingerprint"], "accept")

    assert result.get("pin_required") is not True
    assert result["origin"] == ORIGIN
    store = _pins()
    try:
        assert store.get_pin(ORIGIN) == SERVER_PUB
        assert store.get_pending(ORIGIN) is None
    finally:
        store.close()


async def test_accepting_leaves_the_caller_connected(wired):
    offer = await tools.connect(REMOTE)
    await tools.trust_origin_key(offer["fingerprint"], "accept")

    assert (await tools.where_am_i())["state"] == "on_origin"


async def test_a_second_connect_after_accepting_does_not_ask_again(wired):
    offer = await tools.connect(REMOTE)
    await tools.trust_origin_key(offer["fingerprint"], "accept")

    again = await tools.connect(REMOTE)

    assert again.get("pin_required") is not True


async def test_declining_forgets_the_key_and_stays_disconnected(wired):
    offer = await tools.connect(REMOTE)

    result = await tools.trust_origin_key(offer["fingerprint"], "decline")

    assert result["decision"] == "declined"
    assert result["state"] == "disconnected"
    store = _pins()
    try:
        assert store.get_pin(ORIGIN) is None
        assert store.get_pending(ORIGIN) is None
    finally:
        store.close()


async def test_declining_is_not_remembered(wired):
    """No permanent refusal: connecting again asks again, rather than leaving
    a 'never ask' state that is worse to get stuck in than a repeat prompt."""
    offer = await tools.connect(REMOTE)
    await tools.trust_origin_key(offer["fingerprint"], "decline")

    again = await tools.connect(REMOTE)

    assert again["pin_required"] is True


async def test_a_mismatched_fingerprint_is_refused(wired):
    await tools.connect(REMOTE)

    with pytest.raises(ValueError, match="does not match"):
        await tools.trust_origin_key("ab" * 32, "accept")

    store = _pins()
    try:
        assert store.get_pin(ORIGIN) is None
    finally:
        store.close()


async def test_answering_with_nothing_pending_is_an_error(wired):
    with pytest.raises(ValueError, match="no origin key is awaiting"):
        await tools.trust_origin_key("ab" * 32, "accept")


async def test_an_unknown_decision_is_refused(wired):
    offer = await tools.connect(REMOTE)

    with pytest.raises(ValueError, match="accept.*decline"):
        await tools.trust_origin_key(offer["fingerprint"], "maybe")


# --- a changed key ---------------------------------------------------------


async def _rotated(wired, monkeypatch, publish_rotation: bool):
    """Pin the current key, then serve the same origin under a new one."""
    offer = await tools.connect(REMOTE)
    await tools.trust_origin_key(offer["fingerprint"], "accept")

    new_identity = Identity.generate()
    if publish_rotation:
        _publish_rotation(wired["firehose"], SERVER_IDENTITY, new_identity, ORIGIN)
    handler, app = _second_server(wired, new_identity)
    # _second_server grants anonymous only the event commands, which is all
    # its own tests need. connect() also lists boards, so accepting a key
    # here would otherwise fail *after* the pin moved.
    handler._acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(anonymous=True),
            actions=["read"],
            commands=["BOARD_LIST"],
            boards=["*"],
        )
    )
    _route_at(app, monkeypatch)
    tools.current_origin_url.set(None)
    tools.current_origin.set(None)
    tools._origin_loaded.set(False)
    return handler, new_identity


async def test_a_changed_key_asks_rather_than_failing(wired, monkeypatch):
    """This used to be an unrecoverable wall — a bare 'pin mismatch' with no
    way forward but hand-editing the trust database."""
    handler, new_identity = await _rotated(wired, monkeypatch, publish_rotation=False)
    try:
        result = await tools.connect(REMOTE)

        assert result["pin_required"] is True
        assert result["kind"] == "changed"
        assert result["fingerprint"] == new_identity.public_key.hex()
        assert result["rotation_evidence"] == "no_chain"
        assert "WARNING" in result["message"]
    finally:
        handler.close()


async def test_a_verified_chain_is_reported_as_evidence_not_acted_on(wired, monkeypatch):
    """The chain verifies, and the caller is still asked. It is the origin's
    own account of its key history, signed by the key being replaced — a
    holder of the old key produces an identical one."""
    handler, new_identity = await _rotated(wired, monkeypatch, publish_rotation=True)
    try:
        result = await tools.connect(REMOTE)

        assert result["pin_required"] is True
        assert result["kind"] == "changed"
        assert result["rotation_evidence"] == "chain_verified"
        assert "testimony" in result["message"]
    finally:
        handler.close()


async def test_accepting_a_changed_key_rolls_the_pin_forward(wired, monkeypatch):
    handler, new_identity = await _rotated(wired, monkeypatch, publish_rotation=True)
    try:
        offer = await tools.connect(REMOTE)
        await tools.trust_origin_key(offer["fingerprint"], "accept")

        store = _pins()
        try:
            assert store.get_pin(ORIGIN) == new_identity.public_key
        finally:
            store.close()
    finally:
        handler.close()


async def test_declining_a_changed_key_keeps_the_old_pin(wired, monkeypatch):
    handler, _ = await _rotated(wired, monkeypatch, publish_rotation=True)
    try:
        offer = await tools.connect(REMOTE)
        await tools.trust_origin_key(offer["fingerprint"], "decline")

        store = _pins()
        try:
            assert store.get_pin(ORIGIN) == SERVER_PUB
        finally:
            store.close()
    finally:
        handler.close()


# --- the settings the decision was made under ------------------------------


async def test_accepting_reconnects_under_the_same_tls_setting(wired, monkeypatch):
    """Accepting re-runs connect, and connect's verify_tls default is *on* for
    a non-loopback host. Without carrying the original setting through, a
    caller who deliberately passed verify_tls=False would have verification
    silently turned back on the moment they accepted the key — which fails
    against exactly the self-signed certificate they opted out of checking.
    """
    await tools.connect(REMOTE, verify_tls=False)

    seen = {}
    real_connect = tools.connect

    async def spy(url, verify_tls=None):
        seen["verify_tls"] = verify_tls
        return await real_connect(url, verify_tls)

    monkeypatch.setattr(tools, "connect", spy)
    store = _pins()
    try:
        fingerprint = store.get_pending(ORIGIN)["publickey"].hex()
    finally:
        store.close()

    await tools.trust_origin_key(fingerprint, "accept")

    assert seen["verify_tls"] is False


def test_a_stored_tls_setting_round_trips():
    """Only the boolean forms are reachable from the gateway; anything else
    reads as "verify", which is the fail-safe direction."""
    assert tools._decode_verify("True") is True
    assert tools._decode_verify("False") is False
    assert tools._decode_verify("/etc/ssl/ca.pem") is True
    # A row written before the column existed must not read as "off".
    assert tools._decode_verify("") is True


# --- when it deliberately does not ask -------------------------------------


def test_loopback_is_exempt():
    """No independent anchor exists there and nobody sits between a machine
    and itself, so the prompt would be ceremony."""
    for url in ("https://localhost:2272", "http://127.0.0.1:8080", "https://[::1]:2272"):
        assert tools._pin_mode_for(url) == PIN_MODE_AUTO


def test_a_remote_origin_is_not_exempt():
    assert tools._pin_mode_for("https://bbs.example:2272") == PIN_MODE_CONFIRM


def test_the_anonymous_tenant_is_exempt():
    """Nobody is behind it to answer, and it is read-only regardless."""
    token = tenancy.current_tenant.set(tenancy.ANONYMOUS_TENANT)
    try:
        assert tools._pin_mode_for(REMOTE) == PIN_MODE_AUTO
    finally:
        tenancy.current_tenant.reset(token)


def test_the_prompt_can_be_turned_off(monkeypatch):
    monkeypatch.setenv("BONNET_PIN_PROMPT", "off")
    assert tools._pin_mode_for(REMOTE) == PIN_MODE_AUTO


async def test_turning_it_off_restores_silent_adoption(wired, monkeypatch):
    monkeypatch.setenv("BONNET_PIN_PROMPT", "off")

    result = await tools.connect(REMOTE)

    assert result.get("pin_required") is not True
    store = _pins()
    try:
        assert store.get_pin(ORIGIN) == SERVER_PUB
    finally:
        store.close()
