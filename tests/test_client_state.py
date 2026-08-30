"""Durable client state: origin-key pins and remembered origins.

The pin tests are the load-bearing ones. TOFU only means something if the pin
outlives the process that made it — otherwise every connection is a first
contact and a substituted origin key is never noticed.
"""

import httpx
import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("cryptography")
pytest.importorskip("fastmcp")

from bonnet.core.crypto import Identity
from bonnet.core.trust import TrustStore
from bonnet.gateway import tools
from bonnet.gateway.firehose_client import FirehoseHTTPClient
from bonnet.gateway.paths import OriginStore, trust_db_path
from bonnet.net.firehose_transport import FirehoseClientError
from tests.test_firehose_http_server import ORIGIN, server_stack  # noqa: F401

pytestmark = pytest.mark.slow


@pytest.fixture
def gateway_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("BONNET_GATEWAY_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("BONNET_IDENTITIES_DB", str(tmp_path / "state" / "identities.db"))
    monkeypatch.delenv("BONNET_IDENTITY", raising=False)
    monkeypatch.delenv("BONNET_URL", raising=False)
    monkeypatch.delenv("BONNET_VERIFY_TLS", raising=False)

    saved = (tools.identity_store, tools.origin_store)
    tools.identity_store = None
    tools.origin_store = None
    tools.current_origin_url.set(None)
    tools.current_origin_verify.set(None)
    tools.current_origin.set(None)
    tools._origin_loaded.set(False)

    yield tmp_path / "state"

    for store in (tools.identity_store, tools.origin_store):
        if store is not None:
            store.close()
    tools.identity_store, tools.origin_store = saved
    tools.current_origin_url.set(None)
    tools.current_origin_verify.set(None)
    tools.current_origin.set(None)
    tools._origin_loaded.set(False)
    tools.current_username.set(None)


# --- pinning --------------------------------------------------------------


def _client(app, base_url: str, trust_path: str) -> FirehoseHTTPClient:
    client = FirehoseHTTPClient(base_url, verify=False, trust_store_path=trust_path)
    client._http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url=base_url,
        timeout=30.0,
        verify=False,
    )
    return client


async def test_the_mcp_client_is_built_with_a_trust_store(gateway_dir):
    """Without this the transport's pinning code never runs: _pin_server_key
    is a no-op when _trust_store is None."""
    client = tools._make_client()
    try:
        assert client._trust_store is not None
    finally:
        await client.close()


async def test_trust_store_lives_under_the_gateway_dir(gateway_dir):
    assert trust_db_path() == str(gateway_dir / "trust.db")


async def test_first_contact_records_a_pin(server_stack, gateway_dir):  # noqa: F811
    path = trust_db_path()
    client = _client(server_stack["server"], "https://bbs.test", path)
    try:
        await client.connect_anonymous()
    finally:
        await client.close()

    store = TrustStore(path)
    try:
        assert store.get_pin(ORIGIN) is not None
    finally:
        store.close()


async def test_pin_survives_a_new_client(server_stack, gateway_dir):  # noqa: F811
    """A restarted bridge must recognise the key it saw before — this is the
    whole difference between TOFU and trusting whatever shows up."""
    path = trust_db_path()
    for _ in range(2):
        client = _client(server_stack["server"], "https://bbs.test", path)
        try:
            await client.connect_anonymous()
        finally:
            await client.close()

    store = TrustStore(path)
    try:
        assert store.get_pin_info(ORIGIN)["trust_mode"] == "tofu"
    finally:
        store.close()


async def test_a_substituted_origin_key_is_rejected(server_stack, gateway_dir):  # noqa: F811
    """The point of the pin: a different key for a known origin fails rather
    than being silently adopted."""
    path = trust_db_path()
    store = TrustStore(path)
    try:
        store.tofu_pin(ORIGIN, Identity.generate().public_key)
    finally:
        store.close()

    client = _client(server_stack["server"], "https://bbs.test", path)
    try:
        with pytest.raises(FirehoseClientError, match="pin mismatch"):
            await client.connect_anonymous()
    finally:
        await client.close()


# --- remembered origins ----------------------------------------------------


def test_origin_store_round_trips(tmp_path):
    store = OriginStore(str(tmp_path / "origins.db"))
    try:
        store.remember("bbs.test", "https://bbs.test", True, "scout")

        assert store.active()["origin"] == "bbs.test"
        assert store.get("bbs.test")["identity"] == "scout"
    finally:
        store.close()


def test_rejoining_keeps_the_original_joined_at(tmp_path):
    store = OriginStore(str(tmp_path / "origins.db"))
    try:
        store.remember("bbs.test", "https://bbs.test", True, "scout")
        first = store.get("bbs.test")["joined_at"]
        store.remember("bbs.test", "https://bbs.test", True, "scout")

        assert store.get("bbs.test")["joined_at"] == first
    finally:
        store.close()


def test_switching_active_origin_requires_a_joined_one(tmp_path):
    store = OriginStore(str(tmp_path / "origins.db"))
    try:
        with pytest.raises(ValueError, match="No joined origin"):
            store.set_active("never.joined")
    finally:
        store.close()


def test_forgotten_active_origin_reads_as_none(tmp_path):
    """A dangling active pointer degrades to 'nothing selected' rather than
    breaking every later call."""
    store = OriginStore(str(tmp_path / "origins.db"))
    try:
        store.remember("bbs.test", "https://bbs.test", True, "scout")
        store.forget("bbs.test")

        assert store.active() is None
    finally:
        store.close()


# --- resolution order -----------------------------------------------------


def test_remembered_origin_supplies_url_and_identity(gateway_dir):
    """The restart case: no environment at all, and the client still knows
    where it is and who it is."""
    tools._get_origin_store().remember("bbs.test", "https://bbs.test", False, "scout")
    tools._origin_loaded.set(False)

    tools._ensure_origin_loaded()

    assert tools._current_url() == "https://bbs.test"
    assert tools._default_identity() == "scout"


def test_bonnet_url_overrides_the_remembered_origin(gateway_dir, monkeypatch):
    """An operator who sets BONNET_URL means it; an origin connected later
    must not silently redirect them."""
    tools._get_origin_store().remember("bbs.test", "https://bbs.test", False, "scout")
    monkeypatch.setenv("BONNET_URL", "https://elsewhere.example")
    tools._origin_loaded.set(False)

    tools._ensure_origin_loaded()

    assert tools._current_url() == "https://elsewhere.example"


def test_bonnet_identity_overrides_the_remembered_one(gateway_dir, monkeypatch):
    tools._get_origin_store().remember("bbs.test", "https://bbs.test", False, "scout")
    monkeypatch.setenv("BONNET_IDENTITY", "other")

    assert tools._default_identity() == "other"
