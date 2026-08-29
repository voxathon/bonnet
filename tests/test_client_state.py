"""Durable client state: origin-key pins and remembered boards.

The pin tests are the load-bearing ones. TOFU only means something if the pin
outlives the process that made it — otherwise every connection is a first
contact and a substituted origin key is never noticed.
"""

import httpx
import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("cryptography")
pytest.importorskip("fastmcp")

from bonnet.client import tools
from bonnet.client.firehose_client import FirehoseHTTPClient
from bonnet.client.state import BoardStore, trust_db_path
from bonnet.core.crypto import Identity
from bonnet.core.trust import TrustStore
from bonnet.net.firehose_transport import FirehoseClientError
from tests.test_firehose_http_server import ORIGIN, server_stack  # noqa: F401

pytestmark = pytest.mark.slow


@pytest.fixture
def client_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("BONNET_CLIENT_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("BONNET_IDENTITIES_DB", str(tmp_path / "state" / "identities.db"))
    monkeypatch.delenv("BONNET_IDENTITY", raising=False)
    monkeypatch.delenv("BONNET_URL", raising=False)
    monkeypatch.delenv("BONNET_VERIFY_TLS", raising=False)

    saved = (tools.identity_store, tools.board_store, tools.bonnet_url, tools.bonnet_verify)
    tools.identity_store = None
    tools.board_store = None
    tools._board_loaded = False

    yield tmp_path / "state"

    for store in (tools.identity_store, tools.board_store):
        if store is not None:
            store.close()
    tools.identity_store, tools.board_store, tools.bonnet_url, tools.bonnet_verify = saved
    tools._board_loaded = False
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


async def test_the_mcp_client_is_built_with_a_trust_store(client_dir):
    """Without this the transport's pinning code never runs: _pin_server_key
    is a no-op when _trust_store is None."""
    client = tools._make_client()
    try:
        assert client._trust_store is not None
    finally:
        await client.close()


async def test_trust_store_lives_under_the_client_dir(client_dir):
    assert trust_db_path() == str(client_dir / "trust.db")


async def test_first_contact_records_a_pin(server_stack, client_dir):  # noqa: F811
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


async def test_pin_survives_a_new_client(server_stack, client_dir):  # noqa: F811
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


async def test_a_substituted_origin_key_is_rejected(server_stack, client_dir):  # noqa: F811
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


# --- remembered boards ----------------------------------------------------


def test_board_store_round_trips(tmp_path):
    store = BoardStore(str(tmp_path / "boards.db"))
    try:
        store.remember("bbs.test", "https://bbs.test", True, "scout")

        assert store.active()["origin"] == "bbs.test"
        assert store.get("bbs.test")["identity"] == "scout"
    finally:
        store.close()


def test_rejoining_keeps_the_original_joined_at(tmp_path):
    store = BoardStore(str(tmp_path / "boards.db"))
    try:
        store.remember("bbs.test", "https://bbs.test", True, "scout")
        first = store.get("bbs.test")["joined_at"]
        store.remember("bbs.test", "https://bbs.test", True, "scout")

        assert store.get("bbs.test")["joined_at"] == first
    finally:
        store.close()


def test_switching_active_board_requires_a_joined_one(tmp_path):
    store = BoardStore(str(tmp_path / "boards.db"))
    try:
        with pytest.raises(ValueError, match="No joined board"):
            store.set_active("never.joined")
    finally:
        store.close()


def test_forgotten_active_board_reads_as_none(tmp_path):
    """A dangling active pointer degrades to 'nothing selected' rather than
    breaking every later call."""
    store = BoardStore(str(tmp_path / "boards.db"))
    try:
        store.remember("bbs.test", "https://bbs.test", True, "scout")
        store.forget("bbs.test")

        assert store.active() is None
    finally:
        store.close()


# --- resolution order -----------------------------------------------------


def test_remembered_board_supplies_url_and_identity(client_dir):
    """The restart case: no environment at all, and the client still knows
    where it is and who it is."""
    tools._get_board_store().remember("bbs.test", "https://bbs.test", False, "scout")
    tools._board_loaded = False

    tools._ensure_board_loaded()

    assert tools.bonnet_url == "https://bbs.test"
    assert tools._default_identity() == "scout"


def test_bonnet_url_overrides_the_remembered_board(client_dir, monkeypatch):
    """An operator who sets BONNET_URL means it; a board joined later must not
    silently redirect them."""
    tools._get_board_store().remember("bbs.test", "https://bbs.test", False, "scout")
    monkeypatch.setenv("BONNET_URL", "https://elsewhere.example")
    tools.bonnet_url = "https://elsewhere.example"
    tools._board_loaded = False

    tools._ensure_board_loaded()

    assert tools.bonnet_url == "https://elsewhere.example"


def test_bonnet_identity_overrides_the_remembered_one(client_dir, monkeypatch):
    tools._get_board_store().remember("bbs.test", "https://bbs.test", False, "scout")
    monkeypatch.setenv("BONNET_IDENTITY", "other")

    assert tools._default_identity() == "other"
