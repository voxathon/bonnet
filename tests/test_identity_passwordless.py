"""Passwordless identities, multi-identity holding, and auth resolution.

The identity is the keypair; a password only wraps it at rest. These tests pin
that an agent can hold and select identities without ever handling a password,
that wrapped identities keep working unchanged alongside them, and that a store
written by the password-only code path migrates rather than breaking.
"""

import sqlite3

import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("cryptography")
pytest.importorskip("fastmcp")

from bonnet.client import tools
from bonnet.client.identity import IdentityStore

pytestmark = pytest.mark.slow


@pytest.fixture
def store(tmp_path):
    s = IdentityStore(str(tmp_path / "identities.db"))
    yield s
    s.close()


@pytest.fixture
def wired_store(tmp_path, monkeypatch):
    """Point the module-level singleton at a temp store for _resolve_auth."""
    monkeypatch.setenv("BONNET_CLIENT_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("BONNET_IDENTITIES_DB", str(tmp_path / "identities.db"))
    saved = (tools.identity_store, tools.board_store)
    tools.identity_store = None
    tools.board_store = None
    yield tools._get_identity_store()
    for store in (tools.identity_store, tools.board_store):
        if store is not None:
            store.close()
    tools.identity_store, tools.board_store = saved


# --- store-level ---------------------------------------------------------


def test_passwordless_register_round_trips_without_a_password(store):
    priv, pub = store.register("scout")

    assert store.is_wrapped("scout") is False
    assert store.get_private_key("scout") == priv
    assert store.get_pubkey("scout") == pub


def test_passwordless_key_is_retrievable_despite_a_stray_password(store):
    """A password supplied against an unwrapped identity has nothing to
    unlock, and must not be treated as a mismatch."""
    priv, _ = store.register("scout")

    assert store.get_private_key("scout", "irrelevant") == priv


def test_wrapped_identity_still_requires_its_password(store):
    priv, _ = store.register("alice", "secretpassword")

    assert store.is_wrapped("alice") is True
    assert store.get_private_key("alice", "secretpassword") == priv
    with pytest.raises(ValueError, match="Invalid password"):
        store.get_private_key("alice", "wrongpassword")


def test_wrapped_identity_without_a_password_says_so(store):
    """The failure an agent will actually hit if it omits a password for a
    human's wrapped identity — it must name the identity and the fix, not
    report a generic bad password."""
    store.register("alice", "secretpassword")

    with pytest.raises(ValueError, match="password-protected"):
        store.get_private_key("alice")


def test_wrapped_and_unwrapped_identities_coexist(store):
    apriv, _ = store.register("alice", "secretpassword")
    spriv, _ = store.register("scout")

    assert store.get_private_key("alice", "secretpassword") == apriv
    assert store.get_private_key("scout") == spriv

    listed = {row["username"]: row for row in store.list_users()}
    assert listed["alice"]["wrapped"] is True
    assert listed["scout"]["wrapped"] is False


def test_identities_are_independent_keypairs(store):
    """Multi-identity is the user-level rotation and blast-radius mechanism,
    so two identities must not share key material."""
    priv_a, pub_a = store.register("mod-hat")
    priv_b, pub_b = store.register("everyday")

    assert priv_a != priv_b
    assert pub_a != pub_b


def test_store_predating_the_wrapped_column_migrates_in_place(tmp_path):
    """Rows written before passwordless identities existed came from the
    password path, so they must backfill as wrapped, not as open keys."""
    db_path = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE identities (
            username TEXT PRIMARY KEY,
            scrypt_hash TEXT NOT NULL,
            auth_salt BLOB NOT NULL,
            key_salt BLOB NOT NULL,
            encrypted_private_key BLOB NOT NULL,
            public_key BLOB NOT NULL,
            registered INTEGER DEFAULT 0
        )
    """)
    conn.execute(
        "INSERT INTO identities VALUES ('legacy', 'deadbeef', X'00', X'00', X'00', X'00', 0)"
    )
    conn.commit()
    conn.close()

    store = IdentityStore(db_path)
    try:
        columns = {row[1] for row in store._get_conn().execute("PRAGMA table_info(identities)")}
        assert "wrapped" in columns
        assert store.is_wrapped("legacy") is True
    finally:
        store.close()


# --- auth resolution -----------------------------------------------------


def test_bare_username_resolves_to_a_passwordless_identity(wired_store):
    wired_store.register("scout")

    assert tools._resolve_auth("scout") == ("scout", "")


def test_bare_username_that_is_not_held_is_rejected(wired_store):
    """A typo must fail here, naming the problem, rather than surfacing later
    from inside the signing path."""
    with pytest.raises(ValueError, match="No local identity named 'typo'"):
        tools._resolve_auth("typo")


def test_user_colon_password_still_resolves(wired_store):
    wired_store.register("alice", "secretpassword")

    assert tools._resolve_auth("alice:secretpassword") == ("alice", "secretpassword")


def test_auth_token_takes_precedence_over_a_bare_name(wired_store):
    """Tokens are looked up before names so a token is never mistaken for an
    unknown username and rejected."""
    tools.auth_tokens["tok"] = {
        "username": "alice",
        "password": "secretpassword",
        "expires_at": 2**40,
    }
    try:
        assert tools._resolve_auth("tok") == ("alice", "secretpassword")
    finally:
        del tools.auth_tokens["tok"]


def test_omitted_auth_falls_back_to_bonnet_identity(wired_store, monkeypatch):
    monkeypatch.setenv("BONNET_IDENTITY", "scout")
    wired_store.register("scout")

    assert tools._resolve_auth(None) == ("scout", "")


def test_omitted_auth_with_nothing_selected_explains_the_options(wired_store, monkeypatch):
    monkeypatch.delenv("BONNET_IDENTITY", raising=False)

    with pytest.raises(ValueError, match="No identity selected"):
        tools._resolve_auth(None)


async def test_list_identities_marks_the_active_one(wired_store, monkeypatch):
    monkeypatch.setenv("BONNET_IDENTITY", "everyday")
    wired_store.register("everyday")
    wired_store.register("mod-hat")

    rows = {row["username"]: row for row in await tools.list_identities()}

    assert rows["everyday"]["active"] is True
    assert rows["mod-hat"]["active"] is False
    assert rows["everyday"]["wrapped"] is False
