"""Passwordless identities, multi-identity holding, and auth resolution.

The identity is the keypair; a password only wraps it at rest. These tests pin
that an agent can hold and select identities without ever handling a password,
and that wrapped identities keep working unchanged alongside them.
"""

import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("cryptography")
pytest.importorskip("fastmcp")

from bonnet.gateway import tenancy, tools
from bonnet.gateway.identity import IdentityStore

ORIGIN = "bbs.test"


@pytest.fixture
def store(tmp_path):
    s = IdentityStore(str(tmp_path / "identities.db"))
    yield s
    s.close()


@pytest.fixture
def wired_store(tmp_path, monkeypatch):
    """Point the module-level singleton at a temp store for _resolve_auth."""
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("BONNET_IDENTITIES_DB", str(tmp_path / "identities.db"))
    monkeypatch.delenv("BONNET_URL", raising=False)
    tenancy.reset_store_cache()
    yield tools._get_identity_store()
    tenancy.reset_store_cache()


# --- store-level ---------------------------------------------------------


def test_passwordless_register_round_trips_without_a_password(store):
    priv, pub = store.register(ORIGIN, "scout")

    assert store.is_wrapped(ORIGIN, "scout") is False
    assert store.get_private_key(ORIGIN, "scout") == priv
    assert store.get_pubkey(ORIGIN, "scout") == pub


def test_passwordless_key_is_retrievable_despite_a_stray_password(store):
    """A password supplied against an unwrapped identity has nothing to
    unlock, and must not be treated as a mismatch."""
    priv, _ = store.register(ORIGIN, "scout")

    assert store.get_private_key(ORIGIN, "scout", "irrelevant") == priv


def test_wrapped_identity_still_requires_its_password(store):
    priv, _ = store.register(ORIGIN, "alice", "secretpassword")

    assert store.is_wrapped(ORIGIN, "alice") is True
    assert store.get_private_key(ORIGIN, "alice", "secretpassword") == priv
    with pytest.raises(ValueError, match="Invalid password"):
        store.get_private_key(ORIGIN, "alice", "wrongpassword")


def test_wrapped_identity_without_a_password_says_so(store):
    """The failure an agent will actually hit if it omits a password for a
    human's wrapped identity — it must name the identity and the fix, not
    report a generic bad password."""
    store.register(ORIGIN, "alice", "secretpassword")

    with pytest.raises(ValueError, match="password-protected"):
        store.get_private_key(ORIGIN, "alice")


def test_wrapped_and_unwrapped_identities_coexist(store):
    apriv, _ = store.register(ORIGIN, "alice", "secretpassword")
    spriv, _ = store.register(ORIGIN, "scout")

    assert store.get_private_key(ORIGIN, "alice", "secretpassword") == apriv
    assert store.get_private_key(ORIGIN, "scout") == spriv

    listed = {row["username"]: row for row in store.list_users(ORIGIN)}
    assert listed["alice"]["wrapped"] is True
    assert listed["scout"]["wrapped"] is False


def test_identities_are_independent_keypairs(store):
    """Multi-identity is the user-level rotation and blast-radius mechanism,
    so two identities must not share key material."""
    priv_a, pub_a = store.register(ORIGIN, "mod-hat")
    priv_b, pub_b = store.register(ORIGIN, "everyday")

    assert priv_a != priv_b
    assert pub_a != pub_b


# --- auth resolution -----------------------------------------------------
#
# None of these tests connect to an origin, so _default_origin() falls back to
# the default URL (nothing here sets $BONNET_URL) — matching what identities
# are registered under below.


def test_bare_username_resolves_to_a_passwordless_identity(wired_store):
    wired_store.register(tools._default_origin(), "scout")

    assert tools._resolve_auth("scout") == ("scout", "")


def test_bare_username_that_is_not_held_is_rejected(wired_store):
    """A typo must fail here, naming the problem, rather than surfacing later
    from inside the signing path."""
    with pytest.raises(ValueError, match="No local identity named 'typo'"):
        tools._resolve_auth("typo")


def test_user_colon_password_still_resolves(wired_store):
    wired_store.register(tools._default_origin(), "alice", "secretpassword")

    assert tools._resolve_auth("alice:secretpassword") == ("alice", "secretpassword")


def test_auth_token_takes_precedence_over_a_bare_name(wired_store):
    """Tokens are looked up before names so a token is never mistaken for an
    unknown username and rejected."""
    key = (tenancy.current_tenant.get(), "tok")
    tools.auth_tokens[key] = {
        "username": "alice",
        "password": "secretpassword",
        "expires_at": 2**40,
    }
    try:
        assert tools._resolve_auth("tok") == ("alice", "secretpassword")
    finally:
        del tools.auth_tokens[key]


def test_an_auth_token_does_not_resolve_under_another_tenant(wired_store):
    """A token resolves to a (username, password) that is then looked up in
    whichever identity store the request is running against. Keyed on the
    token alone, one tenant's token would resolve inside another's store."""
    key = (tenancy.current_tenant.get(), "tok")
    tools.auth_tokens[key] = {
        "username": "alice",
        "password": "secretpassword",
        "expires_at": 2**40,
    }
    token = tenancy.current_tenant.set("someone-else")
    try:
        with pytest.raises(ValueError, match="No local identity named 'tok'"):
            tools._resolve_auth("tok")
    finally:
        tenancy.current_tenant.reset(token)
        del tools.auth_tokens[key]


def test_omitted_auth_falls_back_to_bonnet_identity(wired_store, monkeypatch):
    monkeypatch.setenv("BONNET_IDENTITY", "scout")
    wired_store.register(tools._default_origin(), "scout")

    assert tools._resolve_auth(None) == ("scout", "")


def test_omitted_auth_with_nothing_selected_explains_the_options(wired_store, monkeypatch):
    monkeypatch.delenv("BONNET_IDENTITY", raising=False)

    with pytest.raises(ValueError, match="No identity selected"):
        tools._resolve_auth(None)


async def test_list_identities_marks_the_active_one(wired_store, monkeypatch):
    monkeypatch.setenv("BONNET_IDENTITY", "everyday")
    origin = tools._default_origin()
    wired_store.register(origin, "everyday")
    wired_store.register(origin, "mod-hat")

    rows = {row.username: row for row in await tools.list_identities(origin=origin)}

    assert rows["everyday"].active is True
    assert rows["mod-hat"].active is False
    assert rows["everyday"].wrapped is False
