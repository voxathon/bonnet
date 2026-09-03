# Copyright 2026 The Bonnet Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tenant isolation: one account's state must never reach another's.

These are the tests that would have caught the four process-global leaks the
gateway carried while it was still a single-caller client — module-singleton
stores, a flat auth-token dict, and a PERMISSIONS cache keyed without the
tenant. Each one below fails if its tenant component is removed again.
"""

import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("cryptography")
pytest.importorskip("fastmcp")

from bonnet.gateway import needs as needs_module
from bonnet.gateway import paths, tenancy, tools
from bonnet.net.firehose_models import Permissions


@pytest.fixture
def gw(tmp_path, monkeypatch):
    """An empty gateway directory, with the environment neutralised."""
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "gw"))
    for var in ("BONNET_IDENTITIES_DB", "BONNET_IDENTITY", "BONNET_URL", "BONNET_VERIFY_TLS"):
        monkeypatch.delenv(var, raising=False)
    tenancy.reset_store_cache()
    needs_module._cache.clear()
    yield tmp_path / "gw"
    tenancy.reset_store_cache()
    needs_module._cache.clear()


def _as_tenant(name: str):
    return tenancy.current_tenant.set(name)


# --- storage isolation -----------------------------------------------------


def test_each_tenant_gets_its_own_directory(gw):
    for name in ("alice", "bob"):
        token = _as_tenant(name)
        try:
            assert paths.tenant_dir() == str(gw / "tenants" / name)
        finally:
            tenancy.current_tenant.reset(token)


def test_the_same_username_is_a_different_keypair_per_tenant(gw):
    """Identities are named per tenant. Two accounts each registering "scout"
    against the same origin hold two unrelated keys, and neither can sign as
    the other."""
    origin = "bbs.test"
    pubkeys = {}
    for name in ("alice", "bob"):
        token = _as_tenant(name)
        try:
            store = tools._get_identity_store()
            store.register(origin, "scout")
            pubkeys[name] = store.get_pubkey(origin, "scout")
        finally:
            tenancy.current_tenant.reset(token)

    assert pubkeys["alice"] is not None
    assert pubkeys["bob"] is not None
    assert pubkeys["alice"] != pubkeys["bob"]


def test_one_tenant_cannot_see_anothers_identities(gw):
    token = _as_tenant("alice")
    try:
        tools._get_identity_store().register("bbs.test", "scout")
    finally:
        tenancy.current_tenant.reset(token)

    token = _as_tenant("bob")
    try:
        assert tools._get_identity_store().list_users("bbs.test") == []
    finally:
        tenancy.current_tenant.reset(token)


def test_pins_are_per_tenant(gw):
    """A pin is a trust decision. One tenant accepting a key must not
    silently commit another to it."""
    seen = set()
    for name in ("alice", "bob"):
        token = _as_tenant(name)
        try:
            seen.add(tenancy.tenant_trust_db_path())
        finally:
            tenancy.current_tenant.reset(token)
    assert len(seen) == 2


def test_joined_origins_are_per_tenant(gw):
    token = _as_tenant("alice")
    try:
        tools._get_origin_store().remember(
            origin="bbs.test", url="https://bbs.test", verify_tls=False, identity="scout"
        )
    finally:
        tenancy.current_tenant.reset(token)

    token = _as_tenant("bob")
    try:
        assert tools._get_origin_store().list_origins() == []
        assert tools._get_origin_store().active() is None
    finally:
        tenancy.current_tenant.reset(token)


# --- the PERMISSIONS cache -------------------------------------------------


async def test_permissions_cache_does_not_cross_tenants(gw):
    """The leak this test exists for: two tenants can each hold an identity
    named "scout" on the same origin, so (url, identity, board) alone is not
    a distinguishing key and one would be served the other's answer about
    what it may do.

    Remove `current_tenant` from the key in needs.py and this fails: bob's
    lookup hits alice's entry instead of missing. The key is built through
    the module's own `_cache_key` rather than by hand, so this tests the
    behaviour and not merely the tuple's shape.
    """
    granted = Permissions(
        principal="registered",
        role="administrator",
        commands=["PUBLISH_RECORD", "ARTICLE_GET"],
        kinds=["bonnet.article"],
    )

    token = _as_tenant("alice")
    try:
        needs_module._cache[needs_module._cache_key("")] = needs_module._CacheEntry(granted)
        assert await needs_module._permissions_for("") is granted
    finally:
        tenancy.current_tenant.reset(token)

    # bob holds no cached answer. There is no reachable origin here, so a
    # genuine miss falls through to a failed fetch and reports None — which
    # is precisely "I could not ask", not "alice's answer".
    token = _as_tenant("bob")
    try:
        assert await needs_module._permissions_for("") is None
    finally:
        tenancy.current_tenant.reset(token)


# --- the anonymous tenant --------------------------------------------------


def test_anonymous_is_recognised(gw):
    token = _as_tenant(tenancy.ANONYMOUS_TENANT)
    try:
        assert tenancy.is_anonymous() is True
    finally:
        tenancy.current_tenant.reset(token)
    assert tenancy.is_anonymous() is False


async def test_anonymous_tenant_never_reaches_a_signing_path(gw, monkeypatch):
    """_connect_authenticated degrades to an anonymous connection rather than
    refusing, so no argument a caller passes can reach a signing path."""
    calls = []

    class FakeClient:
        async def connect_anonymous(self):
            calls.append("anonymous")

        async def connect(self, identity, username=None):
            calls.append("signed")

    token = _as_tenant(tenancy.ANONYMOUS_TENANT)
    try:
        await tools._connect_authenticated(FakeClient(), "alice:hunter2")
    finally:
        tenancy.current_tenant.reset(token)

    assert calls == ["anonymous"]
