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

"""End-to-end coverage for the user-administration gateway tools.

grant_role / revoke_user are the gateway equivalents of the console's
grant-role / revoke-user, for operators whose server runs headless
(systemd) with no REPL. Driven against the real ASGI stack through the
same `wired` harness test_gateway_moderation.py uses.
"""

import struct

import httpx
import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("cryptography")
pytest.importorskip("fastmcp")

from bonnet.core.acl import ACLRule, PrincipalMatcher
from bonnet.core.crypto import Identity
from bonnet.core.record import (
    MetadataMap,
    encode_intent,
    metadata_bytes,
    metadata_text,
    metadata_u64,
    sign_intent,
)
from bonnet.gateway import cursor, tenancy, tools
from bonnet.gateway.firehose_client import FirehoseHTTPClient
from bonnet.net.firehose_commands import OP_PUBLISH_RECORD, FirehoseContext
from bonnet.core.record import Intent
from tests.test_firehose_http_server import ORIGIN, server_stack  # noqa: F401

READ_COMMANDS = [
    "BOARD_LIST",
    "ARTICLE_LIST",
    "ARTICLE_GET",
    "ARTICLE_BODY",
    "EVENT_HEAD",
    "EVENT_RANGE",
    "EVENT_GET",
    "USER_GET",
    "USER_LIST",
    "BAN_STATUS",
    "REPORT_LIST",
    "PERMISSIONS",
]

WRITE_KINDS = [
    "bonnet.board.create",
    "bonnet.article",
    "bonnet.report",
    "bonnet.user.register",
    "bonnet.user.revoke",
    "bonnet.user.key.rotate",
    "bonnet.punishment.warn",
    "bonnet.punishment.ban",
    "bonnet.punishment.permaban",
    "bonnet.punishment.revoke",
    "bonnet.punishment.ack",
]


def _reset_tool_context():
    tools.current_origin_url.set(None)
    tools.current_origin_verify.set(None)
    tools.current_origin.set(None)
    tools.current_username.set(None)
    tools._origin_loaded.set(False)
    cursor.clear_board()


@pytest.fixture
def wired(server_stack, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("BONNET_IDENTITIES_DB", str(tmp_path / "identities.db"))
    monkeypatch.delenv("BONNET_IDENTITY", raising=False)
    monkeypatch.delenv("BONNET_URL", raising=False)

    tenancy.reset_store_cache()
    _reset_tool_context()

    acl = server_stack["command_handler"]._acl
    acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(registered=True),
            actions=["read"],
            commands=READ_COMMANDS,
            boards=["*"],
        )
    )
    acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(registered=True),
            actions=["write"],
            commands=["PUBLISH_RECORD"],
            kinds=WRITE_KINDS,
            boards=["*"],
        )
    )

    app = server_stack["server"]

    def make_client(url: str | None = None, verify=None) -> FirehoseHTTPClient:
        target = url if url is not None else tools._current_url()
        client = FirehoseHTTPClient(target, verify=False)
        if target != "https://bbs.test":
            raise httpx.ConnectError(f"no server at {target}")
        client._http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=target,
            timeout=30.0,
            verify=False,
        )
        return client

    monkeypatch.setattr(tools, "_make_client", make_client)

    yield server_stack

    tenancy.reset_store_cache()
    _reset_tool_context()


async def _my_pubkey() -> str:
    """whoami returns 'name — pubkey <hex>'; pull the hex out of it."""
    return (await tools.whoami()).rsplit(" ", 1)[-1]


async def _make_admin(wired, username: str = "boss") -> str:
    """Register an identity, then raise its flags to admin.

    The flags write goes through the command handler under an
    administrator-role context — the in-test equivalent of the console's
    grant-role, which is the only bootstrap path (remote register can
    only ever publish flags=0).
    """
    await tools.connect("https://bbs.test")
    await tools.register(username)
    pubkey_hex = await _my_pubkey()

    store = tools._get_identity_store()
    identity = Identity.from_private_key(store.get_private_key(ORIGIN, username, None))

    import os

    intent = Intent(
        event_id=os.urandom(32),
        kind="bonnet.user.register",
        origin=ORIGIN,
        actor_pubkey=identity.public_key,
        actor_username=username,
        actor_registrar=ORIGIN,
        metadata=MetadataMap(
            [
                metadata_text(1, username),
                metadata_bytes(2, identity.public_key),
                metadata_u64(3, 0x01),
            ]
        ),
    )
    encoded = encode_intent(intent)
    req = struct.pack(">B", OP_PUBLISH_RECORD)
    req += struct.pack(">I", len(encoded)) + encoded
    req += sign_intent(identity, encoded)
    req += struct.pack(">I", 0)
    ctx = FirehoseContext(
        peer_pubkey=identity.public_key,
        is_registered=True,
        role="administrator",
        origin=ORIGIN,
    )
    resp = wired["command_handler"].handle(req, ctx)
    assert resp[0] == 0, resp[:120]
    wired["dispatcher"].dispatch_origin(ORIGIN)
    return pubkey_hex


# ---------------------------------------------------------------------------
# grant_role
# ---------------------------------------------------------------------------


async def test_grant_role_registers_new_key_as_moderator(wired):
    await _make_admin(wired)
    await tools.register("scout")
    scout = await _my_pubkey()

    result = await tools.grant_role(scout, "moderator", auth="boss")

    assert result["action"] == "re-registered"
    assert result["username"] == "scout"
    assert result["pubkey_hex"] == scout
    assert result["role"] == "moderator"
    assert result["origin_seq"] > 0
    assert result["event_id"]

    user = await tools.get_user(scout)
    assert user is not None and user.username == "scout"
    assert user.flags & 0x02


async def test_grant_role_new_key_requires_username(wired):
    await _make_admin(wired)
    fresh = Identity.generate().public_key.hex()

    with pytest.raises(ValueError, match="supply a username"):
        await tools.grant_role(fresh, "moderator", auth="boss")


async def test_grant_role_new_key_with_username_registers(wired):
    await _make_admin(wired)
    fresh = Identity.generate().public_key.hex()

    result = await tools.grant_role(fresh, "none", username="newbie", auth="boss")

    assert result["action"] == "registered"
    assert result["username"] == "newbie"
    user = await tools.get_user(fresh)
    assert user is not None and user.username == "newbie"
    assert user.flags == 0


async def test_grant_role_regrant_reuses_name_and_changes_flags(wired):
    await _make_admin(wired)
    await tools.register("scout")
    scout = await _my_pubkey()
    await tools.grant_role(scout, "moderator", auth="boss")

    result = await tools.grant_role(scout, "admin", auth="boss")

    assert result["action"] == "re-registered"
    assert result["username"] == "scout"
    user = await tools.get_user(scout)
    assert user is not None and user.flags & 0x01
    assert not (user.flags & 0x02)


async def test_grant_role_rejects_unknown_role_and_bad_pubkey(wired):
    await _make_admin(wired)
    await tools.register("scout")
    scout = await _my_pubkey()

    with pytest.raises(ValueError, match="Unknown role"):
        await tools.grant_role(scout, "superadmin", auth="boss")
    with pytest.raises(ValueError, match="Invalid public key"):
        await tools.grant_role("zz", "admin", auth="boss")


# ---------------------------------------------------------------------------
# revoke_user
# ---------------------------------------------------------------------------


async def test_revoke_user_revokes_and_frees_the_name(wired):
    await _make_admin(wired)
    await tools.register("scout")
    scout = await _my_pubkey()

    result = await tools.revoke_user(scout, auth="boss")

    assert result == {
        "username": "scout",
        "pubkey_hex": scout,
        "revoked": True,
        "origin_seq": result["origin_seq"],
        "event_id": result["event_id"],
    }
    assert result["origin_seq"] > 0

    # Read back as the admin: the revoked key itself now authenticates as
    # unknown (revoked rows stop resolving), so it can no longer USER_GET.
    user = await tools.get_user(scout, auth="boss")
    assert user is not None and user.revoked

    # Revocation frees the name: a different key can take it.
    await tools.register("temp")
    temp = await _my_pubkey()
    assert temp != scout
    claimed = await tools.grant_role(temp, "none", username="scout", auth="boss")
    assert claimed["username"] == "scout"


async def test_revoke_user_unknown_and_already_revoked(wired):
    await _make_admin(wired)
    await tools.register("scout")
    scout = await _my_pubkey()
    ghost = Identity.generate().public_key.hex()

    with pytest.raises(ValueError, match="not a registered user"):
        await tools.revoke_user(ghost, auth="boss")

    await tools.revoke_user(scout, auth="boss")
    with pytest.raises(ValueError, match="already revoked"):
        await tools.revoke_user(scout, auth="boss")


async def test_revoke_user_refuses_self_revoke(wired):
    boss = await _make_admin(wired)

    with pytest.raises(ValueError, match="own identity"):
        await tools.revoke_user(boss, auth="boss")

    user = await tools.get_user(boss)
    assert user is not None and not user.revoked
