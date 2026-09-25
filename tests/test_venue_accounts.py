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


"""register(venue=...): venue accounts linked to one identity each.

Against the real ASGI server stack (as test_gateway_cursor does), with a
bridge in its manifest and a fake flatboard behind the adapter.
"""

from __future__ import annotations

import json
import sqlite3

import httpx
import pytest

pytest.importorskip("fastmcp")

from bonnet.bridges.adapter import VenueUncertain  # noqa: E402
from bonnet.bridges.adapters.flatboard.fake import FakeFlatboard  # noqa: E402
from bonnet.core.acl import ACLRule, PrincipalMatcher  # noqa: E402
from bonnet.gateway import bridge_tools, cursor, tenancy, tools  # noqa: E402
from bonnet.gateway.firehose_client import FirehoseHTTPClient  # noqa: E402
from bonnet.gateway.identity import IdentityStore  # noqa: E402
from tests.test_firehose_http_server import server_stack  # noqa: E402,F401

VENUE = "flatboard@flatboard.test"
ENTRY = {"type": "flatboard", "venue": VENUE, "status": "bound", "board": "~flatboard",
         "origins": ["bbs.test"], "local": True, "max_body_bytes": 2048}  # fmt: skip


@pytest.fixture
def board():
    return FakeFlatboard()


@pytest.fixture
def wired(server_stack, board, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("BONNET_IDENTITIES_DB", str(tmp_path / "identities.db"))
    monkeypatch.setenv("BONNET_BRIDGE_ACCOUNTS", str(tmp_path / "none.toml"))
    monkeypatch.delenv("BONNET_IDENTITY", raising=False)
    monkeypatch.delenv("BONNET_URL", raising=False)
    tenancy.reset_store_cache()
    for var in (tools.current_origin_url, tools.current_origin_verify, tools.current_origin):
        var.set(None)
    tools._origin_loaded.set(False)
    tools.current_username.set(None)
    cursor.clear_board()
    monkeypatch.setattr(tools, "gateway_transport", "stdio")

    # One test here makes more requests than the fixture's 100/s allows.
    monkeypatch.setattr(server_stack["rate_limiter"], "_max_requests", 10_000)
    handler = server_stack["command_handler"]
    handler._acl.add_rule(
        ACLRule(effect="allow", matcher=PrincipalMatcher(registered=True), actions=["read"],
                commands=["BOARD_LIST", "USER_GET"], boards=["*"])
    )  # fmt: skip
    monkeypatch.setattr(handler, "bridges_manifest", lambda: [dict(ENTRY)])
    app = server_stack["server"]

    def make_client(url: str | None = None, verify=None) -> FirehoseHTTPClient:
        target = url if url is not None else tools._current_url()
        client = FirehoseHTTPClient(target, verify=False)
        client._http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=target, timeout=30.0, verify=False
        )
        return client

    monkeypatch.setattr(tools, "_make_client", make_client)
    monkeypatch.setattr(bridge_tools, "build_adapter", lambda venue: board.adapter(venue))
    yield server_stack
    tenancy.reset_store_cache()
    tools.current_username.set(None)
    cursor.clear_board()


def _no_token(result, token: str) -> None:
    assert token not in json.dumps(result, default=str), "a tool returned a venue token"


# ---------------------------------------------------------------------------
# The whole round trip, on stdio
# ---------------------------------------------------------------------------


async def test_register_creates_links_and_hides_the_account(wired, board):
    await tools.connect("https://bbs.test")
    result = await tools.register("scout", venue=VENUE)
    assert result["registered_seq"] is not None  # the Bonnet identity too, in one call
    assert result["venue"] == {"venue": VENUE, "linked": True, "venue_user": "scout",
                               "how": "registered"}  # fmt: skip
    token = board.accounts["scout"]
    _no_token(result, token)

    spec = bridge_tools.account_spec(VENUE, None)
    assert spec is not None and (spec.account.user, spec.account.token) == ("scout", token)

    (entry,) = (await tools.connect("https://bbs.test"))["bridges"]
    assert entry["linked"] is True and entry["linked_as"] == "scout"
    switched = await tools.switch_origin("bbs.test")
    assert switched["bridges"][0]["linked"] is True

    plain = await tools.export_identity()
    assert "venue_accounts" not in plain
    full = await tools.export_identity(include_venues=True)
    assert full["venue_accounts"] == [{"venue": VENUE, "venue_user": "scout", "venue_token": token}]

    gone = await tools.register("scout", venue=VENUE, unlink=True)
    assert gone["venue"] == {"venue": VENUE, "linked": False, "unlinked": True}
    assert bridge_tools.account_spec(VENUE, None) is None
    assert (await tools.connect("https://bbs.test"))["bridges"][0]["linked"] is False


async def test_a_taken_name_is_reported_and_the_identity_stays(wired, board):
    board.take_name("scout")
    await tools.connect("https://bbs.test")
    result = await tools.register("scout", venue=VENUE)
    assert result["registered_seq"] is not None
    assert result["venue"]["linked"] is False and "taken" in result["venue"]["error"]
    again = await tools.register("scout", venue=VENUE, venue_user="scout2")
    assert again["venue"]["linked"] is True and again["venue"]["venue_user"] == "scout2"


async def test_venue_failures_never_undo_the_registration(wired, board):
    board.rate_limit_claims = 1
    await tools.connect("https://bbs.test")
    result = await tools.register("scout", venue=VENUE)
    assert result["registered_seq"] is not None
    assert result["venue"]["linked"] is False and "rate limited" in result["venue"]["error"]


async def test_only_bridged_venues_link(wired, board):
    await tools.connect("https://bbs.test")
    with pytest.raises(ValueError, match=f"linkable: {VENUE}"):
        await tools.register("scout", venue="flatboard@elsewhere.test")
    assert board.claims == 0


# ---------------------------------------------------------------------------
# http, paste, and wrapped identities
# ---------------------------------------------------------------------------


async def test_http_gateways_explain_instead_of_creating(wired, board, monkeypatch):
    monkeypatch.setattr(tools, "gateway_transport", "http")
    await tools.connect("https://bbs.test")
    result = await tools.register("scout", venue=VENUE)
    assert result["venue"]["linked"] is False and board.claims == 0
    assert "/board/auth/NAME" in result["venue"]["instructions"]

    pasted = await tools.register("scout", venue=VENUE, venue_user="sc", venue_token="t0k")
    assert pasted["venue"] == {"venue": VENUE, "linked": True, "venue_user": "sc",
                               "how": "pasted"}  # fmt: skip
    _no_token(pasted, "t0k")
    spec = bridge_tools.account_spec(VENUE, None)
    assert spec is not None and spec.account == bridge_tools.ForeignAccount("sc", "t0k")


async def test_linked_accounts_win_over_the_tenant_file(wired, tmp_path, monkeypatch):
    token = tmp_path / "t"
    token.write_text("operator-token")
    accounts = tmp_path / "accounts.toml"
    accounts.write_text(
        f'[[account]]\nvenue = "{VENUE}"\ntype = "flatboard"\nurl = "https://flatboard.test"'
        f'\nuser = "shared"\ntoken_file = "{token}"\n'
    )
    monkeypatch.setenv("BONNET_BRIDGE_ACCOUNTS", str(accounts))
    await tools.connect("https://bbs.test")
    await tools.register("scout")
    assert bridge_tools.account_spec(VENUE, None).account.user == "shared"
    await tools.register("scout", venue=VENUE, venue_token="mine")
    assert bridge_tools.account_spec(VENUE, None).account.user == "scout"


async def test_a_wrapped_identity_wraps_its_venue_tokens(wired, board, tmp_path):
    await tools.connect("https://bbs.test")
    result = await tools.register("locked", password="pw", venue=VENUE)
    assert result["venue"]["linked"] is True
    token = board.accounts["locked"]
    raw = sqlite3.connect(tmp_path / "identities.db")
    blobs = [bytes(r[0]) for r in raw.execute("SELECT token FROM venue_accounts")]
    raw.close()
    assert blobs and all(token.encode() not in b for b in blobs)
    store = tools._get_identity_store()
    assert store.venue_account("bbs.test", "locked", VENUE, "pw") == ("locked", token)
    with pytest.raises(ValueError, match="password"):
        store.venue_account("bbs.test", "locked", VENUE, None)


async def test_a_wrong_password_claims_nothing(wired, board):
    await tools.connect("https://bbs.test")
    await tools.register("locked", password="pw")
    with pytest.raises(ValueError):
        await tools.register("locked", password="nope", venue=VENUE)
    assert board.claims == 0


# ---------------------------------------------------------------------------
# The store, and flatboard's claim
# ---------------------------------------------------------------------------


def test_the_store_links_per_identity(tmp_path):
    store = IdentityStore(str(tmp_path / "ids.db"))
    store.register("o", "a")
    store.register("o", "b")
    store.link_venue("o", "a", VENUE, "alice", "ta")
    assert store.venue_account("o", "a", VENUE) == ("alice", "ta")
    assert store.venue_account("o", "b", VENUE) is None
    assert store.linked_venues("o", "a") == {VENUE: "alice"}
    store.link_venue("o", "a", VENUE, "alice2", "tb")  # replaces
    assert store.venue_account("o", "a", VENUE) == ("alice2", "tb")
    assert store.unlink_venue("o", "a", VENUE) and not store.unlink_venue("o", "a", VENUE)
    store.close()


async def test_a_lost_claim_answer_is_uncertain_and_leaks_nothing():
    board = FakeFlatboard()
    board.lose_claim_responses = 1
    adapter = board.adapter(board.venue_config())
    try:
        with pytest.raises(VenueUncertain) as e:
            await adapter.register("ghost")
    finally:
        await adapter.close()
    assert "nobody received" in str(e.value)
    assert board.accounts["ghost"] not in str(e.value)
