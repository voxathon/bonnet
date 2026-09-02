"""End-to-end coverage for the destructive and moderation MCP tools.

Lane 4 of the review brief: 13 of the 45 @mcp.tool functions were never
named in tests/ — every moderation tool and every destructive one except
cancel_article. Given the threat model (agent-authored content arriving over
federation), that was the wrong half to leave uncovered.

Driven against the real ASGI stack through the same `wired` harness
test_gateway_cursor.py uses, so each test publishes, acts, and then reads the
result back through a separate call rather than trusting a return string.
"""

import time

import httpx
import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("cryptography")
pytest.importorskip("fastmcp")

from bonnet.core.acl import ACLRule, PrincipalMatcher
from bonnet.gateway import cursor, tenancy, tools
from bonnet.gateway.firehose_client import FirehoseHTTPClient
from tests.test_firehose_http_server import ORIGIN, server_stack  # noqa: F401

READ_COMMANDS = [
    "BOARD_LIST",
    "ARTICLE_LIST",
    "ARTICLE_GET",
    "ARTICLE_BODY",
    "EVENT_HEAD",
    "USER_GET",
    "USER_LIST",
    "BAN_STATUS",
    "REPORT_LIST",
    "PERMISSIONS",
]

WRITE_KINDS = [
    "bonnet.board.create",
    "bonnet.article",
    "bonnet.article.cancel",
    "bonnet.article.restore",
    "bonnet.article.purge",
    "bonnet.article.pin",
    "bonnet.article.unpin",
    "bonnet.user.register",
    "bonnet.user.key.rotate",
    "bonnet.report",
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


async def _setup(username: str = "scout", board: str = "general") -> None:
    await tools.connect("https://bbs.test")
    await tools.register(username)
    await tools.create_board(board)
    await tools.open_board(board)


async def _setup_with_warden(board: str = "general") -> str:
    """Two identities: 'scout' (active, gets punished) and 'warden' (punishes).

    A punished user's own writes are gated, so the revoke has to come from
    somebody else — see test_a_permabanned_user_cannot_lift_their_own_ban.
    """
    await tools.connect("https://bbs.test")
    await tools.register("warden")
    await tools.register("scout")
    await tools.create_board(board)
    await tools.open_board(board)
    return await _my_pubkey()


# ---------------------------------------------------------------------------
# purge_article — irreversible body deletion
# ---------------------------------------------------------------------------


async def test_purge_article_deletes_the_body_and_keeps_the_metadata(wired):
    """The stated contract: body gone, event metadata retained."""
    await _setup()
    await tools.publish_article("subject", "the body to destroy")
    before = await tools.get_article(1)
    assert before.body_state == "available"
    assert before.body == b"the body to destroy"

    result = await tools.purge_article(reason="spam")
    assert "urge" in result

    after = await tools.get_article(1)
    assert after.body_state == "purged"
    # Metadata survives the purge — this is a body delete, not an event delete.
    assert after.article_id == before.article_id
    assert after.subject == before.subject
    assert after.author_pubkey == before.author_pubkey


# ---------------------------------------------------------------------------
# restore_article
# ---------------------------------------------------------------------------


async def test_restore_article_reverses_a_cancel(wired):
    await _setup()
    await tools.publish_article("subject", "body")
    await tools.get_article(1)

    await tools.cancel_article(reason="mistake")
    assert (await tools.get_article(1)).visibility == "cancelled"

    await tools.restore_article(reason="on reflection")
    assert (await tools.get_article(1)).visibility == "active"


# ---------------------------------------------------------------------------
# supersede_article
# ---------------------------------------------------------------------------


async def test_supersede_article_links_the_replacement(wired):
    await _setup()
    await tools.publish_article("first", "original body")
    original = await tools.get_article(1)

    await tools.supersede_article(original.article_id, "second", "replacement body")

    superseded = await tools.get_article(1)
    assert superseded.visibility == "superseded"
    assert superseded.replacement_article_id, "superseded article does not name its replacement"

    replacement = await tools.get_article(2)
    assert replacement.subject == "second"
    assert replacement.body == b"replacement body"


# ---------------------------------------------------------------------------
# pin_article / unpin_article
# ---------------------------------------------------------------------------


async def test_pin_then_unpin_round_trips(wired):
    await _setup()
    await tools.publish_article("subject", "body")
    assert (await tools.get_article(1)).pin_state == "unpinned"

    # pin_state carries the priority, not a bare flag.
    await tools.pin_article(priority=5)
    assert (await tools.get_article(1)).pin_state == "pinned(5)"

    await tools.unpin_article()
    assert (await tools.get_article(1)).pin_state == "unpinned"


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


async def test_report_reaches_the_moderation_queue(wired):
    await _setup()
    await tools.publish_article("subject", "body")

    await tools.report("this is spam", article_num=1)

    queue = wired["policy"].list_reports(limit=10, offset=0)
    assert len(queue) == 1
    assert queue[0]["target_board"] == "general"


# ---------------------------------------------------------------------------
# punish_warn / acknowledge_punishment / my_punishments
#
# A warning gates the punished user's writes until they acknowledge it. That
# whole cycle is one test because each step is only meaningful against the
# next: pending -> writes blocked -> acknowledged -> writes proceed.
# ---------------------------------------------------------------------------


async def test_warning_blocks_writes_until_acknowledged(wired):
    scout = await _setup_with_warden()

    await tools.punish_warn(scout, "read the rules", auth="warden")

    pending = await tools.my_punishments()
    assert len(pending.punishments) == 1
    assert pending.punishments[0].type == "warning"
    assert pending.blocked

    with pytest.raises(Exception, match="[Ww]rite blocked"):
        await tools.publish_article("blocked", "should not land")

    # An ack is the one write a gated user may still make.
    await tools.acknowledge_punishment(pending.punishments[0].event_id)

    assert (await tools.my_punishments()).punishments == []
    await tools.publish_article("allowed now", "body")


async def test_ban_is_pending_and_carries_its_expiry(wired):
    scout = await _setup_with_warden()
    expires = int(time.time()) + 3600

    await tools.punish_ban(scout, "cooling off", expires, auth="warden")

    pending = (await tools.my_punishments()).punishments
    assert len(pending) == 1
    assert pending[0].type == "ban"
    assert pending[0].expires_at == expires


async def test_permaban_never_expires(wired):
    """A permaban carries no expiry — only punish_revoke lifts it."""
    scout = await _setup_with_warden()

    await tools.punish_permaban(scout, "irredeemable", auth="warden")

    status = await tools.my_punishments()
    assert len(status.punishments) == 1
    assert status.punishments[0].type == "permaban"
    assert status.punishments[0].expires_at == 0
    assert status.banned

    with pytest.raises(Exception, match="[Ww]rite blocked"):
        await tools.publish_article("blocked", "should not land")


async def test_a_permabanned_user_cannot_lift_their_own_ban(wired):
    """The gate applies to the revoke too, which is the point of it.

    Only bonnet.punishment.ack is exempt, so a banned user's only move is to
    acknowledge — lifting the ban has to come from someone else.
    """
    scout = await _setup_with_warden()
    await tools.punish_permaban(scout, "irredeemable", auth="warden")
    event_id = (await tools.my_punishments()).punishments[0].event_id

    with pytest.raises(Exception, match="[Ww]rite blocked"):
        await tools.punish_revoke(event_id, reason="letting myself off")

    assert (await tools.my_punishments()).banned


async def test_revoke_lifts_a_permaban(wired):
    """The only way back from a permaban, so it has to work."""
    scout = await _setup_with_warden()
    await tools.punish_permaban(scout, "irredeemable", auth="warden")
    event_id = (await tools.my_punishments()).punishments[0].event_id

    await tools.punish_revoke(event_id, reason="appeal upheld", auth="warden")

    assert (await tools.my_punishments()).punishments == []
    await tools.publish_article("back in business", "body")


# ---------------------------------------------------------------------------
# rotate_identity_key
# ---------------------------------------------------------------------------


async def test_rotate_identity_key_swaps_the_key_and_keeps_the_name(wired):
    """Username and history survive; the signing key does not."""
    await _setup()
    before = await _my_pubkey()

    result = await tools.rotate_identity_key()

    after = await _my_pubkey()
    assert after != before, "the signing key did not change"
    assert result["old_pubkey"] == before
    assert result["new_pubkey"] == after
    assert result["username"] == "scout", "the username must survive a rotation"


async def test_rotate_identity_key_leaves_a_working_identity(wired):
    """The point of rotating is to keep publishing afterwards."""
    await _setup()
    await tools.publish_article("before rotation", "body")

    await tools.rotate_identity_key()

    await tools.publish_article("after rotation", "body")
    latest = await tools.get_article(2)
    assert latest.subject == "after rotation"
    assert latest.author_username == "scout"
