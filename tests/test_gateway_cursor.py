"""The navigation cursor: open_board / leave_board / back, and board=
defaulting on board-scoped tools.

Exercised against the real ASGI server stack, mirroring test_mcp_join.py's
`wired` fixture — no gating middleware here, since this is about the cursor
itself, not visibility.
"""

import httpx
import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("cryptography")
pytest.importorskip("fastmcp")

from bonnet.core.acl import ACLRule, PrincipalMatcher
from bonnet.gateway import cursor, tenancy, tools
from bonnet.gateway.firehose_client import FirehoseHTTPClient
from tests.test_firehose_http_server import ORIGIN, server_stack  # noqa: F401

pytestmark = pytest.mark.slow


@pytest.fixture
def wired(server_stack, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setenv("BONNET_GATEWAY_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("BONNET_IDENTITIES_DB", str(tmp_path / "identities.db"))
    monkeypatch.delenv("BONNET_IDENTITY", raising=False)
    monkeypatch.delenv("BONNET_URL", raising=False)

    tenancy.reset_store_cache()
    tools.current_origin_url.set(None)
    tools.current_origin_verify.set(None)
    tools.current_origin.set(None)
    tools._origin_loaded.set(False)
    cursor.clear_board()

    server_stack["command_handler"]._acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(registered=True),
            actions=["read"],
            commands=["BOARD_LIST", "ARTICLE_LIST", "ARTICLE_GET", "EVENT_HEAD", "USER_GET"],
            boards=["*"],
        )
    )
    server_stack["command_handler"]._acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(registered=True),
            actions=["write"],
            commands=["PUBLISH_RECORD"],
            kinds=["bonnet.board.create", "bonnet.article", "bonnet.article.cancel"],
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
    tools.current_origin_url.set(None)
    tools.current_origin_verify.set(None)
    tools.current_origin.set(None)
    tools._origin_loaded.set(False)
    tools.current_username.set(None)
    cursor.clear_board()


async def _connect_register_and_create_board(name: str = "general") -> None:
    await tools.connect("https://bbs.test")
    await tools.register("scout")
    await tools.create_board(name)


# --- board defaulting -------------------------------------------------


async def test_board_scoped_call_without_board_or_cursor_raises(wired):
    await tools.connect("https://bbs.test")
    await tools.register("scout")

    with pytest.raises(ValueError, match="no board given and none open"):
        await tools.list_articles()


async def test_open_board_makes_it_the_default(wired):
    await _connect_register_and_create_board("general")

    result = await tools.open_board("general")
    assert result["board"] == "general"

    # No board= passed — resolved from the cursor open_board just set.
    posted = await tools.publish_article("hello", "first post")
    assert "published" in posted

    listing = await tools.list_articles(origin=ORIGIN)
    assert listing.results[0].subject == "hello"


async def test_explicit_board_overrides_the_open_one(wired):
    await _connect_register_and_create_board("general")
    await tools.create_board("other")
    await tools.open_board("general")

    # general is open, but an explicit board= still goes to "other" —
    # the cursor is a default, not a lock.
    posted = await tools.publish_article("hi", "body", board="other")
    assert "published" in posted

    listing = await tools.list_articles(board="other", origin=ORIGIN)
    assert len(listing.results) == 1
    general_listing = await tools.list_articles(origin=ORIGIN)  # still defaults to "general"
    assert len(general_listing.results) == 0


async def test_leave_board_requires_board_again(wired):
    await _connect_register_and_create_board("general")
    await tools.open_board("general")
    await tools.leave_board()

    with pytest.raises(ValueError, match="no board given and none open"):
        await tools.list_articles()


async def test_switching_origin_clears_the_board(wired):
    """A board open on the origin just left may not even exist on the next
    one — carrying it over would silently misroute the next call."""
    await _connect_register_and_create_board("general")
    await tools.open_board("general")

    # connect() already remembered this origin; switching back to it (the
    # only origin this fixture serves) must not carry the board cursor along.
    await tools.switch_origin(ORIGIN)

    with pytest.raises(ValueError, match="no board given and none open"):
        await tools.list_articles()


# --- reading an article -------------------------------------------------


async def test_reading_an_article_sets_the_cursor(wired):
    await _connect_register_and_create_board("general")
    await tools.open_board("general")
    await tools.publish_article("hello", "body")

    view = await tools.get_article(1)
    assert view is not None
    assert cursor.current_article_num.get() == 1
    assert cursor.current_article_board.get() == "general"
    assert cursor.current_article_id.get() == view.article_id


async def test_back_pops_article_then_board(wired):
    await _connect_register_and_create_board("general")
    await tools.open_board("general")
    await tools.publish_article("hello", "body")
    await tools.get_article(1)

    first = await tools.back()
    assert first == {"state": "board", "board": "general"}
    assert cursor.current_article_num.get() is None

    second = await tools.back()
    assert second == {"state": "origin"}
    assert cursor.current_board.get() is None

    # Idempotent at the top.
    third = await tools.back()
    assert third == {"state": "origin"}


# --- acting on the open article -----------------------------------------


async def test_target_article_id_defaults_from_the_open_article(wired):
    await _connect_register_and_create_board("general")
    await tools.open_board("general")
    await tools.publish_article("hello", "body")
    view = await tools.get_article(1)

    result = await tools.cancel_article(reason="testing")
    assert "Cancel event published" in result

    cancelled = await tools.get_article(1)
    assert cancelled.visibility == "cancelled"
    assert cancelled.article_id == view.article_id


async def test_target_article_id_required_without_an_open_article(wired):
    await _connect_register_and_create_board("general")
    await tools.open_board("general")

    with pytest.raises(ValueError, match="no target_article_id given and no matching article open"):
        await tools.cancel_article(reason="testing")


async def test_target_article_id_not_reused_across_boards(wired):
    """The cursor's article belongs to the board it was read on — acting on
    a different board must not silently reuse it."""
    await _connect_register_and_create_board("general")
    await tools.create_board("other")
    await tools.open_board("general")
    await tools.publish_article("hello", "body")
    await tools.get_article(1)

    with pytest.raises(ValueError, match="no target_article_id given and no matching article open"):
        await tools.cancel_article(board="other", reason="testing")


# --- where_am_i -----------------------------------------------------------


async def test_where_am_i_tracks_every_transition(wired):
    disconnected = await tools.where_am_i()
    assert disconnected["state"] == "disconnected"

    await tools.connect("https://bbs.test")
    await tools.register("scout")
    on_origin = await tools.where_am_i()
    assert on_origin["state"] == "on_origin"
    assert on_origin["origin"] == ORIGIN
    assert on_origin["identity"] == "scout"

    await tools.create_board("general")
    await tools.open_board("general")
    in_board = await tools.where_am_i()
    assert in_board["state"] == "in_board"
    assert in_board["board"] == "general"

    await tools.publish_article("hello", "body")
    await tools.get_article(1)
    reading = await tools.where_am_i()
    assert reading["state"] == "reading_article"
    assert reading["article_num"] == 1

    await tools.back()
    await tools.back()
    back_to_origin = await tools.where_am_i()
    assert back_to_origin["state"] == "on_origin"

    await tools.disconnect()
    back_to_disconnected = await tools.where_am_i()
    assert back_to_disconnected["state"] == "disconnected"
    assert back_to_disconnected["identity"] is None
