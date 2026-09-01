"""query_articles: the reply_to and root filters, added alongside the
threading docstring so an agent can walk a thread one level at a time
(reply_to) or fetch it all in one call (root). See test_gateway_thread.py
for read_thread, which nests root's flat result into a tree.

Exercised against the real ASGI server stack, mirroring test_gateway_cursor's
`wired` fixture.
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


@pytest.fixture
def wired(server_stack, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "state"))
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
            commands=["BOARD_LIST", "ARTICLE_LIST", "ARTICLE_GET", "ARTICLE_QUERY", "EVENT_HEAD"],
            boards=["*"],
        )
    )
    # query_articles/get_article default to the anonymous principal when no
    # auth= is passed, same as every other read tool.
    server_stack["command_handler"]._acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(anonymous=True),
            actions=["read"],
            commands=["BOARD_LIST", "ARTICLE_LIST", "ARTICLE_GET", "ARTICLE_QUERY", "EVENT_HEAD"],
            boards=["*"],
        )
    )
    server_stack["command_handler"]._acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(registered=True),
            actions=["write"],
            commands=["PUBLISH_RECORD"],
            kinds=["bonnet.board.create", "bonnet.article"],
            boards=["*"],
        )
    )

    app = server_stack["server"]

    def make_client(url: str | None = None, verify=None) -> FirehoseHTTPClient:
        target = url if url is not None else tools._current_url()
        if target != "https://bbs.test":
            raise httpx.ConnectError(f"no server at {target}")
        # A trust store, as `tools._make_client` always builds one with: TOFU
        # pinning is a no-op without it, and the pin is what the cached epoch
        # table anchors on. Left at the default AUTO pin mode so first contact
        # adopts silently rather than prompting.
        client = FirehoseHTTPClient(
            target, verify=False, trust_store_path=str(tmp_path / "trust.db")
        )
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


async def test_reply_to_returns_only_direct_children(wired):
    """A root with two direct replies, one of which itself has a reply —
    reply_to=root must return exactly the two direct children, not the
    grandchild, and not the root itself."""
    await _connect_register_and_create_board("general")

    root_msg = await tools.publish_article("root", "the start of it", board="general")
    root_num = int(root_msg.split("#")[1].split()[0])
    root = await tools.get_article(root_num, board="general", origin=ORIGIN)
    root_id = root.article_id

    await tools.publish_article(
        "reply one", "first reply", board="general", reply_to_article_id=root_id
    )
    reply_two_msg = await tools.publish_article(
        "reply two", "second reply", board="general", reply_to_article_id=root_id
    )
    reply_two_num = int(reply_two_msg.split("#")[1].split()[0])
    reply_two = await tools.get_article(reply_two_num, board="general", origin=ORIGIN)

    await tools.publish_article(
        "grandchild", "reply to a reply", board="general", reply_to_article_id=reply_two.article_id
    )

    children = await tools.query_articles(board="general", reply_to=root_id, origin=ORIGIN)

    assert {a.subject for a in children.results} == {"reply one", "reply two"}


async def test_root_only_excludes_every_reply(wired):
    await _connect_register_and_create_board("general")

    root_msg = await tools.publish_article("root", "the start of it", board="general")
    root_num = int(root_msg.split("#")[1].split()[0])
    root = await tools.get_article(root_num, board="general", origin=ORIGIN)

    await tools.publish_article(
        "reply", "a reply", board="general", reply_to_article_id=root.article_id
    )

    roots = await tools.query_articles(board="general", root_only=True, origin=ORIGIN)

    assert [a.subject for a in roots.results] == ["root"]


async def test_root_returns_every_reply_at_any_depth(wired):
    """root=<root_id> returns every reply in the thread regardless of depth
    — unlike reply_to, which only returns direct children. It does not
    include the root's own row: a root's root_article_id is the zero
    sentinel, never its own id, so it can never match root=<its own id>."""
    await _connect_register_and_create_board("general")

    root_msg = await tools.publish_article("root", "the start of it", board="general")
    root_num = int(root_msg.split("#")[1].split()[0])
    root = await tools.get_article(root_num, board="general", origin=ORIGIN)
    root_id = root.article_id

    reply_msg = await tools.publish_article(
        "reply", "first reply", board="general", reply_to_article_id=root_id
    )
    reply_num = int(reply_msg.split("#")[1].split()[0])
    reply = await tools.get_article(reply_num, board="general", origin=ORIGIN)

    await tools.publish_article(
        "grandchild", "reply to a reply", board="general", reply_to_article_id=reply.article_id
    )
    await tools.publish_article("other thread", "unrelated", board="general")

    thread = await tools.query_articles(board="general", root=root_id, origin=ORIGIN)

    assert {a.subject for a in thread.results} == {"reply", "grandchild"}


async def test_query_articles_sorts_oldest_first(wired):
    """Unlike list_articles/search_articles (created_at DESC), query_articles
    sorts by article_num ASC — the docstring calls this out explicitly since
    it is easy to assume the tools agree."""
    await _connect_register_and_create_board("general")

    await tools.publish_article("first", "body", board="general")
    await tools.publish_article("second", "body", board="general")

    results = await tools.query_articles(board="general", origin=ORIGIN)

    assert [a.subject for a in results.results] == ["first", "second"]


async def test_get_event_lets_a_reader_check_the_signatures(wired):
    """End to end: connect caches the origin's key history, and get_event
    returns both signatures plus this client's own verdict on them.

    This is the escape hatch `get_article` has always pointed at — "use
    get_event when you need the signed artifact" — which until now returned no
    signatures and verified nothing.
    """
    await _connect_register_and_create_board("general")
    await tools.publish_article("signed", "content", board="general")

    events = await tools.event_range(origin=ORIGIN, start_seq=1, max_count=50)
    article = [e for e in events if e["kind"] == "bonnet.article"][-1]

    got = await tools.get_event(origin=ORIGIN, event_id_hex=article["event_id"])

    assert len(got["actor_signature"]) == 128
    assert len(got["origin_signature"]) == 128
    # Both checkable: the author's key rides in the record, and the origin's
    # key for this sequence came from the epoch table cached during connect.
    assert got["verification"] == {
        "author": "valid",
        "origin": "valid",
        "origin_key_known_for_seq": True,
    }
