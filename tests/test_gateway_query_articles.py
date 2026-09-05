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

    children = await tools.query_articles(
        board="general", reply_to_article_id=root_id, origin=ORIGIN
    )

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
    """root_article_id=<root_id> returns every reply in the thread regardless of depth
    — unlike reply_to_article_id, which only returns direct children. It does not
    include the root's own row: a root's root_article_id is the zero
    sentinel, never its own id, so it can never match root_article_id=<its own id>."""
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

    thread = await tools.query_articles(
        board="general", root_article_id=root_id, origin=ORIGIN
    )

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


async def test_anonymous_author_is_marked_unchecked_not_just_blank(wired):
    """An article from a key that never claimed a name must come back from
    the gateway with author_check='unchecked', not merely an empty
    author_username indistinguishable from any other unverified state.

    The dispatcher/board_projection layer has always computed author_check
    correctly (see test_author_identity.py); this exercises the actual path
    an MCP client uses — ARTICLE_GET and ARTICLE_QUERY over the wire — which
    used to drop the field entirely during encoding.
    """
    import os

    from bonnet.core.board_projection import AUTHOR_UNCHECKED
    from bonnet.core.record import MetadataMap, Record, metadata_text

    await _connect_register_and_create_board("general")

    bp = wired["dispatcher"]._get_board_projection(ORIGIN, "general")
    bp.apply_article(
        Record(
            origin=ORIGIN,
            origin_seq=999,
            event_id=os.urandom(32),
            kind="bonnet.article",
            actor_pubkey=os.urandom(32),
            board="general",
            article_id=os.urandom(32),
            article_num=1,
            metadata=MetadataMap([metadata_text(1, "quiet"), metadata_text(4, "text/plain")]),
            created_at=1,
        ),
        author_check=AUTHOR_UNCHECKED,
    )

    got = await tools.get_article(1, board="general", origin=ORIGIN, include_body=False)
    assert got.author_username == ""
    assert got.author_check == "unchecked"

    listed = await tools.query_articles(board="general", origin=ORIGIN)
    anon = next(a for a in listed.results if a.subject == "quiet")
    assert anon.author_username == ""
    assert anon.author_check == "unchecked"


async def test_get_event_lets_a_reader_check_the_signatures(wired):
    """End to end: connect caches the origin's key history, and get_event
    returns both signatures plus this client's own verdict on them.

    This is the escape hatch `get_article` has always pointed at — "use
    get_event when you need the signed artifact" — which until now returned no
    signatures and verified nothing.
    """
    await _connect_register_and_create_board("general")
    await tools.publish_article("signed", "content", board="general")

    events = await tools.event_range(origin=ORIGIN, offset=1, limit=50)
    article = [e for e in events if e.kind == "bonnet.article"][-1]

    got = await tools.get_event(origin=ORIGIN, event_id_hex=article.event_id)

    assert len(got["actor_signature"]) == 128
    assert len(got["origin_signature"]) == 128
    # Both checkable: the author's key rides in the record, and the origin's
    # key for this sequence came from the epoch table cached during connect.
    assert got["verification"] == {
        "author": "valid",
        "origin": "valid",
        "origin_key_known_for_seq": True,
    }


async def test_publish_article_rejects_lone_surrogate(wired):
    """A lone UTF-16 surrogate in body used to hang the gateway rather
    than fail cleanly: body.encode("utf-8") raised UnicodeEncodeError,
    and something downstream of that failed a second time trying to
    serialize a response, with nothing ever resolving the caller's
    call_tool() future. Reject it up front instead."""
    await _connect_register_and_create_board("general")

    with pytest.raises(Exception) as exc:
        await tools.publish_article("subject", "bad\ud800surrogate", board="general")

    assert "surrogate" in str(exc.value)


async def test_publishing_to_an_uncreated_board_is_refused(wired):
    """A publish to a board nobody ran create_board for must be refused
    outright, not silently mint that board owned by whoever happened to
    publish first — that made any registered user able to spray-create/
    typosquat boards with no authorization event, moderation step, or audit
    trail (see firehose_commands._cmd_publish and dispatcher.py's
    _dispatch_article). Once the board actually exists, the same publish
    succeeds and is fully discoverable."""
    await tools.connect("https://bbs.test")
    await tools.register("scout")

    with pytest.raises(Exception) as exc:
        await tools.publish_article("first post", "body", board="ghost-board")
    assert "does not exist" in str(exc.value)

    boards = await tools.list_boards(origin=ORIGIN)
    assert "ghost-board" not in {b.name for b in boards}

    await tools.create_board("ghost-board")
    await tools.publish_article("first post", "body", board="ghost-board")

    boards = await tools.list_boards(origin=ORIGIN)
    assert "ghost-board" in {b.name for b in boards}
    article = await tools.get_article(1, board="ghost-board")
    assert article is not None
    assert article.subject == "first post"
