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

"""read_thread: a whole thread, already nested — one call instead of walking
query_articles' reply_to one level at a time or building the tree by hand.

Exercised against the real ASGI server stack, mirroring
test_gateway_query_articles's `wired` fixture.
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
        client = FirehoseHTTPClient(target, verify=False)
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


def _num(publish_result: str) -> int:
    return int(publish_result.split("#")[1].split()[0])


async def _post_thread(board: str = "general") -> dict:
    """root -> {reply_one, reply_two}; reply_two -> grandchild. Returns
    article_num for each, keyed by subject."""
    nums = {}
    root_msg = await tools.publish_article("root", "the start of it", board=board)
    nums["root"] = _num(root_msg)
    root = await tools.get_article(nums["root"], board=board, origin=ORIGIN)

    r1_msg = await tools.publish_article(
        "reply one", "first reply", board=board, reply_to_article_id=root.article_id
    )
    nums["reply one"] = _num(r1_msg)

    r2_msg = await tools.publish_article(
        "reply two", "second reply", board=board, reply_to_article_id=root.article_id
    )
    nums["reply two"] = _num(r2_msg)
    reply_two = await tools.get_article(nums["reply two"], board=board, origin=ORIGIN)

    gc_msg = await tools.publish_article(
        "grandchild", "reply to a reply", board=board, reply_to_article_id=reply_two.article_id
    )
    nums["grandchild"] = _num(gc_msg)

    return nums


def _subjects(node) -> set[str]:
    """Every subject reachable from `node`, flattened — order-agnostic
    shape check."""
    out = {node.subject}
    for child in node.children:
        out |= _subjects(child)
    return out


def _find(node, subject: str):
    if node.subject == subject:
        return node
    for child in node.children:
        found = _find(child, subject)
        if found is not None:
            return found
    return None


async def test_read_thread_from_the_root(wired):
    await _connect_register_and_create_board("general")
    nums = await _post_thread()

    result = await tools.read_thread(nums["root"], board="general", origin=ORIGIN)

    assert result.count == 4
    assert result.truncated is False
    assert result.tree.subject == "root"
    assert {c.subject for c in result.tree.children} == {"reply one", "reply two"}
    reply_two = _find(result.tree, "reply two")
    assert [c.subject for c in reply_two.children] == ["grandchild"]
    assert _subjects(result.tree) == {"root", "reply one", "reply two", "grandchild"}


async def test_read_thread_from_a_reply_resolves_to_the_same_tree(wired):
    """article_num can name any article in the thread, not just the root."""
    await _connect_register_and_create_board("general")
    nums = await _post_thread()

    from_root = await tools.read_thread(nums["root"], board="general", origin=ORIGIN)
    from_grandchild = await tools.read_thread(nums["grandchild"], board="general", origin=ORIGIN)

    assert from_grandchild.root_article_id == from_root.root_article_id
    assert _subjects(from_grandchild.tree) == _subjects(from_root.tree)


async def test_read_thread_root_with_no_replies(wired):
    await _connect_register_and_create_board("general")
    root_msg = await tools.publish_article("lonely", "nobody replied", board="general")

    result = await tools.read_thread(_num(root_msg), board="general", origin=ORIGIN)

    assert result.count == 1
    assert result.truncated is False
    assert result.tree.subject == "lonely"
    assert result.tree.children == []


async def test_read_thread_reports_truncated_when_limit_is_hit(wired):
    await _connect_register_and_create_board("general")
    root_msg = await tools.publish_article("root", "the start of it", board="general")
    root_num = _num(root_msg)
    root = await tools.get_article(root_num, board="general", origin=ORIGIN)

    for i in range(3):
        await tools.publish_article(
            f"reply {i}", "body", board="general", reply_to_article_id=root.article_id
        )

    result = await tools.read_thread(root_num, board="general", origin=ORIGIN, limit=2)

    # count is root (1) + replies (limit=2 caps the reply fetch at 2)
    assert result.count == 3
    assert result.truncated is True


async def test_read_thread_does_not_include_bodies(wired):
    """ThreadNode carries subject/author/position, not content — get_article
    is for reading a specific article once you know which one you want."""
    await _connect_register_and_create_board("general")
    root_msg = await tools.publish_article("root", "the start of it", board="general")

    result = await tools.read_thread(_num(root_msg), board="general", origin=ORIGIN)

    assert not hasattr(result.tree, "body")
