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


"""msgboard's own adapter tests, beyond the conformance suite.

`fixtures/` holds responses captured from msgboard.dev: they pin the
adapter's parsing to what the venue really serves, and the fake's shape to
the venue's, so neither drifts unnoticed.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from bonnet.bridges.adapter import (
    ForeignAccount,
    Gone,
    VenueError,
    VenueRateLimited,
    VenueUncertain,
)
from bonnet.bridges.adapters import msgboard
from bonnet.bridges.adapters.msgboard import MAX_TEXT_BYTES, PAGE_SIZE, MsgboardAdapter
from bonnet.bridges.adapters.msgboard.adapter import _parse_created, split_foreign_id
from bonnet.bridges.adapters.msgboard.fake import FakeMsgboard, _NoLimit

FIXTURES = Path(msgboard.__file__).parent / "fixtures"


def fixture(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _serving(routes: dict[str, tuple[int, str]], seen: list[str]) -> MsgboardAdapter:
    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(f"{request.url.path}?{request.url.query.decode()}")
        status, name = routes[request.url.path]
        return httpx.Response(status, json=fixture(name))

    http = httpx.AsyncClient(transport=httpx.MockTransport(handle))
    return MsgboardAdapter(FakeMsgboard().venue_config(), http=http, limiter=_NoLimit())


async def test_msgboard_reads_the_real_thread_envelope():
    seen: list[str] = []
    adapter = _serving({"/messages": (200, "thread.json")}, seen)
    try:
        root, reply, other = await adapter.poll("4ba9c563658f", None)
    finally:
        await adapter._http.aclose()
    # One page reaches the thread's start, so its root costs nothing more.
    assert len(seen) == 1 and "format=json" in seen[0] and "limit=100" in seen[0]
    assert root.foreign_id == "4ba9c563658f/1082"
    assert (root.root_id, root.reply_to) == ("4ba9c563658f/1082", None)
    assert (reply.root_id, reply.reply_to) == ("4ba9c563658f/1082", "4ba9c563658f/1082")
    assert other.author_handle == other.author_id == "Ekurhive"
    assert reply.created_at == _parse_created("2026-09-27T14:34:06Z")
    assert reply.text.startswith("Follow-up and corrections")
    # A poster's own fields ride along in the raw record, not the text.
    assert json.loads(reply.raw)["extra"] == {"model": "claude-opus-5.5"}
    assert reply.url == "https://msgboard.test/messages?thread=4ba9c563658f&before=1268&limit=1"


async def test_msgboard_reads_the_real_firehose_envelope():
    seen: list[str] = []
    adapter = _serving({"/all": (200, "all.json"), "/messages": (404, "missing_thread.json")}, seen)
    try:
        posts = await adapter.poll("", None)
    finally:
        await adapter._http.aclose()
    assert [p.foreign_id for p in posts] == ["35da4acc2cfb/1345", "95ef5dc3b1c5/1346"]
    # Threads whose start can't be read leave their posts unthreaded.
    assert all(p.reply_to is None and p.root_id is None for p in posts)
    assert posts[0].author_handle == "Werbel"


async def test_msgboard_missing_threads():
    seen: list[str] = []
    adapter = _serving({"/messages": (404, "missing_thread.json")}, seen)
    try:
        assert await adapter.fetch("", "nosuchthread0/5") == Gone("nosuchthread0/5", "unknown")
        with pytest.raises(VenueError, match="no thread 'nosuchthread0'"):
            await adapter.poll("nosuchthread0", None)
    finally:
        await adapter._http.aclose()


async def test_msgboard_thread_poll_pages_back_to_the_cursor():
    board = FakeMsgboard()
    for i in range(130):
        board.post("lobby", f"m{i}")
        board.post("elsewhere", f"x{i}")
    adapter = board.adapter(board.venue_config())
    try:
        first = await adapter.poll("lobby", None)  # backfill: one page
        assert len(first) == PAGE_SIZE and first[-1].text == "m129"
        # The root was found beyond the backfill, so every reply threads.
        assert {p.root_id for p in first} == {"lobby/1"}
        cursor = adapter.cursor_after(first[-1])
        for i in range(250):
            board.post("lobby", f"n{i}")
        more = await adapter.poll("lobby", cursor)
        assert [p.text for p in more] == [f"n{i}" for i in range(250)]
    finally:
        await adapter.close()


async def test_msgboard_firehose_fills_a_gap_from_the_threads():
    board = FakeMsgboard()
    board.post("a", "start")
    adapter = board.adapter(board.venue_config())
    try:
        (start,) = await adapter.poll("", None)
        cursor = adapter.cursor_after(start)
        # More than /all's one page arrives between polls, over several
        # threads, with private-channel ids burned in between.
        for i in range(90):
            board.post("abc"[i % 3], f"n{i}")
            board.skip_ids(2)
        for i in range(90, 250):
            board.post("d", f"n{i}")
        more = await adapter.poll("", cursor)
        assert [p.text for p in more] == [f"n{i}" for i in range(250)]
        assert more[0].reply_to == "a/1" and more[1].reply_to is None  # b starts here
        assert adapter.cursor_from_ids([p.foreign_id for p in more]) == adapter.cursor_after(
            more[-1]
        )
    finally:
        await adapter.close()


async def test_msgboard_fetch_reads_one_message():
    board = FakeMsgboard()
    root = board.post("t", "root")
    board.post("u", "other thread")
    later = board.post("t", "later")
    adapter = board.adapter(board.venue_config())
    try:
        got = await adapter.fetch("", f"t/{later}")
        assert got.text == "later" and got.reply_to == f"t/{root}"
        board.messages.pop(later)
        # A missing id reads the one before it, which isn't this post.
        assert await adapter.fetch("", f"t/{later}") == Gone(f"t/{later}", "unknown")
        assert await adapter.fetch("", "no-id") == Gone("no-id", "unknown")
    finally:
        await adapter.close()


def test_msgboard_foreign_ids():
    assert split_foreign_id("lobby/1289") == ("lobby", 1289)
    assert split_foreign_id("a/b/7") == ("a/b", 7)
    for bad in ("1289", "/5", "lobby/", "lobby/x", "lobby/0"):
        assert split_foreign_id(bad) is None
    adapter = MsgboardAdapter(FakeMsgboard().venue_config(), http=httpx.AsyncClient())
    assert adapter.cursor_from_ids(["b/7", "a/12", "junk"]) == "12"


async def test_the_fake_serves_the_shape_the_venue_does():
    """A fake that drifts from the venue tests the adapter against fiction."""
    board = FakeMsgboard()
    board.post("t", "hello", model="m")
    async with board.client() as http:
        base = "https://msgboard.test"
        served = {
            "thread.json": (await http.get(f"{base}/messages?thread=t")).json(),
            "all.json": (await http.get(f"{base}/all?limit=1")).json(),
            "threads.json": (await http.get(f"{base}/threads")).json(),
            "missing_thread.json": (await http.get(f"{base}/messages?thread=zz")).json(),
        }
    for name, body in served.items():
        real = fixture(name)
        # `note` only appears when an answer was cut short.
        assert set(body) == set(real) - {"note"}, name
    for name in ("thread.json", "all.json"):
        real_keys = set().union(*(set(m) for m in fixture(name)["messages"]))
        assert set(served[name]["messages"][0]) <= real_keys | {"extra"}
    assert set(served["thread.json"]["messages"][0]) == set(fixture("thread.json")["messages"][1])
    assert set(served["threads.json"]["threads"][0]) == set(fixture("threads.json")["threads"][0])
    assert set(served["thread.json"]["thread"]) == set(fixture("thread.json")["thread"])


async def test_msgboard_posts_open_threads_and_reply_into_them():
    board = FakeMsgboard()
    adapter = board.adapter(board.venue_config())
    try:
        me = ForeignAccount("lanternfly", "")
        top = await adapter.post(me, "", "a new topic\nmore\n--marker", None, "k1")
        thread = top.foreign_id.split("/")[0]
        assert board.threads[thread]["title"] == "a new topic"
        assert top.root_id == top.foreign_id and top.author_handle == "lanternfly"
        reply = await adapter.post(me, "", "a reply", top.foreign_id, "k2")
        assert reply.foreign_id.startswith(f"{thread}/") and reply.reply_to == top.foreign_id
        # On a thread channel, a top-level post goes into that thread.
        board.open_thread("lobby")
        lobby = await adapter.post(ForeignAccount("", ""), "lobby", "hi", None, "k3")
        assert lobby.foreign_id.startswith("lobby/") and lobby.author_handle == ""
        assert len(board.threads) == 2
    finally:
        await adapter.close()


async def test_msgboard_post_failures():
    board = FakeMsgboard()
    board.open_thread("lobby")
    adapter = board.adapter(board.venue_config())
    me = ForeignAccount("lanternfly", "")
    try:
        # It landed and only the answer was lost: its request_id finds it.
        board.lose_post_responses = 1
        found = await adapter.post(me, "lobby", "landed", None, "k1")
        assert len(board.messages) == 1 and found.foreign_id == f"lobby/{min(board.messages)}"
        # Nothing landed: no message carries this key (only k1's does), so
        # it stays uncertain.
        board.fail_posts = 1
        with pytest.raises(VenueUncertain):
            await adapter.post(me, "lobby", "lost", None, "k2")
        assert len(board.messages) == 1
        board.fail_posts = 1
        with pytest.raises(VenueError):
            await adapter.post(me, "", "no thread opened", None, "k")
        assert len(board.threads) == 1
        board.rate_limit_posts = 1
        with pytest.raises(VenueRateLimited) as e:
            await adapter.post(me, "lobby", "slow", None, "k")
        assert e.value.retry_after == 5
    finally:
        await adapter.close()


def test_msgboard_outbound_text_fits():
    adapter = MsgboardAdapter(FakeMsgboard().venue_config(), http=httpx.AsyncClient())
    out = adapter.render_outbound("é" * 9000, "--marker", "someone")
    assert out.startswith("someone: ") and out.endswith("\n--marker")
    assert len(out.encode("utf-8")) <= MAX_TEXT_BYTES


async def test_msgboard_reads_the_real_post_answers():
    seen: list[str] = []
    routes = {"/threads": (200, "post_thread.json"), "/messages": (200, "post_message.json")}

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(f"{request.method} {request.url.path}")
        if request.method == "GET":  # the read-back: a thread we can't see
            return httpx.Response(404, json=fixture("missing_thread.json"))
        status, name = routes[request.url.path]
        return httpx.Response(status, json=fixture(name))

    http = httpx.AsyncClient(transport=httpx.MockTransport(handle))
    adapter = MsgboardAdapter(FakeMsgboard().venue_config(), http=http, limiter=_NoLimit())
    try:
        posted = await adapter.post(ForeignAccount("lanternfly", ""), "", "probe", None, "k")
    finally:
        await http.aclose()
    assert seen[:2] == ["POST /threads", "POST /messages"]
    assert posted.foreign_id == "p0000000000000000/1350"


async def test_msgboard_replies_keep_their_parent_through_the_venue():
    board = FakeMsgboard()
    adapter = board.adapter(board.venue_config())
    me = ForeignAccount("lanternfly", "")
    try:
        top = await adapter.post(me, "", "topic", None, "k1")
        first = await adapter.post(me, "", "first reply", top.foreign_id, "k2")
        nested = await adapter.post(me, "", "reply to the reply", first.foreign_id, "k3")
        assert nested.reply_to == first.foreign_id and nested.root_id == top.foreign_id
        # A native reply names no parent, so it hangs off the thread's start.
        thread = top.foreign_id.split("/")[0]
        board.post(thread, "native", name="grok")
        polled = {p.text: p for p in await adapter.poll("", None)}
        assert polled["reply to the reply"].reply_to == first.foreign_id
        assert polled["native"].reply_to == top.foreign_id
    finally:
        await adapter.close()


async def test_msgboard_claimed_parents_stay_inside_their_thread():
    board = FakeMsgboard()
    a = board.post("a", "root")
    b = board.post("b", "elsewhere")
    board.post("a", "outside", reply_to=f"b/{b}")
    board.post("a", "later", reply_to=f"a/{a + 99}")
    board.post("a", "junk", reply_to="nonsense")
    adapter = board.adapter(board.venue_config())
    try:
        posts = [p for p in await adapter.poll("", None) if p.text != "elsewhere"]
        assert {p.text: p.reply_to for p in posts} == {
            "root": None, "outside": f"a/{a}", "later": f"a/{a}", "junk": f"a/{a}",
        }  # fmt: skip
        # The claim stays in the raw record either way.
        assert b'"reply_to":"b/2"' in next(p for p in posts if p.text == "outside").raw
    finally:
        await adapter.close()


async def test_the_fake_answers_posts_the_way_the_venue_does():
    board = FakeMsgboard()
    async with board.client() as http:
        base = "https://msgboard.test"
        thread = (await http.post(f"{base}/threads", data={"title": "t"})).json()
        posted = (
            await http.post(
                f"{base}/messages",
                data={"thread": thread["id"], "content": "c", "name": "n", "reply_to": "x/1"},
            )  # fmt: skip
        ).json()
    assert set(thread) == set(fixture("post_thread.json"))
    real = fixture("post_message.json")
    assert set(posted) == set(real)
    assert set(posted["posted"]) == set(real["posted"])
    assert posted["posted"]["extra"] == {"reply_to": "x/1"}
    assert set(posted["thread"]) == set(real["thread"])


async def test_msgboard_thread_titles_travel_both_ways():
    board = FakeMsgboard()
    adapter = board.adapter(board.venue_config())
    me = ForeignAccount("lanternfly", "")
    try:
        top = await adapter.post(me, "", "the body\n--marker", None, "k1", subject="A subject")
        thread = top.foreign_id.split("/")[0]
        assert board.threads[thread]["title"] == "A subject"
        untitled = await adapter.post(me, "", "first line\nsecond", None, "k2")
        assert board.threads[untitled.foreign_id.split("/")[0]]["title"] == "first line"
        reply = await adapter.post(me, "", "a reply", top.foreign_id, "k3", subject="Re: x")
        # Only a thread's first message carries its title, read or fetched.
        assert (top.subject, reply.subject) == ("A subject", None)
        fresh = board.adapter(board.venue_config())
        try:
            by_text = {p.text: p for p in await fresh.poll("", None)}
            assert by_text["the body\n--marker"].subject == "A subject"
            assert by_text["a reply"].subject is None
            assert (await fresh.fetch("", top.foreign_id)).subject == "A subject"
        finally:
            await fresh.close()
    finally:
        await adapter.close()
