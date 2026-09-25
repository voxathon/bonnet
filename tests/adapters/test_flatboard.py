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


"""Flatboard's own adapter tests, beyond the conformance suite.

`fixtures/` holds responses captured from tools.nyrds.net: they pin the
adapter's parsing to what the venue really serves, and the fake's shape to
the venue's, so neither drifts unnoticed.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from bonnet.bridges.adapter import Gone
from bonnet.bridges.adapters import flatboard
from bonnet.bridges.adapters.flatboard import FlatboardAdapter
from bonnet.bridges.adapters.flatboard.adapter import _parse_created
from bonnet.bridges.adapters.flatboard.fake import FakeFlatboard, _NoLimit
from tests.bridge_fakes import venue_config

NOW = 1_800_000_000
FIXTURES = Path(flatboard.__file__).parent / "fixtures"


def fixture(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


async def test_flatboard_poll_pages_back_to_the_cursor():
    board = FakeFlatboard()
    for i in range(130):
        board.post(f"m{i}", created=NOW)
    adapter = board.adapter(venue_config())
    try:
        first = await adapter.poll("", None)  # backfill: one page
        assert [p.foreign_id for p in first] == [str(i) for i in range(81, 131)]
        for i in range(120):
            board.post(f"n{i}", created=NOW)
        more = await adapter.poll("", "130")
        assert [int(p.foreign_id) for p in more] == list(range(131, 251))
    finally:
        await adapter.close()


async def test_flatboard_maps_messages_to_foreign_posts():
    board = FakeFlatboard()
    root = board.post("hello", author="grok", created=NOW)
    board.post("hi", author="lf", reply_to=root, created=NOW)
    adapter = board.adapter(venue_config())
    try:
        a, b = await adapter.poll("", None)
        assert (a.root_id, a.reply_to) == (str(root), None)
        assert (b.root_id, b.reply_to) == (None, str(root))
        assert b.author_id == "lf" and b.created_at == NOW
        assert b.raw_content_type == "application/json" and b"hi" in b.raw
        fetched = await adapter.fetch("", str(root))
        assert fetched.text == "hello" and fetched.raw.startswith(b"{")
        assert await adapter.fetch("", "999") == Gone("999", "unknown")
    finally:
        await adapter.close()


async def test_flatboard_reads_the_real_page_envelope():
    seen = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200, json=fixture("page.json"))

    http = httpx.AsyncClient(transport=httpx.MockTransport(handle))
    adapter = FlatboardAdapter(venue_config(), http=http, limiter=_NoLimit())
    try:
        root, reply = await adapter.poll("", None)
    finally:
        await http.aclose()
    assert seen == ["/board/page/1.json"]
    assert (root.foreign_id, root.root_id, root.reply_to) == ("16", "16", None)
    assert (reply.foreign_id, reply.root_id, reply.reply_to) == ("20", None, "16")
    assert reply.author_handle == "zai_glm" and reply.text == "Decoded"
    assert reply.created_at == _parse_created("2026-09-19T00:17:24Z")


def test_flatboard_parses_timestamps():
    assert _parse_created(NOW) == NOW
    assert _parse_created(str(NOW)) == NOW
    assert _parse_created("2026-09-24T00:00:00Z") == 1_790_208_000
    assert _parse_created("yesterday") is None
    assert _parse_created(True) is None


async def test_the_fake_serves_the_shape_the_venue_does():
    """A fake that drifts from the venue tests the adapter against fiction."""
    real = fixture("page.json")
    board = FakeFlatboard()
    board.post("hello", created=NOW)
    async with board.client() as http:
        served = (await http.get("https://flatboard.test/board/page/1.json")).json()
    assert set(served) == set(real)
    assert set(served["msgs"][0]) == set(real["msgs"][0])
