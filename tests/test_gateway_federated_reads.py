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

"""Reading another origin's board through a homeserver.

A homeserver indexes a peer's records and redirects for their bodies, so a
board only a peer holds (a bridge's `~flatboard`, say) is readable from it.
What used to go wrong there, each pinned below:

- query_articles defaulted to the server's own origin and came back empty;
  it now asks for every origin holding the board.
- get_article and read_thread did the same; with no origin named they now
  fall over to the one origin holding the board.
- single-origin reads returned rows with an empty `origin`, and
  query_articles called another origin's bodies 'unavailable', not 'remote'.
- a body withheld over an unaccepted key, a refused redirect or a network
  error came back as a bare `body: null`.
"""

from types import SimpleNamespace

import httpx
import pytest

pytest.importorskip("fastmcp")

from bonnet.core.record import compute_body_hash
from bonnet.gateway import tools
from bonnet.gateway.firehose_client import FirehoseHTTPClient
from bonnet.net.firehose_models import ArticleListItem, ArticleView
from bonnet.net.firehose_transport import FirehoseClientError, PinConfirmationRequired
from bonnet.net.firehose_wire import ProtocolError

OWN = "sys.test"
BRIDGE = "bridge.test"
BODY = b"a post from the venue"


def _view(origin_body=None):
    return ArticleView(
        article_num=7,
        article_id="aa" * 32,
        event_id="bb" * 32,
        visibility="active",
        body_state="remote",
        body_hash=compute_body_hash(BODY).hex(),
        body_size=len(BODY),
        created_at=0,
        author_pubkey="cc" * 32,
        body=origin_body,
    )


class FakeClient:
    """A homeserver (OWN) that indexes boards held by other origins."""

    def __init__(self, boards, body_error=None):
        self._server_origin = OWN
        self._boards = boards  # [(board, origin)]
        self._body_error = body_error
        self.calls = []

    async def connect_anonymous(self):
        return None

    async def list_boards(self, origin=""):
        return [SimpleNamespace(name=b, origin=o) for b, o in self._boards]

    async def get_article(self, origin, board, article_num, include_body=False):
        self.calls.append(("get_article", origin))
        if (board, origin) not in self._boards:
            raise ProtocolError("error 3: Article not found", code=0x0003)
        return _view()

    async def get_article_by_id(self, origin, board, article_id, include_body=False):
        return _view()

    async def get_article_body(self, origin, board, article_num):
        self.calls.append(("get_article_body", origin))
        if self._body_error is not None:
            raise self._body_error
        return BODY

    async def query_articles(self, origin, board, filters, offset=0, limit=100, newest_first=False):
        self.calls.append(("query_articles", origin))
        self.newest_first = newest_first
        return SimpleNamespace(results=[])

    async def close(self):
        return None


@pytest.fixture
def install(monkeypatch):
    monkeypatch.delenv("BONNET_IDENTITY", raising=False)
    tools.current_username.set(None)

    def _install(client):
        monkeypatch.setattr(tools, "_make_client", lambda *a, **k: client)
        monkeypatch.setattr(tools, "_default_identity", lambda: None)
        return client

    return _install


# --- which origin a read goes to ------------------------------------------


async def test_query_articles_asks_every_origin_holding_the_board(install):
    client = install(FakeClient([("~flatboard", BRIDGE)]))
    await tools.query_articles(board="~flatboard")
    assert client.calls == [("query_articles", "")]
    assert client.newest_first is True


async def test_get_article_falls_over_to_the_one_origin_holding_the_board(install):
    client = install(FakeClient([("~flatboard", BRIDGE)]))
    view = await tools.get_article(7, board="~flatboard")
    assert view.body == BODY
    assert ("get_article", OWN) in client.calls
    assert ("get_article_body", BRIDGE) in client.calls


async def test_a_real_miss_on_the_own_origin_stays_a_miss(install):
    """The own origin holds the board, so its "not found" is the answer."""
    client = install(FakeClient([("general", OWN), ("general", BRIDGE)]))
    client._boards = [("general", OWN), ("general", BRIDGE)]

    async def missing(origin, board, article_num, include_body=False):
        client.calls.append(("get_article", origin))
        raise ProtocolError("error 3: Article not found", code=0x0003)

    client.get_article = missing
    assert await tools.get_article(7, board="general") is None
    assert client.calls == [("get_article", OWN)]


async def test_a_board_on_several_other_origins_is_ambiguous(install):
    install(FakeClient([("~flatboard", BRIDGE), ("~flatboard", "bridge-two.test")]))
    with pytest.raises(ValueError, match="several origins .*pass origin="):
        await tools.get_article(7, board="~flatboard")


async def test_a_refused_board_list_leaves_the_miss_a_miss(install):
    client = install(FakeClient([("~flatboard", BRIDGE)]))

    async def refused(origin=""):
        raise ProtocolError("error 5: Permission denied", code=0x0005)

    client.list_boards = refused
    assert await tools.get_article(7, board="~flatboard") is None


async def test_a_named_origin_is_not_second_guessed(install):
    client = install(FakeClient([("~flatboard", BRIDGE)]))
    assert await tools.get_article(7, board="~flatboard", origin=OWN) is None
    assert client.calls == [("get_article", OWN)]


async def test_read_thread_falls_over_like_get_article(install):
    client = install(FakeClient([("~flatboard", BRIDGE)]))
    result = await tools.read_thread(7, board="~flatboard")
    assert result.count == 1
    assert ("query_articles", BRIDGE) in client.calls
    # A thread reads top-down: a truncated one keeps its opening replies.
    assert client.newest_first is False


# --- why a body is missing ------------------------------------------------


@pytest.mark.parametrize(
    "error, expected",
    [
        (
            PinConfirmationRequired(BRIDGE, bytes.fromhex("57" * 32), "new"),
            "held by bridge.test, whose new key this client has not accepted "
            f"(fingerprint {'57' * 32})",
        ),
        (
            FirehoseClientError("won't dial: it does not resolve"),
            "won't dial: it does not resolve",
        ),
        (httpx.ConnectError("refused"), "could not fetch the body: refused"),
        (ProtocolError("error 3: Body unavailable", code=0x0003), "Body unavailable"),
    ],
)
async def test_a_withheld_body_says_why(install, error, expected):
    install(FakeClient([("~flatboard", BRIDGE)], body_error=error))
    view = await tools.get_article(7, board="~flatboard", origin=BRIDGE)
    assert view.body is None
    assert expected in view.body_unavailable_reason
    # The metadata still stands: a refused hop no longer fails the read.
    assert view.article_num == 7


async def test_a_delivered_body_has_no_reason(install):
    install(FakeClient([("~flatboard", BRIDGE)]))
    view = await tools.get_article(7, board="~flatboard", origin=BRIDGE)
    assert view.body == BODY
    assert view.body_unavailable_reason == ""


# --- row labels -----------------------------------------------------------


def _row(body_state="unavailable", origin=""):
    return ArticleListItem(
        article_num=1,
        article_id="aa" * 32,
        event_id="bb" * 32,
        visibility="active",
        body_state=body_state,
        body_hash="",
        body_size=3,
        created_at=0,
        author_pubkey="cc" * 32,
        origin=origin,
    )


def _client():
    client = FirehoseHTTPClient("https://sys.test", verify=False)
    client._server_origin = OWN
    return client


def test_single_origin_rows_get_their_origin_back():
    rows = [_row()]
    _client()._label_rows(rows, BRIDGE)
    assert rows[0].origin == BRIDGE
    assert rows[0].body_state == "remote"


def test_aggregate_rows_keep_their_own_origin():
    rows = [_row(origin=BRIDGE), _row(origin=OWN)]
    _client()._label_rows(rows, "")
    assert [(r.origin, r.body_state) for r in rows] == [
        (BRIDGE, "remote"),
        (OWN, "unavailable"),
    ]


def test_an_own_origin_body_that_is_missing_stays_unavailable():
    """'remote' means "fetch it from its origin"; for the server's own
    articles there is nowhere else, so 'unavailable' is the truth."""
    rows = [_row()]
    _client()._label_rows(rows, OWN)
    assert (rows[0].origin, rows[0].body_state) == (OWN, "unavailable")
