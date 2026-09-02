"""Gateway tool functions reject wrong-typed args before touching the wire.

`bonnet.gateway.tools` functions are called directly by MCP hosts (and, per
the fuzzing reports this covers, sometimes by a caller that bypasses
JSON-Schema coercion entirely). Before this, a None/list `subject` or a
str `offset` reached a bare `.encode()`/comparison and surfaced as a raw
AttributeError/TypeError instead of a clean ValueError. These checks run
before any network call, so no live server is needed.
"""

import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("fastmcp")

from bonnet.gateway import tools


@pytest.fixture(autouse=True)
def _isolated_gateway_home(tmp_path, monkeypatch):
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("BONNET_IDENTITIES_DB", str(tmp_path / "identities.db"))


class TestPublishArticleArgTypes:
    async def test_rejects_none_subject(self):
        with pytest.raises(ValueError, match="subject"):
            await tools.publish_article(None, "body", board="general")

    async def test_rejects_non_string_subject(self):
        with pytest.raises(ValueError, match="subject"):
            await tools.publish_article(12345, "body", board="general")

    async def test_rejects_none_content(self):
        with pytest.raises(ValueError, match="content"):
            await tools.publish_article("subject", None, board="general")

    async def test_rejects_list_content(self):
        with pytest.raises(ValueError, match="content"):
            await tools.publish_article("subject", ["not", "a", "string"], board="general")


class TestPaginationArgTypes:
    async def test_list_articles_rejects_string_offset(self):
        with pytest.raises(ValueError, match="offset"):
            await tools.list_articles(board="general", offset="not-an-int")

    async def test_list_articles_rejects_string_limit(self):
        with pytest.raises(ValueError, match="limit"):
            await tools.list_articles(board="general", limit="not-an-int")

    async def test_search_articles_rejects_string_offset(self):
        with pytest.raises(ValueError, match="offset"):
            await tools.search_articles("q", board="general", offset="not-an-int")
