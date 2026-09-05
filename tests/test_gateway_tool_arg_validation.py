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

    async def test_rejects_none_body(self):
        with pytest.raises(ValueError, match="body"):
            await tools.publish_article("subject", None, board="general")

    async def test_rejects_list_body(self):
        with pytest.raises(ValueError, match="body"):
            await tools.publish_article("subject", ["not", "a", "string"], board="general")

    async def test_rejects_empty_subject(self):
        with pytest.raises(ValueError, match="subject"):
            await tools.publish_article("", "body", board="general")

    async def test_rejects_whitespace_only_subject(self):
        with pytest.raises(ValueError, match="subject"):
            await tools.publish_article("   \t  ", "body", board="general")


class TestConnectArgValidation:
    async def test_rejects_url_with_path(self):
        """Regression for the chaos-testing report's #2.4: a URL carrying a
        path/query used to be accepted verbatim and silently mangled into a
        malformed discovery URL (.../foo?bar=baz/.well-known/untp) rather
        than rejected up front."""
        with pytest.raises(ValueError, match="scheme\\+host\\+port"):
            await tools.connect("https://bbs.example:2272/foo?bar=baz")

    async def test_rejects_url_with_bare_path(self):
        with pytest.raises(ValueError, match="scheme\\+host\\+port"):
            await tools.connect("https://bbs.example:2272/foo")

    async def test_accepts_url_with_trailing_slash_only(self):
        """A bare trailing slash is not a path component worth rejecting —
        connect() already strips it before storing the origin URL."""
        with pytest.raises(Exception) as exc:
            await tools.connect("https://unreachable.invalid:2272/")
        assert "scheme+host+port" not in str(exc.value)


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

    async def test_search_articles_rejects_oversized_body_query(self):
        """body_query reaches the same MAX_TEXT_FIELD cap as query — added
        alongside wiring body_query through to the relay's ripgrep-backed
        body search (chaos-testing report's #2.1: it used to be dropped
        entirely, hardcoded to "")."""
        with pytest.raises(ValueError, match="body_query"):
            await tools.search_articles("q", board="general", body_query="x" * 5000)


class TestReportArgTypes:
    async def test_report_rejects_oversized_reason(self):
        """Regression for the chaos-testing report's #2.2: report(reason=...)
        had no length cap, unlike every other text field."""
        with pytest.raises(ValueError, match="reason"):
            await tools.report(reason="x" * 200_000, target_article_id="ab" * 32)
