"""Bounds/type checking on outgoing request builders in `firehose_wire`.

Request builders take values straight from a tool caller (or a client library
call), not from an already-validated Record — so unlike the read side (see
`test_wire_truncation.py`), nothing upstream guarantees the value fits the
wire's fixed-width fields. Before this, an out-of-range int or over-long
string reached a bare `struct.pack` and surfaced as a raw `struct.error` or
`TypeError` instead of a clean `ProtocolError`.
"""

import pytest

from bonnet.net.firehose_wire import (
    SELECTOR_BY_NUM,
    ProtocolError,
    build_article_body,
    build_article_get,
    build_article_list,
    build_article_query,
    build_article_search,
    build_event_range,
    build_report_list,
)


class TestArticleNumBounds:
    def test_get_article_rejects_negative_article_num(self):
        with pytest.raises(ProtocolError):
            build_article_get("origin", "general", SELECTOR_BY_NUM, -1)

    def test_get_article_rejects_non_integer_article_num(self):
        with pytest.raises(ProtocolError):
            build_article_get("origin", "general", SELECTOR_BY_NUM, 1.5)

    def test_get_article_rejects_out_of_range_article_num(self):
        with pytest.raises(ProtocolError):
            build_article_get("origin", "general", SELECTOR_BY_NUM, 2**64)

    def test_get_article_accepts_valid_article_num(self):
        build_article_get("origin", "general", SELECTOR_BY_NUM, 1)

    def test_article_body_rejects_negative_article_num(self):
        with pytest.raises(ProtocolError):
            build_article_body("origin", "general", -1)


class TestSearchQueryLength:
    def test_search_rejects_over_long_query(self):
        with pytest.raises(ProtocolError):
            build_article_search("origin", "general", meta_query="a" * 100_000)

    def test_search_accepts_ordinary_query(self):
        build_article_search("origin", "general", meta_query="spam")


class TestPaginationTypeAndBounds:
    def test_list_articles_rejects_non_integer_limit(self):
        with pytest.raises(ProtocolError):
            build_article_list("origin", "general", limit="not-an-int")

    def test_search_articles_rejects_non_integer_limit(self):
        with pytest.raises(ProtocolError):
            build_article_search("origin", "general", limit="not-an-int")

    def test_query_articles_rejects_non_integer_limit(self):
        with pytest.raises(ProtocolError):
            build_article_query("origin", "general", filters=[], limit="not-an-int")

    def test_list_articles_rejects_out_of_range_offset(self):
        with pytest.raises(ProtocolError):
            build_article_list("origin", "general", offset=-1)

    def test_event_range_rejects_negative_start_seq(self):
        with pytest.raises(ProtocolError):
            build_event_range("origin", -1)

    def test_report_list_rejects_out_of_range_limit(self):
        with pytest.raises(ProtocolError):
            build_report_list(limit=2**32)
