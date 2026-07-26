"""Body and metadata search service for the Bonnet Firehose Protocol (PROTOCOL.md §15).

Metadata search queries one board's metadata.db. Body search runs ripgrep
only against that board's flat bodies/ directory. Both enforce bounded time
and result counts. Purged articles are excluded from search regardless of
whether stale bytes remain on disk.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from core.board_projection import BoardProjection
from core.bodies import BodyStore

# ---------------------------------------------------------------------------
# Search result
# ---------------------------------------------------------------------------


@dataclass
class SearchResult:
    article_num: int
    article_id: bytes
    origin: str
    board: str
    subject: str
    author_pubkey: bytes
    created_at: int
    visibility: str
    body_state: str
    body_available: bool
    excerpt: str = ""
    truncated: bool = False


@dataclass
class SearchResults:
    results: list[SearchResult]
    total: int
    truncated: bool


# ---------------------------------------------------------------------------
# Search service
# ---------------------------------------------------------------------------


class SearchService:
    """Metadata and body search over board projections."""

    def __init__(
        self,
        boards_dir: str,
        body_store: BodyStore,
        max_count: int = 1000,
        timeout_seconds: int = 10,
        result_limit: int = 100,
    ):
        self._boards_dir = boards_dir
        self._body_store = body_store
        self._max_count = max_count
        self._timeout_seconds = timeout_seconds
        self._result_limit = result_limit

    def search_metadata(
        self,
        projection: BoardProjection,
        origin: str,
        board: str,
        text_query: str = "",
        actor_pubkey: bytes = None,
        offset: int = 0,
        limit: int = 100,
        include_cancelled: bool = False,
        include_superseded: bool = False,
    ) -> SearchResults:
        """Search article metadata (subject, tags) in one board projection.

        Uses SQL-level filtering for text and actor — only matching rows
        are loaded into Python, bounded by limit.
        """
        articles, total = projection.search_metadata(
            origin,
            board,
            text_query=text_query,
            actor_pubkey=actor_pubkey,
            offset=offset,
            limit=limit,
            include_cancelled=include_cancelled,
            include_superseded=include_superseded,
        )

        results = []
        for art in articles:
            excerpt = None
            if art.body_state == "available" and art.body_size > 0:
                body = self._body_store.get_article_body(
                    art.origin,
                    art.board,
                    art.article_num,
                    art.body_hash,
                    art.body_size,
                )
                if body:
                    text = body.decode("utf-8", errors="replace")
                    excerpt = text[:80]
            results.append(
                SearchResult(
                    article_num=art.article_num,
                    article_id=art.article_id,
                    origin=art.origin,
                    board=art.board,
                    subject=art.subject,
                    author_pubkey=art.author_pubkey,
                    created_at=art.created_at,
                    visibility=art.visibility,
                    body_state=art.body_state,
                    body_available=(art.body_state == "available"),
                    excerpt=excerpt,
                )
            )
        return SearchResults(results=results, total=total, truncated=(offset + limit) < total)

    def search_bodies(
        self,
        projection: BoardProjection,
        origin: str,
        board: str,
        pattern: str,
        offset: int = 0,
        limit: int = 100,
        include_cancelled: bool = False,
        include_superseded: bool = False,
        rg_path: str = None,
    ) -> SearchResults:
        """Search article body text using ripgrep over one board's bodies/."""
        article_nums = self._body_store.search_article_bodies(
            origin,
            board,
            pattern,
            max_count=self._max_count,
            timeout_seconds=self._timeout_seconds,
            result_limit=self._result_limit,
            rg_path=rg_path,
        )

        results = []
        skipped = 0
        for article_num in article_nums:
            art = projection.get_article_by_num(origin, board, article_num)
            if art is None:
                continue
            if art.body_state == "purged":
                continue
            if art.visibility == "cancelled" and not include_cancelled:
                continue
            if art.visibility == "superseded" and not include_superseded:
                continue

            if skipped < offset:
                skipped += 1
                continue

            excerpt = self._get_excerpt(origin, board, article_num, pattern)

            results.append(
                SearchResult(
                    article_num=art.article_num,
                    article_id=art.article_id,
                    origin=art.origin,
                    board=art.board,
                    subject=art.subject,
                    author_pubkey=art.author_pubkey,
                    created_at=art.created_at,
                    visibility=art.visibility,
                    body_state=art.body_state,
                    body_available=(art.body_state == "available"),
                    excerpt=excerpt,
                )
            )

            if len(results) >= limit:
                break

        return SearchResults(
            results=results,
            total=len(results),
            truncated=len(article_nums) > len(results) + skipped,
        )

    def _get_excerpt(self, origin: str, board: str, article_num: int, pattern: str) -> str:
        """Get a short excerpt around the first match in a body file."""
        path = self._body_store._article_body_path(origin, board, article_num)
        if not os.path.exists(path):
            return ""
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                content = f.read()
            idx = content.lower().find(pattern.lower())
            if idx < 0:
                return content[:80]
            start = max(0, idx - 40)
            end = min(len(content), idx + len(pattern) + 40)
            return content[start:end]
        except Exception:
            return ""
