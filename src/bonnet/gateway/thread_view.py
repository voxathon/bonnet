"""Nesting a flat article listing into a thread tree.

Pure data transform, no network I/O — kept out of `tools.py` the same way
`cursor.py`/`gating.py`/`needs.py` already separate concerns from it. Takes
what `query_articles(root=...)` already returns and nests it by
`reply_to_article_id`; nothing server-side pre-nests this, and nothing here
talks to a relay.

Named `thread_view`, not `thread`, so nothing here reads as the stdlib
`threading` module at a glance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from bonnet.net.firehose_models import ArticleListItem


class _ArticleLike(Protocol):
    """What ThreadNode needs, present on both ArticleView (the root, read via
    get_article) and ArticleListItem (its replies, read via query_articles).
    A Protocol rather than a Union so this doesn't have to import ArticleView
    just to describe its shape."""

    article_num: int
    article_id: str
    subject: str
    author_username: str
    author_pubkey: str
    created_at: int
    visibility: str
    pin_state: str


@dataclass
class ThreadNode:
    article_num: int
    article_id: str
    subject: str
    author_username: str
    author_pubkey: str
    created_at: int
    visibility: str
    pin_state: str
    children: list[ThreadNode] = field(default_factory=list)


@dataclass
class ThreadResult:
    root_article_id: str
    count: int
    truncated: bool
    tree: ThreadNode


def _node(item: _ArticleLike) -> ThreadNode:
    return ThreadNode(
        article_num=item.article_num,
        article_id=item.article_id,
        subject=item.subject,
        author_username=item.author_username,
        author_pubkey=item.author_pubkey,
        created_at=item.created_at,
        visibility=item.visibility,
        pin_state=item.pin_state,
    )


def build_tree(root: _ArticleLike, replies: list[ArticleListItem]) -> ThreadNode:
    """Nest `replies` (query_articles(root=root.article_id)'s flat result —
    every article in the thread *except* the root itself, since a root's own
    root_article_id is the zero sentinel and never equals its own id) under
    a node built from `root`.

    One pass: index every reply by its own id, then attach each as a child of
    whatever it replies to (falling back to the root when that parent isn't
    among `replies` — see below), or of the root directly when its own
    reply_to_article_id names the root. Depth is bounded by how many replies
    there are at all — already capped by the caller's `limit` — so this
    doesn't need its own recursion guard.

    An item whose own parent isn't in `replies` — query_articles excludes
    cancelled/superseded articles by default, so a reply can survive while
    the article it replied to doesn't — is attached directly under the root
    rather than dropped. Losing a whole subtree silently because one article
    in the middle of it got cancelled would be a worse surprise than a reply
    appearing one level shallower than it actually is.
    """
    root_node = _node(root)
    nodes: dict[str, ThreadNode] = {item.article_id: _node(item) for item in replies}

    for item in replies:
        parent_id = item.reply_to_article_id
        if parent_id == root.article_id or not parent_id:
            parent = root_node
        else:
            parent = nodes.get(parent_id, root_node)
        parent.children.append(nodes[item.article_id])

    return root_node
