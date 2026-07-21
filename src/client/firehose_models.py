"""Firehose client models for the Bonnet Firehose Protocol (PROTOCOL.md §19).

User-facing data models for article, board, user, ban status, event, and
publication results. These are derived API views, not protocol primitives.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PublishResult:
    """Result of PUBLISH_RECORD."""
    origin_seq: int
    event_id: str
    kind: str
    article_num: int
    origin: str
    board: str
    witness_pubkey: str
    witness_hostname: str


@dataclass
class EventInfo:
    """A firehose event returned by EVENT_GET or EVENT_RANGE."""
    origin_seq: int
    event_id: str
    kind: str
    schema_version: int
    created_at: int
    actor_pubkey: str
    origin: str
    board: str
    article_id: str
    article_num: int
    body_hash: str
    body_size: int
    witness_pubkey: str
    witness_hostname: str
    received_from_pubkey: str
    received_from_hostname: str
    seen_at: int


@dataclass
class HeadInfo:
    """Signed firehose head."""
    origin: str
    latest_origin_seq: int
    latest_event_hash: str
    event_count: int
    generated_at: int
    origin_pubkey: str


@dataclass
class ArticleView:
    """An article projection returned by ARTICLE_GET."""
    article_num: int
    article_id: str
    event_id: str
    visibility: str  # active, cancelled, superseded
    body_state: str  # available, unavailable, purged
    body_hash: str
    body_size: int
    created_at: int
    author_pubkey: str
    subject: str
    tags: str
    content_type: str
    body: Optional[bytes] = None


@dataclass
class ArticleListItem:
    """An article in a list response."""
    article_num: int
    article_id: str
    event_id: str
    visibility: str
    body_state: str
    body_hash: str
    body_size: int
    created_at: int
    author_pubkey: str
    subject: str
    tags: str
    content_type: str


@dataclass
class SearchResult:
    """A single search match."""
    article_num: int
    article_id: str
    subject: str
    author_pubkey: str
    created_at: int
    body_available: bool
    excerpt: str


@dataclass
class SearchResponse:
    """Search response with metadata."""
    results: list[SearchResult]
    total: int
    truncated: bool


@dataclass
class BoardInfo:
    """A board in the directory."""
    name: str
    closed: bool
    owner_pubkey: str
    display_name: str


@dataclass
class UserInfo:
    """A registered user."""
    pubkey: str
    username: str
    flags: int
    reg_seq: int
    created_at: int
    revoked: bool


@dataclass
class BanStatus:
    """Ban status query result."""
    banned: bool
    punishment_event_id: str = ""
    source_origin: str = ""
    expires_at: int = 0


@dataclass
class DiscoveryInfo:
    """Server discovery document."""
    protocol: str
    origin: str
    hostname: str
    public_key: str
    anonymous_key: str
    anonymous_private_key: str
    command_endpoint: str
    capabilities: list[str]
