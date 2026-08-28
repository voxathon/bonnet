"""Firehose client models for the Bonnet Firehose Protocol.

User-facing data models for article, board, user, ban status, event, and
publication results. These are derived API views, not protocol primitives.
"""

from __future__ import annotations

from dataclasses import dataclass, field


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
    """An article projection returned by ARTICLE_GET.

    Note: visibility and body_state are independent dimensions. A purged
    article has visibility='active' and body_state='purged'. Clients MUST
    check body_state alongside visibility to determine body availability.

    body_state values:
      - 'available': body is cached locally on the relay
      - 'unavailable': body should be local but is missing (sync issue)
      - 'purged': body was intentionally deleted (purge event)
      - 'remote': body is on the origin server, not cached locally;
                  fetch via ARTICLE_BODY (may redirect to origin)

    body_verified: True if the body was fetched and its hash+size verified
                   against the origin-signed article metadata. False if the
                   body was not fetched or verification was not performed.
    """

    article_num: int
    article_id: str
    event_id: str
    visibility: str  # active, cancelled, superseded
    body_state: str  # available, unavailable, purged, remote
    body_hash: str
    body_size: int
    created_at: int
    author_pubkey: str
    author_username: str = ""
    author_registrar: str = ""
    subject: str = ""
    tags: str = ""
    content_type: str = ""
    root_article_id: str = ""
    reply_to_article_id: str = ""
    replacement_article_id: str = ""
    pin_state: str = "unpinned"
    thread_state: str = "open"
    body: bytes | None = None
    body_verified: bool = False


@dataclass
class ArticleListItem:
    """An article in a list response.

    body_state may be 'remote' for articles from a different origin than
    the connected server. See ArticleView for the full body_state documentation.
    """

    article_num: int
    article_id: str
    event_id: str
    visibility: str
    body_state: str  # available, unavailable, purged, remote
    body_hash: str
    body_size: int
    created_at: int
    author_pubkey: str
    author_username: str = ""
    author_registrar: str = ""
    subject: str = ""
    tags: str = ""
    content_type: str = ""
    root_article_id: str = ""
    reply_to_article_id: str = ""
    replacement_article_id: str = ""
    pin_state: str = "unpinned"
    thread_state: str = "open"
    origin: str = ""


@dataclass
class SearchResult:
    """A single search match."""

    article_num: int
    article_id: str
    subject: str
    author_pubkey: str
    created_at: int
    body_available: bool
    excerpt: str | None = None
    origin: str = ""


@dataclass
class SearchResponse:
    """Search response with metadata."""

    results: list[SearchResult]
    total: int
    truncated: bool


@dataclass
class QueryResponse:
    """Query response wrapping article list."""

    results: list[ArticleListItem]


@dataclass
class BoardInfo:
    """A board in the directory."""

    name: str
    closed: bool
    owner_pubkey: str
    display_name: str
    origin: str = ""


@dataclass
class UserInfo:
    """A registered user."""

    pubkey: str
    username: str
    flags: int
    reg_seq: int
    created_at: int
    revoked: bool
    revoked_seq: int = 0
    origin: str = ""


@dataclass
class PendingPunishment:
    """A punishment currently gating a user's writes."""

    type: str  # "warning" | "ban" | "permaban"
    event_id: str = ""  # hex
    origin: str = ""
    expires_at: int = 0  # 0 = no expiry
    body_hash: str = ""  # hex
    body_size: int = 0


@dataclass
class BanStatus:
    """Ban status query result: all pending punishments for a pubkey."""

    punishments: list[PendingPunishment] = field(default_factory=list)

    @property
    def banned(self) -> bool:
        return any(p.type in ("ban", "permaban") for p in self.punishments)

    @property
    def blocked(self) -> bool:
        return bool(self.punishments)


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
    known_origins: list = field(default_factory=list)
