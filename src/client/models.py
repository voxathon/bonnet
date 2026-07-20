from pydantic import BaseModel, Field
from typing import Optional


class User(BaseModel):
    username: str
    registrar: str
    record_origin: str
    relay: str
    public_key: str = Field(..., description="Hex-encoded Ed25519 public key")


class Board(BaseModel):
    name: str
    origin: str
    signature: str = Field(..., description="Hex-encoded Ed25519 signature")
    closed: bool
    owner_pubkey: Optional[str] = Field(
        None, description="Hex-encoded owner public key"
    )


class Peer(BaseModel):
    origin: str


class BanStatus(BaseModel):
    """Result of a v3 BAN_STATUS query."""
    banned: bool
    reason: str
    punishment_message_id: str = Field("", description="Hex-encoded 32-byte message ID of the issuing punishment event")
    source_origin: str = Field("", description="Origin that issued the punishment")
    source_board: str = Field("", description="Board on which the punishment was issued")
    expires_at: int = Field(0, description="Unix timestamp when the punishment expires (0=warning, -1=permanent)")


class ArticlePublishResult(BaseModel):
    """Result of publishing an article or control event via ARTICLE_PUBLISH."""
    article_num: int = Field(0, description="Assigned article number (0 for control events)")
    message_id: str = Field(..., description="Hex-encoded 32-byte message ID")
    feed_seq: int = Field(..., description="Assigned feed sequence number")
    event_type: int = Field(..., description="Event type that was published")
    event_type_name: str = Field("", description="Human-readable event type name")
    projected_state: str = Field("active", description="Projected state after publish (active/cancelled/superseded/purged)")
    board: str = Field("", description="Board the event was published to")
    origin: str = Field("", description="Origin the event was published to")


# ---------------------------------------------------------------------------
# Protocol v3 article feed models
# ---------------------------------------------------------------------------

class ArticleEvent(BaseModel):
    """A v3 feed event (ARTICLE or control)."""
    feed_seq: int
    article_num: int
    message_id: str = Field(..., description="Hex-encoded 32-byte message ID")
    event_type: int
    event_type_name: str = Field("", description="Human-readable event type")
    origin: str
    board: str
    created_at: int
    actor_pubkey: str = Field(..., description="Hex-encoded Ed25519 public key")
    actor_username: str
    actor_registrar: str
    root_message_id: str = Field("", description="Hex-encoded root message ID")
    reply_to_message_id: str = Field("", description="Hex-encoded reply-to message ID")
    supersedes_message_id: str = Field("", description="Hex-encoded supersedes message ID")
    target_message_id: str = Field("", description="Hex-encoded target message ID")
    subject: str = ""
    tags: str = ""
    options: str = ""
    body_hash: str = Field(..., description="Hex-encoded body hash")
    body_size: int
    projected_state: str = Field("active", description="active/cancelled/superseded/purged")
    body_available: bool = Field(True, description="Whether the body is locally available")
    control_event_ids: list[str] = Field(default_factory=list,
        description="Hex-encoded message IDs of applicable control events")


class Article(BaseModel):
    """A user-facing article (ARTICLE event with projection state)."""
    article_num: int
    message_id: str = Field(..., description="Hex-encoded 32-byte message ID")
    origin: str
    board: str
    created_at: int
    actor_pubkey: str = Field(..., description="Hex-encoded author public key")
    actor_username: str
    actor_registrar: str
    subject: str
    tags: str
    options: str
    body: Optional[str] = Field(None, description="Article body text (if available and requested)")
    body_available: bool = Field(True)
    projected_state: str = Field("active")
    feed_seq: int
    root_message_id: Optional[str] = Field(None)
    reply_to_message_id: Optional[str] = Field(None)
    supersedes_message_id: Optional[str] = Field(None)
    control_event_ids: list[str] = Field(default_factory=list)


class FeedHeadInfo(BaseModel):
    """Signed feed head information."""
    origin: str
    board: str
    latest_feed_seq: int
    latest_event_hash: str = Field(..., description="Hex-encoded event hash")
    article_count: int
    event_count: int
    snapshot_timestamp: int
    signature: str = Field(..., description="Hex-encoded origin signature")
    accepted_at: int = Field(0, description="When the relay accepted this head (advisory)")
    source_relay: str = Field("", description="Relay that provided this head (advisory)")
