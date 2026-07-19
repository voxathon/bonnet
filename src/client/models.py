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


class PostSummary(BaseModel):
    post_num: int
    creation_date: int
    subject: str
    author: str
    root: int


class Post(BaseModel):
    post_num: int
    last_modified: int
    creation_date: int
    last_bumped: int
    closed: bool
    sticky: int
    tags: list[str]
    subject: str
    options: str
    root: int
    author: str
    author_registrar: str
    signature: str = Field(..., description="Hex-encoded Ed25519 signature")
    content: str


class PostCreateResult(BaseModel):
    post_num: int
    creation_date: int
    last_modified: int
    author: str
    author_registrar: str
    tags: str
    subject: str
    options: str


class Rule(BaseModel):
    rule_num: int
    name: str
    description: str


class Report(BaseModel):
    report_num: int
    rule_num: int
    culprit_pubkey: str = Field(..., description="Hex-encoded Ed25519 public key")
    board: Optional[str]
    post_num: Optional[int]
    reporter_pubkey: str = Field(..., description="Hex-encoded Ed25519 public key")
    report_time: int
    origin: str
    relay: str
    description: str
    origin_sig: str = Field(..., description="Hex-encoded signature")
    reporter_sig: Optional[str] = Field(None, description="Hex-encoded signature")


class Punishment(BaseModel):
    punishment_id: int = Field(..., description="Per-origin punishment ID")
    origin: str = Field("", description="Origin that issued the punishment")
    rollover: int = Field(0, description="Rollover variant for conflicts")
    pubkey: str = Field(..., description="Hex-encoded Ed25519 public key")
    report_ids: list[int]
    expires_at: int = Field(
        ..., description="0=warning, -1=permanent, >0=unix timestamp"
    )
    notes: str
    issued_by: Optional[str] = Field(None, description="Hex-encoded Ed25519 public key of the issuing moderator")
    created_at: int = Field(0, description="Unix timestamp when the punishment was issued")
    origin_sig: Optional[str] = Field(None, description="Hex-encoded origin signature")


class BannedStatus(BaseModel):
    banned: bool
    reason: str


class Peer(BaseModel):
    origin: str


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
