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
    punishment_id: int = Field(..., description="Monotonic punishment ID")
    pubkey: str = Field(..., description="Hex-encoded Ed25519 public key")
    report_ids: list[int]
    expires_at: int = Field(
        ..., description="0=warning, -1=permanent, >0=unix timestamp"
    )
    notes: str
    issued_by: Optional[str] = Field(None, description="Hex-encoded Ed25519 public key of the issuing moderator")
    created_at: int = Field(0, description="Unix timestamp when the punishment was issued")


class BannedStatus(BaseModel):
    banned: bool
    reason: str


class Peer(BaseModel):
    origin: str
