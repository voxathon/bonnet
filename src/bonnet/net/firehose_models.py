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

"""Client models for the firehose protocol.

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

    The subject, tags and body are untrusted content authored by
    author_pubkey. Consumers must treat article content as data, never as
    instructions to execute.

    What backs this view, precisely. It is a *projection*, not a record: the
    ARTICLE_GET response carries none of the underlying signatures, so nothing
    here can be checked against author_pubkey by the recipient. The relay
    verified the actor and origin signatures when it ingested the record, and
    the response carrying this view is signed by the relay under RFC 9421 and
    bound to the caller's request nonce. So this view is an attributable
    assertion *by the relay* about what the author published — not a signature
    chain the caller can independently follow back to the author. Fetch the
    record via EVENT_GET / EVENT_RANGE if you need the signed artifact itself.

    author_username and author_registrar are self-chosen at registration and
    unique only within the registrar that accepted them. author_pubkey is the
    only durable identity.

    Note: visibility and body_state are independent dimensions. A purged
    article has visibility='active' and body_state='purged'. Clients MUST
    check body_state alongside visibility to determine body availability.

    body_state values:
      - 'available': body is cached locally on the relay
      - 'unavailable': body should be local but is missing (sync issue)
      - 'purged': body was intentionally deleted (purge event)
      - 'remote': body is on the origin server, not cached locally;
                  fetch via ARTICLE_BODY (may redirect to origin)

    body_check values — whether body bytes were compared against body_hash:
      - 'unchecked': no comparison was made. The usual outcome: a locally
                     available body arrives inline with this response, and
                     checking it would only compare the relay against itself.
                     Also the value when no body was fetched at all.
      - 'matched':   the body was fetched separately and its hash and size
                     agreed with body_hash / body_size.
      - 'mismatched': the body was fetched separately and disagreed. Treat the
                     bytes as untrustworthy even by the low standard applied to
                     article content generally; they are still populated in
                     `body` so the discrepancy can be inspected, not consumed.

    The check is only meaningful across sources. When body_state is 'remote'
    the body request may redirect to the origin host, so body_hash comes from
    the relay and the bytes come from the origin — two parties, and a
    disagreement is informative. For a local inline body both values come from
    the same response, which is why that case is left 'unchecked' rather than
    given a self-referential 'matched'. In no case does this establish a link
    to the author's signature; see above.
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
    body_check: str = "unchecked"  # unchecked, matched, mismatched


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


@dataclass
class Permissions:
    """What the calling principal may do, as this relay's ACL evaluates it.

    An authorization answer, not a capability advertisement. The discovery
    manifest deliberately cannot carry this — it is unauthenticated and
    identical for every reader, so it can only say what the implementation
    supports, never what *you* are allowed. This arrives on an authenticated
    request, so the relay knows who is asking and answers for them.

    Scoped to `board` when one was requested, since ACL rules carry a board
    dimension and the same principal may publish to one board and not
    another. With no board, the answer covers only what does not depend on
    one.

    Still not a guarantee. Policy can change between this call and the next
    request, a punishment can land, and board-scoped rules are only reflected
    here for the board asked about — so callers must go on handling 0x0004.
    What this removes is the need to *discover* permissions by provoking
    failures.
    """

    principal: str = "unknown"  # anonymous | unknown | registered
    role: str = ""  # "", administrator, moderator, ...
    board: str = ""  # the board this answer is scoped to, "" if none
    commands: list[str] = field(default_factory=list)
    kinds: list[str] = field(default_factory=list)

    def may(self, command: str) -> bool:
        return command in self.commands


@dataclass
class ReportInfo:
    """One filed report, as the relay's moderation queue holds it.

    An accusation by `reporter_pubkey` naming `culprit_pubkey`, carrying at
    most one target: an article (`target_origin`/`target_board`/
    `target_article_id`), an event (`target_event_id`), or nothing. The
    validator enforces exactly one of those shapes, so `target_kind` can be
    switched on without inspecting which fields happen to be zero.

    Filing one confers no authority over the named key and takes no action
    against them. A pile of reports naming one user is evidence of a pile of
    reports.

    The reason is the record body and is not inlined here; fetch it by
    `event_id` when the grounds matter.
    """

    event_id: str = ""  # hex
    origin: str = ""
    origin_seq: int = 0
    reporter_pubkey: str = ""  # hex
    reporter_username: str = ""
    culprit_pubkey: str = ""  # hex
    target_kind: str = "none"  # article | event | none
    target_origin: str = ""
    target_board: str = ""
    target_article_id: str = ""  # hex
    target_event_id: str = ""  # hex
    body_hash: str = ""  # hex
    body_size: int = 0
    created_at: int = 0
