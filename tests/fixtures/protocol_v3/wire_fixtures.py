"""Protocol v3 deterministic wire fixtures.

Known Ed25519 keypairs (RFC 8032 test vectors) with deterministic signature
outputs. These fixtures allow independent implementations to verify byte-level
compatibility with Bonnet's v3 article feed canonical encoding.

RFC 8032 Section 7.1 Test Vector 1 (origin):
  seed:     9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55
  public:   d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
  private:  9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55

RFC 8032 Section 7.1 Test Vector 2 (author):
  seed:     4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
  public:   3d4017c3e843895a92b70fe74e256d05ccc0b6565e8e28b5e2d3a30f1b3f7a36
  private:  4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb

All fixtures use the Bonnet v3 article feed profile:
  - Event encoding per §8 (strict binary, field order frozen)
  - Submission encoding per §13.4
  - Author signature: SHA-256 domain "bonnet-feed-author-signature-v1"
  - Origin signature: SHA-256 domain "bonnet-feed-origin-signature-v1"
  - Head signature: SHA-256 domain "bonnet-feed-head-signature-v1"
  - Ed25519 signatures via nacl.signing
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from core.crypto import Identity
from core.article_feed import (
    FORMAT_VERSION,
    SUBMISSION_VERSION,
    HEAD_FORMAT_VERSION,
    EVENT_ARTICLE,
    EVENT_CANCEL,
    EVENT_REPORT,
    EVENT_PUNISHMENT,
    SCHEME_V3,
    ZERO_HASH,
    ZERO_MESSAGE_ID,
    Submission,
    Event,
    FeedHead,
    ArticleHeaders,
    ReportHeaders,
    PunishmentHeaders,
    Extension,
    encode_submission,
    decode_submission,
    encode_event,
    decode_event,
    encode_head,
    decode_head,
    make_empty_head,
    compute_event_hash,
    compute_body_hash,
    compute_head_hash,
    author_signature_payload,
    sign_author,
    verify_author_signature,
    sign_origin,
    verify_origin_signature,
    sign_head,
    verify_head_signature,
)

# ---------------------------------------------------------------------------
# Known keypairs (RFC 8032)
# ---------------------------------------------------------------------------

ORIGIN_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55"
)
_origin_identity = Identity.from_private_key(ORIGIN_SEED)
ORIGIN_PUBLIC = _origin_identity.public_key
ORIGIN_PRIVATE = ORIGIN_SEED

AUTHOR_SEED = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
)
_author_identity = Identity.from_private_key(AUTHOR_SEED)
AUTHOR_PUBLIC = _author_identity.public_key
AUTHOR_PRIVATE = AUTHOR_SEED

# ---------------------------------------------------------------------------
# Fixed test parameters
# ---------------------------------------------------------------------------

FIXED_ORIGIN = "bbs.example.com"
FIXED_BOARD = "general"
FIXED_CREATED_AT = 1700000000
FIXED_SNAPSHOT_TS = 1700000100

# Fixed 32-byte message IDs (deterministic, non-zero)
FIXED_ARTICLE_MSGID = bytes(range(0x01, 0x21))  # 0x01..0x20
FIXED_CANCEL_MSGID = bytes(range(0x21, 0x41))  # 0x21..0x40
FIXED_REPORT_MSGID = bytes(range(0x41, 0x61))
FIXED_PUNISHMENT_MSGID = bytes(range(0x61, 0x81))

# Fixed body
FIXED_BODY = b"Hello, article feed world!"
FIXED_BODY_HASH = compute_body_hash(FIXED_BODY)
FIXED_BODY_SIZE = len(FIXED_BODY)

# Empty body hash
EMPTY_BODY_HASH = compute_body_hash(b"")

# ---------------------------------------------------------------------------
# Fixed ARTICLE submission + event
# ---------------------------------------------------------------------------

FIXED_ARTICLE_SUBMISSION = Submission(
    submission_version=SUBMISSION_VERSION,
    event_type=EVENT_ARTICLE,
    origin=FIXED_ORIGIN,
    board=FIXED_BOARD,
    message_id=FIXED_ARTICLE_MSGID,
    created_at=FIXED_CREATED_AT,
    actor_pubkey=AUTHOR_PUBLIC,
    actor_username="alice",
    actor_registrar=FIXED_ORIGIN,
    root_message_id=ZERO_MESSAGE_ID,
    reply_to_message_id=ZERO_MESSAGE_ID,
    supersedes_message_id=ZERO_MESSAGE_ID,
    target_message_id=ZERO_MESSAGE_ID,
    headers=ArticleHeaders(subject="Test Article", tags="test,v3", options=""),
    body_hash=FIXED_BODY_HASH,
    body_size=FIXED_BODY_SIZE,
)

FIXED_ARTICLE_SUBMISSION_BYTES = encode_submission(FIXED_ARTICLE_SUBMISSION)

# Author signature over the submission
FIXED_AUTHOR_SIGNATURE = sign_author(FIXED_ARTICLE_SUBMISSION, _author_identity)

# Complete ARTICLE event (feed_seq=1, article_num=1, previous_event_hash=zeros)
FIXED_ARTICLE_EVENT = Event(
    format_version=FORMAT_VERSION,
    event_type=EVENT_ARTICLE,
    origin=FIXED_ORIGIN,
    board=FIXED_BOARD,
    feed_seq=1,
    previous_event_hash=ZERO_HASH,
    message_id=FIXED_ARTICLE_MSGID,
    article_num=1,
    created_at=FIXED_CREATED_AT,
    actor_pubkey=AUTHOR_PUBLIC,
    actor_username="alice",
    actor_registrar=FIXED_ORIGIN,
    root_message_id=ZERO_MESSAGE_ID,
    reply_to_message_id=ZERO_MESSAGE_ID,
    supersedes_message_id=ZERO_MESSAGE_ID,
    target_message_id=ZERO_MESSAGE_ID,
    headers=ArticleHeaders(subject="Test Article", tags="test,v3", options=""),
    extensions=[],
    body_hash=FIXED_BODY_HASH,
    body_size=FIXED_BODY_SIZE,
    author_signature_scheme=SCHEME_V3,
    author_signature=FIXED_AUTHOR_SIGNATURE,
    origin_signature=b"\x00" * 64,
)
FIXED_ARTICLE_EVENT.origin_signature = sign_origin(FIXED_ARTICLE_EVENT, _origin_identity)

FIXED_ARTICLE_EVENT_BYTES = encode_event(FIXED_ARTICLE_EVENT)
FIXED_ARTICLE_EVENT_HASH = compute_event_hash(FIXED_ARTICLE_EVENT_BYTES)

# ---------------------------------------------------------------------------
# Fixed CANCEL event
# ---------------------------------------------------------------------------

FIXED_CANCEL_SUBMISSION = Submission(
    submission_version=SUBMISSION_VERSION,
    event_type=EVENT_CANCEL,
    origin=FIXED_ORIGIN,
    board=FIXED_BOARD,
    message_id=FIXED_CANCEL_MSGID,
    created_at=FIXED_CREATED_AT + 100,
    actor_pubkey=AUTHOR_PUBLIC,
    actor_username="alice",
    actor_registrar=FIXED_ORIGIN,
    root_message_id=ZERO_MESSAGE_ID,
    reply_to_message_id=ZERO_MESSAGE_ID,
    supersedes_message_id=ZERO_MESSAGE_ID,
    target_message_id=FIXED_ARTICLE_MSGID,
    headers=None,
    body_hash=EMPTY_BODY_HASH,
    body_size=0,
)
FIXED_CANCEL_AUTHOR_SIG = sign_author(FIXED_CANCEL_SUBMISSION, _author_identity)

FIXED_CANCEL_EVENT = Event(
    format_version=FORMAT_VERSION,
    event_type=EVENT_CANCEL,
    origin=FIXED_ORIGIN,
    board=FIXED_BOARD,
    feed_seq=2,
    previous_event_hash=FIXED_ARTICLE_EVENT_HASH,
    message_id=FIXED_CANCEL_MSGID,
    article_num=0,
    created_at=FIXED_CREATED_AT + 100,
    actor_pubkey=AUTHOR_PUBLIC,
    actor_username="alice",
    actor_registrar=FIXED_ORIGIN,
    root_message_id=ZERO_MESSAGE_ID,
    reply_to_message_id=ZERO_MESSAGE_ID,
    supersedes_message_id=ZERO_MESSAGE_ID,
    target_message_id=FIXED_ARTICLE_MSGID,
    headers=None,
    extensions=[],
    body_hash=EMPTY_BODY_HASH,
    body_size=0,
    author_signature_scheme=SCHEME_V3,
    author_signature=FIXED_CANCEL_AUTHOR_SIG,
    origin_signature=b"\x00" * 64,
)
FIXED_CANCEL_EVENT.origin_signature = sign_origin(FIXED_CANCEL_EVENT, _origin_identity)
FIXED_CANCEL_EVENT_BYTES = encode_event(FIXED_CANCEL_EVENT)
FIXED_CANCEL_EVENT_HASH = compute_event_hash(FIXED_CANCEL_EVENT_BYTES)

# ---------------------------------------------------------------------------
# Fixed REPORT event
# ---------------------------------------------------------------------------

FIXED_REPORT_SUBMISSION = Submission(
    submission_version=SUBMISSION_VERSION,
    event_type=EVENT_REPORT,
    origin=FIXED_ORIGIN,
    board=FIXED_BOARD,
    message_id=FIXED_REPORT_MSGID,
    created_at=FIXED_CREATED_AT + 200,
    actor_pubkey=AUTHOR_PUBLIC,
    actor_username="alice",
    actor_registrar=FIXED_ORIGIN,
    root_message_id=ZERO_MESSAGE_ID,
    reply_to_message_id=ZERO_MESSAGE_ID,
    supersedes_message_id=ZERO_MESSAGE_ID,
    target_message_id=ZERO_MESSAGE_ID,
    headers=ReportHeaders(
        culprit_pubkey=ORIGIN_PUBLIC,
        target_origin=FIXED_ORIGIN,
        target_board=FIXED_BOARD,
        target_article_id=FIXED_ARTICLE_MSGID,
        rule_message_ids=[],
        evidence_hashes=[],
    ),
    body_hash=EMPTY_BODY_HASH,
    body_size=0,
)
FIXED_REPORT_AUTHOR_SIG = sign_author(FIXED_REPORT_SUBMISSION, _author_identity)

FIXED_REPORT_EVENT = Event(
    format_version=FORMAT_VERSION,
    event_type=EVENT_REPORT,
    origin=FIXED_ORIGIN,
    board=FIXED_BOARD,
    feed_seq=3,
    previous_event_hash=FIXED_CANCEL_EVENT_HASH,
    message_id=FIXED_REPORT_MSGID,
    article_num=0,
    created_at=FIXED_CREATED_AT + 200,
    actor_pubkey=AUTHOR_PUBLIC,
    actor_username="alice",
    actor_registrar=FIXED_ORIGIN,
    root_message_id=ZERO_MESSAGE_ID,
    reply_to_message_id=ZERO_MESSAGE_ID,
    supersedes_message_id=ZERO_MESSAGE_ID,
    target_message_id=ZERO_MESSAGE_ID,
    headers=ReportHeaders(
        culprit_pubkey=ORIGIN_PUBLIC,
        target_origin=FIXED_ORIGIN,
        target_board=FIXED_BOARD,
        target_article_id=FIXED_ARTICLE_MSGID,
        rule_message_ids=[],
        evidence_hashes=[],
    ),
    extensions=[],
    body_hash=EMPTY_BODY_HASH,
    body_size=0,
    author_signature_scheme=SCHEME_V3,
    author_signature=FIXED_REPORT_AUTHOR_SIG,
    origin_signature=b"\x00" * 64,
)
FIXED_REPORT_EVENT.origin_signature = sign_origin(FIXED_REPORT_EVENT, _origin_identity)
FIXED_REPORT_EVENT_BYTES = encode_event(FIXED_REPORT_EVENT)
FIXED_REPORT_EVENT_HASH = compute_event_hash(FIXED_REPORT_EVENT_BYTES)

# ---------------------------------------------------------------------------
# Fixed PUNISHMENT event
# ---------------------------------------------------------------------------

FIXED_PUNISHMENT_SUBMISSION = Submission(
    submission_version=SUBMISSION_VERSION,
    event_type=EVENT_PUNISHMENT,
    origin=FIXED_ORIGIN,
    board=FIXED_BOARD,
    message_id=FIXED_PUNISHMENT_MSGID,
    created_at=FIXED_CREATED_AT + 300,
    actor_pubkey=ORIGIN_PUBLIC,
    actor_username="admin",
    actor_registrar=FIXED_ORIGIN,
    root_message_id=ZERO_MESSAGE_ID,
    reply_to_message_id=ZERO_MESSAGE_ID,
    supersedes_message_id=ZERO_MESSAGE_ID,
    target_message_id=ZERO_MESSAGE_ID,
    headers=PunishmentHeaders(
        punished_pubkey=AUTHOR_PUBLIC,
        expires_at=-1,
        report_ids=[FIXED_REPORT_MSGID],
        rule_ids=[],
    ),
    body_hash=EMPTY_BODY_HASH,
    body_size=0,
)
FIXED_PUNISHMENT_AUTHOR_SIG = sign_author(
    FIXED_PUNISHMENT_SUBMISSION, _origin_identity
)

FIXED_PUNISHMENT_EVENT = Event(
    format_version=FORMAT_VERSION,
    event_type=EVENT_PUNISHMENT,
    origin=FIXED_ORIGIN,
    board=FIXED_BOARD,
    feed_seq=4,
    previous_event_hash=FIXED_REPORT_EVENT_HASH,
    message_id=FIXED_PUNISHMENT_MSGID,
    article_num=0,
    created_at=FIXED_CREATED_AT + 300,
    actor_pubkey=ORIGIN_PUBLIC,
    actor_username="admin",
    actor_registrar=FIXED_ORIGIN,
    root_message_id=ZERO_MESSAGE_ID,
    reply_to_message_id=ZERO_MESSAGE_ID,
    supersedes_message_id=ZERO_MESSAGE_ID,
    target_message_id=ZERO_MESSAGE_ID,
    headers=PunishmentHeaders(
        punished_pubkey=AUTHOR_PUBLIC,
        expires_at=-1,
        report_ids=[FIXED_REPORT_MSGID],
        rule_ids=[],
    ),
    extensions=[],
    body_hash=EMPTY_BODY_HASH,
    body_size=0,
    author_signature_scheme=SCHEME_V3,
    author_signature=FIXED_PUNISHMENT_AUTHOR_SIG,
    origin_signature=b"\x00" * 64,
)
FIXED_PUNISHMENT_EVENT.origin_signature = sign_origin(
    FIXED_PUNISHMENT_EVENT, _origin_identity
)
FIXED_PUNISHMENT_EVENT_BYTES = encode_event(FIXED_PUNISHMENT_EVENT)
FIXED_PUNISHMENT_EVENT_HASH = compute_event_hash(FIXED_PUNISHMENT_EVENT_BYTES)

# ---------------------------------------------------------------------------
# Fixed feed head (after all 4 events)
# ---------------------------------------------------------------------------

FIXED_HEAD = FeedHead(
    format_version=HEAD_FORMAT_VERSION,
    origin=FIXED_ORIGIN,
    board=FIXED_BOARD,
    latest_feed_seq=4,
    latest_event_hash=FIXED_PUNISHMENT_EVENT_HASH,
    article_count=1,
    event_count=4,
    snapshot_timestamp=FIXED_SNAPSHOT_TS,
    signature=b"\x00" * 64,
)
sign_head(FIXED_HEAD, _origin_identity)
FIXED_HEAD_BYTES = encode_head(FIXED_HEAD)
FIXED_HEAD_HASH = compute_head_hash(FIXED_HEAD_BYTES)

# ---------------------------------------------------------------------------
# Fixed empty head (feed with no events)
# ---------------------------------------------------------------------------

FIXED_EMPTY_HEAD = make_empty_head(FIXED_ORIGIN, FIXED_BOARD, FIXED_SNAPSHOT_TS)
sign_head(FIXED_EMPTY_HEAD, _origin_identity)
FIXED_EMPTY_HEAD_BYTES = encode_head(FIXED_EMPTY_HEAD)
FIXED_EMPTY_HEAD_HASH = compute_head_hash(FIXED_EMPTY_HEAD_BYTES)
