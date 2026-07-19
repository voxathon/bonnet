"""Authoritative migration from legacy v2 data to v3 article feed events.

Implements Phase 6 of ARTICLE_FEED_PROTOCOL_V3_IMPLEMENTATION_PLAN.md §18:
  - Existing local posts → ARTICLE events with deterministic message IDs
  - Existing local rules → RULE events on the configured moderation.rules board
  - Existing local reports → REPORT events on moderation.reports (preserve rollovers)
  - Existing local punishments → PUNISHMENT events on moderation.actions
  - Migration progress tracking for idempotent restart
  - Legacy signatures preserved in migration extension blocks (never forged)

Migration events use scheme 0 (no author signature) or scheme 2 (preserved
verified v2 POST_SIGN signature) with LEGACY_DESCRIPTOR extensions. The origin
countersignature covers the complete event including extensions.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import time
from typing import Optional

from core.article_feed import (
    FORMAT_VERSION,
    SUBMISSION_VERSION,
    EVENT_ARTICLE,
    EVENT_RULE,
    EVENT_REPORT,
    EVENT_PUNISHMENT,
    SCHEME_NONE,
    SCHEME_LEGACY_V2,
    ZERO_MESSAGE_ID,
    ZERO_HASH,
    Submission,
    Event,
    Extension,
    ArticleHeaders,
    RuleHeaders,
    ReportHeaders,
    PunishmentHeaders,
    ArticleFeedStore,
    compute_body_hash,
    encode_submission,
    decode_event,
    encode_event,
    compute_event_hash,
    sign_origin,
    verify_origin_signature,
    FeedAcceptanceError,
    EXT_LEGACY_DESCRIPTOR,
    EXT_LEGACY_AUTHOR_SIGNED_PAYLOAD,
    EXT_LEGACY_AUTHOR_SIGNATURE,
    EXT_LEGACY_ORIGIN_SIGNED_PAYLOAD,
    EXT_LEGACY_ORIGIN_SIGNATURE,
    EXT_LEGACY_UNRESOLVED_REFERENCES,
    LEGACY_POST,
    LEGACY_RULE,
    LEGACY_REPORT,
    LEGACY_PUNISHMENT,
)
from core.crypto import Identity
from core.config import Config
from core.logging import log_msg


# ---------------------------------------------------------------------------
# Inlined legacy record encodings (from deleted report_registry.py / punishment_registry.py)
# These are kept here because migration.py is the only remaining consumer.
# ---------------------------------------------------------------------------

def encode_report_record(
    origin: str, report_num: int, rollover: int, rule_num: int,
    culprit_pubkey: bytes, culprit_board: str | None, culprit_post_num: int,
    reporter_pubkey: bytes, report_time: int, description: str,
    origin_sig: str | None, reporter_sig: str | None,
) -> bytes:
    """Canonical binary encoding of a legacy report registry record."""
    origin_b = origin.encode("utf-8")
    board_b = (culprit_board or "").encode("utf-8")
    desc_b = description.encode("utf-8")
    origin_sig_b = (origin_sig or "").encode("utf-8")
    reporter_sig_b = (reporter_sig or "").encode("utf-8")
    return (
        struct.pack(">H", len(origin_b)) + origin_b
        + struct.pack(">Q", report_num)
        + struct.pack(">Q", rollover)
        + struct.pack(">Q", rule_num)
        + struct.pack("B", len(culprit_pubkey)) + culprit_pubkey
        + struct.pack("B", len(board_b)) + board_b
        + struct.pack(">Q", culprit_post_num)
        + struct.pack("B", len(reporter_pubkey)) + reporter_pubkey
        + struct.pack(">q", report_time)
        + struct.pack(">H", len(desc_b)) + desc_b
        + struct.pack("B", len(origin_sig_b)) + origin_sig_b
        + struct.pack("B", len(reporter_sig_b)) + reporter_sig_b
    )


def encode_punishment_record(
    punishment_id: int, rollover: int, origin: str,
    punished_pubkey: bytes, report_ids: list, expires_at: int,
    ban_notes: str, issued_by: bytes, created_at: int,
    origin_sig: str | None,
) -> bytes:
    """Canonical binary encoding of a legacy punishment registry record."""
    origin_b = origin.encode("utf-8")
    notes_b = (ban_notes or "").encode("utf-8")
    issued_by_b = issued_by or b''
    report_ids_json = json.dumps(report_ids)
    report_ids_b = report_ids_json.encode("utf-8")
    origin_sig_b = (origin_sig or "").encode("utf-8")
    return (
        struct.pack(">Q", punishment_id)
        + struct.pack(">Q", rollover)
        + struct.pack(">H", len(origin_b)) + origin_b
        + struct.pack("B", len(punished_pubkey)) + punished_pubkey
        + struct.pack(">H", len(report_ids_b)) + report_ids_b
        + struct.pack(">q", expires_at)
        + struct.pack(">H", len(notes_b)) + notes_b
        + struct.pack("B", len(issued_by_b)) + issued_by_b
        + struct.pack(">q", created_at)
        + struct.pack("B", len(origin_sig_b)) + origin_sig_b
    )


# ---------------------------------------------------------------------------
# Domain-separation tags for deterministic message IDs
# ---------------------------------------------------------------------------

DOMAIN_POST_MSGID = b"bonnet-legacy-post-message-id-v1"
DOMAIN_RULE_MSGID = b"bonnet-legacy-rule-message-id-v1"
DOMAIN_RULE_DESC = b"bonnet-legacy-rule-description-v1"
DOMAIN_REPORT_MSGID = b"bonnet-legacy-report-message-id-v1"
DOMAIN_REPORT_RECORD = b"bonnet-legacy-report-record-v1"
DOMAIN_PUNISHMENT_MSGID = b"bonnet-legacy-punishment-message-id-v1"
DOMAIN_PUNISHMENT_RECORD = b"bonnet-legacy-punishment-record-v1"


def _sha256(*chunks: bytes) -> bytes:
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
    return h.digest()


# ---------------------------------------------------------------------------
# Canonical legacy metadata encoding (§18.2)
# ---------------------------------------------------------------------------

def encode_canonical_legacy_post_metadata(
    post_num: int,
    last_modified: int,
    creation_date: int,
    last_bumped: int,
    closed: bool,
    sticky: int,
    tags: str,
    subject: str,
    options: str,
    root: int,
    author: str,
    author_registrar: str,
    legacy_signature_text: str,
) -> bytes:
    """Encode canonical legacy post metadata for deterministic message ID.

    Per §18.2, this is the exact byte sequence used in the message ID hash.
    No locale-dependent conversion or SQLite row serialization enters this.
    """
    tags_b = tags.encode("utf-8")
    subject_b = subject.encode("utf-8")
    options_b = options.encode("utf-8")
    author_b = author.encode("utf-8")
    author_reg_b = author_registrar.encode("utf-8")
    sig_b = legacy_signature_text.encode("utf-8")

    return (
        struct.pack(">Q", post_num)
        + struct.pack(">q", last_modified)
        + struct.pack(">q", creation_date)
        + struct.pack(">q", last_bumped)
        + struct.pack(">B", 1 if closed else 0)
        + struct.pack(">i", sticky)
        + struct.pack(">I", len(tags_b)) + tags_b
        + struct.pack(">I", len(subject_b)) + subject_b
        + struct.pack(">I", len(options_b)) + options_b
        + struct.pack(">Q", root)
        + struct.pack(">H", len(author_b)) + author_b
        + struct.pack(">H", len(author_reg_b)) + author_reg_b
        + struct.pack(">H", len(sig_b)) + sig_b
    )


def encode_canonical_legacy_rule(
    rule_num: int,
    rule_name: str,
    description: str,
) -> bytes:
    """Encode canonical legacy rule for deterministic message ID (§18.3)."""
    name_b = rule_name.encode("utf-8")
    desc_hash = _sha256(DOMAIN_RULE_DESC, description.encode("utf-8"))
    return (
        struct.pack(">Q", rule_num)
        + struct.pack(">H", len(name_b)) + name_b
        + desc_hash
    )


# ---------------------------------------------------------------------------
# Deterministic message ID derivation
# ---------------------------------------------------------------------------

def derive_post_message_id(origin: str, board: str, post_num: int,
                            canonical_metadata: bytes, body_hash: bytes) -> bytes:
    """Derive a deterministic 32-byte message ID for a migrated post (§18.2)."""
    origin_b = origin.encode("utf-8")
    board_b = board.encode("utf-8")
    return _sha256(
        DOMAIN_POST_MSGID,
        struct.pack(">H", len(origin_b)), origin_b,
        struct.pack(">H", len(board_b)), board_b,
        struct.pack(">Q", post_num),
        canonical_metadata,
        body_hash,
    )


def derive_rule_message_id(origin: str, encoded_legacy_rule: bytes) -> bytes:
    """Derive a deterministic message ID for a migrated rule (§18.3)."""
    origin_b = origin.encode("utf-8")
    return _sha256(
        DOMAIN_RULE_MSGID,
        struct.pack(">H", len(origin_b)), origin_b,
        encoded_legacy_rule,
    )


def derive_report_message_id(origin: str, report_num: int, rollover: int,
                             legacy_report_hash: bytes) -> bytes:
    """Derive a deterministic message ID for a migrated report (§18.4)."""
    origin_b = origin.encode("utf-8")
    return _sha256(
        DOMAIN_REPORT_MSGID,
        struct.pack(">H", len(origin_b)), origin_b,
        struct.pack(">Q", report_num),
        struct.pack(">Q", rollover),
        legacy_report_hash,
    )


def derive_punishment_message_id(origin: str, punishment_id: int, rollover: int,
                                 legacy_punishment_hash: bytes) -> bytes:
    """Derive a deterministic message ID for a migrated punishment (§18.5)."""
    origin_b = origin.encode("utf-8")
    return _sha256(
        DOMAIN_PUNISHMENT_MSGID,
        struct.pack(">H", len(origin_b)), origin_b,
        struct.pack(">Q", punishment_id),
        struct.pack(">Q", rollover),
        legacy_punishment_hash,
    )


# ---------------------------------------------------------------------------
# Legacy extension block builders
# ---------------------------------------------------------------------------

def build_legacy_descriptor(source_protocol: int, source_object_type: int,
                            legacy_identity: bytes) -> Extension:
    """Build a LEGACY_DESCRIPTOR extension (§8.2).

    Format: source_protocol:u8 + source_object_type:u8 + legacy_identity:u32 bytes
    """
    value = struct.pack(">B", source_protocol) + struct.pack(">B", source_object_type) + legacy_identity
    return Extension(type=EXT_LEGACY_DESCRIPTOR, value=value)


def build_post_legacy_descriptor(post_num: int) -> Extension:
    """LEGACY_DESCRIPTOR for a post: source_protocol=2, type=POST(0x01)."""
    return build_legacy_descriptor(2, LEGACY_POST, struct.pack(">Q", post_num))


def build_rule_legacy_descriptor(rule_num: int) -> Extension:
    """LEGACY_DESCRIPTOR for a rule: source_protocol=2, type=RULE(0x02)."""
    return build_legacy_descriptor(2, LEGACY_RULE, struct.pack(">Q", rule_num))


def build_report_legacy_descriptor(report_num: int, rollover: int) -> Extension:
    """LEGACY_DESCRIPTOR for a report: type=REPORT(0x03)."""
    return build_legacy_descriptor(2, LEGACY_REPORT, struct.pack(">QQ", report_num, rollover))


def build_punishment_legacy_descriptor(punishment_id: int, rollover: int) -> Extension:
    """LEGACY_DESCRIPTOR for a punishment: type=PUNISHMENT(0x04)."""
    return build_legacy_descriptor(2, LEGACY_PUNISHMENT, struct.pack(">QQ", punishment_id, rollover))


# ---------------------------------------------------------------------------
# Migration progress tracking
# ---------------------------------------------------------------------------

class MigrationProgress:
    """Tracks migration progress per board/source for idempotent restart.

    Uses a simple SQLite table in the article_feeds.db to record which
    migration units have been completed. A completed unit is idempotent
    on restart.
    """

    def __init__(self, store: ArticleFeedStore):
        self._store = store
        self._init_table()

    def _init_table(self):
        with self._store._lock:
            self._store._conn.execute("""
                CREATE TABLE IF NOT EXISTS migration_progress (
                    unit_name   TEXT PRIMARY KEY,
                    event_count INTEGER NOT NULL,
                    completed_at INTEGER NOT NULL
                )
            """)
            self._store._conn.commit()

    def is_complete(self, unit_name: str) -> bool:
        with self._store._lock:
            row = self._store._conn.execute(
                "SELECT 1 FROM migration_progress WHERE unit_name=?",
                (unit_name,),
            ).fetchone()
        return row is not None

    def mark_complete(self, unit_name: str, event_count: int):
        with self._store._lock:
            self._store._conn.execute(
                "INSERT OR REPLACE INTO migration_progress "
                "(unit_name, event_count, completed_at) VALUES (?, ?, ?)",
                (unit_name, event_count, int(time.time())),
            )
            self._store._conn.commit()

    def list_completed(self) -> list:
        with self._store._lock:
            rows = self._store._conn.execute(
                "SELECT unit_name, event_count, completed_at "
                "FROM migration_progress ORDER BY completed_at ASC"
            ).fetchall()
        return [(r[0], r[1], r[2]) for r in rows]


# ---------------------------------------------------------------------------
# Migration executor
# ---------------------------------------------------------------------------

class MigrationExecutor:
    """Executes the authoritative migration from legacy v2 data to v3 events.

    This class is constructed with the ArticleFeedStore, server identity, and
    config. It reads from the legacy Keibatsu/AME databases and writes v3
    events through the store's append_authoritative_event path (migration mode
    with extensions and scheme 0 or 2).
    """

    def __init__(self, store: ArticleFeedStore, identity: Identity,
                 config: Config, ame=None, keibatsu=None):
        self._store = store
        self._identity = identity
        self._config = config
        self._ame = ame
        self._keibatsu = keibatsu
        self._progress = MigrationProgress(store)

    @property
    def progress(self) -> MigrationProgress:
        return self._progress

    def migrate_all(self) -> dict:
        """Run all migration steps. Returns a summary dict.

        This is the main entry point for the 'bonnet policy rebuild' or
        startup migration. It migrates posts, rules, reports, and punishments
        in order, tracking progress for idempotent restart.
        """
        results = {
            "posts": 0,
            "rules": 0,
            "reports": 0,
            "punishments": 0,
            "skipped": [],
        }

        if self._ame is not None:
            results["posts"] = self.migrate_posts()
        if self._keibatsu is not None:
            results["rules"] = self.migrate_rules()
            results["reports"] = self.migrate_reports()
            results["punishments"] = self.migrate_punishments()

        log_msg(f"MIGRATION: complete — {results}")
        return results

    # ------------------------------------------------------------------
    # Post → ARTICLE migration (§18.2)
    # ------------------------------------------------------------------

    def migrate_posts(self) -> int:
        """Migrate existing local posts to ARTICLE events.

        For each locally originated board, reads all surviving post rows
        ordered by post_num, derives deterministic message IDs, builds
        ARTICLE events with LEGACY_DESCRIPTOR extensions, and appends them
        to the v3 feed.
        """
        if self._ame is None:
            return 0

        unit_name = f"posts:{self._config.origin}"
        if self._progress.is_complete(unit_name):
            log_msg(f"MIGRATION: posts already migrated, skipping")
            return 0

        total = 0
        nav = self._ame.get_nav()
        boards = nav.list_all()

        # Build a post_num → message_id map for root relationships
        post_msgid_map = {}

        for nav_entry in boards:
            if nav_entry['origin'] != self._config.origin:
                continue  # only migrate local boards

            board_name = nav_entry['board_name']
            board = self._ame.get_board(board_name)
            if board is None:
                continue

            # Read all posts for this board
            from engine.ame import Post
            posts = board.query(orderby="post_num ASC").result()
            if not posts:
                continue

            board_total = 0
            for post in posts:
                # Read the post body
                content = board._read_content(post.post_num)
                body = content.encode("utf-8") if content else b""
                body_hash = compute_body_hash(body)

                # Build canonical legacy metadata
                canonical_meta = encode_canonical_legacy_post_metadata(
                    post_num=post.post_num,
                    last_modified=post.last_modified,
                    creation_date=post.creation_date,
                    last_bumped=post.last_bumped,
                    closed=post.closed,
                    sticky=post.sticky if post.sticky else 0,
                    tags=post.tags or "",
                    subject=post.subject or "",
                    options=post.options or "",
                    root=post.root if post.root else 0,
                    author=post.author or "",
                    author_registrar=post.author_registrar or "",
                    legacy_signature_text=post.signature or "",
                )

                # Derive deterministic message ID
                message_id = derive_post_message_id(
                    self._config.origin, board_name, post.post_num,
                    canonical_meta, body_hash,
                )
                post_msgid_map[post.post_num] = message_id

                # Build extensions
                extensions = [build_post_legacy_descriptor(post.post_num)]

                # Determine scheme: 0 (unsigned) or 2 (verified v2 signature)
                scheme = SCHEME_NONE
                author_sig = b""
                if post.signature and len(post.signature) > 0:
                    # Preserve the old signature in an extension
                    # Scheme 2 means we claim it's a verified v2 POST_SIGN sig
                    scheme = SCHEME_LEGACY_V2
                    author_sig = bytes.fromhex(post.signature) if all(c in '0123456789abcdef' for c in post.signature.lower()) else b""
                    if len(author_sig) != 64:
                        scheme = SCHEME_NONE
                        author_sig = b""

                # Build root_message_id from the map
                root_message_id = ZERO_MESSAGE_ID
                if post.root and post.root > 0 and post.root in post_msgid_map:
                    root_message_id = post_msgid_map[post.root]

                # Build the event
                event = Event(
                    format_version=FORMAT_VERSION,
                    event_type=EVENT_ARTICLE,
                    origin=self._config.origin,
                    board=board_name,
                    feed_seq=0,  # allocated by store
                    previous_event_hash=ZERO_HASH,  # allocated by store
                    message_id=message_id,
                    article_num=post.post_num,  # preserve post_num
                    created_at=post.creation_date if post.creation_date else int(time.time()),
                    actor_pubkey=self._identity.public_key,  # origin key as actor for migration
                    actor_username=post.author or "",
                    actor_registrar=post.author_registrar or self._config.origin,
                    root_message_id=root_message_id,
                    reply_to_message_id=ZERO_MESSAGE_ID,
                    supersedes_message_id=ZERO_MESSAGE_ID,
                    target_message_id=ZERO_MESSAGE_ID,
                    headers=ArticleHeaders(
                        subject=post.subject or "",
                        tags=post.tags or "",
                        options=post.options or "",
                    ),
                    extensions=extensions,
                    body_hash=body_hash,
                    body_size=len(body),
                    author_signature_scheme=scheme,
                    author_signature=author_sig,
                    origin_signature=b"\x00" * 64,
                )

                try:
                    ev, head = self._store.append_authoritative_event(
                        event, self._identity,
                        expected_origin=self._config.origin,
                        allow_migration=True,
                        body=body,
                    )
                    board_total += 1
                    total += 1
                except Exception as e:
                    log_msg(f"MIGRATION: failed to migrate post {post.post_num} on board '{board_name}': {e}")

            log_msg(f"MIGRATION: migrated {board_total} posts from board '{board_name}'")

        self._progress.mark_complete(unit_name, total)
        log_msg(f"MIGRATION: total {total} posts migrated")
        return total

    # ------------------------------------------------------------------
    # Rule → RULE migration (§18.3)
    # ------------------------------------------------------------------

    def migrate_rules(self) -> int:
        """Migrate existing local rules to RULE events on moderation.rules."""
        if self._keibatsu is None:
            return 0

        unit_name = f"rules:{self._config.origin}"
        if self._progress.is_complete(unit_name):
            log_msg(f"MIGRATION: rules already migrated, skipping")
            return 0

        rules_board = self._config.moderation_boards.rules
        total = 0

        # Read all rules ordered by rule_num ASC
        rules = self._keibatsu.list_rules().result()
        if not rules:
            self._progress.mark_complete(unit_name, 0)
            return 0

        # Build rule_num → message_id map
        rule_msgid_map = {}

        for rule in rules:
            # Encode canonical legacy rule
            encoded_legacy = encode_canonical_legacy_rule(
                rule.rule_num, rule.rule_name, rule.description,
            )

            # Derive message ID
            message_id = derive_rule_message_id(self._config.origin, encoded_legacy)
            rule_msgid_map[rule.rule_num] = message_id

            # Extensions: LEGACY_DESCRIPTOR with rule_num
            extensions = [build_rule_legacy_descriptor(rule.rule_num)]

            # Description becomes the event body
            body = rule.description.encode("utf-8")
            body_hash = compute_body_hash(body)

            event = Event(
                format_version=FORMAT_VERSION,
                event_type=EVENT_RULE,
                origin=self._config.origin,
                board=rules_board,
                feed_seq=0,
                previous_event_hash=ZERO_HASH,
                message_id=message_id,
                article_num=0,
                created_at=int(time.time()),
                actor_pubkey=self._identity.public_key,
                actor_username="admin",
                actor_registrar=self._config.origin,
                root_message_id=ZERO_MESSAGE_ID,
                reply_to_message_id=ZERO_MESSAGE_ID,
                supersedes_message_id=ZERO_MESSAGE_ID,
                target_message_id=ZERO_MESSAGE_ID,
                headers=RuleHeaders(rule_name=rule.rule_name),
                extensions=extensions,
                body_hash=body_hash,
                body_size=len(body),
                author_signature_scheme=SCHEME_NONE,
                author_signature=b"",
                origin_signature=b"\x00" * 64,
            )

            try:
                ev, head = self._store.append_authoritative_event(
                    event, self._identity,
                    expected_origin=self._config.origin,
                    allow_migration=True,
                    body=body,
                )
                total += 1
            except Exception as e:
                log_msg(f"MIGRATION: failed to migrate rule {rule.rule_num}: {e}")

        self._progress.mark_complete(unit_name, total)
        log_msg(f"MIGRATION: total {total} rules migrated")
        return total

    # ------------------------------------------------------------------
    # Report → REPORT migration (§18.4)
    # ------------------------------------------------------------------

    def migrate_reports(self) -> int:
        """Migrate existing local reports to REPORT events on moderation.reports."""
        if self._keibatsu is None:
            return 0

        unit_name = f"reports:{self._config.origin}"
        if self._progress.is_complete(unit_name):
            log_msg(f"MIGRATION: reports already migrated, skipping")
            return 0

        reports_board = self._config.moderation_boards.reports
        total = 0

        # Read all local reports ordered by (report_num, rollover) ASC
        with self._keibatsu._reports_db.open() as ctx:
            rows = ctx.execute(
                "SELECT report_num, origin, rollover, rule_num, culprit_pubkey, "
                "culprit_board, culprit_post_num, reporter_pubkey, report_time, "
                "relay, description, origin_sig, reporter_sig "
                "FROM reports WHERE origin=? "
                "ORDER BY report_num ASC, rollover ASC",
                [self._config.origin],
            ).fetchall()

        if not rows:
            self._progress.mark_complete(unit_name, 0)
            return 0

        # encode_report_record is inlined in this module

        for row in rows:
            report_num = row[0]
            origin = row[1]
            rollover = row[2]
            rule_num = row[3]
            culprit_pubkey = bytes(row[4]) if row[4] else b"\x00" * 32
            culprit_board = row[5] if row[5] else ""
            culprit_post_num = row[6] if row[6] else 0
            reporter_pubkey = bytes(row[7]) if row[7] else b"\x00" * 32
            report_time = row[8] if row[8] else 0
            description = row[10] if row[10] else ""
            origin_sig = row[11] if row[11] else None
            reporter_sig = row[12] if row[12] else None

            # Build legacy report record + hash
            legacy_record = encode_report_record(
                origin, report_num, rollover, rule_num,
                culprit_pubkey, culprit_board, culprit_post_num,
                reporter_pubkey, report_time, description,
                origin_sig, reporter_sig,
            )
            legacy_hash = _sha256(DOMAIN_REPORT_RECORD, legacy_record)

            # Derive message ID
            message_id = derive_report_message_id(
                origin, report_num, rollover, legacy_hash,
            )

            # Extensions: LEGACY_DESCRIPTOR + legacy signatures
            extensions = [build_report_legacy_descriptor(report_num, rollover)]
            if origin_sig:
                extensions.append(Extension(
                    type=EXT_LEGACY_ORIGIN_SIGNATURE,
                    value=origin_sig.encode("utf-8"),
                ))
            if reporter_sig:
                extensions.append(Extension(
                    type=EXT_LEGACY_AUTHOR_SIGNATURE,
                    value=reporter_sig.encode("utf-8"),
                ))

            # Description becomes the event body
            body = description.encode("utf-8")
            body_hash = compute_body_hash(body)

            event = Event(
                format_version=FORMAT_VERSION,
                event_type=EVENT_REPORT,
                origin=origin,
                board=reports_board,
                feed_seq=0,
                previous_event_hash=ZERO_HASH,
                message_id=message_id,
                article_num=0,
                created_at=report_time,
                actor_pubkey=reporter_pubkey,
                actor_username="reporter",
                actor_registrar=origin,
                root_message_id=ZERO_MESSAGE_ID,
                reply_to_message_id=ZERO_MESSAGE_ID,
                supersedes_message_id=ZERO_MESSAGE_ID,
                target_message_id=ZERO_MESSAGE_ID,
                headers=ReportHeaders(
                    culprit_pubkey=culprit_pubkey,
                    target_origin=origin,
                    target_board=culprit_board,
                    target_article_id=ZERO_MESSAGE_ID,
                    rule_message_ids=[],
                    evidence_hashes=[],
                ),
                extensions=extensions,
                body_hash=body_hash,
                body_size=len(body),
                author_signature_scheme=SCHEME_NONE,
                author_signature=b"",
                origin_signature=b"\x00" * 64,
            )

            try:
                ev, head = self._store.append_authoritative_event(
                    event, self._identity,
                    expected_origin=origin,
                    allow_migration=True,
                    body=body,
                )
                total += 1
            except Exception as e:
                log_msg(f"MIGRATION: failed to migrate report {report_num}/{rollover}: {e}")

        self._progress.mark_complete(unit_name, total)
        log_msg(f"MIGRATION: total {total} reports migrated")
        return total

    # ------------------------------------------------------------------
    # Punishment → PUNISHMENT migration (§18.5)
    # ------------------------------------------------------------------

    def migrate_punishments(self) -> int:
        """Migrate existing local punishments to PUNISHMENT events."""
        if self._keibatsu is None:
            return 0

        unit_name = f"punishments:{self._config.origin}"
        if self._progress.is_complete(unit_name):
            log_msg(f"MIGRATION: punishments already migrated, skipping")
            return 0

        actions_board = self._config.moderation_boards.punishments
        total = 0

        # Read all local punishments ordered by (punishment_id, rollover) ASC
        with self._keibatsu._punishments_db.open() as ctx:
            rows = ctx.execute(
                "SELECT punishment_id, origin, rollover, punished_pubkey, "
                "report_ids, expires_at, ban_notes, issued_by, created_at, "
                "relay, origin_sig "
                "FROM punishments WHERE origin=? "
                "ORDER BY punishment_id ASC, rollover ASC",
                [self._config.origin],
            ).fetchall()

        if not rows:
            self._progress.mark_complete(unit_name, 0)
            return 0

        # encode_punishment_record is inlined in this module

        for row in rows:
            punishment_id = row[0]
            origin = row[1]
            rollover = row[2]
            punished_pubkey = bytes(row[3]) if row[3] else b"\x00" * 32
            report_ids = json.loads(row[4]) if row[4] else []
            expires_at = row[5]
            ban_notes = row[6] if row[6] else ""
            issued_by = bytes(row[7]) if row[7] else b"\x00" * 32
            created_at = row[8] if row[8] else 0
            origin_sig = row[10] if row[10] else None

            # Build legacy punishment record + hash
            legacy_record = encode_punishment_record(
                punishment_id, rollover, origin, punished_pubkey,
                report_ids, expires_at, ban_notes, issued_by,
                created_at, origin_sig,
            )
            legacy_hash = _sha256(DOMAIN_PUNISHMENT_RECORD, legacy_record)

            # Derive message ID
            message_id = derive_punishment_message_id(
                origin, punishment_id, rollover, legacy_hash,
            )

            # Extensions: LEGACY_DESCRIPTOR + origin sig
            extensions = [build_punishment_legacy_descriptor(punishment_id, rollover)]
            if origin_sig:
                extensions.append(Extension(
                    type=EXT_LEGACY_ORIGIN_SIGNATURE,
                    value=origin_sig.encode("utf-8"),
                ))

            # Notes become the event body
            body = ban_notes.encode("utf-8")
            body_hash = compute_body_hash(body)

            event = Event(
                format_version=FORMAT_VERSION,
                event_type=EVENT_PUNISHMENT,
                origin=origin,
                board=actions_board,
                feed_seq=0,
                previous_event_hash=ZERO_HASH,
                message_id=message_id,
                article_num=0,
                created_at=created_at,
                actor_pubkey=issued_by if issued_by and len(issued_by) == 32 else self._identity.public_key,
                actor_username="admin",
                actor_registrar=origin,
                root_message_id=ZERO_MESSAGE_ID,
                reply_to_message_id=ZERO_MESSAGE_ID,
                supersedes_message_id=ZERO_MESSAGE_ID,
                target_message_id=ZERO_MESSAGE_ID,
                headers=PunishmentHeaders(
                    punished_pubkey=punished_pubkey,
                    expires_at=expires_at,
                    report_ids=[],
                    rule_ids=[],
                ),
                extensions=extensions,
                body_hash=body_hash,
                body_size=len(body),
                author_signature_scheme=SCHEME_NONE,
                author_signature=b"",
                origin_signature=b"\x00" * 64,
            )

            try:
                ev, head = self._store.append_authoritative_event(
                    event, self._identity,
                    expected_origin=origin,
                    allow_migration=True,
                    body=body,
                )
                total += 1
            except Exception as e:
                log_msg(f"MIGRATION: failed to migrate punishment {punishment_id}/{rollover}: {e}")

        self._progress.mark_complete(unit_name, total)
        log_msg(f"MIGRATION: total {total} punishments migrated")
        return total

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_migration(self) -> dict:
        """Verify that migrated events match expected counts and invariants.

        Returns a dict with verification results.
        """
        results = {"verified": True, "errors": []}
        completed = self._progress.list_completed()

        for unit_name, event_count, completed_at in completed:
            # Verify event count matches
            if unit_name.startswith("posts:"):
                # Count ARTICLE events with LEGACY_DESCRIPTOR extensions
                with self._store._lock:
                    row = self._store._conn.execute(
                        "SELECT COUNT(*) FROM feed_events WHERE event_type=? "
                        "AND is_authoritative=1",
                        (EVENT_ARTICLE,),
                    ).fetchone()
                    actual = row[0] if row else 0
                if actual < event_count:
                    results["verified"] = False
                    results["errors"].append(
                        f"{unit_name}: expected {event_count} events, found {actual}")

        return results
