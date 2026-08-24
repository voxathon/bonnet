"""Firehose event store for the Bonnet Firehose Protocol (PROTOCOL.md §14.1).

Phase 1: origin-global append-only event store with per-origin sequence
allocation, board-local article-number counters, signed heads, equivocation
conflict storage, key-epoch tracking for rotation, relay witness storage, and
remote range acceptance with full chain verification.

Uses raw sqlite3 (not core.orm) with BEGIN IMMEDIATE, WAL mode, and a
threading.RLock for writer serialization.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field

from bonnet.core.crypto import Identity
from bonnet.core.logging import log_msg
from bonnet.core.record import (
    HEAD_FORMAT,
    MAX_U63,
    RECORD_FORMAT,
    WITNESS_FORMAT,
    ZERO_HASH,
    ZERO_ID,
    Head,
    Intent,
    Record,
    Witness,
    compute_event_hash,
    compute_head_hash,
    decode_record,
    encode_head,
    encode_intent,
    encode_record,
    encode_unsigned_head,
    encode_unsigned_record,
    reconstruct_intent_from_record,
    sign_head,
    sign_record,
    verify_head_signature,
    verify_intent_signature,
    verify_key_rotation_proof,
    verify_record_signature,
)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class FirehoseError(Exception):
    pass


class EventIdCollision(FirehoseError):
    pass


class ArticleIdCollision(FirehoseError):
    pass


class ChainBreak(FirehoseError):
    pass


class SignatureInvalid(FirehoseError):
    pass


class HeadMismatch(FirehoseError):
    pass


# ---------------------------------------------------------------------------
# Kind constants (§11)
# ---------------------------------------------------------------------------

KIND_ARTICLE = "bonnet.article"
KIND_ORIGIN_KEY_ROTATE = "bonnet.origin.key.rotate"


# ---------------------------------------------------------------------------
# Accept result
# ---------------------------------------------------------------------------


@dataclass
class AcceptResult:
    accepted: bool
    accepted_count: int = 0
    idempotent: bool = False
    conflicts: list = field(default_factory=list)
    reason: str = ""


# ---------------------------------------------------------------------------
# FirehoseStore
# ---------------------------------------------------------------------------


class FirehoseStore:
    """SQLite-backed origin-global firehose event store.

    All origins share one database file but maintain independent chains.
    The local origin appends with BEGIN IMMEDIATE under a single writer lock.
    Remote ranges are verified and accepted atomically.
    """

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._lock = threading.RLock()
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._init_schema()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -----------------------------------------------------------------------
    # Schema
    # -----------------------------------------------------------------------

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                origin              TEXT NOT NULL,
                origin_seq          INTEGER NOT NULL,
                event_hash          BLOB NOT NULL,
                previous_event_hash BLOB NOT NULL,
                event_id            BLOB NOT NULL,
                kind                TEXT NOT NULL,
                schema_version      INTEGER NOT NULL,
                created_at          INTEGER NOT NULL,
                actor_pubkey        BLOB NOT NULL,
                board               TEXT NOT NULL,
                article_id          BLOB NOT NULL,
                article_num         INTEGER NOT NULL,
                target_origin       TEXT NOT NULL,
                target_board        TEXT NOT NULL,
                target_article_id   BLOB NOT NULL,
                target_event_id     BLOB NOT NULL,
                body_hash           BLOB NOT NULL,
                body_size           INTEGER NOT NULL,
                encoded_record      BLOB NOT NULL,
                is_authoritative    INTEGER NOT NULL DEFAULT 0,
                source              TEXT NOT NULL DEFAULT '',
                accepted_at         INTEGER NOT NULL,
                PRIMARY KEY (origin, origin_seq),
                UNIQUE (origin, event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_events_kind
                ON events(origin, kind);
            CREATE INDEX IF NOT EXISTS idx_events_board
                ON events(origin, board, article_num);
            CREATE INDEX IF NOT EXISTS idx_events_target
                ON events(target_origin, target_board, target_article_id);

            CREATE TABLE IF NOT EXISTS origin_heads (
                origin              TEXT NOT NULL,
                latest_origin_seq   INTEGER NOT NULL,
                latest_event_hash   BLOB NOT NULL,
                event_count         INTEGER NOT NULL,
                generated_at        INTEGER NOT NULL,
                origin_pubkey       BLOB NOT NULL,
                origin_signature    BLOB NOT NULL,
                head_hash           BLOB NOT NULL,
                is_authoritative    INTEGER NOT NULL DEFAULT 0,
                observed_at         INTEGER NOT NULL,
                source              TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (origin, latest_origin_seq, head_hash)
            );

            CREATE TABLE IF NOT EXISTS origin_state (
                origin              TEXT PRIMARY KEY,
                highest_seq         INTEGER NOT NULL DEFAULT 0,
                current_event_hash  BLOB NOT NULL DEFAULT x'0000000000000000000000000000000000000000000000000000000000000000',
                current_head_hash   BLOB NOT NULL DEFAULT x'0000000000000000000000000000000000000000000000000000000000000000'
            );

            CREATE TABLE IF NOT EXISTS board_counters (
                origin              TEXT NOT NULL,
                board               TEXT NOT NULL,
                next_article_num    INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (origin, board)
            );

            CREATE TABLE IF NOT EXISTS relay_witnesses (
                event_origin        TEXT NOT NULL,
                event_id            BLOB NOT NULL,
                event_hash          BLOB NOT NULL,
                relay_pubkey        BLOB NOT NULL,
                relay_hostname      TEXT NOT NULL,
                received_from_pubkey BLOB NOT NULL,
                received_from_hostname TEXT NOT NULL,
                seen_at             INTEGER NOT NULL,
                relay_signature     BLOB NOT NULL,
                PRIMARY KEY (event_origin, event_id, relay_pubkey)
            );

            CREATE TABLE IF NOT EXISTS event_conflicts (
                origin              TEXT NOT NULL,
                origin_seq          INTEGER NOT NULL,
                event_hash          BLOB NOT NULL,
                encoded_record      BLOB NOT NULL,
                source              TEXT NOT NULL DEFAULT '',
                observed_at         INTEGER NOT NULL,
                reason              TEXT NOT NULL,
                PRIMARY KEY (origin, origin_seq, event_hash)
            );

            CREATE TABLE IF NOT EXISTS origin_key_epochs (
                origin              TEXT NOT NULL,
                start_seq           INTEGER NOT NULL,
                end_seq             INTEGER,
                publickey           BLOB NOT NULL,
                first_seen          INTEGER NOT NULL,
                PRIMARY KEY (origin, start_seq)
            );

            CREATE TABLE IF NOT EXISTS projection_checkpoints (
                origin              TEXT PRIMARY KEY,
                last_applied_seq    INTEGER NOT NULL DEFAULT 0
            );
        """)

    # -----------------------------------------------------------------------
    # Local publication
    # -----------------------------------------------------------------------

    def append_record(
        self,
        origin_identity: Identity,
        intent: Intent,
        actor_signature: bytes,
        body: bytes,
        created_at: int = None,
    ) -> Record:
        """Accept and append a locally-authored record to the firehose.

        Allocates origin_seq, article_num (if applicable), signs the
        origin record, and updates the head — all in one BEGIN IMMEDIATE
        transaction.

        Raises EventIdCollision if the event_id is already used with
        different content, or ArticleIdCollision for article ID reuse.
        """
        encoded_intent = encode_intent(intent)
        if not verify_intent_signature(intent.actor_pubkey, encoded_intent, actor_signature):
            raise SignatureInvalid("actor signature verification failed")

        body_hash = intent.body_hash
        body_size = intent.body_size
        if body_size > 0:
            from bonnet.core.record import compute_body_hash

            actual_hash = compute_body_hash(body)
            if actual_hash != body_hash or len(body) != body_size:
                raise FirehoseError("body hash or size mismatch")

        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                origin = intent.origin
                row = self._conn.execute(
                    "SELECT highest_seq, current_event_hash FROM origin_state WHERE origin=?",
                    (origin,),
                ).fetchone()

                if row:
                    prev_seq = row[0]
                    prev_hash = bytes(row[1])
                else:
                    prev_seq = 0
                    prev_hash = ZERO_HASH

                origin_seq = prev_seq + 1
                if origin_seq > MAX_U63:
                    raise FirehoseError("origin sequence exhausted")

                existing = self._conn.execute(
                    "SELECT encoded_record FROM events WHERE origin=? AND event_id=?",
                    (origin, intent.event_id),
                ).fetchone()
                if existing:
                    existing_rec = decode_record(bytes(existing[0]))
                    existing_intent = reconstruct_intent_from_record(existing_rec)
                    if encode_intent(existing_intent) == encoded_intent:
                        return existing_rec
                    raise EventIdCollision(
                        f"event_id {intent.event_id.hex()[:16]} already at seq {existing_rec.origin_seq} with different content"
                    )

                article_num = 0
                if intent.kind == KIND_ARTICLE and intent.article_id != ZERO_ID:
                    counter_row = self._conn.execute(
                        "SELECT next_article_num FROM board_counters WHERE origin=? AND board=?",
                        (origin, intent.board),
                    ).fetchone()
                    if counter_row:
                        article_num = counter_row[0]
                        self._conn.execute(
                            "UPDATE board_counters SET next_article_num=? WHERE origin=? AND board=?",
                            (article_num + 1, origin, intent.board),
                        )
                    else:
                        article_num = 1
                        self._conn.execute(
                            "INSERT INTO board_counters (origin, board, next_article_num) VALUES (?, ?, ?)",
                            (origin, intent.board, 2),
                        )

                    art_existing = self._conn.execute(
                        "SELECT 1 FROM events WHERE origin=? AND board=? AND article_id=? AND article_id != x'0000000000000000000000000000000000000000000000000000000000000000'",
                        (origin, intent.board, intent.article_id),
                    ).fetchone()
                    if art_existing:
                        raise ArticleIdCollision(
                            f"article_id {intent.article_id.hex()[:16]} already used in ({origin}, {intent.board})"
                        )

                rec = Record(
                    record_format=RECORD_FORMAT,
                    origin=origin,
                    origin_seq=origin_seq,
                    previous_event_hash=prev_hash,
                    event_id=intent.event_id,
                    kind=intent.kind,
                    schema_version=intent.schema_version,
                    created_at=created_at if created_at is not None else int(time.time()),
                    actor_pubkey=intent.actor_pubkey,
                    actor_username=intent.actor_username,
                    actor_registrar=intent.actor_registrar,
                    board=intent.board,
                    article_id=intent.article_id,
                    article_num=article_num,
                    target_origin=intent.target_origin,
                    target_board=intent.target_board,
                    target_article_id=intent.target_article_id,
                    target_event_id=intent.target_event_id,
                    metadata=intent.metadata,
                    body_hash=body_hash,
                    body_size=body_size,
                    actor_signature=actor_signature,
                )

                unsigned = encode_unsigned_record(rec)
                rec.origin_signature = sign_record(origin_identity, unsigned)
                encoded = encode_record(rec)
                event_hash = compute_event_hash(encoded)

                self._conn.execute(
                    "INSERT INTO events (origin, origin_seq, event_hash, previous_event_hash, "
                    "event_id, kind, schema_version, created_at, actor_pubkey, board, "
                    "article_id, article_num, target_origin, target_board, target_article_id, "
                    "target_event_id, body_hash, body_size, encoded_record, "
                    "is_authoritative, source, accepted_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        origin,
                        origin_seq,
                        event_hash,
                        prev_hash,
                        intent.event_id,
                        intent.kind,
                        intent.schema_version,
                        rec.created_at,
                        intent.actor_pubkey,
                        intent.board,
                        intent.article_id,
                        article_num,
                        intent.target_origin,
                        intent.target_board,
                        intent.target_article_id,
                        intent.target_event_id,
                        body_hash,
                        body_size,
                        encoded,
                        1,
                        "",
                        int(time.time()),
                    ),
                )

                self._update_head_locked(origin, origin_seq, event_hash, origin_identity)

                if intent.kind == KIND_ORIGIN_KEY_ROTATE:
                    self._apply_rotation_locked(origin, origin_seq, intent, origin_identity)

                self._conn.execute(
                    "INSERT OR REPLACE INTO origin_state (origin, highest_seq, current_event_hash, current_head_hash) "
                    "VALUES (?, ?, ?, "
                    "(SELECT head_hash FROM origin_heads WHERE origin=? ORDER BY observed_at DESC LIMIT 1))",
                    (origin, origin_seq, event_hash, origin),
                )

                self._conn.execute("COMMIT")
                return rec
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def _update_head_locked(
        self, origin: str, seq: int, event_hash: bytes, identity: Identity
    ) -> None:
        head = Head(
            head_format=HEAD_FORMAT,
            origin=origin,
            latest_origin_seq=seq,
            latest_event_hash=event_hash,
            event_count=seq,
            generated_at=int(time.time()),
            origin_pubkey=identity.public_key,
        )
        unsigned = encode_unsigned_head(head)
        head.origin_signature = sign_head(identity, unsigned)
        encoded = encode_head(head)
        head_hash = compute_head_hash(encoded)

        self._conn.execute(
            "INSERT OR REPLACE INTO origin_heads "
            "(origin, latest_origin_seq, latest_event_hash, event_count, "
            "generated_at, origin_pubkey, origin_signature, head_hash, "
            "is_authoritative, observed_at, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, '')",
            (
                origin,
                seq,
                event_hash,
                seq,
                head.generated_at,
                identity.public_key,
                head.origin_signature,
                head_hash,
                int(time.time()),
            ),
        )

    # -----------------------------------------------------------------------
    # Key epoch management
    # -----------------------------------------------------------------------

    def init_origin_key(self, origin: str, pubkey: bytes) -> None:
        """Initialize the key epoch for a new origin (TOFU or local)."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    "SELECT 1 FROM origin_key_epochs WHERE origin=?",
                    (origin,),
                ).fetchone()
                if existing:
                    self._conn.execute("ROLLBACK")
                    return
                self._conn.execute(
                    "INSERT INTO origin_key_epochs (origin, start_seq, end_seq, publickey, first_seen) "
                    "VALUES (?, 1, NULL, ?, ?)",
                    (origin, pubkey, int(time.time())),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def get_key_for_seq(self, origin: str, seq: int) -> bytes | None:
        """Return the public key valid for the given origin sequence."""
        with self._lock:
            row = self._conn.execute(
                "SELECT publickey FROM origin_key_epochs "
                "WHERE origin=? AND start_seq<=? "
                "AND (end_seq IS NULL OR end_seq>=?) "
                "ORDER BY start_seq DESC LIMIT 1",
                (origin, seq, seq),
            ).fetchone()
            return bytes(row[0]) if row else None

    def get_current_key(self, origin: str) -> bytes | None:
        """Return the current (latest epoch) public key for an origin."""
        with self._lock:
            row = self._conn.execute(
                "SELECT publickey FROM origin_key_epochs "
                "WHERE origin=? AND end_seq IS NULL "
                "ORDER BY start_seq DESC LIMIT 1",
                (origin,),
            ).fetchone()
            return bytes(row[0]) if row else None

    def _apply_rotation_locked(
        self,
        origin: str,
        seq: int,
        intent: Intent,
        origin_identity: Identity | None,
    ) -> None:
        """Process a bonnet.origin.key.rotate record at sequence N."""
        new_pubkey = intent.metadata.get_bytes(1)
        proof = intent.metadata.get_bytes(2)
        if new_pubkey is None or proof is None:
            raise FirehoseError("rotation record missing required metadata fields")

        old_pubkey = self.get_current_key(origin)
        if old_pubkey is None:
            if origin_identity is not None:
                old_pubkey = origin_identity.public_key
            else:
                raise FirehoseError("no key epoch found for rotation record")

        if not verify_key_rotation_proof(new_pubkey, origin, old_pubkey, proof):
            raise SignatureInvalid("key rotation proof verification failed")

        self._conn.execute(
            "UPDATE origin_key_epochs SET end_seq=? WHERE origin=? AND end_seq IS NULL",
            (seq, origin),
        )
        self._conn.execute(
            "INSERT INTO origin_key_epochs (origin, start_seq, end_seq, publickey, first_seen) "
            "VALUES (?, ?, NULL, ?, ?)",
            (origin, seq + 1, new_pubkey, int(time.time())),
        )

    # -----------------------------------------------------------------------
    # Remote range acceptance
    # -----------------------------------------------------------------------

    def accept_remote_range(
        self,
        origin: str,
        records: list[Record],
        head: Head,
        origin_pubkey: bytes,
        source: str = "",
    ) -> AcceptResult:
        """Accept a contiguous range of remote records verified against a head.

        Implements §17.1 acceptance rules. The caller provides pre-decoded
        records and the signed head. This method verifies chain continuity,
        signatures, collisions, and commits atomically.
        """
        if not records:
            return AcceptResult(accepted=False, reason="empty record range")

        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT highest_seq, current_event_hash FROM origin_state WHERE origin=?",
                    (origin,),
                ).fetchone()
                local_seq = row[0] if row else 0
                local_hash = bytes(row[1]) if row else ZERO_HASH

                first_seq = records[0].origin_seq
                last_seq = records[-1].origin_seq

                if last_seq < local_seq:
                    self._conn.execute("ROLLBACK")
                    return AcceptResult(
                        accepted=False, reason="rollback: range below local sequence"
                    )

                expected_prev = local_hash if first_seq == local_seq + 1 else None
                conflicts = []
                idempotent_count = 0
                newly_accepted = 0
                last_accepted_seq = local_seq
                last_accepted_hash = local_hash
                conflict_found = False

                for rec in records:
                    if rec.origin != origin:
                        self._conn.execute("ROLLBACK")
                        raise FirehoseError(f"record origin {rec.origin!r} != expected {origin!r}")

                    encoded = encode_record(rec)
                    event_hash = compute_event_hash(encoded)

                    existing = self._conn.execute(
                        "SELECT event_hash FROM events WHERE origin=? AND origin_seq=?",
                        (origin, rec.origin_seq),
                    ).fetchone()

                    if existing:
                        existing_hash = bytes(existing[0])
                        if existing_hash == event_hash:
                            idempotent_count += 1
                            expected_prev = event_hash
                            last_accepted_seq = rec.origin_seq
                            last_accepted_hash = event_hash
                            continue
                        else:
                            conflicts.append((rec.origin_seq, event_hash))
                            self._conn.execute(
                                "INSERT OR IGNORE INTO event_conflicts "
                                "(origin, origin_seq, event_hash, encoded_record, source, observed_at, reason) "
                                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                                (
                                    origin,
                                    rec.origin_seq,
                                    event_hash,
                                    encoded,
                                    source,
                                    int(time.time()),
                                    "equivocation: different hash at same seq",
                                ),
                            )
                            conflict_found = True
                            break

                    eid_existing = self._conn.execute(
                        "SELECT 1 FROM events WHERE origin=? AND event_id=?",
                        (origin, rec.event_id),
                    ).fetchone()
                    if eid_existing:
                        self._conn.execute("ROLLBACK")
                        raise EventIdCollision(
                            f"event_id {rec.event_id.hex()[:16]} collision at seq {rec.origin_seq}"
                        )

                    if rec.article_id != ZERO_ID and rec.board:
                        art_existing = self._conn.execute(
                            "SELECT 1 FROM events WHERE origin=? AND board=? AND article_id=?",
                            (origin, rec.board, rec.article_id),
                        ).fetchone()
                        if art_existing:
                            self._conn.execute("ROLLBACK")
                            raise ArticleIdCollision(
                                f"article_id {rec.article_id.hex()[:16]} collision"
                            )

                    if expected_prev is not None:
                        if rec.previous_event_hash != expected_prev:
                            self._conn.execute("ROLLBACK")
                            raise ChainBreak(
                                f"chain break at seq {rec.origin_seq}: previous_event_hash mismatch"
                            )
                    expected_prev = event_hash

                    unsigned = encode_unsigned_record(rec)
                    key = self.get_key_for_seq(origin, rec.origin_seq)
                    if key is None:
                        key = origin_pubkey

                    if not verify_record_signature(key, unsigned, rec.origin_signature):
                        log_msg(
                            f"ACCEPT_RANGE: origin='{origin}' seq={rec.origin_seq} sig_verify FAILED"
                        )
                        log_msg(f"ACCEPT_RANGE:   key_used={key.hex()[:32]}...")
                        log_msg(f"ACCEPT_RANGE:   head_origin_pubkey={origin_pubkey.hex()[:32]}...")
                        log_msg(
                            f"ACCEPT_RANGE:   record_origin_sig={rec.origin_signature.hex()[:32]}..."
                        )
                        log_msg(
                            f"ACCEPT_RANGE:   record_actor_pubkey={rec.actor_pubkey.hex()[:32]}..."
                        )
                        self._conn.execute("ROLLBACK")
                        raise SignatureInvalid(
                            f"origin signature verification failed at seq {rec.origin_seq}"
                        )

                    reconstructed = reconstruct_intent_from_record(rec)
                    if not verify_intent_signature(
                        rec.actor_pubkey,
                        encode_intent(reconstructed),
                        rec.actor_signature,
                    ):
                        self._conn.execute("ROLLBACK")
                        raise SignatureInvalid(
                            f"actor signature verification failed at seq {rec.origin_seq}"
                        )

                    self._conn.execute(
                        "INSERT INTO events (origin, origin_seq, event_hash, previous_event_hash, "
                        "event_id, kind, schema_version, created_at, actor_pubkey, board, "
                        "article_id, article_num, target_origin, target_board, target_article_id, "
                        "target_event_id, body_hash, body_size, encoded_record, "
                        "is_authoritative, source, accepted_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            origin,
                            rec.origin_seq,
                            event_hash,
                            rec.previous_event_hash,
                            rec.event_id,
                            rec.kind,
                            rec.schema_version,
                            rec.created_at,
                            rec.actor_pubkey,
                            rec.board,
                            rec.article_id,
                            rec.article_num,
                            rec.target_origin,
                            rec.target_board,
                            rec.target_article_id,
                            rec.target_event_id,
                            rec.body_hash,
                            rec.body_size,
                            encoded,
                            0,
                            source,
                            int(time.time()),
                        ),
                    )

                    if rec.kind == KIND_ORIGIN_KEY_ROTATE:
                        self._apply_rotation_locked(origin, rec.origin_seq, reconstructed, None)

                    last_accepted_seq = rec.origin_seq
                    last_accepted_hash = event_hash
                    newly_accepted += 1

                if conflict_found:
                    self._conn.execute(
                        "INSERT OR REPLACE INTO origin_state "
                        "(origin, highest_seq, current_event_hash, current_head_hash) "
                        "VALUES (?, ?, ?, "
                        "(SELECT head_hash FROM origin_heads WHERE origin=? ORDER BY observed_at DESC LIMIT 1))",
                        (origin, last_accepted_seq, last_accepted_hash, origin),
                    )
                    self._conn.execute("COMMIT")
                    return AcceptResult(
                        accepted=True,
                        accepted_count=newly_accepted,
                        idempotent=idempotent_count > 0,
                        conflicts=conflicts,
                        reason="equivocation detected; range partially accepted",
                    )

                if head.latest_origin_seq != last_seq:
                    self._conn.execute("ROLLBACK")
                    raise HeadMismatch("head latest_origin_seq does not match last record")

                final_hash = expected_prev if records[-1].origin_seq == last_seq else None
                if final_hash is None:
                    final_hash = compute_event_hash(encode_record(records[-1]))

                if head.latest_event_hash != final_hash:
                    self._conn.execute("ROLLBACK")
                    raise HeadMismatch("head latest_event_hash does not match final event hash")

                if head.event_count != head.latest_origin_seq:
                    self._conn.execute("ROLLBACK")
                    raise HeadMismatch("head event_count does not equal latest_origin_seq")

                unsigned_head = encode_unsigned_head(head)
                head_key = self.get_key_for_seq(origin, head.latest_origin_seq)
                if head_key is None:
                    head_key = origin_pubkey
                if not verify_head_signature(head_key, unsigned_head, head.origin_signature):
                    self._conn.execute("ROLLBACK")
                    raise SignatureInvalid("head signature verification failed")

                encoded_head = encode_head(head)
                head_hash = compute_head_hash(encoded_head)

                self._conn.execute(
                    "INSERT OR REPLACE INTO origin_heads "
                    "(origin, latest_origin_seq, latest_event_hash, event_count, "
                    "generated_at, origin_pubkey, origin_signature, head_hash, "
                    "is_authoritative, observed_at, source) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
                    (
                        origin,
                        head.latest_origin_seq,
                        head.latest_event_hash,
                        head.event_count,
                        head.generated_at,
                        head.origin_pubkey,
                        head.origin_signature,
                        head_hash,
                        int(time.time()),
                        source,
                    ),
                )

                new_seq = max(local_seq, last_seq)
                self._conn.execute(
                    "INSERT OR REPLACE INTO origin_state "
                    "(origin, highest_seq, current_event_hash, current_head_hash) "
                    "VALUES (?, ?, ?, ?)",
                    (origin, new_seq, final_hash, head_hash),
                )

                self._conn.execute("COMMIT")
                return AcceptResult(
                    accepted=True,
                    accepted_count=len(records) - idempotent_count,
                    idempotent=idempotent_count > 0,
                    conflicts=conflicts,
                )
            except Exception:
                try:
                    self._conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise

    # -----------------------------------------------------------------------
    # Head queries
    # -----------------------------------------------------------------------

    def get_head(self, origin: str) -> Head | None:
        """Return the latest head for an origin, or None."""
        with self._lock:
            row = self._conn.execute(
                "SELECT origin_pubkey, origin_signature, latest_origin_seq, "
                "latest_event_hash, event_count, generated_at "
                "FROM origin_heads WHERE origin=? "
                "ORDER BY latest_origin_seq DESC, observed_at DESC LIMIT 1",
                (origin,),
            ).fetchone()
            if not row:
                return None
            return Head(
                head_format=HEAD_FORMAT,
                origin=origin,
                latest_origin_seq=row[2],
                latest_event_hash=bytes(row[3]),
                event_count=row[4],
                generated_at=row[5],
                origin_pubkey=bytes(row[0]),
                origin_signature=bytes(row[1]),
            )

    def get_or_create_empty_head(self, origin: str, identity: Identity) -> Head:
        """Return the current head, or create and store an empty one."""
        existing = self.get_head(origin)
        if existing is not None:
            return existing
        head = Head(
            head_format=HEAD_FORMAT,
            origin=origin,
            origin_pubkey=identity.public_key,
        )
        unsigned = encode_unsigned_head(head)
        head.origin_signature = sign_head(identity, unsigned)
        encoded = encode_head(head)
        head_hash = compute_head_hash(encoded)
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "INSERT OR IGNORE INTO origin_heads "
                    "(origin, latest_origin_seq, latest_event_hash, event_count, "
                    "generated_at, origin_pubkey, origin_signature, head_hash, "
                    "is_authoritative, observed_at, source) "
                    "VALUES (?, 0, ?, 0, ?, ?, ?, ?, 1, ?, '')",
                    (
                        origin,
                        ZERO_HASH,
                        int(time.time()),
                        identity.public_key,
                        head.origin_signature,
                        head_hash,
                        int(time.time()),
                    ),
                )
                self._conn.execute(
                    "INSERT OR IGNORE INTO origin_state (origin, highest_seq, current_event_hash, current_head_hash) "
                    "VALUES (?, 0, ?, ?)",
                    (origin, ZERO_HASH, head_hash),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return head

    # -----------------------------------------------------------------------
    # Event queries
    # -----------------------------------------------------------------------

    def get_event_by_id(self, origin: str, event_id: bytes) -> Record | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT encoded_record FROM events WHERE origin=? AND event_id=?",
                (origin, event_id),
            ).fetchone()
            if not row:
                return None
            return decode_record(bytes(row[0]))

    def get_events_range(self, origin: str, start_seq: int, max_count: int = 100) -> list[Record]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT encoded_record FROM events WHERE origin=? AND origin_seq>=? "
                "ORDER BY origin_seq ASC LIMIT ?",
                (origin, start_seq, max_count),
            ).fetchall()
            return [decode_record(bytes(r[0])) for r in rows]

    def get_highest_seq(self, origin: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT highest_seq FROM origin_state WHERE origin=?",
                (origin,),
            ).fetchone()
            return row[0] if row else 0

    def get_next_article_num(self, origin: str, board: str) -> int:
        """Return the next article number that will be allocated for this board."""
        with self._lock:
            row = self._conn.execute(
                "SELECT next_article_num FROM board_counters WHERE origin=? AND board=?",
                (origin, board),
            ).fetchone()
            return row[0] if row else 1

    # -----------------------------------------------------------------------
    # Witness storage
    # -----------------------------------------------------------------------

    def store_witness(self, w: Witness) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO relay_witnesses "
                "(event_origin, event_id, event_hash, relay_pubkey, relay_hostname, "
                "received_from_pubkey, received_from_hostname, seen_at, relay_signature) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    w.event_origin,
                    w.event_id,
                    w.event_hash,
                    w.relay_pubkey,
                    w.relay_hostname,
                    w.received_from_pubkey,
                    w.received_from_hostname,
                    w.seen_at,
                    w.relay_signature,
                ),
            )
            self._conn.commit()

    def get_witness(
        self, event_origin: str, event_id: bytes, relay_pubkey: bytes
    ) -> Witness | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT event_hash, relay_hostname, received_from_pubkey, "
                "received_from_hostname, seen_at, relay_signature "
                "FROM relay_witnesses WHERE event_origin=? AND event_id=? AND relay_pubkey=?",
                (event_origin, event_id, relay_pubkey),
            ).fetchone()
            if not row:
                return None
            return Witness(
                witness_format=WITNESS_FORMAT,
                event_origin=event_origin,
                event_id=event_id,
                event_hash=bytes(row[0]),
                relay_pubkey=relay_pubkey,
                relay_hostname=row[1],
                received_from_pubkey=bytes(row[2]),
                received_from_hostname=row[3],
                seen_at=row[4],
                relay_signature=bytes(row[5]),
            )

    # -----------------------------------------------------------------------
    # Conflict queries
    # -----------------------------------------------------------------------

    def get_conflicts(self, origin: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT origin_seq, event_hash, source, observed_at, reason "
                "FROM event_conflicts WHERE origin=? ORDER BY origin_seq ASC",
                (origin,),
            ).fetchall()
            return [
                {
                    "origin": origin,
                    "origin_seq": r[0],
                    "event_hash": bytes(r[1]),
                    "source": r[2],
                    "observed_at": r[3],
                    "reason": r[4],
                }
                for r in rows
            ]

    # -----------------------------------------------------------------------
    # Projection checkpoint
    # -----------------------------------------------------------------------

    def get_checkpoint(self, origin: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT last_applied_seq FROM projection_checkpoints WHERE origin=?",
                (origin,),
            ).fetchone()
            return row[0] if row else 0

    def set_checkpoint(self, origin: str, seq: int) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO projection_checkpoints (origin, last_applied_seq) "
                "VALUES (?, ?)",
                (origin, seq),
            )
            self._conn.commit()

    def list_origins(self) -> list[str]:
        with self._lock:
            return [
                r[0]
                for r in self._conn.execute(
                    "SELECT origin FROM origin_state ORDER BY origin"
                ).fetchall()
            ]

    # -----------------------------------------------------------------------
    # Origin lifecycle (depeer/purge/reset-key)
    # -----------------------------------------------------------------------

    def get_origin_summary(self, origin: str) -> dict:
        """Return a summary of stored data for an origin."""
        with self._lock:
            event_count = self._conn.execute(
                "SELECT COUNT(*) FROM events WHERE origin=?", (origin,)
            ).fetchone()[0]
            head_count = self._conn.execute(
                "SELECT COUNT(*) FROM origin_heads WHERE origin=?", (origin,)
            ).fetchone()[0]
            witness_count = self._conn.execute(
                "SELECT COUNT(*) FROM relay_witnesses WHERE event_origin=?", (origin,)
            ).fetchone()[0]
            conflict_count = self._conn.execute(
                "SELECT COUNT(*) FROM event_conflicts WHERE origin=?", (origin,)
            ).fetchone()[0]
            board_count = self._conn.execute(
                "SELECT COUNT(DISTINCT board) FROM events WHERE origin=? AND board != ''", (origin,)
            ).fetchone()[0]
            checkpoint = self.get_checkpoint(origin)
            return {
                "origin": origin,
                "event_count": event_count,
                "head_count": head_count,
                "witness_count": witness_count,
                "conflict_count": conflict_count,
                "board_count": board_count,
                "checkpoint": checkpoint,
            }

    def delete_origin_data(self, origin: str) -> dict:
        """Delete all firehose data for an origin. Returns per-table counts."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                counts = {}
                for table, col in [
                    ("events", "origin"),
                    ("origin_heads", "origin"),
                    ("origin_state", "origin"),
                    ("relay_witnesses", "event_origin"),
                    ("event_conflicts", "origin"),
                    ("origin_key_epochs", "origin"),
                    ("board_counters", "origin"),
                    ("projection_checkpoints", "origin"),
                ]:
                    c = self._conn.execute(f"DELETE FROM {table} WHERE {col}=?", (origin,)).rowcount
                    counts[table] = c
                self._conn.execute("COMMIT")
                return counts
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def reset_origin_key(self, origin: str) -> None:
        """Clear key epoch pinning and origin_state for an origin.

        Forces re-TOFU on next sync. Does not touch events, projections,
        or bodies.
        """
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("DELETE FROM origin_key_epochs WHERE origin=?", (origin,))
                self._conn.execute("DELETE FROM origin_state WHERE origin=?", (origin,))
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
