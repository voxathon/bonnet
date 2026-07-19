"""Moderation service — v3 event-derived effective ban evaluation.

Implements Phase 5 of ARTICLE_FEED_PROTOCOL_V3_IMPLEMENTATION_PLAN.md §17:
  - Effective punishment rules from accepted PUNISHMENT events
  - Revocation via PUNISHMENT_REVOKE events
  - Per-origin temporal filter preservation
  - Materialized query methods for reports/punishments by pubkey
  - Control policy filtering (only apply from configured enforcement feeds)

This service wraps ArticleFeedStore and evaluates effective bans from the
punishment_projection table, cross-referencing with PUNISHMENT_REVOKE events.
It is the v3 replacement for Keibatsu's _is_banned logic.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from core.article_feed import (
    EVENT_PUNISHMENT,
    EVENT_PUNISHMENT_REVOKE,
    EVENT_REPORT,
    EVENT_RULE,
    EVENT_RULE_REVOKE,
    PunishmentHeaders,
    ReportHeaders,
    RuleHeaders,
    ArticleFeedStore,
    decode_event,
)
from core.config import Config


@dataclass
class EffectiveBan:
    """Result of an effective-ban evaluation."""
    banned: bool
    reason: str = ""
    punishment_message_id: bytes = b"\x00" * 32
    source_origin: str = ""
    source_board: str = ""
    expires_at: int = 0


class ModerationService:
    """Evaluates effective bans from accepted v3 moderation events."""

    def __init__(self, store: ArticleFeedStore, config: Config):
        self._store = store
        self._config = config

    @property
    def store(self) -> ArticleFeedStore:
        return self._store

    def is_banned(self, pubkey: bytes) -> EffectiveBan:
        """Check if a public key is effectively banned.

        Per §17.1, an effective punishment must:
        1. Come from an accepted event matched by a control_policy whose
           apply includes "punishment".
        2. Have a valid origin/event chain already accepted.
        3. Not be a warning (expires_at == 0).
        4. Be permanent (expires_at < 0) or unexpired.
        5. Not have an applicable later PUNISHMENT_REVOKE event.
        6. Pass the per-origin temporal filter.

        Returns EffectiveBan with banned=True if any active punishment exists.
        """
        now = int(time.time())
        punishments = self._get_active_punishments_for_pubkey(pubkey, now)

        for p in punishments:
            # Check if revoked
            if self._is_revoked(p["message_id"], p["origin"], p["board"]):
                continue

            # Check temporal filter
            if not self._config.record_in_window(p["origin"], p["created_at"]):
                continue

            # Check control policy
            if not self._is_enforceable(p["origin"], p["board"]):
                continue

            # This is an effective ban
            return EffectiveBan(
                banned=True,
                reason=self._get_punishment_reason(p["message_id"]),
                punishment_message_id=p["message_id"],
                source_origin=p["origin"],
                source_board=p["board"],
                expires_at=p["expires_at"],
            )

        return EffectiveBan(banned=False)

    def _get_active_punishments_for_pubkey(self, pubkey: bytes, now: int) -> list:
        """Get all active (non-warning, non-expired) punishment projections
        for a public key, ordered by the deterministic ordering in §17.1."""
        with self._store._lock:
            rows = self._store._conn.execute(
                "SELECT message_id, origin, board, feed_seq, punished_pubkey, "
                "expires_at, created_at, issuer_pubkey, body_hash, revoked_by "
                "FROM punishment_projection "
                "WHERE punished_pubkey=? "
                "AND expires_at != 0 "
                "AND (expires_at < 0 OR expires_at > ?) "
                "ORDER BY created_at DESC, origin ASC, board ASC, feed_seq DESC",
                (pubkey, now),
            ).fetchall()

        results = []
        for row in rows:
            revoked_by = row[9]
            if revoked_by is not None and len(bytes(revoked_by)) == 32 and bytes(revoked_by) != b"\x00" * 32:
                continue  # already revoked in projection
            results.append({
                "message_id": bytes(row[0]),
                "origin": row[1],
                "board": row[2],
                "feed_seq": row[3],
                "punished_pubkey": bytes(row[4]),
                "expires_at": row[5],
                "created_at": row[6],
                "issuer_pubkey": bytes(row[7]),
                "body_hash": bytes(row[8]),
                "revoked_by": bytes(revoked_by) if revoked_by else None,
            })
        return results

    def _is_revoked(self, punishment_message_id: bytes, origin: str, board: str) -> bool:
        """Check if a punishment has been revoked by a PUNISHMENT_REVOKE event."""
        with self._store._lock:
            rows = self._store._conn.execute(
                "SELECT encoded_event FROM feed_events "
                "WHERE origin=? AND board=? AND event_type=? "
                "AND target_message_id=? "
                "ORDER BY feed_seq ASC",
                (origin, board, EVENT_PUNISHMENT_REVOKE, punishment_message_id),
            ).fetchall()
        return len(rows) > 0

    def _is_enforceable(self, origin: str, board: str) -> bool:
        """Check if a (origin, board) feed has a control policy that includes
        'punishment'."""
        policy = self._config.get_control_policy(origin, board)
        if policy is None:
            return False
        return "punishment" in policy.apply

    def _get_punishment_reason(self, message_id: bytes) -> str:
        """Get the reason/notes body for a punishment by fetching its body."""
        event = self._store.get_event_by_message_id(message_id)
        if event is None:
            return "Banned"
        if event.body_size > 0:
            body = self._store.get_body(event.body_hash)
            if body:
                try:
                    return body.decode("utf-8")
                except Exception:
                    return "Banned"
        return "Banned"

    def list_punishments_by_pubkey(self, pubkey: bytes) -> list:
        """List all punishment projections for a public key (including revoked
        and expired, for audit)."""
        with self._store._lock:
            rows = self._store._conn.execute(
                "SELECT message_id, origin, board, feed_seq, punished_pubkey, "
                "expires_at, created_at, issuer_pubkey, body_hash, revoked_by "
                "FROM punishment_projection "
                "WHERE punished_pubkey=? "
                "ORDER BY created_at DESC, origin ASC, board ASC, feed_seq DESC",
                (pubkey,),
            ).fetchall()

        results = []
        for row in rows:
            results.append({
                "message_id": bytes(row[0]),
                "origin": row[1],
                "board": row[2],
                "feed_seq": row[3],
                "punished_pubkey": bytes(row[4]),
                "expires_at": row[5],
                "created_at": row[6],
                "issuer_pubkey": bytes(row[7]),
                "body_hash": bytes(row[8]),
                "revoked_by": bytes(row[9]) if row[9] and len(bytes(row[9])) == 32 else None,
            })
        return results

    def list_reports_by_culprit(self, culprit_pubkey: bytes) -> list:
        """List all REPORT events targeting a culprit public key."""
        with self._store._lock:
            rows = self._store._conn.execute(
                "SELECT encoded_event FROM feed_events "
                "WHERE event_type=? "
                "ORDER BY feed_seq ASC",
                (EVENT_REPORT,),
            ).fetchall()

        results = []
        for row in rows:
            try:
                ev = decode_event(bytes(row[0]))
                if isinstance(ev.headers, ReportHeaders):
                    if ev.headers.culprit_pubkey == culprit_pubkey:
                        results.append(ev)
            except Exception:
                continue
        return results

    def list_rules(self) -> list:
        """List all RULE events from the configured moderation.rules board."""
        mb = self._config.moderation_boards
        with self._store._lock:
            rows = self._store._conn.execute(
                "SELECT encoded_event FROM feed_events "
                "WHERE event_type=? AND board=? "
                "ORDER BY feed_seq ASC",
                (EVENT_RULE, mb.rules),
            ).fetchall()

        results = []
        for row in rows:
            try:
                ev = decode_event(bytes(row[0]))
                results.append(ev)
            except Exception:
                continue
        return results

    def rebuild_punishment_projections(self) -> int:
        """Rebuild all punishment projections from accepted events.

        This is the 'bonnet policy rebuild' operation (§15). It recomputes
        materialized moderation state from accepted events under current
        control policies.
        """
        count = 0
        with self._store._lock:
            # Get all (origin, board) pairs that have PUNISHMENT events
            rows = self._store._conn.execute(
                "SELECT DISTINCT origin, board FROM feed_events "
                "WHERE event_type=?",
                (EVENT_PUNISHMENT,),
            ).fetchall()

            for row in rows:
                origin = row[0]
                board = row[1]
                count += self._store.rebuild_punishment_projection(origin, board)

        # Now update revoked_by for punishments that have been revoked
        self._update_revocations()
        return count

    def _update_revocations(self):
        """Update punishment_projection.revoked_by for all revocations."""
        with self._store._lock:
            # Find all PUNISHMENT_REVOKE events
            rows = self._store._conn.execute(
                "SELECT target_message_id, origin, board, message_id "
                "FROM feed_events "
                "WHERE event_type=?",
                (EVENT_PUNISHMENT_REVOKE,),
            ).fetchall()

            for row in rows:
                target_id = bytes(row[0])
                origin = row[1]
                board = row[2]
                revoke_id = bytes(row[3])
                self._store._conn.execute(
                    "UPDATE punishment_projection SET revoked_by=? "
                    "WHERE message_id=?",
                    (revoke_id, target_id),
                )
            self._store._conn.commit()
