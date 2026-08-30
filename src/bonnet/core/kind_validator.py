"""Kind-specific validation for the firehose protocol.

Enforces schema rules: required metadata fields, target tuple completeness,
same-origin restrictions, board/user lifecycle constraints, and report/punishment
target rules. Called before origin acceptance of a publication request.
"""

from __future__ import annotations

from collections.abc import Callable

from bonnet.core.kinds import (
    ALL_KNOWN_KINDS,
    ARTICLE_LIFECYCLE_KINDS,
    BOARD_LIFECYCLE_KINDS,
    KIND_ARTICLE,
    KIND_ARTICLE_PIN,
    KIND_BOARD_CREATE,
    KIND_ORIGIN_KEY_ROTATE,
    KIND_PUNISHMENT_ACK,
    KIND_PUNISHMENT_BAN,
    KIND_PUNISHMENT_REVOKE,
    KIND_REPORT,
    KIND_RULE_PUBLISH,
    KIND_RULE_REVOKE,
    KIND_USER_KEY_ROTATE,
    KIND_USER_REGISTER,
    KIND_USER_REVOKE,
    PIN_THREAD_CONTROL_KINDS,
    PUNISHMENT_ISSUE_KINDS,
)
from bonnet.core.record import ZERO_ID, Intent

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ValidationError(Exception):
    pass


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


class KindValidator:
    """Validates an Intent against its kind schema.

    Dispatch is a registry (kind -> validator method) built once at
    construction, rather than an inline elif chain, so a new kind is added
    in one place: a KIND_* constant in kinds.py, a `_validate_*` method
    below, and one line registering the two.
    """

    def __init__(self) -> None:
        self._validators: dict[str, Callable[[Intent], None]] = {
            KIND_ARTICLE: self._validate_article,
            KIND_USER_REGISTER: self._validate_user_register,
            KIND_USER_REVOKE: self._validate_user_revoke,
            KIND_USER_KEY_ROTATE: self._validate_user_key_rotate,
            KIND_RULE_PUBLISH: self._validate_rule_publish,
            KIND_RULE_REVOKE: self._validate_event_target,
            KIND_REPORT: self._validate_report,
            KIND_PUNISHMENT_REVOKE: self._validate_event_target,
            KIND_PUNISHMENT_ACK: self._validate_punishment_ack,
            KIND_ORIGIN_KEY_ROTATE: self._validate_key_rotation,
        }
        for kind in ARTICLE_LIFECYCLE_KINDS:
            self._validators[kind] = self._validate_lifecycle_control
        for kind in PIN_THREAD_CONTROL_KINDS:
            self._validators[kind] = self._validate_pin_thread_control
        for kind in BOARD_LIFECYCLE_KINDS:
            self._validators[kind] = self._validate_board_lifecycle
        for kind in PUNISHMENT_ISSUE_KINDS:
            self._validators[kind] = self._validate_punishment_issue

    def validate(self, intent: Intent) -> None:
        kind = intent.kind
        if not kind or not all(32 <= ord(c) <= 126 for c in kind):
            raise ValidationError("kind must be printable ASCII")

        if kind not in ALL_KNOWN_KINDS:
            return

        validator = self._validators.get(kind)
        if validator is not None:
            validator(intent)

    # ------------------------------------------------------------------
    # Article
    # ------------------------------------------------------------------

    def _validate_article(self, intent: Intent) -> None:
        if not intent.board:
            raise ValidationError("bonnet.article requires non-empty board")
        if intent.article_id == ZERO_ID:
            raise ValidationError("bonnet.article requires non-zero article_id")
        self._require_empty_targets(intent)

        m = intent.metadata
        if m.get_text(1) is None:
            raise ValidationError("bonnet.article requires metadata field 1 (subject)")
        if m.get_text(4) is None:
            raise ValidationError("bonnet.article requires metadata field 4 (content type)")

    # ------------------------------------------------------------------
    # Lifecycle controls (cancel, restore, purge)
    # ------------------------------------------------------------------

    def _validate_lifecycle_control(self, intent: Intent) -> None:
        self._require_article_target(intent)
        if intent.board:
            raise ValidationError(
                f"{intent.kind} must have empty board (target tuple carries board)"
            )

    # ------------------------------------------------------------------
    # Pin/thread controls
    # ------------------------------------------------------------------

    def _validate_pin_thread_control(self, intent: Intent) -> None:
        self._require_article_target(intent)
        if intent.board:
            raise ValidationError(f"{intent.kind} must have empty board")

        if intent.kind == KIND_ARTICLE_PIN:
            if intent.metadata.get_i64(1) is None:
                raise ValidationError("bonnet.article.pin requires metadata field 1 (priority)")

    # ------------------------------------------------------------------
    # Board lifecycle
    # ------------------------------------------------------------------

    def _validate_board_lifecycle(self, intent: Intent) -> None:
        if not intent.board:
            raise ValidationError(f"{intent.kind} requires non-empty board")
        self._require_empty_article_targets(intent)

        if intent.kind == KIND_BOARD_CREATE:
            if intent.metadata.get_bytes(1) is None:
                raise ValidationError(
                    "bonnet.board.create requires metadata field 1 (owner public key)"
                )

    # ------------------------------------------------------------------
    # User lifecycle
    # ------------------------------------------------------------------

    def _validate_user_register(self, intent: Intent) -> None:
        self._require_empty_board(intent)
        self._require_empty_article_targets(intent)

        m = intent.metadata
        if m.get_text(1) is None:
            raise ValidationError("bonnet.user.register requires metadata field 1 (username)")
        if m.get_bytes(2) is None:
            raise ValidationError(
                "bonnet.user.register requires metadata field 2 (user public key)"
            )
        flags = m.get_u64(3)
        if flags is None:
            raise ValidationError("bonnet.user.register requires metadata field 3 (flags)")
        if flags & ~0x03:
            raise ValidationError("bonnet.user.register reserved flag bits must be zero")

    def _validate_user_revoke(self, intent: Intent) -> None:
        self._require_event_target(intent)
        self._require_empty_board(intent)
        if intent.metadata.get_bytes(1) is None:
            raise ValidationError(
                "bonnet.user.revoke requires metadata field 1 (revoked user public key)"
            )

    def _validate_user_key_rotate(self, intent: Intent) -> None:
        """An actor succeeding its own signing key.

        The subject is always the actor itself — `firehose_commands` already
        requires `intent.actor_pubkey == ctx.peer_pubkey`, so the old key is
        necessarily the authenticated caller and there is no target tuple to
        carry a third party. Mutual consent comes from the pair of signatures:
        the record is signed by the outgoing key, and field 2 is a rotation
        proof signed by the incoming one (verified at apply time, since only
        the projection knows the origin string to bind it to).
        """
        self._require_empty_board(intent)
        self._require_empty_article_targets(intent)
        self._require_empty_targets(intent)

        m = intent.metadata
        new_pubkey = m.get_bytes(1)
        if new_pubkey is None:
            raise ValidationError(
                "bonnet.user.key.rotate requires metadata field 1 (new actor public key)"
            )
        if m.get_bytes(2) is None:
            raise ValidationError(
                "bonnet.user.key.rotate requires metadata field 2 (new-key proof signature)"
            )
        if new_pubkey == intent.actor_pubkey:
            raise ValidationError(
                "bonnet.user.key.rotate must name a different key than the actor's own"
            )

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    def _validate_rule_publish(self, intent: Intent) -> None:
        if not intent.board:
            raise ValidationError("bonnet.rule.publish requires non-empty board")
        if intent.metadata.get_text(1) is None:
            raise ValidationError("bonnet.rule.publish requires metadata field 1 (rule name)")

    def _validate_event_target(self, intent: Intent) -> None:
        self._require_event_target(intent)

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    def _validate_report(self, intent: Intent) -> None:
        if intent.metadata.get_bytes(1) is None:
            raise ValidationError("bonnet.report requires metadata field 1 (culprit public key)")

        has_article_target = (
            intent.target_origin
            and intent.target_board
            and intent.target_article_id != ZERO_ID
            and intent.target_event_id == ZERO_ID
        )
        has_event_target = (
            intent.target_origin
            and intent.target_event_id != ZERO_ID
            and not intent.target_board
            and intent.target_article_id == ZERO_ID
        )
        has_no_target = (
            not intent.target_origin
            and not intent.target_board
            and intent.target_article_id == ZERO_ID
            and intent.target_event_id == ZERO_ID
        )

        if not has_article_target and not has_event_target and not has_no_target:
            raise ValidationError(
                "bonnet.report must use either complete article target tuple, "
                "event target, or no target — not a mix"
            )

    # ------------------------------------------------------------------
    # Punishments
    # ------------------------------------------------------------------

    def _validate_punishment_issue(self, intent: Intent) -> None:
        kind = intent.kind
        if not intent.board:
            raise ValidationError(f"{kind} requires non-empty board")
        self._require_empty_article_targets(intent)
        self._require_empty_targets(intent)

        m = intent.metadata
        punished = m.get_bytes(1)
        if punished is None:
            raise ValidationError(f"{kind} requires metadata field 1 (punished public key)")
        if len(punished) != 32:
            raise ValidationError(f"{kind} metadata field 1 (punished public key) must be 32 bytes")

        expires_at = m.get_i64(2)
        if kind == KIND_PUNISHMENT_BAN:
            if expires_at is None:
                raise ValidationError(
                    "bonnet.punishment.ban requires metadata field 2 (expiry timestamp)"
                )
            if expires_at <= 0:
                raise ValidationError("bonnet.punishment.ban expiry must be a positive timestamp")
        elif expires_at is not None:
            raise ValidationError(
                f"{kind} must not carry metadata field 2 (only bonnet.punishment.ban has an expiry)"
            )

        if intent.body_size <= 0:
            raise ValidationError(f"{kind} requires a non-empty body (the reason)")

    def _validate_punishment_ack(self, intent: Intent) -> None:
        self._require_empty_board(intent)
        self._require_empty_article_targets(intent)
        self._require_empty_targets(intent)

        target = intent.metadata.get_bytes(1)
        if target is None:
            raise ValidationError(
                "bonnet.punishment.ack requires metadata field 1 (punishment event ID)"
            )
        if len(target) != 32:
            raise ValidationError(
                "bonnet.punishment.ack metadata field 1 (punishment event ID) must be 32 bytes"
            )

    # ------------------------------------------------------------------
    # Key rotation
    # ------------------------------------------------------------------

    def _validate_key_rotation(self, intent: Intent) -> None:
        self._require_empty_board(intent)
        self._require_empty_article_targets(intent)
        self._require_empty_targets(intent)

        m = intent.metadata
        if m.get_bytes(1) is None:
            raise ValidationError(
                "bonnet.origin.key.rotate requires metadata field 1 (new origin public key)"
            )
        if m.get_bytes(2) is None:
            raise ValidationError(
                "bonnet.origin.key.rotate requires metadata field 2 (new-key proof signature)"
            )

    # ------------------------------------------------------------------
    # Target helpers
    # ------------------------------------------------------------------

    def _require_article_target(self, intent: Intent) -> None:
        if not intent.target_origin:
            raise ValidationError(f"{intent.kind} requires non-empty target_origin")
        if not intent.target_board:
            raise ValidationError(f"{intent.kind} requires non-empty target_board")
        if intent.target_article_id == ZERO_ID:
            raise ValidationError(f"{intent.kind} requires non-zero target_article_id")
        if intent.target_event_id != ZERO_ID:
            raise ValidationError(f"{intent.kind} requires zero target_event_id")

    def _require_event_target(self, intent: Intent) -> None:
        if not intent.target_origin:
            raise ValidationError(f"{intent.kind} requires non-empty target_origin")
        if intent.target_event_id == ZERO_ID:
            raise ValidationError(f"{intent.kind} requires non-zero target_event_id")
        if intent.target_board:
            raise ValidationError(f"{intent.kind} requires empty target_board")
        if intent.target_article_id != ZERO_ID:
            raise ValidationError(f"{intent.kind} requires zero target_article_id")

    def _require_empty_targets(self, intent: Intent) -> None:
        if intent.target_origin:
            raise ValidationError(f"{intent.kind} requires empty target_origin")
        if intent.target_board:
            raise ValidationError(f"{intent.kind} requires empty target_board")
        if intent.target_article_id != ZERO_ID:
            raise ValidationError(f"{intent.kind} requires zero target_article_id")
        if intent.target_event_id != ZERO_ID:
            raise ValidationError(f"{intent.kind} requires zero target_event_id")

    def _require_empty_article_targets(self, intent: Intent) -> None:
        if intent.article_id != ZERO_ID:
            raise ValidationError(f"{intent.kind} requires zero article_id")
        if intent.target_article_id != ZERO_ID:
            raise ValidationError(f"{intent.kind} requires zero target_article_id")

    def _require_empty_board(self, intent: Intent) -> None:
        if intent.board:
            raise ValidationError(f"{intent.kind} requires empty board")
