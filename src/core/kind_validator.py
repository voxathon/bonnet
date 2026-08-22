"""Kind-specific validation for the Bonnet Firehose Protocol (PROTOCOL.md §12).

Enforces schema rules: required metadata fields, target tuple completeness,
same-origin restrictions, board/user lifecycle constraints, and report/punishment
target rules. Called before origin acceptance of a publication request.
"""

from __future__ import annotations

from core.record import ZERO_ID, Intent

# ---------------------------------------------------------------------------
# Kind constants
# ---------------------------------------------------------------------------

KIND_ARTICLE = "bonnet.article"
KIND_ARTICLE_CANCEL = "bonnet.article.cancel"
KIND_ARTICLE_RESTORE = "bonnet.article.restore"
KIND_ARTICLE_PURGE = "bonnet.article.purge"
KIND_ARTICLE_PIN = "bonnet.article.pin"
KIND_ARTICLE_UNPIN = "bonnet.article.unpin"
KIND_THREAD_CLOSE = "bonnet.thread.close"
KIND_THREAD_REOPEN = "bonnet.thread.reopen"
KIND_BOARD_CREATE = "bonnet.board.create"
KIND_BOARD_CLOSE = "bonnet.board.close"
KIND_BOARD_REOPEN = "bonnet.board.reopen"
KIND_USER_REGISTER = "bonnet.user.register"
KIND_USER_REVOKE = "bonnet.user.revoke"
KIND_RULE_PUBLISH = "bonnet.rule.publish"
KIND_RULE_REVOKE = "bonnet.rule.revoke"
KIND_REPORT = "bonnet.report"
KIND_PUNISHMENT_ISSUE = "bonnet.punishment.issue"
KIND_PUNISHMENT_REVOKE = "bonnet.punishment.revoke"
KIND_ORIGIN_KEY_ROTATE = "bonnet.origin.key.rotate"

ALL_KNOWN_KINDS = frozenset(
    {
        KIND_ARTICLE,
        KIND_ARTICLE_CANCEL,
        KIND_ARTICLE_RESTORE,
        KIND_ARTICLE_PURGE,
        KIND_ARTICLE_PIN,
        KIND_ARTICLE_UNPIN,
        KIND_THREAD_CLOSE,
        KIND_THREAD_REOPEN,
        KIND_BOARD_CREATE,
        KIND_BOARD_CLOSE,
        KIND_BOARD_REOPEN,
        KIND_USER_REGISTER,
        KIND_USER_REVOKE,
        KIND_RULE_PUBLISH,
        KIND_RULE_REVOKE,
        KIND_REPORT,
        KIND_PUNISHMENT_ISSUE,
        KIND_PUNISHMENT_REVOKE,
        KIND_ORIGIN_KEY_ROTATE,
    }
)

ARTICLE_LIFECYCLE_KINDS = frozenset(
    {
        KIND_ARTICLE_CANCEL,
        KIND_ARTICLE_RESTORE,
        KIND_ARTICLE_PURGE,
    }
)

ARTICLE_TARGET_KINDS = frozenset(
    {
        KIND_ARTICLE_CANCEL,
        KIND_ARTICLE_RESTORE,
        KIND_ARTICLE_PURGE,
        KIND_ARTICLE_PIN,
        KIND_ARTICLE_UNPIN,
        KIND_THREAD_CLOSE,
        KIND_THREAD_REOPEN,
    }
)

EVENT_TARGET_KINDS = frozenset(
    {
        KIND_USER_REVOKE,
        KIND_RULE_REVOKE,
        KIND_PUNISHMENT_REVOKE,
    }
)

BOARD_LIFECYCLE_KINDS = frozenset(
    {
        KIND_BOARD_CREATE,
        KIND_BOARD_CLOSE,
        KIND_BOARD_REOPEN,
    }
)

USER_LIFECYCLE_KINDS = frozenset(
    {
        KIND_USER_REGISTER,
        KIND_USER_REVOKE,
    }
)

MODERATION_KINDS = frozenset(
    {
        KIND_RULE_PUBLISH,
        KIND_RULE_REVOKE,
        KIND_REPORT,
        KIND_PUNISHMENT_ISSUE,
        KIND_PUNISHMENT_REVOKE,
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ValidationError(Exception):
    pass


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


class KindValidator:
    """Validates an Intent against its kind schema (§12)."""

    def validate(self, intent: Intent) -> None:
        kind = intent.kind
        if not kind or not all(32 <= ord(c) <= 126 for c in kind):
            raise ValidationError("kind must be printable ASCII")

        if kind not in ALL_KNOWN_KINDS:
            return

        if kind == KIND_ARTICLE:
            self._validate_article(intent)
        elif kind in ARTICLE_LIFECYCLE_KINDS:
            self._validate_lifecycle_control(intent)
        elif kind in (KIND_ARTICLE_PIN, KIND_ARTICLE_UNPIN, KIND_THREAD_CLOSE, KIND_THREAD_REOPEN):
            self._validate_pin_thread_control(intent)
        elif kind in BOARD_LIFECYCLE_KINDS:
            self._validate_board_lifecycle(intent)
        elif kind == KIND_USER_REGISTER:
            self._validate_user_register(intent)
        elif kind == KIND_USER_REVOKE:
            self._validate_user_revoke(intent)
        elif kind == KIND_RULE_PUBLISH:
            self._validate_rule_publish(intent)
        elif kind == KIND_RULE_REVOKE:
            self._validate_event_target(intent)
        elif kind == KIND_REPORT:
            self._validate_report(intent)
        elif kind == KIND_PUNISHMENT_ISSUE:
            self._validate_punishment_issue(intent)
        elif kind == KIND_PUNISHMENT_REVOKE:
            self._validate_event_target(intent)
        elif kind == KIND_ORIGIN_KEY_ROTATE:
            self._validate_key_rotation(intent)

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
        if not intent.board:
            raise ValidationError("bonnet.punishment.issue requires non-empty board")
        self._require_empty_article_targets(intent)

        m = intent.metadata
        if m.get_bytes(1) is None:
            raise ValidationError(
                "bonnet.punishment.issue requires metadata field 1 (punished public key)"
            )
        if m.get_i64(2) is None:
            raise ValidationError("bonnet.punishment.issue requires metadata field 2 (expiration)")

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
