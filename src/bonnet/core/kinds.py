"""Bonnet record kind constants.

Single source of truth for kind name strings and their groupings. Other
modules import from here rather than redefining these constants locally.
"""

from __future__ import annotations

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
KIND_PUNISHMENT_WARN = "bonnet.punishment.warn"
KIND_PUNISHMENT_BAN = "bonnet.punishment.ban"
KIND_PUNISHMENT_PERMABAN = "bonnet.punishment.permaban"
KIND_PUNISHMENT_REVOKE = "bonnet.punishment.revoke"
KIND_PUNISHMENT_ACK = "bonnet.punishment.ack"
KIND_ORIGIN_KEY_ROTATE = "bonnet.origin.key.rotate"

PUNISHMENT_ISSUE_KINDS = frozenset(
    {
        KIND_PUNISHMENT_WARN,
        KIND_PUNISHMENT_BAN,
        KIND_PUNISHMENT_PERMABAN,
    }
)

# Issuing kind -> stored punishment type name.
PUNISHMENT_TYPE_BY_KIND = {
    KIND_PUNISHMENT_WARN: "warning",
    KIND_PUNISHMENT_BAN: "ban",
    KIND_PUNISHMENT_PERMABAN: "permaban",
}

ARTICLE_LIFECYCLE_KINDS = frozenset(
    {
        KIND_ARTICLE_CANCEL,
        KIND_ARTICLE_RESTORE,
        KIND_ARTICLE_PURGE,
    }
)

ARTICLE_CONTROL_KINDS = frozenset(
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

ARTICLE_TARGET_KINDS = ARTICLE_CONTROL_KINDS

PIN_THREAD_CONTROL_KINDS = frozenset(
    {
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
        KIND_PUNISHMENT_WARN,
        KIND_PUNISHMENT_BAN,
        KIND_PUNISHMENT_PERMABAN,
        KIND_PUNISHMENT_REVOKE,
        KIND_PUNISHMENT_ACK,
    }
)

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
        KIND_PUNISHMENT_WARN,
        KIND_PUNISHMENT_BAN,
        KIND_PUNISHMENT_PERMABAN,
        KIND_PUNISHMENT_REVOKE,
        KIND_PUNISHMENT_ACK,
        KIND_ORIGIN_KEY_ROTATE,
    }
)
