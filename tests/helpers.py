"""Shared test helpers for command/object ACL tests (Phase 1).

Provides reusable ACL fixtures so individual test files don't duplicate the
default-deny ACL set needed to replace the obsolete public_commands mechanism.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.config import Config, Matcher, ACLEntry
from core.commands import COMMAND_SPECS


def all_read_command_names():
    """All read-action command names from the canonical CommandSpec table."""
    return [s.name for s in COMMAND_SPECS.values() if s.action == "read"]


def all_write_command_names():
    """All write-action command names from the canonical CommandSpec table."""
    return [s.name for s in COMMAND_SPECS.values() if s.action == "write"]


def anonymous_read_command_names():
    """Read commands granted to anonymous by default (excludes
    POST_CONTENT_SEARCH, which remains default-deny for anonymous)."""
    return [
        "GET_USER", "LIST_USERS", "LIST_PEERS", "BOARD_LIST", "POST_GET",
        "POST_LIST", "QUERY_POSTS", "GET_PUBKEY", "RULE_GET", "RULE_GET_BY_NAME",
        "RULE_LIST", "REPORT_GET", "REPORT_LIST_BY_CULPRIT", "REPORT_LIST_SINCE",
        "PUNISHMENT_GET", "PUNISHMENT_LIST_ACTIVE", "IS_BANNED",
        "PUNISHMENT_LIST_BY_PUBKEY", "PEER_KEY_LIST",
        "USER_REGISTRY_HEAD", "USER_REGISTRY_NODES", "USER_REGISTRY_RECORDS",
        "USER_REGISTRY_HEADS", "USER_REGISTRY_HEAD_CHAIN",
    ]


def default_test_acls(origin="local.test"):
    """Default ACL set matching generated defaults, for a test origin.

    Returns:
        local-full-access: origin match, all commands, all boards, read+write
        anonymous-read: anonymous match, read commands (no search), read only
        unknown-read: unknown match, read commands (no search), read only
        unknown-registration: unknown match, REGISTER only, write only
    """
    local_acl = ACLEntry(
        "local-full-access",
        Matcher(origin_pattern=origin),
        ["*"], True, True,
        command_patterns=["*"],
    )

    anon_acl = ACLEntry(
        "anonymous-read",
        Matcher(anonymous=True),
        ["*"], True, False,
        command_patterns=anonymous_read_command_names(),
    )

    unknown_read_acl = ACLEntry(
        "unknown-read",
        Matcher(unknown=True),
        ["*"], True, False,
        command_patterns=anonymous_read_command_names(),
    )

    unknown_acl = ACLEntry(
        "unknown-registration",
        Matcher(unknown=True),
        ["*"], False, True,
        command_patterns=["REGISTER"],
    )

    return [local_acl, anon_acl, unknown_read_acl, unknown_acl]


def make_test_config(temp_dir, origin="local.test", acls=None, **kwargs):
    """Build a Config with default test ACLs (or custom ACLs) for command tests.

    Replaces the old pattern of acls=[] + public_commands={...}.
    """
    if acls is None:
        acls = default_test_acls(origin)

    defaults = dict(
        origin=origin,
        ame_path=os.path.join(temp_dir, "boards"),
        data_dir=temp_dir,
        nav_db_path=os.path.join(temp_dir, "nav.db"),
        reports_db_path=os.path.join(temp_dir, "reports.db"),
        punishments_db_path=os.path.join(temp_dir, "punishments.db"),
        log_dir=os.path.join(temp_dir, "logs"),
        acls=acls,
        anonymous_read=True,
    )
    defaults.update(kwargs)
    return Config(**defaults)
