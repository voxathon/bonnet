"""Canonical command registry for Bonnet protocol v2.

Single authoritative opcode -> CommandSpec map used by:
  - CommandHandler (server dispatch + ACL gating)
  - Config (command ACL pattern matching)
  - logging

Per PEERED_MODERATION_MERKLE_ACL_IMPLEMENTATION_PLAN §5.1/§5.2, commands are
classified by effect (read vs write), not by whether they were historically
"public". object_name is None for every existing command in Phase 1; report and
punishment registry export commands (Phase 4/5) will populate it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional


@dataclass(frozen=True)
class CommandSpec:
    opcode: int
    name: str
    action: Literal["read", "write"]
    object_name: Optional[str] = None


COMMAND_SPECS: dict[int, CommandSpec] = {
    spec.opcode: spec for spec in [
        CommandSpec(0x01, "REGISTER", "write"),
        CommandSpec(0x02, "GET_USER", "read"),
        CommandSpec(0x03, "LIST_USERS", "read"),
        CommandSpec(0x04, "LIST_PEERS", "read"),
        CommandSpec(0x05, "USER_REGISTRY_HEAD", "read"),
        CommandSpec(0x06, "USER_REGISTRY_NODES", "read"),
        CommandSpec(0x07, "USER_REGISTRY_RECORDS", "read"),
        CommandSpec(0x08, "USER_REGISTRY_HEADS", "read"),
        CommandSpec(0x09, "USER_REGISTRY_HEAD_CHAIN", "read"),
        CommandSpec(0x10, "BOARD_CREATE", "write"),
        CommandSpec(0x11, "BOARD_LIST", "read"),
        CommandSpec(0x12, "POST_CREATE", "write"),
        CommandSpec(0x13, "POST_GET", "read"),
        CommandSpec(0x14, "POST_LIST", "read"),
        CommandSpec(0x15, "POST_UPDATE", "write"),
        CommandSpec(0x16, "POST_DELETE", "write"),
        CommandSpec(0x17, "BOARD_CLOSE", "write"),
        CommandSpec(0x18, "BOARD_DELETE", "write"),
        CommandSpec(0x19, "QUERY_POSTS", "read"),
        CommandSpec(0x1A, "POST_CONTENT_SEARCH", "read"),
        CommandSpec(0x20, "USER_PROMOTE", "write"),
        CommandSpec(0x21, "USER_DEMOTE", "write"),
        CommandSpec(0x22, "POST_SIGN", "write"),
        CommandSpec(0x30, "GET_PUBKEY", "read"),
        CommandSpec(0x40, "RULE_CREATE", "write"),
        CommandSpec(0x41, "RULE_GET", "read"),
        CommandSpec(0x42, "RULE_GET_BY_NAME", "read"),
        CommandSpec(0x43, "RULE_LIST", "read"),
        CommandSpec(0x44, "RULE_UPDATE", "write"),
        CommandSpec(0x50, "REPORT_CREATE", "write"),
        CommandSpec(0x51, "REPORT_GET", "read"),
        CommandSpec(0x52, "REPORT_LIST_BY_CULPRIT", "read"),
        CommandSpec(0x53, "REPORT_SIGN", "write"),
        CommandSpec(0x54, "REPORT_LIST_SINCE", "read"),
        CommandSpec(0x55, "REPORT_REGISTRY_HEAD", "read", "reports"),
        CommandSpec(0x56, "REPORT_REGISTRY_NODES", "read", "reports"),
        CommandSpec(0x57, "REPORT_REGISTRY_RECORDS", "read", "reports"),
        CommandSpec(0x58, "REPORT_REGISTRY_HEADS", "read", "reports"),
        CommandSpec(0x59, "REPORT_REGISTRY_HEAD_CHAIN", "read", "reports"),
        CommandSpec(0x60, "PUNISHMENT_CREATE", "write"),
        CommandSpec(0x61, "PUNISHMENT_GET", "read"),
        CommandSpec(0x62, "PUNISHMENT_LIST_ACTIVE", "read"),
        CommandSpec(0x63, "IS_BANNED", "read"),
        CommandSpec(0x64, "PUNISHMENT_LIST_BY_PUBKEY", "read"),
        CommandSpec(0x65, "PUNISHMENT_REGISTRY_HEAD", "read", "punishments"),
        CommandSpec(0x66, "PUNISHMENT_REGISTRY_NODES", "read", "punishments"),
        CommandSpec(0x67, "PUNISHMENT_REGISTRY_RECORDS", "read", "punishments"),
        CommandSpec(0x68, "PUNISHMENT_REGISTRY_HEADS", "read", "punishments"),
        CommandSpec(0x69, "PUNISHMENT_REGISTRY_HEAD_CHAIN", "read", "punishments"),
        CommandSpec(0x70, "PEER_KEY_ROTATE", "write"),
        CommandSpec(0x71, "PEER_KEY_LIST", "read"),
    ]
}

SPECS_BY_NAME: dict[str, CommandSpec] = {spec.name: spec for spec in COMMAND_SPECS.values()}


def get_spec(opcode: int) -> Optional[CommandSpec]:
    return COMMAND_SPECS.get(opcode)


def get_spec_by_name(name: str) -> Optional[CommandSpec]:
    return SPECS_BY_NAME.get(name)
