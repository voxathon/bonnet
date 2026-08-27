"""Compositional ACL evaluator for the Bonnet Firehose Protocol (PROTOCOL.md §16).

Authorization is explicit, compositional, and default-deny. There are no
implicit administrator, moderator, owner, origin, or root bypasses.

Applicable dimensions: command, kind, board, object.
For each dimension: any matching deny wins; otherwise at least one matching
allow is required; no match means deny.

Every applicable dimension MUST pass. Business invariants and effective-ban
checks are additional conjunctive gates.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ACLError(Exception):
    pass


# ---------------------------------------------------------------------------
# Matcher
# ---------------------------------------------------------------------------


@dataclass
class PrincipalMatcher:
    pubkey: bytes | None = None
    role: str | None = None
    origin: str | None = None
    anonymous: bool = False
    unknown: bool = False
    wildcard: bool = False

    def matches(self, ctx: AuthContext) -> bool:
        if self.anonymous:
            return ctx.is_anonymous
        if self.unknown:
            return ctx.is_unknown
        if self.wildcard:
            return True
        matched_any = False
        if self.pubkey is not None:
            if ctx.pubkey != self.pubkey:
                return False
            matched_any = True
        if self.role is not None:
            if ctx.role != self.role:
                return False
            matched_any = True
        if self.origin is not None:
            if ctx.origin != self.origin:
                return False
            matched_any = True
        return matched_any

    @staticmethod
    def from_dict(data: dict) -> PrincipalMatcher:
        m = PrincipalMatcher()
        if "pubkey" in data:
            pk = data["pubkey"]
            if pk.startswith("hex:"):
                pk = pk[4:]
            m.pubkey = bytes.fromhex(pk)
        if "role" in data:
            m.role = data["role"].lower()
        if "origin" in data:
            m.origin = data["origin"].lower()
        if data.get("anonymous"):
            m.anonymous = True
        if data.get("unknown"):
            m.unknown = True
        if data.get("wildcard"):
            m.wildcard = True
        return m


# ---------------------------------------------------------------------------
# ACL Rule
# ---------------------------------------------------------------------------


@dataclass
class ACLRule:
    effect: str  # "allow" or "deny"
    matcher: PrincipalMatcher
    actions: list = field(default_factory=list)  # ["read", "write"]
    commands: list | None = None  # ["PUBLISH_RECORD", ...] or ["*"]
    kinds: list | None = None
    boards: list | None = None
    objects: list | None = None

    def action_matches(self, action: str) -> bool:
        return action in self.actions or "*" in self.actions

    def command_matches(self, command: str) -> bool:
        if self.commands is None:
            return False
        return _list_matches(self.commands, command)

    def kind_matches(self, kind: str) -> bool:
        if self.kinds is None:
            return False
        return _list_matches(self.kinds, kind)

    def board_matches(self, board: str) -> bool:
        if self.boards is None:
            return False
        return _list_matches(self.boards, board)

    def object_matches(self, object_name: str) -> bool:
        if self.objects is None:
            return False
        return _list_matches(self.objects, object_name)

    @staticmethod
    def from_dict(data: dict) -> ACLRule:
        effect = data.get("effect", "allow")
        if effect not in ("allow", "deny"):
            raise ACLError(f"invalid effect: {effect}")
        matcher = PrincipalMatcher.from_dict(data.get("match", {}))
        actions = data.get("actions", [])
        if isinstance(actions, str):
            actions = [actions]
        commands = data.get("commands")
        if isinstance(commands, str):
            commands = [commands]
        kinds = data.get("kinds")
        if isinstance(kinds, str):
            kinds = [kinds]
        boards = data.get("boards")
        if isinstance(boards, str):
            boards = [boards]
        objects = data.get("objects")
        if isinstance(objects, str):
            objects = [objects]
        return ACLRule(
            effect=effect,
            matcher=matcher,
            actions=actions,
            commands=commands,
            kinds=kinds,
            boards=boards,
            objects=objects,
        )


def _list_matches(patterns: list, value: str) -> bool:
    for p in patterns:
        if p == "*" or fnmatch.fnmatch(value, p):
            return True
    return False


# ---------------------------------------------------------------------------
# Auth Context
# ---------------------------------------------------------------------------


@dataclass
class AuthContext:
    pubkey: bytes = b""
    role: str = ""  # "administrator", "moderator", "", etc.
    origin: str = ""
    is_anonymous: bool = False
    is_unknown: bool = False
    is_registered: bool = False


# ---------------------------------------------------------------------------
# ACL Evaluator
# ---------------------------------------------------------------------------


class ACLEvaluator:
    """Compositional ACL evaluator (§16).

    Every applicable dimension MUST pass. Within each dimension:
    1. collect rules matching the principal and action;
    2. if any matching deny covers the selector, deny;
    3. otherwise require at least one matching allow;
    4. no match means deny.
    """

    def __init__(self, rules: list[ACLRule] = None):
        self._rules = rules or []

    def add_rule(self, rule: ACLRule) -> None:
        self._rules.append(rule)

    def check(
        self,
        ctx: AuthContext,
        action: str,
        command: str = None,
        kind: str = None,
        board: str = None,
        object_name: str = None,
    ) -> bool:
        applicable = []
        if command is not None:
            applicable.append(("command", command))
        if kind is not None:
            applicable.append(("kind", kind))
        if board is not None:
            applicable.append(("board", board))
        if object_name is not None:
            applicable.append(("object", object_name))

        if not applicable:
            return False

        for dim_name, selector in applicable:
            if not self._check_dimension(ctx, action, dim_name, selector):
                return False

        return True

    def _check_dimension(
        self,
        ctx: AuthContext,
        action: str,
        dim: str,
        selector: str,
    ) -> bool:
        matching_rules = []
        for rule in self._rules:
            if not rule.matcher.matches(ctx):
                continue
            if not rule.action_matches(action):
                continue

            if dim == "command":
                dim_matches = rule.command_matches(selector)
            elif dim == "kind":
                dim_matches = rule.kind_matches(selector)
            elif dim == "board":
                dim_matches = rule.board_matches(selector)
            elif dim == "object":
                dim_matches = rule.object_matches(selector)
            else:
                continue

            if dim_matches:
                matching_rules.append(rule)

        if not matching_rules:
            return False

        for rule in matching_rules:
            if rule.effect == "deny":
                return False

        has_allow = any(rule.effect == "allow" for rule in matching_rules)
        return has_allow

    @staticmethod
    def from_toml(data: dict) -> ACLEvaluator:
        rules = []
        for acl_data in data.get("acl", []):
            rules.append(ACLRule.from_dict(acl_data))
        return ACLEvaluator(rules)


# ---------------------------------------------------------------------------
# Default ACL generator
# ---------------------------------------------------------------------------


def default_rules_for_admin(pubkey_hex: str) -> list[ACLRule]:
    """Generate default explicit grants for the initial local admin key."""
    return [
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(pubkey=bytes.fromhex(pubkey_hex)),
            actions=["read", "write"],
            commands=["*"],
            kinds=["*"],
            boards=["*"],
            objects=["*"],
        ),
    ]
