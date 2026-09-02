"""Compositional ACL evaluator for the firehose protocol.

Authorization is explicit, compositional, and default-deny. There are no
implicit administrator, moderator, owner, origin, or root bypasses.

Applicable dimensions: command, kind, board, object. A rule is a candidate
for a check only if it, BY ITSELF, satisfies every dimension the caller
supplied — a rule granting a command says nothing about a board unless that
same rule also grants the board. Among the candidates: any deny wins;
otherwise at least one matching allow is required; no candidates means deny.

Omitting a dimension field on a rule (leaving it `None`) is not neutral, and
means something different depending on the rule's effect:
  - on an `allow` rule, it means the rule grants NOTHING on that axis — an
    allow that doesn't mention `boards` can never satisfy a check that asks
    about a board, however that board is spelled. This is what keeps a
    narrowly-scoped grant narrow: it cannot be widened by some *other* rule
    that happens to carry `boards=["*"]` for a different command.
  - on a `deny` rule, it means the rule is UNRESTRICTED on that axis — a
    deny with no `commands` field blocks every command, on whatever boards
    it does name. This is what makes "nothing may write to board X, no
    matter what" expressible as one line, and it is deliberately the
    opposite convention from allow: a deny is presumed broad until narrowed,
    an allow is presumed narrow until widened.

Business invariants and effective-ban checks are additional conjunctive
gates on top of this.

On "no implicit bypasses", precisely. That statement is about *this*
evaluator: no role, origin or key is privileged in the rule algebra, and
nothing here grants what a rule did not. It is not a claim that role is
unused elsewhere. `firehose_commands._cmd_publish` consults `ctx.role`
in several places — the punishment gate, the author checks on cancel /
restore / purge, and the privilege gate on registration flags. Every one of
those runs *after* this evaluator has already allowed the action, and can
only narrow it further or, for the punishment gate, widen a moderation
exemption the operator asked for. They are conjunctive gates layered on an
allow, never a path to an allow this evaluator denied.

Worth knowing which axis a grant travels on, because the two do not feed
each other. `server.admin_pubkey` grants power through *rules* here and
leaves `ctx.role` empty; `ctx.role` comes only from the `flags` on a user's
registration record (see `firehose_http_server`). An operator who wants both
needs both.
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
    registered: bool = False
    wildcard: bool = False

    def matches(self, ctx: AuthContext) -> bool:
        if self.anonymous:
            return ctx.is_anonymous
        if self.unknown:
            return ctx.is_unknown
        if self.registered:
            return ctx.is_registered
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
        if data.get("registered"):
            m.registered = True
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

    def covers(
        self,
        action: str,
        command: str | None = None,
        kind: str | None = None,
        board: str | None = None,
        object_name: str | None = None,
    ) -> bool:
        """Whether this rule, alone, grants/denies every dimension supplied.

        The per-field `*_matches` methods above answer one dimension at a
        time and are still what `covers` calls into; this is what stops a
        caller from checking each dimension against a *different* rule and
        concluding a single grant exists where none does. See the module
        docstring for why an omitted field means opposite things on allow
        vs. deny rules.

        A deny also needs at least one dimension where it makes an actual,
        tested claim — a queried dimension whose field it specifies, and
        that field matches. Otherwise a deny that restricts only `boards`
        would "match" a check that never asks about board at all (nothing
        to test its one real restriction against), purely because its other,
        merely-omitted fields count as unrestricted. That would make a
        board-scoped deny fire against the coarse, board-agnostic check that
        `handle()` runs before a board is even known — see
        `_board_read_allowed`'s docstring on that two-stage design. An allow
        can't have this problem: it already returns False the moment any
        queried dimension has no field to grant it, so by the time one
        reaches the end of this loop at least one field genuinely matched.
        """
        if not self.action_matches(action):
            return False
        matched_any = False
        for selector, dim_field, matches in (
            (command, self.commands, self.command_matches),
            (kind, self.kinds, self.kind_matches),
            (board, self.boards, self.board_matches),
            (object_name, self.objects, self.object_matches),
        ):
            if selector is None:
                continue
            if dim_field is None:
                if self.effect == "deny":
                    continue
                return False
            if not matches(selector):
                return False
            matched_any = True
        return matched_any

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
    """Compositional ACL evaluator.

    A rule is a candidate only if it, by itself, covers every dimension
    supplied to `check()` — see `ACLRule.covers` and the module docstring.
    Among the candidates: any deny wins; otherwise at least one matching
    allow is required; no candidates means deny.
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
        if command is None and kind is None and board is None and object_name is None:
            return False

        candidates = [
            rule
            for rule in self._rules
            if rule.matcher.matches(ctx) and rule.covers(action, command, kind, board, object_name)
        ]
        if not candidates:
            return False
        if any(rule.effect == "deny" for rule in candidates):
            return False
        return any(rule.effect == "allow" for rule in candidates)

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
