"""Per-tool authorization declarations, checked against the relay's PERMISSIONS.

Tiering was tried first and withdrawn: a bucket like "read" or "moderate"
would be a third, independent copy of policy after the ACL itself and the
PERMISSIONS opcode, and buckets cannot express a compound tool — one that
needs several grants at once, and should stay hidden if it holds only some
of them. `publish_article` issues ARTICLE_GET (for a reply lookup) *and*
publishes `bonnet.article`; `report` issues ARTICLE_GET *and* publishes
`bonnet.report`. A caller who can read but not publish should not be shown
either tool and then fail partway through.

So each origin-facing tool instead declares, at its own decorator, exactly
which PERMISSIONS commands and PUBLISH_RECORD kinds its implementation can
issue — a `Needs`. Declared, never inferred: an earlier pass tried scraping
tool bodies with a regex to guess this and got several kinds wrong (see
`test_needs_declarations.py`, which now checks the declarations against the
real client-method calls instead of trusting either by itself).

`check()` answers per tool by fetching PERMISSIONS for the caller's current
origin and identity (cached briefly — it is a relay's live policy snapshot,
not a constant) and testing the declared commands/kinds against it. That can
come back `None` rather than True/False: an anonymous principal that
PERMISSIONS itself refuses, an origin too old to know the opcode, or a
network failure. gating.py only consults this after its own local heuristic
(origin present, identity present if the tool needs one) already passes —
PERMISSIONS can narrow that answer further (the caller has an identity, but
the relay's ACL does not grant this tool's commands) but never widen it, and
a `None` here just means the narrowing did not happen, not that everything
is denied. A real relay outage or an old server degrades to the local
heuristic rather than hiding every origin-facing tool.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TypeVar

from bonnet.gateway import tenancy
from bonnet.net.firehose_models import Permissions

_F = TypeVar("_F", bound=Callable)


@dataclass(frozen=True)
class Needs:
    """What a tool requires the relay to grant, to work at all.

    `commands` are PERMISSIONS command names (e.g. "ARTICLE_GET") — every
    command the tool's implementation can issue, not just its primary one.
    `kinds` are record kinds the tool may publish via PUBLISH_RECORD, checked
    only when "PUBLISH_RECORD" is itself in `commands`.

    A tool that only optionally calls a command — get_article's fallback
    ARTICLE_BODY fetch is wrapped in try/except and silently skipped on
    failure — leaves that command out. Needs lists what the tool cannot work
    at all without, not everything it might touch.
    """

    commands: frozenset[str]
    kinds: frozenset[str] = frozenset()

    def satisfied_by(self, perms: Permissions) -> bool:
        if not self.commands <= set(perms.commands):
            return False
        if self.kinds and not self.kinds <= set(perms.kinds):
            return False
        return True


#: tool name -> its declared Needs. Populated by the `needs()` decorator at
#: module load, so it can never drift from which tools actually declare one.
NEEDS: dict[str, Needs] = {}


def needs(*, commands: list[str], kinds: tuple[str, ...] = ()) -> Callable[[_F], _F]:
    """Decorate a tool function with the PERMISSIONS it requires.

    Apply below `@mcp.tool(...)` so it runs first, on the plain function,
    before FastMCP wraps it — the registry keys on `fn.__name__`, which must
    still be the tool's own name at that point.
    """

    def decorator(fn: _F) -> _F:
        NEEDS[fn.__name__] = Needs(frozenset(commands), frozenset(kinds))
        return fn

    return decorator


#: How long a fetched Permissions answer is trusted before asking again.
#: Short on purpose — it is a live policy snapshot (a punishment can land, a
#: rule can change), not a constant, but long enough that listing tools every
#: turn does not mean a PERMISSIONS round trip every turn.
_TTL_SECONDS = 30.0


@dataclass
class _CacheEntry:
    perms: Permissions
    fetched_at: float = field(default_factory=time.monotonic)


#: Keyed by (tenant, url, identity, board). The tenant belongs in the key even
#: though the identity is already there: identities are named per tenant, so
#: two tenants can each hold a "scout" on the same origin, and without it one
#: would be served the other's answer about what it may do.
_cache: dict[tuple[str, str, str, str], _CacheEntry] = {}


def invalidate() -> None:
    """Drop every cached answer for the current tenant.

    Called whenever the (origin, identity) a cache entry is keyed on could
    have changed underneath it: connect, switch_origin, register. Scoped to
    the calling tenant rather than clearing the whole dict — the cache is
    already keyed by tenant so another tenant's entries are unaffected by
    this one's connect, and a shared HTTP bridge with several tenants active
    at once must not force them all back to a PERMISSIONS round trip because
    one of them reconnected.
    """
    tenant = tenancy.current_tenant.get()
    for key in [k for k in _cache if k[0] == tenant]:
        del _cache[key]


def _cache_key(board: str, auth: str | None = None) -> tuple[str, str, str, str]:
    """The cache key for the current tenant, origin, identity and board.

    One function rather than the expression written out at each use, so the
    two callers cannot drift apart — a `refresh` that computed a different
    key than `_permissions_for` would silently stop invalidating anything.

    `auth`, when given, is a call's own per-call identity override — the same
    parameter every origin-facing tool accepts — and takes priority over the
    session's default identity, the same way `_tools._connect_authenticated`
    already treats it.
    """
    # Imported here, not at module scope: tools imports this module for the
    # needs()/NEEDS registry it decorates with, so a top-level import would
    # cycle the same way gating.py's does.
    from bonnet.gateway import tools as _tools

    identity = auth or _tools.current_username.get() or _tools._default_identity() or ""
    return (tenancy.current_tenant.get(), _tools._current_url(), identity, board)


async def _permissions_for(board: str, auth: str | None = None) -> Permissions | None:
    """Cached PERMISSIONS for the current origin, identity and board.

    None means the answer is unavailable — a denied PERMISSIONS call, an
    origin that predates the opcode, or a connection failure — not that
    everything is denied. Callers fall back to a coarser heuristic in that
    case rather than reading None as "no permissions".
    """
    from bonnet.gateway import tools as _tools

    key = _cache_key(board, auth)
    entry = _cache.get(key)
    now = time.monotonic()
    if entry is not None and now - entry.fetched_at < _TTL_SECONDS:
        return entry.perms

    # Read back off the key rather than recomputed, so what is fetched is
    # provably the identity the entry will be filed under.
    identity = key[2]

    client = _tools._make_client()
    try:
        if identity:
            # No anonymous fallback here: a named identity that fails to
            # connect (bad/missing password, unknown local identity, ...)
            # must not be answered for as anonymous — that would produce a
            # confident denial cached under the *real* identity's key,
            # exactly the wrong side of the None/False distinction this
            # function documents. Let it fall to `except Exception` below
            # and come back as None ("unavailable"), same as any other
            # connection failure.
            await _tools._connect_authenticated(client, auth)
        else:
            await _tools._connect_anonymous(client)
        perms = await client.get_permissions(board)
    except Exception:
        return None
    finally:
        await client.close()

    _cache[key] = _CacheEntry(perms)
    return perms


async def refresh(board: str = "") -> Permissions | None:
    """Force a fresh PERMISSIONS fetch for `board`, bypassing the cache.

    This is what makes per-board permissions expressible in tool visibility
    at all: open_board calls this on entry, rather than waiting for a stale
    cache entry to expire or for some other tool call to trigger a refetch.
    """
    _cache.pop(_cache_key(board), None)
    return await _permissions_for(board)


async def check(tool_name: str, board: str = "", auth: str | None = None) -> bool | None:
    """Whether the caller identified by `auth` (or the session default, if
    `auth` is not given) satisfies `tool_name`'s declared Needs.

    True/False when PERMISSIONS answered; None when it could not be asked at
    all (see `_permissions_for`), which callers should treat as "fall back",
    not as "denied".
    """
    declared = NEEDS.get(tool_name)
    if declared is None:
        return None
    perms = await _permissions_for(board, auth)
    if perms is None:
        return None
    return declared.satisfied_by(perms)
