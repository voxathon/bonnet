from net.context import CommandContext
from core.commands import CommandSpec


class BonnetEngine:
    def __init__(self, ume, ame, keibatsu, config, server_identity):
        self.ume = ume
        self.ame = ame
        self.keibatsu = keibatsu
        self.config = config
        self.server_identity = server_identity
        self.article_service = None
        self.moderation_service = None

    def check_permission(self, action: str, board: str, ctx: CommandContext) -> bool:
        """
        Check if context has permission for action on board.

        Args:
            action: "read" or "write"
            board: board name or None for global actions
            ctx: CommandContext with peer_public_key, user, and permission methods

        Returns:
            True if permission granted, False otherwise
        """
        peer_pubkey = ctx.peer_public_key if ctx.peer_public_key else None
        is_admin = ctx.is_administrator()
        is_mod = ctx.is_moderator()
        is_anonymous = ctx.is_anonymous
        is_unknown = ctx.is_unknown
        origin = self._resolve_origin(ctx)
        board_owner = None

        if board:
            board_owner = self.ame.get_board_owner(board)

        creation_time = None
        record_origin = None
        if ctx.user is not None:
            creation_time = getattr(ctx.user, 'creation_time', None)
            record_origin = getattr(ctx.user, 'record_origin', None)

        return self.config.check_permission(action, board, peer_pubkey, origin, is_admin, is_mod, board_owner, is_anonymous, creation_time, record_origin, is_unknown)

    def check_command_permission(self, spec: CommandSpec, ctx: CommandContext) -> bool:
        """Command ACL check (§5.4). No admin/owner/mod bypass. Default-deny."""
        peer_pubkey = ctx.peer_public_key if ctx.peer_public_key else None
        is_anonymous = ctx.is_anonymous
        is_unknown = ctx.is_unknown
        origin = self._resolve_origin(ctx)
        creation_time = None
        record_origin = None
        if ctx.user is not None:
            creation_time = getattr(ctx.user, 'creation_time', None)
            record_origin = getattr(ctx.user, 'record_origin', None)
        return self.config.check_command_permission(
            spec.name, spec.action, peer_pubkey, origin,
            is_anonymous, is_unknown, creation_time, record_origin,
        )

    def check_object_permission(self, action: str, object_name: str, ctx: CommandContext) -> bool:
        """Object ACL check (§5.5). No admin bypass. Default-deny."""
        peer_pubkey = ctx.peer_public_key if ctx.peer_public_key else None
        is_anonymous = ctx.is_anonymous
        is_unknown = ctx.is_unknown
        origin = self._resolve_origin(ctx)
        creation_time = None
        record_origin = None
        if ctx.user is not None:
            creation_time = getattr(ctx.user, 'creation_time', None)
            record_origin = getattr(ctx.user, 'record_origin', None)
        return self.config.check_object_permission(
            action, object_name, peer_pubkey, origin,
            is_anonymous, is_unknown, creation_time, record_origin,
        )

    def _resolve_origin(self, ctx: CommandContext) -> str:
        """
        Resolve origin for ACL matching.

        Only a *locally-registered* user's record_origin is trusted for ACL
        decisions, and only when it equals this server's configured origin.
        The WebSocket `Host` header is client-controllable and MUST NOT be used
        for ACL matching (#4); and a remote-synced user's record_origin is
        peer-supplied and forgeable, so it must not become an ACL principal (R1).
        Locally-registered users (created via REGISTER) and the root user always
        have record_origin == config.origin, so they still match origin-pattern
        ACLs. Anonymous/unresolved contexts, and any user whose
        record_origin != config.origin, resolve to the literal "unknown", which
        matches no origin-pattern ACL unless an explicit `anonymous` matcher
        grants access. Cross-origin trust should use `match.pubkey`.
        """
        if ctx.user and hasattr(ctx.user, 'record_origin') and ctx.user.record_origin:
            if ctx.user.record_origin == self.config.origin:
                return ctx.user.record_origin
        return "unknown"
