import os
import tomllib
import fnmatch
from typing import Dict, List, Any

from core.article_feed import normalize_origin


class Matcher:
    def __init__(self, pubkey: bytes = None, origin_pattern: str = None, wildcard: bool = False, anonymous: bool = False, unknown: bool = False):
        self.pubkey = pubkey
        self.origin_pattern = origin_pattern
        self.wildcard = wildcard
        self.anonymous = anonymous
        self.unknown = unknown

    def matches(self, peer_pubkey: bytes, origin: str, is_anonymous: bool = False, is_unknown: bool = False) -> bool:
        if self.anonymous and is_anonymous:
            return True
        if self.anonymous and not is_anonymous:
            return False
        if self.unknown and is_unknown:
            return True
        if self.unknown and not is_unknown:
            return False
        if self.pubkey is not None:
            return peer_pubkey == self.pubkey
        if self.origin_pattern is not None:
            if origin is None:
                return False
            return fnmatch.fnmatch(origin, self.origin_pattern)
        if self.wildcard:
            return True
        return False

    @staticmethod
    def from_dict(data: dict) -> 'Matcher':
        if 'pubkey' in data:
            pubkey_hex = data['pubkey']
            if pubkey_hex.startswith('hex:'):
                pubkey_hex = pubkey_hex[4:]
            return Matcher(pubkey=bytes.fromhex(pubkey_hex))
        if 'origin' in data:
            return Matcher(origin_pattern=data['origin'])
        if 'anonymous' in data and data['anonymous']:
            return Matcher(anonymous=True)
        if 'unknown' in data and data['unknown']:
            return Matcher(unknown=True)
        if 'wildcard' in data and data['wildcard']:
            return Matcher(wildcard=True)
        return Matcher(wildcard=True)


class ACLEntry:
    def __init__(self, name: str, matcher: Matcher, board_patterns: list, read_perm: bool, write_perm: bool,
                 command_patterns: list = None, object_patterns: list = None):
        self.name = name
        self.matcher = matcher
        self.board_patterns = board_patterns
        self.read_perm = read_perm
        self.write_perm = write_perm
        self.command_patterns = command_patterns
        self.object_patterns = object_patterns

    def board_matches(self, board_name: str) -> bool:
        if board_name is None:
            return False
        for pattern in self.board_patterns:
            if fnmatch.fnmatch(board_name, pattern):
                return True
        return False

    def command_matches(self, command_name: str) -> bool:
        if self.command_patterns is None:
            return False
        if command_name is None:
            return False
        for pattern in self.command_patterns:
            if pattern == "*" or fnmatch.fnmatch(command_name, pattern):
                return True
        return False

    def object_matches(self, object_name: str) -> bool:
        if self.object_patterns is None:
            return False
        if object_name is None:
            return False
        for pattern in self.object_patterns:
            if pattern == "*" or fnmatch.fnmatch(object_name, pattern):
                return True
        return False

    @staticmethod
    def from_dict(name: str, data: dict) -> 'ACLEntry':
        match_data = data.get('match', {})
        matcher = Matcher.from_dict(match_data)

        boards = data.get('boards', ['*'])
        if isinstance(boards, str):
            boards = [boards]

        commands = data.get('commands', None)
        if isinstance(commands, str):
            commands = [commands]

        objects = data.get('objects', None)
        if isinstance(objects, str):
            objects = [objects]

        read_perm = data.get('read', False)
        write_perm = data.get('write', False)

        return ACLEntry(name, matcher, boards, read_perm, write_perm,
                        command_patterns=commands, object_patterns=objects)


class Filter:
    """Per-origin eval-time creation-date window.

    A record is in-window if its creation_time falls within [created_after,
    created_before]. Either bound is optional. Multiple Filter entries sharing
    an origin are OR'd. `origin = "*"` is a wildcard fallback used only when no
    specific entry matches a record's origin. Unconfigured origins default
    allow.
    """
    def __init__(self, origin: str, created_after: int = None, created_before: int = None):
        self.origin = origin
        self.created_after = created_after
        self.created_before = created_before

    def contains(self, creation_time: int) -> bool:
        if self.created_after is not None and creation_time < self.created_after:
            return False
        if self.created_before is not None and creation_time > self.created_before:
            return False
        return True

    @staticmethod
    def from_dict(data: dict) -> 'Filter':
        origin = data.get('origin', '*')
        created_after = data.get('created_after', None)
        created_before = data.get('created_before', None)
        return Filter(origin, created_after, created_before)


class FeedSubscription:
    """Feed subscription config (§15).

    A subscription says "import metadata for these boards from this origin,
    dialing these relay candidates." Matching is against event origin and
    board, never relay hostname. Peers replicate metadata only; article
    bodies are served by the origin and fetched directly by clients.
    """
    def __init__(self, origin: str, boards: list, relays: list):
        self.origin = normalize_origin(origin) if origin else origin
        self.boards = boards  # list of board names, or ["*"] for all
        self.relays = relays

    def matches_board(self, board: str) -> bool:
        if not self.boards:
            return False
        if "*" in self.boards:
            return True
        return board in self.boards

    @staticmethod
    def from_dict(data: dict) -> 'FeedSubscription':
        origin = data.get('origin', '')
        boards = data.get('boards', [])
        if isinstance(boards, str):
            boards = [boards]
        relays = data.get('relays', [])
        if isinstance(relays, str):
            relays = [relays]
        return FeedSubscription(origin, boards, relays)


class ControlPolicy:
    """Control enforcement policy (§15).

    Specifies which event types to apply from a specific (origin, board) feed.
    Evaluated only over already accepted events.
    """
    def __init__(self, origin: str, board: str, apply: list):
        self.origin = normalize_origin(origin) if origin else origin
        self.board = board
        self.apply = apply  # e.g. ["punishment", "punishment-revoke"]

    @staticmethod
    def from_dict(data: dict) -> 'ControlPolicy':
        origin = data.get('origin', '')
        board = data.get('board', '')
        apply_types = data.get('apply', [])
        if isinstance(apply_types, str):
            apply_types = [apply_types]
        return ControlPolicy(origin, board, apply_types)


class ModerationBoards:
    """Configured local moderation board names (§15)."""
    def __init__(self, rules: str = "moderation.rules",
                 reports: str = "moderation.reports",
                 punishments: str = "moderation.actions",
                 users: str = "users.registry"):
        self.rules = rules
        self.reports = reports
        self.punishments = punishments
        self.users = users

    @staticmethod
    def from_dict(data: dict) -> 'ModerationBoards':
        return ModerationBoards(
            rules=data.get('rules', 'moderation.rules'),
            reports=data.get('reports', 'moderation.reports'),
            punishments=data.get('punishments', 'moderation.actions'),
            users=data.get('users', 'users.registry'),
        )


class Config:
    def __init__(self, registrars: List[str] = None, timeout_seconds: int = 30, ame_path: str = None, origin: str = None, anonymous_read: bool = True, nav_db_path: str = None, reports_db_path: str = None, punishments_db_path: str = None, log_dir: str = None, acls: List[ACLEntry] = None, admin_bypass_acl: bool = True, public_commands: set = None, data_dir: str = None, identity_path: str = None, userfile_path: str = None, port_standard: int = 2272, port_privileged: int = 272, max_connections: int = 100, max_request_size: int = 10485760, rate_limit_requests: int = 100, rate_limit_window: int = 1, tls_enabled: bool = False, tls_cert_path: str = None, tls_key_path: str = None, tls_ca_bundle: bool | str = True, search_max_count: int = 1000, search_timeout_seconds: int = 10, search_result_limit: int = 100, search_per_identity_concurrency: int = 1, search_rate_limit: int = 10, search_rate_window_seconds: int = 60, rg_path: str = None, http_port: int = 2272, http_host: str = "0.0.0.0", signature_lifetime_seconds: int = 60, clock_skew_seconds: int = 30, replay_db_path: str = None, max_concurrent_requests: int = 100, keepalive_seconds: int = 15, allow_cleartext_loopback: bool = False, trusted_proxies: list = None, max_creation_time_correction: int = 86400, allow_legacy_unsigned_user_sync: bool = False, filters: List['Filter'] = None, import_allowlist: dict = None, feed_subscriptions: List['FeedSubscription'] = None, control_policies: List['ControlPolicy'] = None, moderation_boards: 'ModerationBoards' = None, sync_interval_seconds: int = 300, sync_backoff_max_seconds: int = 3600, sync_max_events_per_cycle: int = 5000, max_article_body_size: int = 1048576):
        if registrars is None:
            registrars = ["knolastna.me"]
        self.registrars = [r.lower() for r in registrars]
        self.timeout_seconds = timeout_seconds
        if ame_path is None:
            ame_path = "./boards"
        self.ame_path = ame_path
        if origin is None:
            origin = "localhost"
        self.origin = normalize_origin(origin)
        self.anonymous_read = anonymous_read

        if public_commands is None:
            public_commands = set()
        self.public_commands = public_commands

        if data_dir is None:
            data_dir = "./data"
        self.data_dir = data_dir

        self._resolve_paths(identity_path, userfile_path, nav_db_path, reports_db_path, punishments_db_path, log_dir)

        self.port_standard = port_standard
        self.port_privileged = port_privileged
        self.max_connections = max_connections
        self.max_request_size = max_request_size
        self.rate_limit_requests = rate_limit_requests
        self.rate_limit_window = rate_limit_window

        if tls_cert_path is None:
            tls_cert_path = "./certs/bonnet.crt"
        if tls_key_path is None:
            tls_key_path = "./certs/bonnet.key"
        self.tls_enabled = tls_enabled
        self.tls_cert_path = tls_cert_path
        self.tls_key_path = tls_key_path
        self.tls_ca_bundle = tls_ca_bundle

        self.search_max_count = search_max_count
        self.search_timeout_seconds = search_timeout_seconds
        self.search_result_limit = search_result_limit
        self.search_per_identity_concurrency = search_per_identity_concurrency
        self.search_rate_limit = search_rate_limit
        self.search_rate_window_seconds = search_rate_window_seconds
        self.rg_path = rg_path

        self.http_port = http_port
        self.http_host = http_host
        self.signature_lifetime_seconds = signature_lifetime_seconds
        self.clock_skew_seconds = clock_skew_seconds
        self.replay_db_path = replay_db_path or os.path.join(self.data_dir, "replay.db")
        self.max_concurrent_requests = max_concurrent_requests
        self.keepalive_seconds = keepalive_seconds
        self.allow_cleartext_loopback = allow_cleartext_loopback
        self.trusted_proxies = trusted_proxies or []
        self.max_creation_time_correction = max_creation_time_correction
        self.allow_legacy_unsigned_user_sync = allow_legacy_unsigned_user_sync

        # Import allowlist (§13): per-object-type origin allowlists, default-deny.
        # import_allowlist is a dict like {"boards": ["origin.example"], ...}.
        # Origins are normalized to lowercase. Empty/missing lists deny all.
        self._import_allowlist: Dict[str, set] = {}
        if import_allowlist:
            for obj_type, origins in import_allowlist.items():
                if isinstance(origins, str):
                    origins = [origins]
                self._import_allowlist[obj_type] = {o.lower() for o in origins if o}

        if acls is None:
            acls = []
        self.acls = acls
        self.admin_bypass_acl = admin_bypass_acl
        self.filters = filters or []

        # Feed subscriptions (§15): per-(origin, boards) import config.
        self.feed_subscriptions: List[FeedSubscription] = feed_subscriptions or []
        self.control_policies: List[ControlPolicy] = control_policies or []
        self.moderation_boards: ModerationBoards = moderation_boards or ModerationBoards()
        self.sync_interval_seconds = sync_interval_seconds
        self.sync_backoff_max_seconds = sync_backoff_max_seconds
        self.sync_max_events_per_cycle = sync_max_events_per_cycle
        self.max_article_body_size = max_article_body_size

    def _resolve_paths(self, identity_path: str, userfile_path: str, nav_db_path: str, reports_db_path: str, punishments_db_path: str, log_dir: str) -> None:
        """
        Resolve paths relative to data_dir if not explicitly set.
        """
        self.identity_path = self._resolve_path(identity_path, "identity")
        self.userfile_path = self._resolve_path(userfile_path, "userfile")
        self.nav_db_path = self._resolve_path(nav_db_path, "nav.db")
        self.reports_db_path = self._resolve_path(reports_db_path, "reports.db")
        self.punishments_db_path = self._resolve_path(punishments_db_path, "punishments.db")

        if log_dir is None:
            self.log_dir = "./logs"
        else:
            self.log_dir = log_dir

    def _resolve_path(self, explicit_path: str, default_name: str) -> str:
        """
        Resolve a path: use explicit if absolute, otherwise relative to data_dir.
        """
        if explicit_path is not None:
            if os.path.isabs(explicit_path):
                return explicit_path
            return os.path.join(self.data_dir, explicit_path).replace('\\', '/')
        return os.path.join(self.data_dir, default_name).replace('\\', '/')

    @staticmethod
    def load(path: str) -> 'Config':
        if not os.path.exists(path):
            return Config._create_default(path)

        with open(path, 'rb') as f:
            data = tomllib.load(f)

        server = data.get('server', {})
        limits = data.get('limits', {})
        boards = data.get('boards', {})
        keibatsu = data.get('keibatsu', {})
        tls = data.get('tls', {})
        search = data.get('search', {})

        registrars = server.get('registrars', ["knolastna.me"])
        origin = server.get('origin', "localhost")
        timeout_seconds = limits.get('timeout_seconds', 30)
        ame_path = boards.get('path', "./boards")
        anonymous_read = server.get('anonymous_read', True)
        admin_bypass_acl = server.get('admin_bypass_acl', True)

        # public_commands is obsolete and silently ignored (§5.7). It may
        # remain in TOML for backward compatibility but has no authorization
        # effect. Command access is now governed by command/object ACLs.
        # No cmd_map parsing is needed.

        data_dir = server.get('data_dir', "./data")
        identity_path = server.get('identity_path', None)
        userfile_path = server.get('userfile_path', None)
        nav_db_path = server.get('nav_db_path', None)
        reports_db_path = keibatsu.get('reports_path', None)
        punishments_db_path = keibatsu.get('punishments_path', None)
        log_dir = server.get('log_dir', None)

        port_standard = server.get('port_standard', 2272)
        port_privileged = server.get('port_privileged', 272)

        max_connections = limits.get('max_connections', 100)
        max_request_size = limits.get('max_request_size', 10485760)
        rate_limit_requests = limits.get('rate_limit_requests', 100)
        rate_limit_window = limits.get('rate_limit_window', 1)

        tls_enabled = tls.get('enabled', False)
        tls_cert_path = tls.get('cert_path', None)
        tls_key_path = tls.get('key_path', None)
        tls_ca_bundle = tls.get('ca_bundle', True)

        search_max_count = search.get('max_count', 1000)
        search_timeout_seconds = search.get('timeout_seconds', 10)
        search_result_limit = search.get('result_limit', 100)
        search_per_identity_concurrency = search.get('per_identity_concurrency', 1)
        search_rate_limit = search.get('rate_limit', 10)
        search_rate_window_seconds = search.get('rate_window_seconds', 60)
        rg_path = search.get('rg_path', None)

        acls = []
        if 'acl' in data:
            for acl_data in data['acl']:
                name = acl_data.get('name', f'acl-{len(acls)}')
                acls.append(ACLEntry.from_dict(name, acl_data))

        filters = []
        if 'filter' in data:
            for filter_data in data['filter']:
                filters.append(Filter.from_dict(filter_data))

        import_allowlist = {}
        if 'import_allowlist' in data:
            ia = data['import_allowlist']
            if isinstance(ia, dict):
                for obj_type, origins in ia.items():
                    if isinstance(origins, str):
                        origins = [origins]
                    if isinstance(origins, list):
                        import_allowlist[obj_type] = [o for o in origins if isinstance(o, str) and o]

        feed_subscriptions = []
        if 'feed_subscription' in data:
            for sub_data in data['feed_subscription']:
                feed_subscriptions.append(FeedSubscription.from_dict(sub_data))

        control_policies = []
        if 'control_policy' in data:
            for pol_data in data['control_policy']:
                control_policies.append(ControlPolicy.from_dict(pol_data))

        moderation_boards = None
        if 'moderation_boards' in data:
            moderation_boards = ModerationBoards.from_dict(data['moderation_boards'])

        sync_cfg = data.get('sync', {})
        sync_interval_seconds = sync_cfg.get('interval_seconds', 300)
        sync_backoff_max_seconds = sync_cfg.get('backoff_max_seconds', 3600)
        sync_max_events_per_cycle = sync_cfg.get('max_events_per_cycle', 5000)

        limits_cfg = data.get('limits', {})
        max_article_body_size = limits_cfg.get('max_article_body_size', 1048576)

        return Config(
            registrars=registrars,
            timeout_seconds=timeout_seconds,
            ame_path=ame_path,
            origin=origin,
            anonymous_read=anonymous_read,
            nav_db_path=nav_db_path,
            reports_db_path=reports_db_path,
            punishments_db_path=punishments_db_path,
            log_dir=log_dir,
            acls=acls,
            admin_bypass_acl=admin_bypass_acl,
            data_dir=data_dir,
            identity_path=identity_path,
            userfile_path=userfile_path,
            port_standard=port_standard,
            port_privileged=port_privileged,
            max_connections=max_connections,
            max_request_size=max_request_size,
            rate_limit_requests=rate_limit_requests,
            rate_limit_window=rate_limit_window,
            tls_enabled=tls_enabled,
            tls_cert_path=tls_cert_path,
            tls_key_path=tls_key_path,
            tls_ca_bundle=tls_ca_bundle,
            search_max_count=search_max_count,
            search_timeout_seconds=search_timeout_seconds,
            search_result_limit=search_result_limit,
            search_per_identity_concurrency=search_per_identity_concurrency,
            search_rate_limit=search_rate_limit,
            search_rate_window_seconds=search_rate_window_seconds,
            rg_path=rg_path,
            filters=filters,
            import_allowlist=import_allowlist,
            feed_subscriptions=feed_subscriptions,
            control_policies=control_policies,
            moderation_boards=moderation_boards,
            sync_interval_seconds=sync_interval_seconds,
            sync_backoff_max_seconds=sync_backoff_max_seconds,
            sync_max_events_per_cycle=sync_max_events_per_cycle,
            max_article_body_size=max_article_body_size,
        )

    @staticmethod
    def _create_default(path: str) -> 'Config':
        default_content = """[server]
registrars = ["localhost"]
origin = "localhost"
anonymous_read = true
admin_bypass_acl = true
data_dir = "./data"
log_dir = "./logs"
port_standard = 2272
port_privileged = 272
# public_commands is obsolete and silently ignored. Command access is now
# governed by command and object ACLs below. Authorization is default-deny:
# every command requires an explicit ACL grant.

[[acl]]
name = "local-full-access"
match.origin = "localhost"
commands = ["*"]
objects = ["*"]
boards = ["*"]
read = true
write = true

[[acl]]
name = "anonymous-read"
match.anonymous = true
commands = ["GET_USERS_BY_PUBKEY", "LIST_USERS", "LIST_PEERS", "BOARD_LIST", "POST_GET", "POST_LIST", "GET_PUBKEY", "ARTICLE_GET", "ARTICLE_LIST", "ARTICLE_SEARCH", "BAN_STATUS", "FEED_HEAD", "FEED_EVENTS", "ARTICLE_BODY", "FEED_HEADS", "PEER_KEY_LIST"]
objects = ["articles"]
read = true
write = false

[[acl]]
name = "unknown-read"
match.unknown = true
commands = ["GET_USERS_BY_PUBKEY", "LIST_USERS", "LIST_PEERS", "BOARD_LIST", "POST_GET", "POST_LIST", "GET_PUBKEY", "ARTICLE_GET", "ARTICLE_LIST", "ARTICLE_SEARCH", "BAN_STATUS", "FEED_HEAD", "FEED_EVENTS", "ARTICLE_BODY", "FEED_HEADS", "PEER_KEY_LIST"]
objects = ["articles"]
read = true
write = false

[[acl]]
name = "unknown-registration"
match.unknown = true
commands = ["REGISTER"]
write = true

[limits]
timeout_seconds = 30
max_connections = 100
max_request_size = 10485760
rate_limit_requests = 100
rate_limit_window = 1

[boards]
path = "./boards"

[keibatsu]
reports_path = "reports.db"
punishments_path = "punishments.db"

[search]
# Content search via ripgrep. rg is resolved at runtime (bundled in frozen
# builds via _MEIPASS, otherwise via PATH); the server returns 503 if missing.
# Override the binary location explicitly:
# rg_path = "/usr/local/bin/rg"
max_count = 1000
timeout_seconds = 10
result_limit = 100
per_identity_concurrency = 1
rate_limit = 10
rate_window_seconds = 60

[tls]
enabled = false
cert_path = "./certs/bonnet.crt"
key_path = "./certs/bonnet.key"
# Outbound (federation) TLS verification:
#   true            use system trust store (default, recommended for production)
#   "/path/to/ca"   use a specific CA bundle file
#   false           disable verification (dev/test only — insecure)
# ca_bundle = true

# Import allowlists (§13): per-object-type origin allowlists, default-deny.
# Only origins listed here are imported during federation sync. Missing or
# empty lists deny all imports for that object type. Trust pinning and
# signatures remain mandatory — an allowlist entry says "we bother to copy
# this origin", it does not establish cryptographic trust.
# This never affects exports; export visibility is controlled by ACLs.
[import_allowlist]
# boards = ["boards.example"]
# users = ["identity.example"]
# reports = ["moderation.example"]
# punishments = ["moderation.example"]
"""
        config_dir = os.path.dirname(path)
        if config_dir:
            os.makedirs(config_dir, exist_ok=True)

        with open(path, 'w') as f:
            f.write(default_content)

        os.chmod(path, 0o600)

        local_acl = ACLEntry(
            "local-full-access",
            Matcher(origin_pattern="localhost"),
            ["*"], True, True,
            command_patterns=["*"],
            object_patterns=["*"],
        )

        anonymous_read_commands = [
            "GET_USERS_BY_PUBKEY", "LIST_USERS", "LIST_PEERS", "BOARD_LIST",
            "POST_GET", "POST_LIST", "GET_PUBKEY", "PEER_KEY_LIST",
            "ARTICLE_GET", "ARTICLE_LIST", "ARTICLE_SEARCH",
            "FEED_HEAD", "FEED_EVENTS", "ARTICLE_BODY", "FEED_HEADS",
            "BAN_STATUS",
        ]
        anonymous_acl = ACLEntry(
            "anonymous-read",
            Matcher(anonymous=True),
            ["*"], True, False,
            command_patterns=anonymous_read_commands,
            object_patterns=["reports", "punishments"],
        )

        unknown_read_acl = ACLEntry(
            "unknown-read",
            Matcher(unknown=True),
            ["*"], True, False,
            command_patterns=anonymous_read_commands,
            object_patterns=["reports", "punishments"],
        )

        unknown_acl = ACLEntry(
            "unknown-registration",
            Matcher(unknown=True),
            ["*"], False, True,
            command_patterns=["REGISTER"],
        )

        return Config(
            registrars=["localhost"],
            timeout_seconds=30,
            ame_path="./boards",
            origin="localhost",
            anonymous_read=True,
            nav_db_path=None,
            reports_db_path=None,
            punishments_db_path=None,
            log_dir="./logs",
            acls=[local_acl, anonymous_acl, unknown_read_acl, unknown_acl],
            admin_bypass_acl=True,
            data_dir="./data",
            identity_path=None,
            userfile_path=None,
            port_standard=2272,
            port_privileged=272,
            max_connections=100,
            max_request_size=10485760,
            rate_limit_requests=100,
            rate_limit_window=1,
            tls_enabled=False,
            tls_cert_path="./certs/bonnet.crt",
            tls_key_path="./certs/bonnet.key"
        )

    def registrar_valid(self, registrar: str) -> bool:
        if not registrar:
            return False
        return registrar.lower() in self.registrars

    def is_import_origin_allowed(self, object_type: str, origin: str) -> bool:
        """Import allowlist check (§13.2).

        Returns True only if `origin` is in the configured allowlist for the
        given object_type. Default-deny: unknown object type, missing object
        list, or empty list all deny. Origin comparison is case-insensitive.

        This check is for importing/copying remote data only (§13.5). It must
        never be used in command handlers or registry export services — export
        visibility is controlled solely by ACLs.
        """
        if not object_type or not origin:
            return False
        allowed = self._import_allowlist.get(object_type)
        if not allowed:
            return False
        return origin.lower() in allowed

    def get_feed_subscription(self, origin: str, board: str):
        """Find the first matching FeedSubscription for (origin, board).

        Returns the FeedSubscription or None. Matching is against event origin
        and board, never relay hostname. A subscription with boards=["*"]
        matches any board for that origin.
        """
        for sub in self.feed_subscriptions:
            if sub.origin == origin and sub.matches_board(board):
                return sub
        return None

    def is_feed_subscribed(self, origin: str, board: str) -> bool:
        """Check if a (origin, board) feed is subscribed for import."""
        return self.get_feed_subscription(origin, board) is not None

    def get_control_policy(self, origin: str, board: str):
        """Find the ControlPolicy for (origin, board), or None."""
        for policy in self.control_policies:
            if policy.origin == origin and policy.board == board:
                return policy
        return None

    def record_in_window(self, origin: str, creation_time: int) -> bool:
        """Eval-time creation-date window for a record's origin.

        Returns True if `creation_time` falls within any configured Filter for
        `origin`. Exact-origin entries are consulted first (OR'd); if none
        exist, wildcard ("*") entries are consulted; if neither exist, the
        record is allowed (default).
        """
        if not self.filters:
            return True
        exact = [f for f in self.filters if f.origin == origin]
        if exact:
            return any(f.contains(creation_time) for f in exact)
        wildcard = [f for f in self.filters if f.origin == '*']
        if wildcard:
            return any(f.contains(creation_time) for f in wildcard)
        return True

    def check_permission(self, action: str, board: str, peer_pubkey: bytes, origin: str, is_admin: bool, is_mod: bool, board_owner: object, is_anonymous: bool = False, creation_time: int = None, record_origin: str = None, is_unknown: bool = False) -> bool:
        if self.admin_bypass_acl and is_admin:
            return True

        if board_owner is not None and peer_pubkey is not None and peer_pubkey == board_owner:
            return True

        if action == "write" and is_mod:
            return True

        return self._eval_buckets(
            action,
            lambda acl: acl.board_matches(board),
            peer_pubkey, origin, is_anonymous, is_unknown,
            creation_time, record_origin,
        )

    def check_command_permission(self, command_name: str, action: str, peer_pubkey: bytes, origin: str, is_anonymous: bool = False, is_unknown: bool = False, creation_time: int = None, record_origin: str = None) -> bool:
        """Command ACL check (§5.4). No admin/owner/mod bypass. Default-deny."""
        return self._eval_buckets(
            action,
            lambda acl: acl.command_matches(command_name),
            peer_pubkey, origin, is_anonymous, is_unknown,
            creation_time, record_origin,
        )

    def check_object_permission(self, action: str, object_name: str, peer_pubkey: bytes, origin: str, is_anonymous: bool = False, is_unknown: bool = False, creation_time: int = None, record_origin: str = None) -> bool:
        """Object ACL check (§5.5). No admin bypass. Default-deny."""
        return self._eval_buckets(
            action,
            lambda acl: acl.object_matches(object_name),
            peer_pubkey, origin, is_anonymous, is_unknown,
            creation_time, record_origin,
        )

    def _eval_buckets(self, action: str, acl_filter, peer_pubkey: bytes, origin: str, is_anonymous: bool, is_unknown: bool, creation_time, record_origin) -> bool:
        """Shared 5-bucket ACL precedence scan with temporal filter.

        Precedence (§3.5): anonymous → pubkey → unknown → origin → wildcard.
        First-match-wins within each bucket. Temporal filter (out_of_window)
        applies to anonymous, origin, and wildcard buckets; pubkey and unknown
        buckets are always admitted (they have no creation_time to filter).

        acl_filter: callable(acl) -> bool selecting which ACLs participate
        (board_matches, command_matches, or object_matches).
        """
        out_of_window = (
            creation_time is not None
            and record_origin is not None
            and not self.record_in_window(record_origin, creation_time)
        )

        anonymous_matches = []
        pubkey_matches = []
        unknown_matches = []
        origin_matches = []
        wildcard_matches = []

        for acl in self.acls:
            if not acl_filter(acl):
                continue
            if not acl.matcher.matches(peer_pubkey, origin, is_anonymous, is_unknown):
                continue
            if acl.matcher.anonymous:
                if not out_of_window:
                    anonymous_matches.append(acl)
            elif acl.matcher.pubkey is not None:
                pubkey_matches.append(acl)
            elif acl.matcher.unknown:
                unknown_matches.append(acl)
            elif acl.matcher.origin_pattern is not None:
                if not out_of_window:
                    origin_matches.append(acl)
            else:
                if not out_of_window:
                    wildcard_matches.append(acl)

        for bucket in (anonymous_matches, pubkey_matches, unknown_matches, origin_matches, wildcard_matches):
            for acl in bucket:
                if action == "read":
                    return acl.read_perm
                if action == "write":
                    return acl.write_perm

        return False
