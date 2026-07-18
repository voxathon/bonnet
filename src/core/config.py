import os
import tomllib
import fnmatch
from typing import Dict, List, Any


class Matcher:
    def __init__(self, pubkey: bytes = None, origin_pattern: str = None, wildcard: bool = False, anonymous: bool = False):
        self.pubkey = pubkey
        self.origin_pattern = origin_pattern
        self.wildcard = wildcard
        self.anonymous = anonymous

    def matches(self, peer_pubkey: bytes, origin: str, is_anonymous: bool = False) -> bool:
        if self.anonymous and is_anonymous:
            return True
        if self.anonymous and not is_anonymous:
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
        if 'wildcard' in data and data['wildcard']:
            return Matcher(wildcard=True)
        return Matcher(wildcard=True)


class ACLEntry:
    def __init__(self, name: str, matcher: Matcher, board_patterns: list, read_perm: bool, write_perm: bool):
        self.name = name
        self.matcher = matcher
        self.board_patterns = board_patterns
        self.read_perm = read_perm
        self.write_perm = write_perm

    def board_matches(self, board_name: str) -> bool:
        if board_name is None:
            return False
        for pattern in self.board_patterns:
            if fnmatch.fnmatch(board_name, pattern):
                return True
        return False

    @staticmethod
    def from_dict(name: str, data: dict) -> 'ACLEntry':
        match_data = data.get('match', {})
        matcher = Matcher.from_dict(match_data)

        boards = data.get('boards', ['*'])
        if isinstance(boards, str):
            boards = [boards]

        read_perm = data.get('read', False)
        write_perm = data.get('write', False)

        return ACLEntry(name, matcher, boards, read_perm, write_perm)


class Config:
    def __init__(self, registrars: List[str] = None, timeout_seconds: int = 30, ame_path: str = None, origin: str = None, anonymous_read: bool = True, nav_db_path: str = None, reports_db_path: str = None, punishments_db_path: str = None, log_dir: str = None, acls: List[ACLEntry] = None, admin_bypass_acl: bool = True, public_commands: set = None, data_dir: str = None, identity_path: str = None, userfile_path: str = None, port_standard: int = 2272, port_privileged: int = 272, max_connections: int = 100, max_request_size: int = 10485760, rate_limit_requests: int = 100, rate_limit_window: int = 1, tls_enabled: bool = False, tls_cert_path: str = None, tls_key_path: str = None, tls_ca_bundle: bool | str = True, search_max_count: int = 1000, search_timeout_seconds: int = 10, search_result_limit: int = 100, search_per_identity_concurrency: int = 1, search_rate_limit: int = 10, search_rate_window_seconds: int = 60, rg_path: str = None, http_port: int = 2272, http_host: str = "0.0.0.0", signature_lifetime_seconds: int = 60, clock_skew_seconds: int = 30, replay_db_path: str = None, max_concurrent_requests: int = 100, keepalive_seconds: int = 15, allow_cleartext_loopback: bool = False, trusted_proxies: list = None):
        if registrars is None:
            registrars = ["knolastna.me"]
        self.registrars = [r.lower() for r in registrars]
        self.timeout_seconds = timeout_seconds
        if ame_path is None:
            ame_path = "./boards"
        self.ame_path = ame_path
        if origin is None:
            origin = "localhost"
        self.origin = origin
        self.anonymous_read = anonymous_read

        if public_commands is None:
            public_commands = {0x02, 0x03, 0x04, 0x11, 0x13, 0x14, 0x19, 0x30, 0x41, 0x42, 0x43, 0x51, 0x52, 0x54, 0x61, 0x62, 0x63, 0x71}
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

        if acls is None:
            acls = []
        self.acls = acls
        self.admin_bypass_acl = admin_bypass_acl

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

        cmd_map = {
            'GET_USER': 0x02, 'LIST_USERS': 0x03, 'LIST_PEERS': 0x04,
            'BOARD_LIST': 0x11, 'POST_GET': 0x13, 'POST_LIST': 0x14,
            'QUERY_POSTS': 0x19, 'POST_CONTENT_SEARCH': 0x1A, 'GET_PUBKEY': 0x30,
            'RULE_GET': 0x41, 'RULE_GET_BY_NAME': 0x42, 'RULE_LIST': 0x43,
            'REPORT_GET': 0x51, 'REPORT_LIST_BY_CULPRIT': 0x52, 'REPORT_LIST_SINCE': 0x54,
            'PUNISHMENT_GET': 0x61, 'PUNISHMENT_LIST_ACTIVE': 0x62, 'IS_BANNED': 0x63,
            'PEER_KEY_LIST': 0x71, 'REGISTER': 0x01
        }
        default_public = {0x02, 0x03, 0x04, 0x11, 0x13, 0x14, 0x19, 0x30, 0x41, 0x42, 0x43, 0x51, 0x52, 0x54, 0x61, 0x62, 0x63, 0x71}

        public_commands_raw = server.get('public_commands', None)
        if public_commands_raw is not None:
            public_commands = set()
            for cmd in public_commands_raw:
                if isinstance(cmd, int):
                    public_commands.add(cmd)
                elif isinstance(cmd, str):
                    if cmd.upper() in cmd_map:
                        public_commands.add(cmd_map[cmd.upper()])
                    elif cmd.startswith('0x'):
                        public_commands.add(int(cmd, 16))
        else:
            public_commands = default_public

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
            public_commands=public_commands,
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
            rg_path=rg_path
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
# public_commands = ["REGISTER", "LIST_USERS", "LIST_PEERS", "BOARD_LIST", "POST_GET", "POST_LIST", "QUERY_POSTS", "GET_PUBKEY", "RULE_GET", "RULE_GET_BY_NAME", "RULE_LIST", "REPORT_GET", "REPORT_LIST_BY_CULPRIT", "REPORT_LIST_SINCE", "PUNISHMENT_GET", "PUNISHMENT_LIST_ACTIVE", "IS_BANNED", "PEER_KEY_LIST"]
# Content search (POST_CONTENT_SEARCH) is default-deny for anonymous callers;
# opt in by adding it to public_commands above if anonymous search is desired.

[[acl]]
name = "local-full-access"
match.origin = "localhost"
boards = ["*"]
read = true
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
"""
        config_dir = os.path.dirname(path)
        if config_dir:
            os.makedirs(config_dir, exist_ok=True)

        with open(path, 'w') as f:
            f.write(default_content)

        os.chmod(path, 0o600)

        default_acl = ACLEntry(
            "local-full-access",
            Matcher(origin_pattern="localhost"),
            ["*"],
            True,
            True
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
            acls=[default_acl],
            admin_bypass_acl=True,
            public_commands=None,
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

    def check_permission(self, action: str, board: str, peer_pubkey: bytes, origin: str, is_admin: bool, is_mod: bool, board_owner: object, is_anonymous: bool = False) -> bool:
        if self.admin_bypass_acl and is_admin:
            return True

        if board_owner is not None and peer_pubkey is not None and peer_pubkey == board_owner:
            return True

        if action == "write" and is_mod:
            return True

        anonymous_matches = []
        pubkey_matches = []
        origin_matches = []
        wildcard_matches = []

        for acl in self.acls:
            if acl.matcher.matches(peer_pubkey, origin, is_anonymous):
                if acl.board_matches(board):
                    if acl.matcher.anonymous:
                        anonymous_matches.append(acl)
                    elif acl.matcher.pubkey is not None:
                        pubkey_matches.append(acl)
                    elif acl.matcher.origin_pattern is not None:
                        origin_matches.append(acl)
                    else:
                        wildcard_matches.append(acl)

        for acl in anonymous_matches:
            if action == "read":
                return acl.read_perm
            if action == "write":
                return acl.write_perm

        for acl in pubkey_matches:
            if action == "read":
                return acl.read_perm
            if action == "write":
                return acl.write_perm

        for acl in origin_matches:
            if action == "read":
                return acl.read_perm
            if action == "write":
                return acl.write_perm

        for acl in wildcard_matches:
            if action == "read":
                return acl.read_perm
            if action == "write":
                return acl.write_perm

        return False
