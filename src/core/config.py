"""Firehose protocol configuration loader (PROTOCOL.md §16, §18).

Parses TOML config into a FirehoseConfig object with ACL rules, origin
settings, data paths, and operational parameters. Replaces the old v3
Config class entirely.
"""

from __future__ import annotations

import os
import tomllib
from typing import Optional

from core.acl import ACLEvaluator, ACLRule, PrincipalMatcher


def _normalize_origin(origin: str) -> str:
    if not origin:
        return ""
    return origin.strip().lower().rstrip(".")


class FirehoseConfig:
    """Configuration for a Bonnet firehose server."""

    def __init__(
        self,
        origin: str = "localhost",
        hostname: str = "",
        data_dir: str = "./data",
        boards_dir: str = "./boards",
        events_bodies_dir: str = "./event_bodies",
        port: int = 2272,
        tls_enabled: bool = False,
        tls_cert_path: str = "",
        tls_key_path: str = "",
        tls_ca_bundle: bool | str = True,
        max_request_size: int = 10 * 1024 * 1024,
        max_article_body_size: int = 1024 * 1024,
        rate_limit_requests: int = 100,
        rate_limit_window: int = 1,
        signature_lifetime_seconds: int = 60,
        clock_skew_seconds: int = 30,
        search_max_count: int = 1000,
        search_timeout_seconds: int = 10,
        search_result_limit: int = 100,
        rg_path: str = "",
        sync_interval_seconds: int = 300,
        allow_private_dial: bool = False,
        acl: ACLEvaluator = None,
        admin_pubkey_hex: str = "",
    ):
        self.origin = _normalize_origin(origin)
        self.hostname = hostname or self.origin
        self.data_dir = data_dir
        self.boards_dir = boards_dir
        self.events_bodies_dir = events_bodies_dir
        self.port = port
        self.tls_enabled = tls_enabled
        self.tls_cert_path = tls_cert_path
        self.tls_key_path = tls_key_path
        self.tls_ca_bundle = tls_ca_bundle
        self.max_request_size = max_request_size
        self.max_article_body_size = max_article_body_size
        self.rate_limit_requests = rate_limit_requests
        self.rate_limit_window = rate_limit_window
        self.signature_lifetime_seconds = signature_lifetime_seconds
        self.clock_skew_seconds = clock_skew_seconds
        self.search_max_count = search_max_count
        self.search_timeout_seconds = search_timeout_seconds
        self.search_result_limit = search_result_limit
        self.rg_path = rg_path
        self.sync_interval_seconds = sync_interval_seconds
        self.allow_private_dial = allow_private_dial
        self.acl = acl or ACLEvaluator([])
        self.admin_pubkey_hex = admin_pubkey_hex

    @property
    def identity_path(self) -> str:
        return os.path.join(self.data_dir, "identity")

    @property
    def events_db_path(self) -> str:
        return os.path.join(self.data_dir, "events.db")

    @property
    def nav_db_path(self) -> str:
        return os.path.join(self.data_dir, "nav.db")

    @property
    def users_db_path(self) -> str:
        return os.path.join(self.data_dir, "users.db")

    @property
    def policy_db_path(self) -> str:
        return os.path.join(self.data_dir, "policy.db")

    @property
    def replay_db_path(self) -> str:
        return os.path.join(self.data_dir, "replay.db")

    @property
    def http_host(self) -> str:
        return "0.0.0.0"

    @staticmethod
    def load(path: str) -> "FirehoseConfig":
        if not os.path.exists(path):
            return FirehoseConfig._create_default(path)

        with open(path, "rb") as f:
            data = tomllib.load(f)

        server = data.get("server", {})
        limits = data.get("limits", {})
        search = data.get("search", {})
        tls = data.get("tls", {})
        sync = data.get("sync", {})

        origin = server.get("origin", "localhost")
        hostname = server.get("hostname", "")
        data_dir = server.get("data_dir", "./data")
        boards_dir = server.get("boards_dir", "./boards")
        events_bodies_dir = server.get("events_bodies_dir", "./event_bodies")
        port = server.get("port", 2272)
        admin_pubkey_hex = server.get("admin_pubkey", "")

        acl = ACLEvaluator.from_toml(data)

        if not acl._rules and admin_pubkey_hex:
            from core.acl import default_rules_for_admin
            acl = ACLEvaluator(default_rules_for_admin(admin_pubkey_hex))

        return FirehoseConfig(
            origin=origin,
            hostname=hostname,
            data_dir=data_dir,
            boards_dir=boards_dir,
            events_bodies_dir=events_bodies_dir,
            port=port,
            tls_enabled=tls.get("enabled", False),
            tls_cert_path=tls.get("cert_path", ""),
            tls_key_path=tls.get("key_path", ""),
            tls_ca_bundle=tls.get("ca_bundle", True),
            max_request_size=limits.get("max_request_size", 10 * 1024 * 1024),
            max_article_body_size=limits.get("max_article_body_size", 1024 * 1024),
            rate_limit_requests=limits.get("rate_limit_requests", 100),
            rate_limit_window=limits.get("rate_limit_window", 1),
            signature_lifetime_seconds=server.get("signature_lifetime_seconds", 60),
            clock_skew_seconds=server.get("clock_skew_seconds", 30),
            search_max_count=search.get("max_count", 1000),
            search_timeout_seconds=search.get("timeout_seconds", 10),
            search_result_limit=search.get("result_limit", 100),
            rg_path=search.get("rg_path", ""),
            sync_interval_seconds=sync.get("interval_seconds", 300),
            allow_private_dial=sync.get("allow_private_dial", False),
            acl=acl,
            admin_pubkey_hex=admin_pubkey_hex,
        )

    @staticmethod
    def _create_default(path: str) -> "FirehoseConfig":
        default_content = """[server]
origin = "localhost"
hostname = ""
data_dir = "./data"
boards_dir = "./boards"
events_bodies_dir = "./event_bodies"
port = 2272
# admin_pubkey = "<hex-encoded Ed25519 public key for full access>"

[limits]
max_request_size = 10485760
max_article_body_size = 1048576
rate_limit_requests = 100
rate_limit_window = 1

[search]
max_count = 1000
timeout_seconds = 10
result_limit = 100

[tls]
enabled = false
# cert_path = "./certs/bonnet.crt"
# key_path = "./certs/bonnet.key"
# ca_bundle = true

[sync]
interval_seconds = 300
# allow_private_dial = false

# ACL rules (§16): explicit deny-wins, conjunctive dimensions.
# Supported matchers: pubkey, role, origin, anonymous, unknown, wildcard.
# Selector lists: commands, kinds, boards, objects. Omit = not granted. "*" = all.
#
# [[acl]]
# effect = "allow"
# match.pubkey = "hex:<64 hex chars>"
# actions = ["read", "write"]
# commands = ["*"]
# kinds = ["*"]
# boards = ["*"]
# objects = ["*"]
#
# [[acl]]
# effect = "allow"
# match.anonymous = true
# actions = ["read"]
# commands = ["EVENT_HEAD", "EVENT_RANGE", "EVENT_GET", "BOARD_LIST", "ARTICLE_GET", "ARTICLE_LIST", "ARTICLE_SEARCH", "ARTICLE_BODY", "USER_GET", "USER_LIST", "BAN_STATUS", "EVENT_BODY"]
# boards = ["*"]
#
# [[acl]]
# effect = "allow"
# match.unknown = true
# actions = ["write"]
# commands = ["PUBLISH_RECORD"]
# kinds = ["bonnet.user.register"]
"""
        config_dir = os.path.dirname(path)
        if config_dir:
            os.makedirs(config_dir, exist_ok=True)
        with open(path, "w") as f:
            f.write(default_content)
        return FirehoseConfig(acl=ACLEvaluator([]))
