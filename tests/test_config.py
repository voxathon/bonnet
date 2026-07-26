"""Tests for src/core/config.py — FirehoseConfig loading and defaults."""

import os
import pytest

from core.config import FirehoseConfig, PeerConfig, _normalize_origin
from core.acl import ACLEvaluator


def _write_config(tmp_path, content):
    path = str(tmp_path / "config.toml")
    with open(path, "w") as f:
        f.write(content)
    return path


# ---------------------------------------------------------------------------
# Origin normalization
# ---------------------------------------------------------------------------

def test_normalize_origin_lowercases():
    assert _normalize_origin("BBS.TEST") == "bbs.test"


def test_normalize_origin_strips_trailing_dot():
    assert _normalize_origin("bbs.test.") == "bbs.test"


def test_normalize_origin_strips_whitespace():
    assert _normalize_origin("  bbs.test  ") == "bbs.test"


def test_normalize_origin_empty_returns_empty():
    assert _normalize_origin("") == ""


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

def test_defaults():
    c = FirehoseConfig()
    assert c.origin == "localhost"
    assert c.port == 2272
    assert c.tls_enabled is False
    assert c.max_request_size == 10 * 1024 * 1024
    assert c.max_article_body_size == 1024 * 1024
    assert c.rate_limit_requests == 100
    assert c.rate_limit_window == 1
    assert c.signature_lifetime_seconds == 60
    assert c.clock_skew_seconds == 30
    assert c.peers == []
    assert isinstance(c.acl, ACLEvaluator)


def test_path_properties(tmp_path):
    c = FirehoseConfig(data_dir=str(tmp_path / "data"))
    assert c.identity_path == os.path.join(str(tmp_path / "data"), "identity")
    assert c.events_db_path == os.path.join(str(tmp_path / "data"), "events.db")
    assert c.nav_db_path == os.path.join(str(tmp_path / "data"), "nav.db")
    assert c.users_db_path == os.path.join(str(tmp_path / "data"), "users.db")
    assert c.policy_db_path == os.path.join(str(tmp_path / "data"), "policy.db")
    assert c.replay_db_path == os.path.join(str(tmp_path / "data"), "replay.db")


def test_http_host_default():
    c = FirehoseConfig()
    assert c.http_host == "0.0.0.0"


# ---------------------------------------------------------------------------
# TOML loading
# ---------------------------------------------------------------------------

def test_load_complete_config(tmp_path):
    path = _write_config(tmp_path, """
[server]
origin = "bbs.example"
hostname = "bbs.example.com"
data_dir = "./data"
boards_dir = "./boards"
events_bodies_dir = "./event_bodies"
port = 8443
admin_pubkey = "abcdef0123456789"

[limits]
max_request_size = 5242880
max_article_body_size = 524288
rate_limit_requests = 50
rate_limit_window = 2

[search]
max_count = 500
timeout_seconds = 5
result_limit = 25

[tls]
enabled = true
cert_path = "/certs/bonnet.crt"
key_path = "/certs/bonnet.key"

[sync]
interval_seconds = 120

[[sync.peers]]
origin = "peer.example"
hostname = "peer.example.com"
port = 8443
verify_tls = true
""")
    c = FirehoseConfig.load(path)

    assert c.origin == "bbs.example"
    assert c.hostname == "bbs.example.com"
    assert c.port == 8443
    assert c.admin_pubkey_hex == "abcdef0123456789"
    assert c.max_request_size == 5242880
    assert c.max_article_body_size == 524288
    assert c.rate_limit_requests == 50
    assert c.rate_limit_window == 2
    assert c.search_max_count == 500
    assert c.search_timeout_seconds == 5
    assert c.search_result_limit == 25
    assert c.tls_enabled is True
    assert c.tls_cert_path == "/certs/bonnet.crt"
    assert c.tls_key_path == "/certs/bonnet.key"
    assert c.sync_interval_seconds == 120
    assert len(c.peers) == 1
    assert c.peers[0].origin == "peer.example"
    assert c.peers[0].hostname == "peer.example.com"
    assert c.peers[0].port == 8443
    assert c.peers[0].verify_tls is True


def test_load_defaults_for_omitted_values(tmp_path):
    path = _write_config(tmp_path, """
[server]
origin = "bbs.test"
""")
    c = FirehoseConfig.load(path)

    assert c.origin == "bbs.test"
    assert c.port == 2272
    assert c.tls_enabled is False
    assert c.max_request_size == 10 * 1024 * 1024
    assert c.max_article_body_size == 1024 * 1024
    assert c.rate_limit_requests == 100
    assert c.peers == []


def test_load_normalizes_origin(tmp_path):
    path = _write_config(tmp_path, """
[server]
origin = "BBS.TEST."
""")
    c = FirehoseConfig.load(path)
    assert c.origin == "bbs.test"


def test_load_hostname_defaults_to_origin(tmp_path):
    path = _write_config(tmp_path, """
[server]
origin = "bbs.test"
""")
    c = FirehoseConfig.load(path)
    assert c.hostname == "bbs.test"


def test_load_admin_pubkey_creates_default_acl(tmp_path):
    pubkey = "dd" * 32
    path = _write_config(tmp_path, f"""
[server]
origin = "bbs.test"
admin_pubkey = "{pubkey}"
""")
    c = FirehoseConfig.load(path)
    assert len(c.acl._rules) >= 1
    assert any(r.matcher.pubkey == bytes.fromhex(pubkey) for r in c.acl._rules)


def test_load_no_admin_no_acl(tmp_path):
    path = _write_config(tmp_path, """
[server]
origin = "bbs.test"
""")
    c = FirehoseConfig.load(path)
    assert len(c.acl._rules) == 0


def test_load_multiple_peers(tmp_path):
    path = _write_config(tmp_path, """
[server]
origin = "bbs.test"

[[sync.peers]]
origin = "a.test"
hostname = "a.test"
port = 2272

[[sync.peers]]
origin = "b.test"
hostname = "b.test"
port = 9999
verify_tls = true
""")
    c = FirehoseConfig.load(path)
    assert len(c.peers) == 2
    assert c.peers[0].origin == "a.test"
    assert c.peers[1].origin == "b.test"
    assert c.peers[1].port == 9999
    assert c.peers[1].verify_tls is True


# ---------------------------------------------------------------------------
# Missing config behavior
# ---------------------------------------------------------------------------

def test_load_missing_config_creates_default_file(tmp_path):
    path = str(tmp_path / "subdir" / "config.toml")
    c = FirehoseConfig.load(path)

    assert os.path.exists(path)
    assert c.origin == "localhost"
    assert len(c.acl._rules) == 0


def test_load_missing_config_creates_parent_dir(tmp_path):
    path = str(tmp_path / "nested" / "deep" / "config.toml")
    FirehoseConfig.load(path)
    assert os.path.exists(path)


# ---------------------------------------------------------------------------
# ACL from TOML
# ---------------------------------------------------------------------------

def test_load_acl_from_toml(tmp_path):
    pubkey = "ab" * 32
    path = _write_config(tmp_path, f"""
[server]
origin = "bbs.test"

[[acl]]
effect = "allow"
match.pubkey = "hex:{pubkey}"
actions = ["read", "write"]
commands = ["*"]
kinds = ["*"]
boards = ["*"]

[[acl]]
effect = "allow"
match.anonymous = true
actions = ["read"]
commands = ["BOARD_LIST"]
boards = ["*"]
""")
    c = FirehoseConfig.load(path)
    assert len(c.acl._rules) == 2
