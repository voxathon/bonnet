# Copyright 2026 The Bonnet Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for src/bonnet/core/config.py — FirehoseConfig loading and defaults."""

import os

import pytest

from bonnet.core.acl import ACLEvaluator
from bonnet.core.config import FirehoseConfig, PeerConfig, _normalize_origin


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
    assert c.signature_lifetime_seconds == 300
    assert c.clock_skew_seconds == 300
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
    assert c.http_host == "127.0.0.1"


# ---------------------------------------------------------------------------
# TOML loading
# ---------------------------------------------------------------------------


def test_load_complete_config(tmp_path):
    path = _write_config(
        tmp_path,
        """
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
""",
    )
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
    path = _write_config(
        tmp_path,
        """
[server]
origin = "bbs.test"
""",
    )
    c = FirehoseConfig.load(path)

    assert c.origin == "bbs.test"
    assert c.port == 2272
    assert c.tls_enabled is False
    assert c.max_request_size == 10 * 1024 * 1024
    assert c.max_article_body_size == 1024 * 1024
    assert c.rate_limit_requests == 100
    assert c.peers == []


def test_load_normalizes_origin(tmp_path):
    path = _write_config(
        tmp_path,
        """
[server]
origin = "BBS.TEST."
""",
    )
    c = FirehoseConfig.load(path)
    assert c.origin == "bbs.test"


def test_load_hostname_defaults_to_origin(tmp_path):
    path = _write_config(
        tmp_path,
        """
[server]
origin = "bbs.test"
""",
    )
    c = FirehoseConfig.load(path)
    assert c.hostname == "bbs.test"


def test_load_admin_pubkey_creates_default_acl(tmp_path):
    pubkey = "dd" * 32
    path = _write_config(
        tmp_path,
        f"""
[server]
origin = "bbs.test"
admin_pubkey = "{pubkey}"
""",
    )
    c = FirehoseConfig.load(path)
    assert len(c.acl._rules) >= 1
    assert any(r.matcher.pubkey == bytes.fromhex(pubkey) for r in c.acl._rules)


def test_load_admin_pubkey_grants_admin_alongside_existing_acl_rules(tmp_path):
    """admin_pubkey must grant admin even when [[acl]] already has rules —
    it used to only take effect when the [[acl]] table was completely
    empty. This is exactly the documented first-run flow: keep the sample
    config's default rules, uncomment admin_pubkey."""
    pubkey = "ab" * 32
    path = _write_config(
        tmp_path,
        f"""
[server]
origin = "bbs.test"
admin_pubkey = "{pubkey}"

[[acl]]
effect = "allow"
match.anonymous = true
actions = ["read"]
commands = ["BOARD_LIST"]
boards = ["*"]

[[acl]]
effect = "allow"
match.registered = true
actions = ["write"]
commands = ["PUBLISH_RECORD"]
kinds = ["bonnet.article"]
boards = ["*"]
""",
    )
    c = FirehoseConfig.load(path)
    assert len(c.acl._rules) == 3
    admin_bytes = bytes.fromhex(pubkey)
    assert any(r.matcher.pubkey == admin_bytes and r.effect == "allow" for r in c.acl._rules), (
        "admin_pubkey must still grant admin when other [[acl]] rules exist"
    )


def test_load_admin_pubkey_not_duplicated_if_already_present(tmp_path):
    """If config.toml already has an explicit rule for admin_pubkey's own
    key, loading must not add a second, redundant one."""
    pubkey = "ef" * 32
    path = _write_config(
        tmp_path,
        f"""
[server]
origin = "bbs.test"
admin_pubkey = "{pubkey}"

[[acl]]
effect = "allow"
match.pubkey = "hex:{pubkey}"
actions = ["read", "write"]
commands = ["*"]
kinds = ["*"]
boards = ["*"]
objects = ["*"]
""",
    )
    c = FirehoseConfig.load(path)
    admin_bytes = bytes.fromhex(pubkey)
    matching = [r for r in c.acl._rules if r.matcher.pubkey == admin_bytes and r.effect == "allow"]
    assert len(matching) == 1


def test_load_no_admin_no_acl(tmp_path):
    path = _write_config(
        tmp_path,
        """
[server]
origin = "bbs.test"
""",
    )
    c = FirehoseConfig.load(path)
    assert len(c.acl._rules) == 0


def test_load_multiple_peers(tmp_path):
    path = _write_config(
        tmp_path,
        """
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
""",
    )
    c = FirehoseConfig.load(path)
    assert len(c.peers) == 2
    assert c.peers[0].origin == "a.test"
    assert c.peers[1].origin == "b.test"
    assert c.peers[1].port == 9999
    assert c.peers[1].verify_tls is True


def test_peer_allow_private_defaults_false(tmp_path):
    path = _write_config(
        tmp_path,
        """
[server]
origin = "bbs.test"

[[sync.peers]]
origin = "a.test"
hostname = "10.0.0.15"
""",
    )
    c = FirehoseConfig.load(path)
    assert c.peers[0].allow_private is False


def test_peer_allow_private_true(tmp_path):
    path = _write_config(
        tmp_path,
        """
[server]
origin = "bbs.test"

[[sync.peers]]
origin = "a.test"
hostname = "10.0.0.15"
allow_private = true
""",
    )
    c = FirehoseConfig.load(path)
    assert c.peers[0].allow_private is True


def test_peer_scheme_defaults_https(tmp_path):
    path = _write_config(
        tmp_path,
        """
[server]
origin = "bbs.test"

[[sync.peers]]
origin = "a.test"
hostname = "a.test"
""",
    )
    c = FirehoseConfig.load(path)
    assert c.peers[0].scheme == "https"


def test_peer_scheme_explicit_http(tmp_path):
    path = _write_config(
        tmp_path,
        """
[server]
origin = "bbs.test"

[[sync.peers]]
origin = "a.test"
hostname = "a.test"
scheme = "http"
""",
    )
    c = FirehoseConfig.load(path)
    assert c.peers[0].scheme == "http"


def test_peer_scheme_invalid_rejected(tmp_path):
    path = _write_config(
        tmp_path,
        """
[server]
origin = "bbs.test"

[[sync.peers]]
origin = "a.test"
hostname = "a.test"
scheme = "ftp"
""",
    )
    c = FirehoseConfig.load(path)
    with pytest.raises(ValueError, match="scheme"):
        c.validate()


def test_peer_import_flags_default_to_false(tmp_path):
    path = _write_config(
        tmp_path,
        """
[server]
origin = "bbs.test"

[[sync.peers]]
origin = "a.test"
hostname = "a.test"
""",
    )
    c = FirehoseConfig.load(path)
    peer = c.peers[0]
    assert peer.import_warnings is False
    assert peer.import_temp_bans is False
    assert peer.import_permabans is False


def test_peer_import_flags_from_toml(tmp_path):
    path = _write_config(
        tmp_path,
        """
[server]
origin = "bbs.test"

[[sync.peers]]
origin = "a.test"
hostname = "a.test"
import_warnings = true
import_temp_bans = true
import_permabans = false

[[sync.peers]]
origin = "b.test"
hostname = "b.test"
import_warnings = false
import_temp_bans = false
import_permabans = false
""",
    )
    c = FirehoseConfig.load(path)
    assert c.peers[0].imported_punishment_types() == {"warning", "ban"}
    assert c.peers[1].imported_punishment_types() == set()


def test_validate_rejects_non_bool_peer_import_flag():
    c = FirehoseConfig(
        peers=[PeerConfig(origin="a.test", hostname="a.test", import_warnings="yes")]
    )
    with pytest.raises(ValueError, match="import_warnings"):
        c.validate()


def test_as_bool_rejects_non_bool_toml_value(tmp_path):
    path = _write_config(
        tmp_path,
        """
[server]
origin = "bbs.test"

[[sync.peers]]
origin = "a.test"
hostname = "a.test"
import_permabans = 1
""",
    )
    with pytest.raises(ValueError, match="import_permabans"):
        FirehoseConfig.load(path)


def test_tls_enabled_rejects_a_quoted_string(tmp_path):
    """`enabled = "false"` (quoted, not bare) used to load as a Python string,
    which is truthy for any non-empty value including "false" itself - a
    server config trying to explicitly disable TLS by writing that would
    silently run with TLS on instead, with no error or warning anywhere."""
    path = _write_config(
        tmp_path,
        """
[server]
origin = "bbs.test"

[tls]
enabled = "false"
""",
    )
    with pytest.raises(ValueError, match="tls.enabled"):
        FirehoseConfig.load(path)


# ---------------------------------------------------------------------------
# Missing config behavior
# ---------------------------------------------------------------------------


def test_load_missing_config_raises(tmp_path):
    """Loading a missing config raises FileNotFoundError."""
    path = str(tmp_path / "subdir" / "config.toml")
    with pytest.raises(FileNotFoundError):
        FirehoseConfig.load(path)


def test_load_directory_path_raises_cleanly(tmp_path):
    """Pointing --config at a directory raises IsADirectoryError, not a
    raw open()-triggered traceback."""
    path = str(tmp_path)  # tmp_path itself is a directory
    with pytest.raises(IsADirectoryError):
        FirehoseConfig.load(path)


def test_create_default_config(tmp_path):
    """create_default_config writes a valid TOML file."""
    path = str(tmp_path / "config.toml")
    config = FirehoseConfig.create_default_config(path)

    assert os.path.exists(path)
    assert config.origin == "localhost"
    assert len(config.acl._rules) == 0


def test_create_default_config_honors_a_custom_port(tmp_path):
    """--init/--create-config used to always write port = 2272 to the sample
    file regardless of a --port override the caller passed at generation
    time - the flag was silently ignored until the file was hand-edited."""
    path = str(tmp_path / "config.toml")
    config = FirehoseConfig.create_default_config(path, port=19273)

    assert config.port == 19273
    with open(path, encoding="utf-8") as f:
        content = f.read()
    assert "port = 19273" in content

    reloaded = FirehoseConfig.load(path)
    assert reloaded.port == 19273


def test_create_default_config_creates_parent_dir(tmp_path):
    path = str(tmp_path / "nested" / "deep" / "config.toml")
    FirehoseConfig.create_default_config(path)
    assert os.path.exists(path)


def test_create_default_config_refuses_existing_file(tmp_path):
    path = str(tmp_path / "config.toml")
    FirehoseConfig.create_default_config(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write('[server]\norigin = "precious"\n')

    with pytest.raises(FileExistsError):
        FirehoseConfig.create_default_config(path)

    with open(path, encoding="utf-8") as f:
        content = f.read()
    assert "precious" in content


def test_create_default_config_force_overwrites(tmp_path):
    path = str(tmp_path / "config.toml")
    FirehoseConfig.create_default_config(path)
    config = FirehoseConfig.create_default_config(path, force=True)

    assert os.path.exists(path)
    assert config.origin == "localhost"


# ---------------------------------------------------------------------------
# ACL from TOML
# ---------------------------------------------------------------------------


def test_load_acl_from_toml(tmp_path):
    pubkey = "ab" * 32
    path = _write_config(
        tmp_path,
        f"""
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
""",
    )
    c = FirehoseConfig.load(path)
    assert len(c.acl._rules) == 2


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_validate_rejects_empty_origin():
    c = FirehoseConfig(origin="")
    with pytest.raises(ValueError, match="origin"):
        c.validate()


def test_validate_rejects_bad_port():
    c = FirehoseConfig(port=0)
    with pytest.raises(ValueError, match="port"):
        c.validate()
    c = FirehoseConfig(port=99999)
    with pytest.raises(ValueError, match="port"):
        c.validate()


def test_validate_rejects_non_int_port():
    """A quoted port ("22721") in config.toml used to raise a bare
    TypeError from `1 <= self.port <= 65535` instead of a clean ValueError."""
    c = FirehoseConfig(port="22721")
    with pytest.raises(ValueError, match="port must be an integer"):
        c.validate()


def test_validate_rejects_zero_limits():
    c = FirehoseConfig(max_request_size=0)
    with pytest.raises(ValueError, match="max_request_size"):
        c.validate()


def test_validate_allows_generous_lifetime_and_skew():
    # No upper cap: a permissive node only weakens itself (receiver-side
    # verification). Operators accept the wider replay window explicitly.
    c = FirehoseConfig(signature_lifetime_seconds=3600, clock_skew_seconds=3600)
    c.validate()
    assert c.signature_lifetime_seconds == 3600
    assert c.clock_skew_seconds == 3600


def test_validate_rejects_nonpositive_lifetime():
    c = FirehoseConfig(signature_lifetime_seconds=0)
    with pytest.raises(ValueError, match="signature_lifetime"):
        c.validate()


def test_validate_rejects_negative_clock_skew():
    c = FirehoseConfig(clock_skew_seconds=-1)
    with pytest.raises(ValueError, match="clock_skew"):
        c.validate()


@pytest.mark.parametrize(
    "bad_origin",
    ["not a url ://bad", "bad host name", "has/slash", "üñîçødé.example"],
)
def test_validate_rejects_malformed_origin(bad_origin):
    """Regression for the chaos-testing report's #1.4: origin/hostname used
    to accept any non-empty string, so a typo'd origin passed --check-config
    and became the server's permanent federation identity. Only emptiness
    was checked; format never was."""
    c = FirehoseConfig(origin=bad_origin)
    with pytest.raises(ValueError, match="not a valid hostname"):
        c.validate()


def test_validate_rejects_malformed_hostname():
    c = FirehoseConfig(origin="bbs.test", hostname="bad host name")
    with pytest.raises(ValueError, match="not a valid hostname"):
        c.validate()


def test_validate_accepts_ip_literal_origin():
    """config.example.toml models origin as an IP literal too - the format
    check must not reject the dotted-quad shape it explicitly documents."""
    c = FirehoseConfig(origin="10.0.0.15")
    c.validate()


def test_validate_rejects_duplicate_peers():
    c = FirehoseConfig(
        peers=[
            PeerConfig(origin="a.test", hostname="a.test"),
            PeerConfig(origin="a.test", hostname="b.test"),
        ]
    )
    with pytest.raises(ValueError, match="duplicate"):
        c.validate()


def test_validate_accepts_valid_config():
    c = FirehoseConfig(
        origin="bbs.test",
        port=2272,
        peers=[PeerConfig(origin="peer.test", hostname="peer.test")],
    )
    c.validate()


# ---------------------------------------------------------------------------
# Configurable bind host
# ---------------------------------------------------------------------------


def test_configurable_host():
    c = FirehoseConfig(host="127.0.0.1")
    assert c.http_host == "127.0.0.1"


def test_host_default():
    c = FirehoseConfig()
    assert c.http_host == "127.0.0.1"


def test_host_from_toml(tmp_path):
    path = _write_config(
        tmp_path,
        """
[server]
origin = "bbs.test"
host = "127.0.0.1"
""",
    )
    c = FirehoseConfig.load(path)
    assert c.http_host == "127.0.0.1"


# ---------------------------------------------------------------------------
# BONNET_SERVER_HOME storage-path fallback
# ---------------------------------------------------------------------------


def test_bonnet_server_home_used_when_storage_paths_unset(tmp_path, monkeypatch):
    home = str(tmp_path / "home")
    monkeypatch.setenv("BONNET_SERVER_HOME", home)
    path = _write_config(tmp_path, '[server]\norigin = "bbs.test"\n')
    c = FirehoseConfig.load(path)
    assert c.data_dir == os.path.join(home, "data")
    assert c.boards_dir == os.path.join(home, "boards")
    assert c.events_bodies_dir == os.path.join(home, "event_bodies")


def test_explicit_config_storage_paths_win_over_bonnet_server_home(tmp_path, monkeypatch):
    home = str(tmp_path / "home")
    monkeypatch.setenv("BONNET_SERVER_HOME", home)
    explicit_data_dir = str(tmp_path / "custom_data")
    path = _write_config(
        tmp_path,
        f"""
[server]
origin = "bbs.test"
data_dir = "{explicit_data_dir.replace(os.sep, "/")}"
""",
    )
    c = FirehoseConfig.load(path)
    assert c.data_dir == explicit_data_dir.replace(os.sep, "/")
    # boards_dir/events_bodies_dir were left unset, so BONNET_SERVER_HOME
    # still applies to those independently of the explicit data_dir override.
    assert c.boards_dir == os.path.join(home, "boards")
    assert c.events_bodies_dir == os.path.join(home, "event_bodies")


def test_storage_paths_default_to_the_loaded_configs_own_directory(tmp_path, monkeypatch):
    """Without BONNET_SERVER_HOME, storage paths default next to *this*
    config.toml — not core.home's globally-remembered `--dir`/`--init`
    pointer. That pointer is a single file per OS user shared by every
    `bonnet server` invocation regardless of which `--config` it was given,
    so two concurrent instances started with distinct `--config` paths used
    to silently share (and race on) whichever instance's `--dir`/`--init`
    happened to write it last. Basing the default on the config file's own
    directory makes each instance's storage follow the config it was
    actually told to load. `--dir`/`--init` are unaffected: they set
    `args.config` to `<dir>/config.toml`, so the config's own directory
    already equals the directory named."""
    monkeypatch.delenv("BONNET_SERVER_HOME", raising=False)
    monkeypatch.setattr("platformdirs.user_config_dir", lambda *a, **k: str(tmp_path / "cfg"))
    monkeypatch.setattr("platformdirs.user_data_dir", lambda *a, **k: str(tmp_path / "data-root"))
    config_dir = tmp_path / "instance-a"
    config_dir.mkdir()
    path = _write_config(config_dir, '[server]\norigin = "bbs.test"\n')

    c = FirehoseConfig.load(path)

    assert c.data_dir == os.path.join(str(config_dir), "data")
    assert c.boards_dir == os.path.join(str(config_dir), "boards")
    assert c.events_bodies_dir == os.path.join(str(config_dir), "event_bodies")


def test_storage_paths_do_not_collide_across_concurrent_configs(tmp_path, monkeypatch):
    """Regression for the home-collision bug: two configs loaded in the same
    process (standing in for two concurrent `bonnet server` instances) must
    resolve independent storage paths purely from where each config lives —
    neither may leak the other's directory via a shared global fallback."""
    monkeypatch.delenv("BONNET_SERVER_HOME", raising=False)
    monkeypatch.setattr("platformdirs.user_config_dir", lambda *a, **k: str(tmp_path / "cfg"))
    monkeypatch.setattr("platformdirs.user_data_dir", lambda *a, **k: str(tmp_path / "data-root"))
    (tmp_path / "instance-a").mkdir()
    (tmp_path / "instance-b").mkdir()
    path_a = _write_config(tmp_path / "instance-a", '[server]\norigin = "a.test"\n')
    path_b = _write_config(tmp_path / "instance-b", '[server]\norigin = "b.test"\n')

    c_a = FirehoseConfig.load(path_a)
    c_b = FirehoseConfig.load(path_b)

    assert c_a.data_dir == os.path.join(str(tmp_path / "instance-a"), "data")
    assert c_b.data_dir == os.path.join(str(tmp_path / "instance-b"), "data")
    assert c_a.data_dir != c_b.data_dir


# ---------------------------------------------------------------------------
# Unknown key detection
# ---------------------------------------------------------------------------


def test_load_reports_unknown_keys(tmp_path):
    path = _write_config(
        tmp_path,
        """
typo_section = true

[server]
origin = "bbs.test"
admin_key = "abc123"

[limits]
max_requests = 5
""",
    )
    c = FirehoseConfig.load(path)
    assert sorted(c.unknown_keys) == ["limits.max_requests", "server.admin_key", "typo_section"]


def test_load_clean_config_has_no_unknown_keys(tmp_path):
    path = _write_config(
        tmp_path,
        """
[server]
origin = "bbs.test"

[tls]
enabled = false

[sync]
interval_seconds = 300
""",
    )
    c = FirehoseConfig.load(path)
    assert c.unknown_keys == []


def test_load_reports_unknown_peer_keys(tmp_path):
    path = _write_config(
        tmp_path,
        """
[[sync.peers]]
origin = "peer.test"
hostname = "peer.test"
import_warns = true
""",
    )
    c = FirehoseConfig.load(path)
    assert c.unknown_keys == ["sync.peers[0].import_warns"]


def test_constructed_config_defaults_to_no_unknown_keys():
    c = FirehoseConfig()
    assert c.unknown_keys == []


# ---------------------------------------------------------------------------
# Sample config template
# ---------------------------------------------------------------------------


def test_generated_sample_is_utf8_loadable_and_valid(tmp_path):
    """--create-config output must round-trip through the real loader.

    Regression guard for locale-dependent writes (cp1252 on Windows made the
    generated file unparseable by tomllib).
    """
    import tomllib

    path = str(tmp_path / "config.toml")
    FirehoseConfig._write_default(path)

    with open(path, "rb") as f:
        raw = f.read()
    data = tomllib.loads(raw.decode("utf-8"))
    assert data["server"]["origin"] == "localhost"

    c = FirehoseConfig.load(path)
    c.validate()
    assert c.unknown_keys == []


def test_example_config_matches_generated_template(tmp_path):
    """config.example.toml and the --create-config template stay in sync.

    server.origin/hostname are excluded: the tracked example ships a
    placeholder origin, the generated sample starts local.
    """
    import tomllib

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    example_path = os.path.join(repo_root, "config.example.toml")
    generated_path = str(tmp_path / "generated.toml")
    FirehoseConfig._write_default(generated_path)

    def load_normalized(path):
        with open(path, "rb") as f:
            data = tomllib.load(f)
        data.get("server", {}).pop("origin", None)
        data.get("server", {}).pop("hostname", None)
        return data

    assert load_normalized(example_path) == load_normalized(generated_path)


# ---------------------------------------------------------------------------
# conf.d-style includes ([[acl]] / [[sync.peers]] only)
# ---------------------------------------------------------------------------


def test_include_merges_acl_and_peers(tmp_path):
    (tmp_path / "acl.d").mkdir()
    (tmp_path / "peers.d").mkdir()

    (tmp_path / "acl.d" / "mods.toml").write_text(
        """
[[acl]]
effect = "allow"
match.role = "moderator"
actions = ["write"]
commands = ["PUBLISH_RECORD"]
kinds = ["bonnet.punishment.warn"]
""",
        encoding="utf-8",
    )
    (tmp_path / "peers.d" / "friend.toml").write_text(
        """
[[sync.peers]]
origin = "friend.example"
hostname = "friend.example"
""",
        encoding="utf-8",
    )

    path = _write_config(
        tmp_path,
        """
include = ["acl.d/*.toml", "peers.d/*.toml"]

[server]
origin = "bbs.test"

[[acl]]
effect = "allow"
match.wildcard = true
actions = ["read"]
commands = ["*"]
""",
    )

    c = FirehoseConfig.load(path)
    assert len(c.acl._rules) == 2
    assert len(c.peers) == 1
    assert c.peers[0].origin == "friend.example"
    assert c.unknown_keys == []


def test_include_glob_matching_nothing_raises(tmp_path):
    path = _write_config(
        tmp_path,
        """
include = ["nowhere.d/*.toml"]

[server]
origin = "bbs.test"
""",
    )
    with pytest.raises(ValueError, match="matched no files"):
        FirehoseConfig.load(path)


def test_include_non_list_raises(tmp_path):
    path = _write_config(
        tmp_path,
        """
include = "acl.d/*.toml"

[server]
origin = "bbs.test"
""",
    )
    with pytest.raises(ValueError, match="must be a list"):
        FirehoseConfig.load(path)


def test_nested_include_raises(tmp_path):
    (tmp_path / "acl.d").mkdir()
    (tmp_path / "acl.d" / "bad.toml").write_text('include = ["nope.toml"]\n', encoding="utf-8")
    path = _write_config(
        tmp_path,
        """
include = ["acl.d/*.toml"]

[server]
origin = "bbs.test"
""",
    )
    with pytest.raises(ValueError, match="must not itself use 'include'"):
        FirehoseConfig.load(path)


def test_include_file_disallows_non_acl_sync_keys(tmp_path):
    (tmp_path / "acl.d").mkdir()
    (tmp_path / "acl.d" / "bad.toml").write_text("[server]\nport = 9999\n", encoding="utf-8")
    path = _write_config(
        tmp_path,
        """
include = ["acl.d/*.toml"]

[server]
origin = "bbs.test"
""",
    )
    with pytest.raises(ValueError, match="unsupported top-level key"):
        FirehoseConfig.load(path)


def test_include_file_sync_section_disallows_non_peers_keys(tmp_path):
    (tmp_path / "peers.d").mkdir()
    (tmp_path / "peers.d" / "bad.toml").write_text(
        "[sync]\ninterval_seconds = 60\n", encoding="utf-8"
    )
    path = _write_config(
        tmp_path,
        """
include = ["peers.d/*.toml"]

[server]
origin = "bbs.test"
""",
    )
    with pytest.raises(ValueError, match=r"\[sync\] may only contain 'peers'"):
        FirehoseConfig.load(path)


def test_include_missing_matched_file_raises(tmp_path):
    # Directly exercises _load_include_file's own not-found guard, since a
    # glob match is normally guaranteed to exist on disk.
    from bonnet.core.config import _load_include_file

    with pytest.raises(FileNotFoundError):
        _load_include_file(str(tmp_path / "nope.toml"))


def test_include_file_unknown_peer_key_is_prefixed_with_relative_path(tmp_path):
    (tmp_path / "peers.d").mkdir()
    (tmp_path / "peers.d" / "typo.toml").write_text(
        """
[[sync.peers]]
origin = "friend.example"
hostname = "friend.example"
bogus_field = true
""",
        encoding="utf-8",
    )
    path = _write_config(
        tmp_path,
        """
include = ["peers.d/*.toml"]

[server]
origin = "bbs.test"
""",
    )
    c = FirehoseConfig.load(path)
    assert len(c.unknown_keys) == 1
    assert c.unknown_keys[0].startswith("peers.d")
    assert c.unknown_keys[0].endswith("typo.toml:sync.peers[0].bogus_field")


def test_include_relative_to_config_file_not_cwd(tmp_path, monkeypatch):
    other_dir = tmp_path / "elsewhere"
    other_dir.mkdir()
    monkeypatch.chdir(other_dir)

    (tmp_path / "acl.d").mkdir()
    (tmp_path / "acl.d" / "mods.toml").write_text(
        """
[[acl]]
effect = "allow"
match.wildcard = true
actions = ["read"]
commands = ["*"]
""",
        encoding="utf-8",
    )
    path = _write_config(
        tmp_path,
        """
include = ["acl.d/*.toml"]

[server]
origin = "bbs.test"
""",
    )

    c = FirehoseConfig.load(path)
    assert len(c.acl._rules) == 1


# ---------------------------------------------------------------------------
# admin_pubkey_file (secret indirection)
# ---------------------------------------------------------------------------


def test_admin_pubkey_file_is_read_and_stripped(tmp_path):
    pubkey = "ab" * 32
    keyfile = tmp_path / "admin.key"
    keyfile.write_text(f"  {pubkey}  \n", encoding="utf-8")

    path = _write_config(
        tmp_path,
        f"""
[server]
origin = "bbs.test"
admin_pubkey_file = "{keyfile.as_posix()}"
""",
    )
    c = FirehoseConfig.load(path)
    assert c.admin_pubkey_hex == pubkey
    assert any(r.matcher.pubkey == bytes.fromhex(pubkey) for r in c.acl._rules)


def test_admin_pubkey_and_admin_pubkey_file_are_mutually_exclusive(tmp_path):
    keyfile = tmp_path / "admin.key"
    keyfile.write_text("ab" * 32, encoding="utf-8")

    path = _write_config(
        tmp_path,
        f"""
[server]
origin = "bbs.test"
admin_pubkey = "{"cd" * 32}"
admin_pubkey_file = "{keyfile.as_posix()}"
""",
    )
    with pytest.raises(ValueError, match="mutually exclusive"):
        FirehoseConfig.load(path)


def test_admin_pubkey_file_missing_raises(tmp_path):
    path = _write_config(
        tmp_path,
        f"""
[server]
origin = "bbs.test"
admin_pubkey_file = "{(tmp_path / "nope.key").as_posix()}"
""",
    )
    with pytest.raises(ValueError, match="could not read"):
        FirehoseConfig.load(path)


def test_admin_pubkey_file_empty_raises(tmp_path):
    keyfile = tmp_path / "admin.key"
    keyfile.write_text("   \n", encoding="utf-8")

    path = _write_config(
        tmp_path,
        f"""
[server]
origin = "bbs.test"
admin_pubkey_file = "{keyfile.as_posix()}"
""",
    )
    with pytest.raises(ValueError, match="is empty"):
        FirehoseConfig.load(path)


def test_no_admin_pubkey_or_file_is_fine(tmp_path):
    path = _write_config(
        tmp_path,
        """
[server]
origin = "bbs.test"
""",
    )
    c = FirehoseConfig.load(path)
    assert c.admin_pubkey_hex == ""
