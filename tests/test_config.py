# -*- coding: utf-8 -*-

import pytest
import tempfile
import os

from core.config import Config, Filter


class TestConfigPaths:
    def test_data_dir_default(self):
        """Default data_dir is ./data"""
        config = Config()
        assert config.data_dir == "./data"
        assert config.identity_path == "./data/identity"
        assert config.userfile_path == "./data/userfile"
        assert config.nav_db_path == "./data/nav.db"

    def test_data_dir_explicit(self):
        """Explicit data_dir is used"""
        config = Config(data_dir="./bonnet_data")
        assert config.data_dir == "./bonnet_data"
        assert config.identity_path == "./bonnet_data/identity"
        assert config.userfile_path == "./bonnet_data/userfile"

    def test_identity_path_override(self):
        """Explicit identity_path overrides data_dir derivation"""
        config = Config(data_dir="./data", identity_path="secure/identity")
        assert config.data_dir == "./data"
        assert config.identity_path == "./data/secure/identity"

    def test_userfile_path_override(self):
        """Explicit userfile_path overrides data_dir derivation"""
        config = Config(data_dir="./data", userfile_path="etc/users")
        assert config.userfile_path == "./data/etc/users"

    def test_relative_path_resolves_from_data_dir(self):
        """Relative paths resolve from data_dir"""
        config = Config(data_dir="./bonnet_data", nav_db_path="custom/nav.db")
        assert config.nav_db_path == "./bonnet_data/custom/nav.db"

    def test_log_dir_default(self):
        """Default log_dir is ./logs"""
        config = Config()
        assert config.log_dir == "./logs"

    def test_log_dir_explicit(self):
        """Explicit log_dir is used"""
        config = Config(log_dir="./bonnet_logs")
        assert config.log_dir == "./bonnet_logs"


class TestConfigPorts:
    def test_port_defaults(self):
        """Default ports are 2272 and 272"""
        config = Config()
        assert config.port_standard == 2272
        assert config.port_privileged == 272

    def test_port_explicit(self):
        """Explicit ports are used"""
        config = Config(port_standard=8080, port_privileged=80)
        assert config.port_standard == 8080
        assert config.port_privileged == 80


class TestConfigLimits:
    def test_limits_defaults(self):
        """Default limits are set"""
        config = Config()
        assert config.timeout_seconds == 30
        assert config.max_connections == 100
        assert config.max_request_size == 10485760
        assert config.rate_limit_requests == 100
        assert config.rate_limit_window == 1

    def test_limits_explicit(self):
        """Explicit limits are used"""
        config = Config(
            timeout_seconds=60,
            max_connections=200,
            max_request_size=20971520,
            rate_limit_requests=50,
            rate_limit_window=2,
        )
        assert config.timeout_seconds == 60
        assert config.max_connections == 200
        assert config.max_request_size == 20971520
        assert config.rate_limit_requests == 50
        assert config.rate_limit_window == 2


class TestConfigTLS:
    def test_tls_defaults(self):
        """TLS is disabled by default"""
        config = Config()
        assert config.tls_enabled is False
        assert config.tls_cert_path == "./certs/bonnet.crt"
        assert config.tls_key_path == "./certs/bonnet.key"

    def test_tls_enabled(self):
        """TLS can be enabled"""
        config = Config(
            tls_enabled=True, tls_cert_path="./ssl/cert.pem", tls_key_path="./ssl/key.pem"
        )
        assert config.tls_enabled is True
        assert config.tls_cert_path == "./ssl/cert.pem"
        assert config.tls_key_path == "./ssl/key.pem"


class TestConfigLoad:
    def test_load_from_file(self):
        """Config can be loaded from TOML file"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[server]
origin = "test.example.com"
data_dir = "./test_data"
port_standard = 9000
port_privileged = 90

[limits]
timeout_seconds = 45
max_connections = 50
max_request_size = 5242880
rate_limit_requests = 25
rate_limit_window = 2

[tls]
enabled = true
cert_path = "./test_certs/cert.pem"
key_path = "./test_certs/key.pem"
""")
            f.flush()
            path = f.name

        try:
            config = Config.load(path)
            assert config.origin == "test.example.com"
            assert config.data_dir == "./test_data"
            assert config.port_standard == 9000
            assert config.port_privileged == 90
            assert config.timeout_seconds == 45
            assert config.max_connections == 50
            assert config.max_request_size == 5242880
            assert config.rate_limit_requests == 25
            assert config.rate_limit_window == 2
            assert config.tls_enabled is True
            assert config.tls_cert_path == "./test_certs/cert.pem"
            assert config.tls_key_path == "./test_certs/key.pem"
        finally:
            os.unlink(path)

    def test_load_creates_default(self):
        """Loading non-existent file creates default config"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "new_config.toml")
            assert not os.path.exists(path)

            config = Config.load(path)

            assert os.path.exists(path)
            assert config.data_dir == "./data"
            assert config.port_standard == 2272

    def test_load_keibatsu_paths(self):
        """Keibatsu paths can be configured"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[keibatsu]
reports_path = "custom/reports.db"
punishments_path = "custom/punishments.db"
""")
            f.flush()
            path = f.name

        try:
            config = Config.load(path)
            assert config.reports_db_path == "./data/custom/reports.db"
            assert config.punishments_db_path == "./data/custom/punishments.db"
        finally:
            os.unlink(path)

    def test_load_keibatsu_relative_paths(self):
        """Keibatsu relative paths resolve from data_dir"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[server]
data_dir = "./bonnet_data"

[keibatsu]
reports_path = "data/reports.db"
""")
            f.flush()
            path = f.name

        try:
            config = Config.load(path)
            assert config.reports_db_path == "./bonnet_data/data/reports.db"
        finally:
            os.unlink(path)


class TestConfigSearch:
    def test_search_defaults(self):
        config = Config(data_dir="./tmp_x")
        assert config.search_max_count == 1000
        assert config.search_timeout_seconds == 10
        assert config.search_result_limit == 100
        assert config.search_per_identity_concurrency == 1
        assert config.search_rate_limit == 10
        assert config.search_rate_window_seconds == 60

    def test_public_commands_obsolete_empty_by_default(self):
        """public_commands is obsolete and empty by default (§5.7)."""
        config = Config(data_dir="./tmp_x")
        assert config.public_commands == set()

    def test_load_search_section_from_toml(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[server]
origin = "test.example.com"

[search]
max_count = 500
timeout_seconds = 5
result_limit = 25
per_identity_concurrency = 2
rate_limit = 3
rate_window_seconds = 30
""")
            f.flush()
            path = f.name
        try:
            config = Config.load(path)
            assert config.search_max_count == 500
            assert config.search_timeout_seconds == 5
            assert config.search_result_limit == 25
            assert config.search_per_identity_concurrency == 2
            assert config.search_rate_limit == 3
            assert config.search_rate_window_seconds == 30
        finally:
            os.unlink(path)

    def test_load_public_commands_silently_ignored(self):
        """public_commands in TOML is silently ignored — no authorization effect (§5.7)."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[server]
origin = "test.example.com"
public_commands = ["POST_CONTENT_SEARCH", "QUERY_POSTS"]
""")
            f.flush()
            path = f.name
        try:
            config = Config.load(path)
            # public_commands is silently ignored — remains empty
            assert config.public_commands == set()
        finally:
            os.unlink(path)


class TestFilter:
    def test_filter_contains_both_bounds(self):
        f = Filter("evil.example", created_after=100, created_before=200)
        assert f.contains(100) is True
        assert f.contains(150) is True
        assert f.contains(200) is True
        assert f.contains(99) is False
        assert f.contains(201) is False

    def test_filter_contains_only_after(self):
        f = Filter("evil.example", created_after=100)
        assert f.contains(100) is True
        assert f.contains(999999) is True
        assert f.contains(99) is False

    def test_filter_contains_only_before(self):
        f = Filter("evil.example", created_before=200)
        assert f.contains(0) is True
        assert f.contains(200) is True
        assert f.contains(201) is False

    def test_filter_contains_neither_bound(self):
        f = Filter("evil.example")
        assert f.contains(0) is True
        assert f.contains(999999) is True


class TestRecordInWindow:
    def test_no_filters_default_allow(self):
        config = Config()
        assert config.record_in_window("any.origin", 0) is True
        assert config.record_in_window("any.origin", 999999) is True

    def test_exact_origin_matches(self):
        config = Config(filters=[Filter("evil.example", created_after=100, created_before=200)])
        assert config.record_in_window("evil.example", 150) is True
        assert config.record_in_window("evil.example", 50) is False
        assert config.record_in_window("evil.example", 250) is False

    def test_unconfigured_origin_default_allow(self):
        config = Config(filters=[Filter("evil.example", created_after=100)])
        assert config.record_in_window("other.example", 50) is True

    def test_wildcard_fallback_only_when_no_exact(self):
        config = Config(filters=[Filter("*", created_after=100)])
        assert config.record_in_window("other.example", 50) is False
        assert config.record_in_window("other.example", 150) is True
        # exact origin takes precedence over wildcard
        config2 = Config(filters=[
            Filter("*", created_after=100),
            Filter("evil.example", created_after=300),
        ])
        assert config2.record_in_window("evil.example", 150) is False
        assert config2.record_in_window("evil.example", 350) is True
        # other origins still use wildcard
        assert config2.record_in_window("other.example", 150) is True

    def test_multiple_windows_same_origin_ored(self):
        config = Config(filters=[
            Filter("evil.example", created_after=100, created_before=200),
            Filter("evil.example", created_after=300, created_before=400),
        ])
        assert config.record_in_window("evil.example", 150) is True
        assert config.record_in_window("evil.example", 350) is True
        assert config.record_in_window("evil.example", 250) is False
        assert config.record_in_window("evil.example", 450) is False


class TestFilterParsing:
    def test_load_filter_section(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[server]
origin = "localhost"

[[filter]]
origin = "evil.example"
created_after = 100
created_before = 200

[[filter]]
origin = "*"
created_after = 50
""")
            f.flush()
            path = f.name
        try:
            config = Config.load(path)
            assert len(config.filters) == 2
            assert config.filters[0].origin == "evil.example"
            assert config.filters[0].created_after == 100
            assert config.filters[0].created_before == 200
            assert config.filters[1].origin == "*"
            assert config.filters[1].created_after == 50
            assert config.filters[1].created_before is None
        finally:
            os.unlink(path)

    def test_load_no_filter_section(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[server]
origin = "localhost"
""")
            f.flush()
            path = f.name
        try:
            config = Config.load(path)
            assert config.filters == []
        finally:
            os.unlink(path)
