# -*- coding: utf-8 -*-

import pytest
import tempfile
import os

from core.config import Config


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
        config = Config(data_dir="/var/lib/bonnet")
        assert config.data_dir == "/var/lib/bonnet"
        assert config.identity_path == "/var/lib/bonnet/identity"
        assert config.userfile_path == "/var/lib/bonnet/userfile"

    def test_identity_path_override(self):
        """Explicit identity_path overrides data_dir derivation"""
        config = Config(data_dir="./data", identity_path="/secure/identity")
        assert config.data_dir == "./data"
        assert config.identity_path == "/secure/identity"

    def test_userfile_path_override(self):
        """Explicit userfile_path overrides data_dir derivation"""
        config = Config(data_dir="./data", userfile_path="/etc/bonnet/users")
        assert config.userfile_path == "/etc/bonnet/users"

    def test_relative_path_resolves_from_data_dir(self):
        """Relative paths resolve from data_dir"""
        config = Config(data_dir="/var/lib/bonnet", nav_db_path="custom/nav.db")
        assert config.nav_db_path == "/var/lib/bonnet/custom/nav.db"

    def test_log_dir_default(self):
        """Default log_dir is ./logs"""
        config = Config()
        assert config.log_dir == "./logs"

    def test_log_dir_explicit(self):
        """Explicit log_dir is used"""
        config = Config(log_dir="/var/log/bonnet")
        assert config.log_dir == "/var/log/bonnet"


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
            tls_enabled=True, tls_cert_path="/ssl/cert.pem", tls_key_path="/ssl/key.pem"
        )
        assert config.tls_enabled is True
        assert config.tls_cert_path == "/ssl/cert.pem"
        assert config.tls_key_path == "/ssl/key.pem"


class TestConfigLoad:
    def test_load_from_file(self):
        """Config can be loaded from TOML file"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[server]
origin = "test.example.com"
data_dir = "/test/data"
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
cert_path = "/test/cert.pem"
key_path = "/test/key.pem"
""")
            f.flush()
            path = f.name

        try:
            config = Config.load(path)
            assert config.origin == "test.example.com"
            assert config.data_dir == "/test/data"
            assert config.port_standard == 9000
            assert config.port_privileged == 90
            assert config.timeout_seconds == 45
            assert config.max_connections == 50
            assert config.max_request_size == 5242880
            assert config.rate_limit_requests == 25
            assert config.rate_limit_window == 2
            assert config.tls_enabled is True
            assert config.tls_cert_path == "/test/cert.pem"
            assert config.tls_key_path == "/test/key.pem"
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
reports_path = "/custom/reports.db"
punishments_path = "/custom/punishments.db"
""")
            f.flush()
            path = f.name

        try:
            config = Config.load(path)
            assert config.reports_db_path == "/custom/reports.db"
            assert config.punishments_db_path == "/custom/punishments.db"
        finally:
            os.unlink(path)

    def test_load_keibatsu_relative_paths(self):
        """Keibatsu relative paths resolve from data_dir"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[server]
data_dir = "/var/lib/bonnet"

[keibatsu]
reports_path = "data/reports.db"
""")
            f.flush()
            path = f.name

        try:
            config = Config.load(path)
            assert config.reports_db_path == "/var/lib/bonnet/data/reports.db"
        finally:
            os.unlink(path)
