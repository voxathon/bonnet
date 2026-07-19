# -*- coding: utf-8 -*-
"""Tests for import allowlists (Phase 3, §13/§17.5).

Covers:
  - Config.is_import_origin_allowed() default-deny semantics
  - Missing list denies; empty list denies; exact origin allows
  - Case-insensitive origin matching
  - TOML parsing of [import_allowlist] section
  - String-to-list normalization
  - Unknown object type denies
  - Local origin not implicitly allowed
"""

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.config import Config


class TestImportAllowlist:
    """Config.is_import_origin_allowed() semantics (§13.2)."""

    def test_missing_object_type_denies(self):
        config = Config(import_allowlist={"boards": ["origin.example"]})
        assert config.is_import_origin_allowed("users", "origin.example") is False

    def test_empty_list_denies(self):
        config = Config(import_allowlist={"boards": []})
        assert config.is_import_origin_allowed("boards", "origin.example") is False

    def test_missing_list_denies(self):
        config = Config(import_allowlist={})
        assert config.is_import_origin_allowed("boards", "origin.example") is False

    def test_no_allowlist_at_all_denies(self):
        config = Config()
        assert config.is_import_origin_allowed("boards", "origin.example") is False
        assert config.is_import_origin_allowed("users", "origin.example") is False
        assert config.is_import_origin_allowed("reports", "origin.example") is False
        assert config.is_import_origin_allowed("punishments", "origin.example") is False

    def test_exact_origin_allows(self):
        config = Config(import_allowlist={"boards": ["boards.example"]})
        assert config.is_import_origin_allowed("boards", "boards.example") is True

    def test_disallowed_origin_denied(self):
        config = Config(import_allowlist={"boards": ["boards.example"]})
        assert config.is_import_origin_allowed("boards", "evil.example") is False

    def test_case_insensitive_origin(self):
        config = Config(import_allowlist={"boards": ["Boards.Example"]})
        assert config.is_import_origin_allowed("boards", "boards.example") is True
        assert config.is_import_origin_allowed("boards", "BOARDS.EXAMPLE") is True

    def test_multiple_origins(self):
        config = Config(import_allowlist={
            "users": ["identity.example", "relay-origin.example"],
            "punishments": ["moderation.example", "appeals.example"],
        })
        assert config.is_import_origin_allowed("users", "identity.example") is True
        assert config.is_import_origin_allowed("users", "relay-origin.example") is True
        assert config.is_import_origin_allowed("users", "other.example") is False
        assert config.is_import_origin_allowed("punishments", "moderation.example") is True
        assert config.is_import_origin_allowed("punishments", "appeals.example") is True
        assert config.is_import_origin_allowed("punishments", "evil.example") is False

    def test_local_origin_not_implicitly_allowed(self):
        """Per §13.2: local origin is not implicitly allowed for import."""
        config = Config(origin="local.test", import_allowlist={"users": ["other.test"]})
        assert config.is_import_origin_allowed("users", "local.test") is False

    def test_empty_origin_denied(self):
        config = Config(import_allowlist={"boards": ["boards.example"]})
        assert config.is_import_origin_allowed("boards", "") is False

    def test_empty_object_type_denied(self):
        config = Config(import_allowlist={"boards": ["boards.example"]})
        assert config.is_import_origin_allowed("", "boards.example") is False

    def test_string_origin_normalized_to_list(self):
        """A single string origin is normalized to a one-element list."""
        config = Config(import_allowlist={"boards": "boards.example"})
        assert config.is_import_origin_allowed("boards", "boards.example") is True
        assert config.is_import_origin_allowed("boards", "other.example") is False


class TestImportAllowlistParsing:
    """TOML parsing of [import_allowlist] section (§13.1)."""

    def test_load_import_allowlist(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[server]
origin = "test.local"

[import_allowlist]
boards = ["boards.example"]
users = ["identity.example", "relay-origin.example"]
reports = ["moderation.example"]
punishments = ["moderation.example", "appeals.example"]
""")
            f.flush()
            path = f.name
        try:
            config = Config.load(path)
            assert config.is_import_origin_allowed("boards", "boards.example") is True
            assert config.is_import_origin_allowed("users", "identity.example") is True
            assert config.is_import_origin_allowed("users", "relay-origin.example") is True
            assert config.is_import_origin_allowed("reports", "moderation.example") is True
            assert config.is_import_origin_allowed("punishments", "appeals.example") is True
            # Disallowed origins
            assert config.is_import_origin_allowed("boards", "evil.example") is False
            assert config.is_import_origin_allowed("users", "evil.example") is False
        finally:
            os.unlink(path)

    def test_load_import_allowlist_string_origin(self):
        """TOML with a single string origin is parsed correctly."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[server]
origin = "test.local"

[import_allowlist]
boards = "boards.example"
""")
            f.flush()
            path = f.name
        try:
            config = Config.load(path)
            assert config.is_import_origin_allowed("boards", "boards.example") is True
        finally:
            os.unlink(path)

    def test_load_import_allowlist_empty(self):
        """Empty allowlist denies all."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[server]
origin = "test.local"

[import_allowlist]
boards = []
""")
            f.flush()
            path = f.name
        try:
            config = Config.load(path)
            assert config.is_import_origin_allowed("boards", "boards.example") is False
        finally:
            os.unlink(path)

    def test_load_no_import_allowlist_section(self):
        """Missing [import_allowlist] section denies all imports."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[server]
origin = "test.local"
""")
            f.flush()
            path = f.name
        try:
            config = Config.load(path)
            assert config.is_import_origin_allowed("boards", "any.example") is False
            assert config.is_import_origin_allowed("users", "any.example") is False
        finally:
            os.unlink(path)

    def test_load_import_allowlist_partial(self):
        """Only configured object types have allowlists; others deny."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[server]
origin = "test.local"

[import_allowlist]
boards = ["boards.example"]
""")
            f.flush()
            path = f.name
        try:
            config = Config.load(path)
            assert config.is_import_origin_allowed("boards", "boards.example") is True
            assert config.is_import_origin_allowed("users", "boards.example") is False
            assert config.is_import_origin_allowed("reports", "boards.example") is False
        finally:
            os.unlink(path)


class TestImportAllowlistExportIndependence:
    """Per §13.5: import allowlists never affect exports.

    Export visibility is controlled solely by ACLs. A locally disallowed import
    origin may still have cached records, and those records remain exportable.
    """

    def test_export_not_filtered_by_import_allowlist(self):
        """is_import_origin_allowed is not used in command handlers or export.
        This test documents the constraint: the method exists only for sync
        import paths, and the config does not wire it into any export logic."""
        config = Config(
            origin="local.test",
            import_allowlist={"users": ["allowed.example"]},
        )
        # Disallowed origin is denied for import
        assert config.is_import_origin_allowed("users", "disallowed.example") is False
        # But there is no Config method that filters exports by import allowlist.
        # check_command_permission and check_object_permission do not consult
        # the import allowlist — they use ACLs only.
        assert not hasattr(config, "is_export_origin_allowed")
        # The only import-allowlist-related method is is_import_origin_allowed.
        assert callable(getattr(config, "is_import_origin_allowed", None))


class TestLegacyUserSyncRemoved:
    """Per §14.2: legacy _sync_users is removed from the active sync path."""

    def test_sync_users_method_removed(self):
        """SyncManager must not have a _sync_users method."""
        from net.sync import SyncManager
        assert not hasattr(SyncManager, "_sync_users")

    def test_build_list_users_not_imported_in_sync(self):
        """sync.py must not import build_list_users (legacy command builder)."""
        import net.sync as sync_module
        assert not hasattr(sync_module, "build_list_users")

    def test_legacy_sync_methods_removed(self):
        """Both _sync_users and _sync_reports have been removed from
        SyncManager (Phase 3 removed _sync_users; Phase 7 removed
        _sync_reports in favor of the report registry)."""
        from net.sync import SyncManager
        assert not hasattr(SyncManager, "_sync_users")
        assert not hasattr(SyncManager, "_sync_reports")

        import inspect
        source = inspect.getsource(SyncManager)
        assert "_sync_users" not in source
        assert "await self._sync_reports" not in source
