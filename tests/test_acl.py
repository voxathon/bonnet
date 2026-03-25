# -*- coding: utf-8 -*-

import pytest
import tempfile
import os
from unittest.mock import MagicMock

from core.config import Config, Matcher, ACLEntry
from engine.ume import User
from core.crypto import Identity


class TestMatcher:
    def test_matcher_pubkey_exact_match(self):
        identity = Identity.generate()
        pubkey = identity.public_key
        matcher = Matcher(pubkey=pubkey)

        assert matcher.matches(pubkey, "any-origin") is True
        assert matcher.matches(b"\x00" * 32, "any-origin") is False

    def test_matcher_pubkey_no_match(self):
        matcher = Matcher(pubkey=b"\x01" * 32)
        other_key = b"\x02" * 32

        assert matcher.matches(other_key, "localhost") is False

    def test_matcher_origin_exact(self):
        matcher = Matcher(origin_pattern="localhost")

        assert matcher.matches(b"\x00" * 32, "localhost") is True
        assert matcher.matches(b"\x01" * 32, "localhost") is True
        assert matcher.matches(b"\x00" * 32, "other-host") is False

    def test_matcher_origin_wildcard(self):
        matcher = Matcher(origin_pattern="*.trusted.net")

        assert matcher.matches(b"\x00" * 32, "server.trusted.net") is True
        assert matcher.matches(b"\x00" * 32, "peer.trusted.net") is True
        assert matcher.matches(b"\x00" * 32, "untrusted.net") is False
        assert matcher.matches(b"\x00" * 32, "trusted.net") is False

    def test_matcher_origin_partial_wildcard(self):
        matcher = Matcher(origin_pattern="server*.example.com")

        assert matcher.matches(b"\x00" * 32, "server1.example.com") is True
        assert matcher.matches(b"\x00" * 32, "server2.example.com") is True
        assert matcher.matches(b"\x00" * 32, "server.example.com") is True
        assert matcher.matches(b"\x00" * 32, "other.example.com") is False

    def test_matcher_wildcard(self):
        matcher = Matcher(wildcard=True)

        assert matcher.matches(b"\x00" * 32, "any-origin") is True
        assert matcher.matches(b"\x01" * 32, "other-origin") is True
        assert matcher.matches(None, None) is True

    def test_matcher_from_dict_pubkey_hex_prefix(self):
        pubkey = b"\xab" * 32
        pubkey_hex = "hex:" + pubkey.hex()

        matcher = Matcher.from_dict({"pubkey": pubkey_hex})
        assert matcher.pubkey == pubkey

    def test_matcher_from_dict_pubkey_no_prefix(self):
        pubkey = b"\xab" * 32
        pubkey_hex = pubkey.hex()

        matcher = Matcher.from_dict({"pubkey": pubkey_hex})
        assert matcher.pubkey == pubkey

    def test_matcher_from_dict_origin(self):
        matcher = Matcher.from_dict({"origin": "*.example.com"})
        assert matcher.origin_pattern == "*.example.com"
        assert matcher.pubkey is None

    def test_matcher_from_dict_wildcard(self):
        matcher = Matcher.from_dict({"wildcard": True})
        assert matcher.wildcard is True

    def test_matcher_from_dict_empty(self):
        matcher = Matcher.from_dict({})
        assert matcher.wildcard is True


class TestACLEntry:
    def test_acl_entry_board_matches_exact(self):
        matcher = Matcher(wildcard=True)
        acl = ACLEntry("test", matcher, ["general", "tech"], True, False)

        assert acl.board_matches("general") is True
        assert acl.board_matches("tech") is True
        assert acl.board_matches("other") is False

    def test_acl_entry_board_matches_pattern(self):
        matcher = Matcher(wildcard=True)
        acl = ACLEntry("test", matcher, ["public-*", "admin*"], True, False)

        assert acl.board_matches("public-board") is True
        assert acl.board_matches("public-test") is True
        assert acl.board_matches("admin") is True
        assert acl.board_matches("admin-secret") is True
        assert acl.board_matches("private") is False

    def test_acl_entry_board_matches_star(self):
        matcher = Matcher(wildcard=True)
        acl = ACLEntry("test", matcher, ["*"], True, False)

        assert acl.board_matches("any-board") is True
        assert acl.board_matches("another-board") is True

    def test_acl_entry_from_dict(self):
        acl = ACLEntry.from_dict(
            "test-acl",
            {
                "match": {"origin": "localhost"},
                "boards": ["general", "tech"],
                "read": True,
                "write": False,
            },
        )

        assert acl.name == "test-acl"
        assert acl.matcher.origin_pattern == "localhost"
        assert acl.board_patterns == ["general", "tech"]
        assert acl.read_perm is True
        assert acl.write_perm is False

    def test_acl_entry_from_dict_boards_string(self):
        acl = ACLEntry.from_dict(
            "test-acl", {"match": {"wildcard": True}, "boards": "*", "read": True}
        )

        assert acl.board_patterns == ["*"]

    def test_acl_entry_from_dict_defaults(self):
        acl = ACLEntry.from_dict("test-acl", {"match": {}})

        assert acl.read_perm is False
        assert acl.write_perm is False
        assert acl.matcher.wildcard is True


class TestConfigACL:
    def test_load_config_with_acls(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[server]
origin = "test.local"
admin_bypass_acl = true

[[acl]]
name = "local-access"
match.origin = "localhost"
boards = ["*"]
read = true
write = true

[[acl]]
name = "trusted-readonly"
match.origin = "*.trusted.net"
boards = ["public"]
read = true
write = false

[[acl]]
name = "admin-user"
match.pubkey = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
boards = ["admin"]
read = true
write = true
""")
            f.flush()
            config = Config.load(f.name)

        os.unlink(f.name)

        assert config.origin == "test.local"
        assert config.admin_bypass_acl is True
        assert len(config.acls) == 3

        assert config.acls[0].name == "local-access"
        assert config.acls[0].matcher.origin_pattern == "localhost"
        assert config.acls[0].board_patterns == ["*"]
        assert config.acls[0].read_perm is True
        assert config.acls[0].write_perm is True

        assert config.acls[1].name == "trusted-readonly"
        assert config.acls[1].matcher.origin_pattern == "*.trusted.net"
        assert config.acls[1].board_patterns == ["public"]
        assert config.acls[1].read_perm is True
        assert config.acls[1].write_perm is False

        assert config.acls[2].name == "admin-user"
        assert (
            config.acls[2].matcher.pubkey.hex()
            == "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
        )

    def test_load_config_default_acls(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[server]
origin = "localhost"
""")
            f.flush()
            config = Config.load(f.name)

        os.unlink(f.name)

        assert len(config.acls) == 0
        assert config.admin_bypass_acl is True

    def test_check_permission_admin_bypass(self):
        config = Config(acls=[], admin_bypass_acl=True)

        identity = Identity.generate()

        assert (
            config.check_permission(
                "read",
                "any-board",
                identity.public_key,
                "any-origin",
                True,
                False,
                None,
            )
            is True
        )
        assert (
            config.check_permission(
                "write",
                "any-board",
                identity.public_key,
                "any-origin",
                True,
                False,
                None,
            )
            is True
        )

    def test_check_permission_board_owner(self):
        identity = Identity.generate()
        owner_pubkey = identity.public_key

        config = Config(acls=[])

        assert (
            config.check_permission(
                "read", "board", owner_pubkey, "any-origin", False, False, owner_pubkey
            )
            is True
        )
        assert (
            config.check_permission(
                "write", "board", owner_pubkey, "any-origin", False, False, owner_pubkey
            )
            is True
        )

        other_identity = Identity.generate()
        assert (
            config.check_permission(
                "read",
                "board",
                other_identity.public_key,
                "any-origin",
                False,
                False,
                owner_pubkey,
            )
            is False
        )

    def test_check_permission_mod_write_override(self):
        config = Config(acls=[])

        identity = Identity.generate()

        assert (
            config.check_permission(
                "write",
                "any-board",
                identity.public_key,
                "any-origin",
                False,
                True,
                None,
            )
            is True
        )
        assert (
            config.check_permission(
                "read",
                "any-board",
                identity.public_key,
                "any-origin",
                False,
                True,
                None,
            )
            is False
        )

    def test_check_permission_acl_match(self):
        acl = ACLEntry(
            "local", Matcher(origin_pattern="localhost"), ["general"], True, False
        )
        config = Config(acls=[acl])

        identity = Identity.generate()

        assert (
            config.check_permission(
                "read", "general", identity.public_key, "localhost", False, False, None
            )
            is True
        )
        assert (
            config.check_permission(
                "write", "general", identity.public_key, "localhost", False, False, None
            )
            is False
        )
        assert (
            config.check_permission(
                "read",
                "other-board",
                identity.public_key,
                "localhost",
                False,
                False,
                None,
            )
            is False
        )

    def test_check_permission_acl_order_first_match_wins(self):
        acl1 = ACLEntry(
            "first", Matcher(origin_pattern="localhost"), ["general"], True, False
        )
        acl2 = ACLEntry(
            "second", Matcher(origin_pattern="localhost"), ["general"], True, True
        )
        config = Config(acls=[acl1, acl2])

        identity = Identity.generate()

        assert (
            config.check_permission(
                "write", "general", identity.public_key, "localhost", False, False, None
            )
            is False
        )

    def test_check_permission_acl_wildcard_matcher(self):
        acl = ACLEntry("public", Matcher(wildcard=True), ["public"], True, False)
        config = Config(acls=[acl])

        identity = Identity.generate()

        assert (
            config.check_permission(
                "read", "public", identity.public_key, "any-origin", False, False, None
            )
            is True
        )
        assert (
            config.check_permission(
                "write", "public", identity.public_key, "any-origin", False, False, None
            )
            is False
        )

    def test_check_permission_acl_pubkey_matcher(self):
        identity = Identity.generate()
        other_identity = Identity.generate()

        acl = ACLEntry(
            "specific-user", Matcher(pubkey=identity.public_key), ["admin"], True, True
        )
        config = Config(acls=[acl])

        assert (
            config.check_permission(
                "read", "admin", identity.public_key, "any-origin", False, False, None
            )
            is True
        )
        assert (
            config.check_permission(
                "write", "admin", identity.public_key, "any-origin", False, False, None
            )
            is True
        )
        assert (
            config.check_permission(
                "read",
                "admin",
                other_identity.public_key,
                "any-origin",
                False,
                False,
                None,
            )
            is False
        )

    def test_check_permission_default_deny(self):
        config = Config(acls=[])

        identity = Identity.generate()

        assert (
            config.check_permission(
                "read", "board", identity.public_key, "localhost", False, False, None
            )
            is False
        )
        assert (
            config.check_permission(
                "write", "board", identity.public_key, "localhost", False, False, None
            )
            is False
        )


class TestConfigCheckPermissionIntegration:
    def test_private_server_model(self):
        acl = ACLEntry(
            "local-only", Matcher(origin_pattern="localhost"), ["*"], True, True
        )
        config = Config(acls=[acl])

        local_identity = Identity.generate()
        remote_identity = Identity.generate()

        assert (
            config.check_permission(
                "read",
                "any-board",
                local_identity.public_key,
                "localhost",
                False,
                False,
                None,
            )
            is True
        )
        assert (
            config.check_permission(
                "write",
                "any-board",
                local_identity.public_key,
                "localhost",
                False,
                False,
                None,
            )
            is True
        )
        assert (
            config.check_permission(
                "read",
                "any-board",
                remote_identity.public_key,
                "remote.net",
                False,
                False,
                None,
            )
            is False
        )

    def test_public_read_model(self):
        public_acl = ACLEntry(
            "public-read",
            Matcher(wildcard=True),
            ["public", "announcements"],
            True,
            False,
        )
        auth_acl = ACLEntry(
            "auth-write",
            Matcher(origin_pattern="localhost"),
            ["public", "announcements"],
            True,
            True,
        )
        config = Config(acls=[public_acl, auth_acl])

        anon_identity = Identity.generate()
        auth_identity = Identity.generate()

        assert (
            config.check_permission(
                "read",
                "public",
                anon_identity.public_key,
                "any.net",
                False,
                False,
                None,
            )
            is True
        )
        assert (
            config.check_permission(
                "write",
                "public",
                anon_identity.public_key,
                "any.net",
                False,
                False,
                None,
            )
            is False
        )
        assert (
            config.check_permission(
                "write",
                "public",
                auth_identity.public_key,
                "localhost",
                False,
                False,
                None,
            )
            is True
        )

    def test_federation_hub_model(self):
        local_acl = ACLEntry(
            "local-full", Matcher(origin_pattern="localhost"), ["*"], True, True
        )
        trusted_acl = ACLEntry(
            "trusted-ro", Matcher(origin_pattern="*.trusted.net"), ["*"], True, False
        )
        config = Config(acls=[local_acl, trusted_acl])

        identity = Identity.generate()

        assert (
            config.check_permission(
                "read", "board", identity.public_key, "localhost", False, False, None
            )
            is True
        )
        assert (
            config.check_permission(
                "write", "board", identity.public_key, "localhost", False, False, None
            )
            is True
        )
        assert (
            config.check_permission(
                "read",
                "board",
                identity.public_key,
                "peer.trusted.net",
                False,
                False,
                None,
            )
            is True
        )
        assert (
            config.check_permission(
                "write",
                "board",
                identity.public_key,
                "peer.trusted.net",
                False,
                False,
                None,
            )
            is False
        )
        assert (
            config.check_permission(
                "read",
                "board",
                identity.public_key,
                "untrusted.net",
                False,
                False,
                None,
            )
            is False
        )

    def test_invite_only_model(self):
        identity1 = Identity.generate()
        identity2 = Identity.generate()

        acl1 = ACLEntry(
            "user1", Matcher(pubkey=identity1.public_key), ["private"], True, True
        )
        acl2 = ACLEntry(
            "user2", Matcher(pubkey=identity2.public_key), ["private"], True, False
        )
        config = Config(acls=[acl1, acl2])

        assert (
            config.check_permission(
                "write", "private", identity1.public_key, "any", False, False, None
            )
            is True
        )
        assert (
            config.check_permission(
                "write", "private", identity2.public_key, "any", False, False, None
            )
            is False
        )

        other_identity = Identity.generate()
        assert (
            config.check_permission(
                "read", "private", other_identity.public_key, "any", False, False, None
            )
            is False
        )
