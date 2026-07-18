# -*- coding: utf-8 -*-

import pytest
import tempfile
import os
from unittest.mock import MagicMock

from core.config import Config, Matcher, ACLEntry, Filter
from engine.ume import User
from engine.facade import BonnetEngine
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


class TestACLOriginResolution:
    """#4 -- conn.origin (Host header) must not be trusted for ACL matching.

    Only an authenticated user's record_origin satisfies an origin-pattern ACL;
    an anonymous connection that spoofs Host: localhost must NOT match.
    """

    def _engine_with_local_acl(self):
        config = Config(
            acls=[ACLEntry("local-full-access", Matcher(origin_pattern="localhost"), ["*"], True, True)],
            admin_bypass_acl=False,
        )
        ame = MagicMock()
        ame.get_board_owner.return_value = None
        ume = MagicMock()
        ident = Identity.generate()
        return BonnetEngine(ume, ame, MagicMock(), config, ident), ident, config

    def _conn(self, ident, host_header, user=None, peer_pubkey=None):
        from net.context import CommandContext
        return CommandContext(
            peer_public_key=peer_pubkey or b"\x22" * 32,
            user=user,
            username=user.username if user else None,
            remote_addr="203.0.113.9",
            is_anonymous=user is None,
            origin=host_header,
        )

    def test_anonymous_host_localhost_does_not_match(self):
        engine, ident, config = self._engine_with_local_acl()
        conn = self._conn(ident, host_header="localhost")  # spoofed Host header
        # anonymous => _resolve_origin returns "unknown", not "localhost"
        assert engine.check_permission("write", "anyboard", conn) is False
        assert engine.check_permission("read", "anyboard", conn) is False

    def test_authenticated_record_origin_localhost_matches(self):
        engine, ident, config = self._engine_with_local_acl()
        user = MagicMock()
        user.record_origin = "localhost"
        user.is_administrator = False
        user.is_moderator = False
        conn = self._conn(ident, host_header="evil.example", user=user)
        # authenticated user with record_origin=localhost => matches ACL
        assert engine.check_permission("write", "anyboard", conn) is True
        assert engine.check_permission("read", "anyboard", conn) is True

    def test_authenticated_wrong_record_origin_does_not_match(self):
        engine, ident, config = self._engine_with_local_acl()
        user = MagicMock()
        user.record_origin = "remote.test"
        user.is_administrator = False
        user.is_moderator = False
        conn = self._conn(ident, host_header="localhost", user=user)
        # record_origin is remote.test, and the spoofed Host header is ignored
        assert engine.check_permission("write", "anyboard", conn) is False

    def test_anonymous_explicit_anonymous_acl_still_grants_read(self):
        """An explicit `anonymous` ACL must still work for anonymous reads,
        preserving read semantics after removing the Host-header fallback."""
        config = Config(
            acls=[
                ACLEntry("anon-read", Matcher(anonymous=True), ["public"], True, False),
                ACLEntry("local", Matcher(origin_pattern="localhost"), ["*"], True, True),
            ],
            admin_bypass_acl=False,
        )
        ame = MagicMock()
        ame.get_board_owner.return_value = None
        engine = BonnetEngine(MagicMock(), ame, MagicMock(), config, Identity.generate())
        ident = Identity.generate()
        conn = self._conn(ident, host_header="localhost")  # anonymous, spoofed Host
        assert engine.check_permission("read", "public", conn) is True
        assert engine.check_permission("write", "public", conn) is False


class TestACLOriginLocalOnly:
    """R1 -- only a *locally-registered* user's record_origin (== config.origin)
    is trusted for ACL matching. A remote-synced user's record_origin is
    peer-supplied and forgeable, so it must not become an ACL principal.

    Cross-origin trust must instead use `match.pubkey`.
    """

    def _engine(self, origin, acls):
        config = Config(origin=origin, acls=acls, admin_bypass_acl=False)
        ame = MagicMock()
        ame.get_board_owner.return_value = None
        return BonnetEngine(MagicMock(), ame, MagicMock(), config, Identity.generate()), Identity.generate(), config

    def _conn(self, ident, user, peer_pubkey=None):
        from net.context import CommandContext
        return CommandContext(
            peer_public_key=peer_pubkey or b"\x33" * 32,
            user=user,
            username=user.username if user else None,
            remote_addr="203.0.113.9",
            is_anonymous=user is None,
            origin="evil.example",
        )

    def _user(self, record_origin, pubkey, is_admin=False, is_mod=False):
        u = MagicMock()
        u.record_origin = record_origin
        u.is_administrator = is_admin
        u.is_moderator = is_mod
        return u

    def test_local_record_origin_matches_origin_acl(self):
        """Authenticated user with record_origin == config.origin is granted by
        a matching origin-pattern ACL (the locally-registered happy path)."""
        engine, ident, config = self._engine(
            origin="local.test",
            acls=[ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, True)],
        )
        pubkey = Identity.generate().public_key
        user = self._user("local.test", pubkey)
        conn = self._conn(ident, user, peer_pubkey=pubkey)
        assert engine.check_permission("write", "anyboard", conn) is True
        assert engine.check_permission("read", "anyboard", conn) is True

    def test_remote_record_origin_localhost_does_not_match_localhost_acl(self):
        """R1 attack: a remote-synced user with record_origin='localhost' must
        NOT satisfy a `match.origin = 'localhost'` ACL when config.origin !=
        'localhost'. Previously this was the ACL-bypass the reviewer flagged."""
        engine, ident, config = self._engine(
            origin="local.test",  # server is NOT localhost
            acls=[ACLEntry("local-full", Matcher(origin_pattern="localhost"), ["*"], True, True)],
        )
        pubkey = Identity.generate().public_key
        user = self._user("localhost", pubkey)  # forgeable peer-supplied origin
        conn = self._conn(ident, user, peer_pubkey=pubkey)
        assert engine.check_permission("write", "anyboard", conn) is False
        assert engine.check_permission("read", "anyboard", conn) is False

    def test_remote_record_origin_does_not_match_its_own_origin_acl(self):
        """A user whose record_origin is some remote origin resolves to
        'unknown', so an origin-pattern ACL for that remote origin no longer
        matches (the origin is peer-supplied and untrusted)."""
        engine, ident, config = self._engine(
            origin="local.test",
            acls=[ACLEntry("peer", Matcher(origin_pattern="peer.example.com"), ["*"], True, True)],
        )
        pubkey = Identity.generate().public_key
        user = self._user("peer.example.com", pubkey)
        conn = self._conn(ident, user, peer_pubkey=pubkey)
        assert engine.check_permission("read", "anyboard", conn) is False

    def test_cross_origin_trust_via_pubkey_still_works(self):
        """Cross-origin trust is still possible via `match.pubkey`: a remote-
        origin user whose pubkey matches a pubkey ACL is granted even though
        their record_origin does not equal config.origin."""
        pubkey = Identity.generate().public_key
        engine, ident, config = self._engine(
            origin="local.test",
            acls=[
                ACLEntry("peer-user", Matcher(pubkey=pubkey), ["*"], True, True),
                ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, True),
            ],
        )
        user = self._user("peer.example.com", pubkey)  # remote origin, untrusted for origin ACL
        conn = self._conn(ident, user, peer_pubkey=pubkey)
        assert engine.check_permission("write", "anyboard", conn) is True
        assert engine.check_permission("read", "anyboard", conn) is True

    def test_local_record_origin_mismatch_with_acl_denied(self):
        """A locally-registered user (record_origin == config.origin) is still
        subject to the ACL pattern: if the ACL matches a different origin,
        access is denied even though record_origin is trusted."""
        engine, ident, config = self._engine(
            origin="local.test",
            acls=[ACLEntry("other", Matcher(origin_pattern="other.test"), ["*"], True, True)],
        )
        pubkey = Identity.generate().public_key
        user = self._user("local.test", pubkey)
        conn = self._conn(ident, user, peer_pubkey=pubkey)
        assert engine.check_permission("write", "anyboard", conn) is False


class TestACLTemporalFilter:
    """Eval-time creation-date window: an out-of-window user fails origin,
    wildcard, and anonymous ACL buckets but keeps pubkey ACL matches.
    Role bypasses (admin_bypass_acl, mod write) remain in effect.
    """

    def _engine(self, origin, acls, filters=None):
        config = Config(origin=origin, acls=acls, admin_bypass_acl=False, filters=filters or [])
        ame = MagicMock()
        ame.get_board_owner.return_value = None
        return BonnetEngine(MagicMock(), ame, MagicMock(), config, Identity.generate()), Identity.generate(), config

    def _conn(self, ident, user, peer_pubkey=None):
        from net.context import CommandContext
        return CommandContext(
            peer_public_key=peer_pubkey or b"\x44" * 32,
            user=user,
            username=user.username if user else None,
            remote_addr="203.0.113.9",
            is_anonymous=user is None,
            origin="evil.example",
        )

    def _user(self, record_origin, pubkey, creation_time=0, is_admin=False, is_mod=False):
        u = MagicMock()
        u.record_origin = record_origin
        u.creation_time = creation_time
        u.is_administrator = is_admin
        u.is_moderator = is_mod
        return u

    def test_out_of_window_user_origin_acl_denied(self):
        """An out-of-window user does not match an origin-pattern ACL."""
        engine, ident, config = self._engine(
            origin="local.test",
            acls=[ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, True)],
            filters=[Filter("local.test", created_after=200)],
        )
        pubkey = Identity.generate().public_key
        user = self._user("local.test", pubkey, creation_time=100)  # before 200
        conn = self._conn(ident, user, peer_pubkey=pubkey)
        assert engine.check_permission("read", "anyboard", conn) is False
        assert engine.check_permission("write", "anyboard", conn) is False

    def test_in_window_user_origin_acl_granted(self):
        """An in-window user matches an origin-pattern ACL normally."""
        engine, ident, config = self._engine(
            origin="local.test",
            acls=[ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, True)],
            filters=[Filter("local.test", created_after=200)],
        )
        pubkey = Identity.generate().public_key
        user = self._user("local.test", pubkey, creation_time=300)
        conn = self._conn(ident, user, peer_pubkey=pubkey)
        assert engine.check_permission("read", "anyboard", conn) is True
        assert engine.check_permission("write", "anyboard", conn) is True

    def test_out_of_window_user_wildcard_acl_denied(self):
        """An out-of-window user does not match a wildcard ACL."""
        engine, ident, config = self._engine(
            origin="local.test",
            acls=[ACLEntry("all", Matcher(wildcard=True), ["*"], True, True)],
            filters=[Filter("local.test", created_after=200)],
        )
        pubkey = Identity.generate().public_key
        user = self._user("local.test", pubkey, creation_time=100)
        conn = self._conn(ident, user, peer_pubkey=pubkey)
        assert engine.check_permission("read", "anyboard", conn) is False

    def test_out_of_window_user_pubkey_acl_still_grants(self):
        """An out-of-window user still matches a pubkey-based ACL."""
        pubkey = Identity.generate().public_key
        engine, ident, config = self._engine(
            origin="local.test",
            acls=[ACLEntry("pinned", Matcher(pubkey=pubkey), ["*"], True, True)],
            filters=[Filter("local.test", created_after=200)],
        )
        user = self._user("local.test", pubkey, creation_time=100)  # out of window
        conn = self._conn(ident, user, peer_pubkey=pubkey)
        assert engine.check_permission("read", "anyboard", conn) is True
        assert engine.check_permission("write", "anyboard", conn) is True

    def test_no_filters_all_users_allowed(self):
        """Without any configured filters, all users match ACLs normally."""
        engine, ident, config = self._engine(
            origin="local.test",
            acls=[ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, True)],
        )
        pubkey = Identity.generate().public_key
        user = self._user("local.test", pubkey, creation_time=0)
        conn = self._conn(ident, user, peer_pubkey=pubkey)
        assert engine.check_permission("write", "anyboard", conn) is True

    def test_out_of_window_admin_still_bypasses(self):
        """An out-of-window admin still bypasses ACLs via admin_bypass_acl."""
        pubkey = Identity.generate().public_key
        config = Config(
            origin="local.test",
            acls=[ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, True)],
            admin_bypass_acl=True,
            filters=[Filter("local.test", created_after=200)],
        )
        ame = MagicMock()
        ame.get_board_owner.return_value = None
        engine = BonnetEngine(MagicMock(), ame, MagicMock(), config, Identity.generate())
        ident = Identity.generate()
        user = self._user("local.test", pubkey, creation_time=100, is_admin=True)
        conn = self._conn(ident, user, peer_pubkey=pubkey)
        assert engine.check_permission("write", "anyboard", conn) is True

    def test_out_of_window_mod_still_gets_write(self):
        """An out-of-window mod still gets the write override."""
        pubkey = Identity.generate().public_key
        engine, ident, config = self._engine(
            origin="local.test",
            acls=[ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, True)],
            filters=[Filter("local.test", created_after=200)],
        )
        user = self._user("local.test", pubkey, creation_time=100, is_mod=True)
        conn = self._conn(ident, user, peer_pubkey=pubkey)
        assert engine.check_permission("write", "anyboard", conn) is True
        # read still goes through the filtered ACL buckets -> denied
        assert engine.check_permission("read", "anyboard", conn) is False
