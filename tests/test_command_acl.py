# -*- coding: utf-8 -*-
"""Tests for command and object ACL evaluation (Phase 1, §17.2/§17.3).

Covers:
  - Default deny with no command ACL
  - Read/write selection from CommandSpec
  - Anonymous, pubkey, unknown, origin, wildcard precedence
  - Specific pubkey overrides generic unknown
  - Admin does not bypass command ACL
  - Object/board handler checks remain conjunctive
  - Legacy public_commands is silently ignored
  - Object ACL: missing object ACL denies even when command ACL grants
  - Object ACL: admin does not bypass
  - Anonymous and unknown grants can differ
"""

import os
import sys
import tempfile
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.config import Config, Matcher, ACLEntry
from core.commands import COMMAND_SPECS, get_spec, get_spec_by_name, CommandSpec
from engine.facade import BonnetEngine
from net.context import CommandContext
from core.crypto import Identity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ctx(peer_pubkey=None, user=None, is_anonymous=False, is_unknown=False, origin="unknown"):
    return CommandContext(
        peer_public_key=peer_pubkey or b"\x00" * 32,
        user=user,
        username=user.username if user else None,
        is_anonymous=is_anonymous,
        is_unknown=is_unknown,
        origin=origin,
    )


def _mock_user(pubkey, record_origin="local.test", is_admin=False, is_mod=False, creation_time=0):
    u = MagicMock()
    u.publickey = pubkey
    u.record_origin = record_origin
    u.is_administrator = is_admin
    u.is_moderator = is_mod
    u.creation_time = creation_time
    u.username = "testuser"
    return u


def _engine(acls, origin="local.test", admin_bypass_acl=True):
    config = Config(origin=origin, acls=acls, admin_bypass_acl=admin_bypass_acl)
    ame = MagicMock()
    ame.get_board_owner.return_value = None
    return BonnetEngine(MagicMock(), ame, MagicMock(), config, Identity.generate())


# ---------------------------------------------------------------------------
# CommandSpec table tests
# ---------------------------------------------------------------------------

class TestCommandSpecTable:
    def test_all_19_commands_present(self):
        assert len(COMMAND_SPECS) == 19

    def test_get_spec_by_opcode(self):
        spec = get_spec(0x01)
        assert spec.name == "REGISTER"
        assert spec.action == "write"

    def test_get_spec_by_name(self):
        spec = get_spec_by_name("BOARD_LIST")
        assert spec.opcode == 0x11
        assert spec.action == "read"

    def test_unknown_opcode_returns_none(self):
        assert get_spec(0xFF) is None

    def test_read_commands_classified(self):
        reads = {s.name for s in COMMAND_SPECS.values() if s.action == "read"}
        assert "GET_USER" in reads
        assert "BOARD_LIST" in reads
        assert "POST_GET" in reads
        assert "USER_REGISTRY_HEAD" in reads
        assert "PEER_KEY_LIST" in reads

    def test_write_commands_classified(self):
        writes = {s.name for s in COMMAND_SPECS.values() if s.action == "write"}
        assert "REGISTER" in writes
        assert "BOARD_CREATE" in writes
        assert "POST_CREATE" in writes
        assert "PEER_KEY_ROTATE" in writes

    def test_non_registry_commands_have_no_object_name(self):
        """All commands except report/punishment registry have object_name=None."""
        registry_opcodes = {0x55, 0x56, 0x57, 0x58, 0x59, 0x65, 0x66, 0x67, 0x68, 0x69}
        for opcode, spec in COMMAND_SPECS.items():
            if opcode in registry_opcodes:
                continue
            assert spec.object_name is None, f"{spec.name} (0x{opcode:02x}) should have object_name=None"


# ---------------------------------------------------------------------------
# §17.2 Command ACL tests
# ---------------------------------------------------------------------------

class TestCommandACL:
    """Command permission evaluation (§5.4, §17.2)."""

    def test_default_deny_with_no_command_acl(self):
        """No command ACL means deny, even for a known local user."""
        engine = _engine([ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, True)])
        spec = get_spec_by_name("BOARD_LIST")
        ctx = _ctx(peer_pubkey=b"\x11" * 32, user=_mock_user(b"\x11" * 32, record_origin="local.test"))
        assert engine.check_command_permission(spec, ctx) is False

    def test_command_acl_grants_read(self):
        """A command ACL with commands=["*"] grants read for a read command."""
        engine = _engine([
            ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, True, command_patterns=["*"]),
        ])
        spec = get_spec_by_name("BOARD_LIST")
        ctx = _ctx(peer_pubkey=b"\x11" * 32, user=_mock_user(b"\x11" * 32, record_origin="local.test"))
        assert engine.check_command_permission(spec, ctx) is True

    def test_command_acl_grants_write(self):
        """A command ACL with commands=["*"] grants write for a write command."""
        engine = _engine([
            ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, True, command_patterns=["*"]),
        ])
        spec = get_spec_by_name("POST_CREATE")
        ctx = _ctx(peer_pubkey=b"\x11" * 32, user=_mock_user(b"\x11" * 32, record_origin="local.test"))
        assert engine.check_command_permission(spec, ctx) is True

    def test_read_write_selection_from_spec(self):
        """A read-only command ACL denies write commands even with commands=["*"]."""
        engine = _engine([
            ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, False, command_patterns=["*"]),
        ])
        read_spec = get_spec_by_name("BOARD_LIST")
        write_spec = get_spec_by_name("POST_CREATE")
        ctx = _ctx(peer_pubkey=b"\x11" * 32, user=_mock_user(b"\x11" * 32, record_origin="local.test"))
        assert engine.check_command_permission(read_spec, ctx) is True
        assert engine.check_command_permission(write_spec, ctx) is False

    def test_anonymous_command_acl_grants(self):
        """Anonymous matcher grants read for anonymous principal."""
        engine = _engine([
            ACLEntry("anon", Matcher(anonymous=True), ["*"], True, False, command_patterns=["BOARD_LIST"]),
        ])
        spec = get_spec_by_name("BOARD_LIST")
        ctx = _ctx(is_anonymous=True)
        assert engine.check_command_permission(spec, ctx) is True

    def test_anonymous_command_acl_denies_write(self):
        """Anonymous read-only ACL denies write commands."""
        engine = _engine([
            ACLEntry("anon", Matcher(anonymous=True), ["*"], True, False, command_patterns=["*"]),
        ])
        spec = get_spec_by_name("POST_CREATE")
        ctx = _ctx(is_anonymous=True)
        assert engine.check_command_permission(spec, ctx) is False

    def test_unknown_command_acl_grants(self):
        """Unknown matcher grants for unknown principal."""
        engine = _engine([
            ACLEntry("unknown-reg", Matcher(unknown=True), ["*"], False, True, command_patterns=["REGISTER"]),
        ])
        spec = get_spec_by_name("REGISTER")
        ctx = _ctx(is_unknown=True)
        assert engine.check_command_permission(spec, ctx) is True

    def test_unknown_matcher_does_not_match_known(self):
        """Unknown matcher does not match a known (registered) principal."""
        engine = _engine([
            ACLEntry("unknown-reg", Matcher(unknown=True), ["*"], False, True, command_patterns=["REGISTER"]),
        ])
        spec = get_spec_by_name("REGISTER")
        ctx = _ctx(peer_pubkey=b"\x11" * 32, user=_mock_user(b"\x11" * 32))
        assert engine.check_command_permission(spec, ctx) is False

    def test_unknown_matcher_does_not_match_anonymous(self):
        """Unknown matcher does not match an anonymous principal."""
        engine = _engine([
            ACLEntry("unknown-reg", Matcher(unknown=True), ["*"], False, True, command_patterns=["REGISTER"]),
        ])
        spec = get_spec_by_name("REGISTER")
        ctx = _ctx(is_anonymous=True)
        assert engine.check_command_permission(spec, ctx) is False

    def test_pubkey_overrides_unknown(self):
        """A specific pubkey rule overrides a generic unknown rule (§3.5 precedence)."""
        pubkey = b"\x22" * 32
        engine = _engine([
            ACLEntry("pubkey-grant", Matcher(pubkey=pubkey), ["*"], True, True, command_patterns=["*"]),
            ACLEntry("unknown-deny", Matcher(unknown=True), ["*"], False, False, command_patterns=["*"]),
        ])
        spec = get_spec_by_name("BOARD_LIST")
        ctx = _ctx(peer_pubkey=pubkey, user=_mock_user(pubkey, record_origin="local.test"))
        assert engine.check_command_permission(spec, ctx) is True

    def test_anonymous_precedence_over_pubkey(self):
        """Anonymous bucket is checked before pubkey (§3.5 precedence)."""
        pubkey = b"\x33" * 32
        engine = _engine([
            ACLEntry("anon-deny", Matcher(anonymous=True), ["*"], False, False, command_patterns=["*"]),
            ACLEntry("pubkey-grant", Matcher(pubkey=pubkey), ["*"], True, True, command_patterns=["*"]),
        ])
        spec = get_spec_by_name("BOARD_LIST")
        # Anonymous principal with the pubkey — anonymous bucket wins (deny)
        ctx = _ctx(peer_pubkey=pubkey, is_anonymous=True)
        assert engine.check_command_permission(spec, ctx) is False

    def test_admin_does_not_bypass_command_acl(self):
        """Admin bypass must not apply to command ACLs (§5.4, §3.6)."""
        engine = _engine([
            ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, True, command_patterns=["*"]),
        ], admin_bypass_acl=True)
        spec = get_spec_by_name("BOARD_LIST")
        # Admin user with origin that doesn't match any command ACL
        ctx = _ctx(peer_pubkey=b"\x44" * 32, user=_mock_user(b"\x44" * 32, record_origin="remote.test", is_admin=True))
        assert engine.check_command_permission(spec, ctx) is False

    def test_legacy_public_commands_silently_ignored(self):
        """public_commands in Config has no authorization effect (§5.7)."""
        config = Config(
            origin="local.test",
            acls=[
                ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, True, command_patterns=["BOARD_LIST"]),
            ],
            admin_bypass_acl=False,
            public_commands={0x11, 0x12, 0x13},
        )
        ame = MagicMock()
        ame.get_board_owner.return_value = None
        engine = BonnetEngine(MagicMock(), ame, MagicMock(), config, Identity.generate())

        # BOARD_LIST is in command ACL → granted
        spec_read = get_spec_by_name("BOARD_LIST")
        ctx = _ctx(peer_pubkey=b"\x11" * 32, user=_mock_user(b"\x11" * 32, record_origin="local.test"))
        assert engine.check_command_permission(spec_read, ctx) is True

        # POST_CREATE is in public_commands but NOT in command ACL → denied
        spec_write = get_spec_by_name("POST_CREATE")
        assert engine.check_command_permission(spec_write, ctx) is False

    def test_wildcard_command_acl_grants(self):
        """Wildcard matcher grants command access."""
        engine = _engine([
            ACLEntry("all", Matcher(wildcard=True), ["*"], True, False, command_patterns=["*"]),
        ])
        spec = get_spec_by_name("BOARD_LIST")
        ctx = _ctx(peer_pubkey=b"\x55" * 32, user=_mock_user(b"\x55" * 32, record_origin="remote.test"))
        assert engine.check_command_permission(spec, ctx) is True

    def test_specific_command_pattern_match(self):
        """A command pattern matches only the specified command name."""
        engine = _engine([
            ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, True,
                     command_patterns=["BOARD_LIST", "POST_GET"]),
        ])
        ctx = _ctx(peer_pubkey=b"\x11" * 32, user=_mock_user(b"\x11" * 32, record_origin="local.test"))

        assert engine.check_command_permission(get_spec_by_name("BOARD_LIST"), ctx) is True
        assert engine.check_command_permission(get_spec_by_name("POST_GET"), ctx) is True
        assert engine.check_command_permission(get_spec_by_name("POST_CREATE"), ctx) is False

    def test_command_wildcard_pattern(self):
        """commands=["*"] matches all command names."""
        engine = _engine([
            ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, True, command_patterns=["*"]),
        ])
        ctx = _ctx(peer_pubkey=b"\x11" * 32, user=_mock_user(b"\x11" * 32, record_origin="local.test"))

        for spec in COMMAND_SPECS.values():
            assert engine.check_command_permission(spec, ctx) is True


# ---------------------------------------------------------------------------
# §17.3 Object ACL tests
# ---------------------------------------------------------------------------

class TestObjectACL:
    """Object permission evaluation (§5.5, §17.3).

    In Phase 1, no existing command has object_name set, so these tests
    exercise the Config/engine methods directly.
    """

    def test_missing_object_acl_denies(self):
        """No object ACL means deny, even when command ACL grants."""
        config = Config(
            origin="local.test",
            acls=[
                ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, True,
                         command_patterns=["*"]),
            ],
            admin_bypass_acl=False,
        )
        assert config.check_object_permission("read", "reports", b"\x11" * 32, "local.test") is False

    def test_object_acl_grants(self):
        """An object ACL with objects=["reports"] grants for reports."""
        config = Config(
            origin="local.test",
            acls=[
                ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, True,
                         command_patterns=["*"], object_patterns=["reports"]),
            ],
            admin_bypass_acl=False,
        )
        assert config.check_object_permission("read", "reports", b"\x11" * 32, "local.test") is True

    def test_object_acl_denies_wrong_object(self):
        """An object ACL for reports does not grant for punishments."""
        config = Config(
            origin="local.test",
            acls=[
                ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, True,
                         object_patterns=["reports"]),
            ],
            admin_bypass_acl=False,
        )
        assert config.check_object_permission("read", "reports", b"\x11" * 32, "local.test") is True
        assert config.check_object_permission("read", "punishments", b"\x11" * 32, "local.test") is False

    def test_admin_does_not_bypass_object_acl(self):
        """Admin bypass must not apply to object ACLs (§5.5)."""
        config = Config(
            origin="local.test",
            acls=[
                ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, True,
                         command_patterns=["*"], object_patterns=["reports"]),
            ],
            admin_bypass_acl=True,
        )
        # Admin user with origin that doesn't match any object ACL
        assert config.check_object_permission("read", "reports", b"\x44" * 32, "remote.test",
                                               is_anonymous=False, is_unknown=False) is False

    def test_anonymous_object_acl(self):
        """Anonymous matcher grants object access for anonymous principal."""
        config = Config(
            origin="local.test",
            acls=[
                ACLEntry("anon", Matcher(anonymous=True), ["*"], True, False,
                         object_patterns=["reports", "punishments"]),
            ],
            admin_bypass_acl=False,
        )
        assert config.check_object_permission("read", "reports", b"\x00" * 32, "any",
                                               is_anonymous=True) is True
        assert config.check_object_permission("write", "reports", b"\x00" * 32, "any",
                                               is_anonymous=True) is False

    def test_anonymous_and_unknown_grants_differ(self):
        """Anonymous and unknown principals can have different object grants."""
        config = Config(
            origin="local.test",
            acls=[
                ACLEntry("anon", Matcher(anonymous=True), ["*"], True, False,
                         object_patterns=["reports"]),
                ACLEntry("unknown", Matcher(unknown=True), ["*"], True, True,
                         object_patterns=["reports", "punishments"]),
            ],
            admin_bypass_acl=False,
        )
        # Anonymous: read reports only
        assert config.check_object_permission("read", "reports", b"\x00" * 32, "any",
                                               is_anonymous=True) is True
        assert config.check_object_permission("write", "reports", b"\x00" * 32, "any",
                                               is_anonymous=True) is False
        # Unknown: read+write reports and punishments
        assert config.check_object_permission("read", "reports", b"\x00" * 32, "any",
                                               is_anonymous=False, is_unknown=True) is True
        assert config.check_object_permission("write", "punishments", b"\x00" * 32, "any",
                                               is_anonymous=False, is_unknown=True) is True

    def test_object_wildcard_pattern(self):
        """objects=["*"] matches all object names."""
        config = Config(
            origin="local.test",
            acls=[
                ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, True,
                         object_patterns=["*"]),
            ],
            admin_bypass_acl=False,
        )
        assert config.check_object_permission("read", "reports", b"\x11" * 32, "local.test") is True
        assert config.check_object_permission("write", "punishments", b"\x11" * 32, "local.test") is True


# ---------------------------------------------------------------------------
# §17.1 Principal classification tests
# ---------------------------------------------------------------------------

class TestPrincipalClassification:
    """CommandContext principal classification (§4.1, §17.1)."""

    def test_anonymous_is_not_unknown(self):
        ctx = _ctx(is_anonymous=True)
        assert ctx.is_anonymous is True
        assert ctx.is_unknown is False

    def test_unknown_is_not_anonymous(self):
        ctx = _ctx(is_unknown=True)
        assert ctx.is_anonymous is False
        assert ctx.is_unknown is True
        assert ctx.user is None

    def test_known_is_neither(self):
        user = _mock_user(b"\x11" * 32)
        ctx = _ctx(peer_pubkey=b"\x11" * 32, user=user)
        assert ctx.is_anonymous is False
        assert ctx.is_unknown is False
        assert ctx.is_registered is True

    def test_anonymous_not_registered(self):
        ctx = _ctx(is_anonymous=True)
        assert ctx.is_registered is False

    def test_unknown_not_registered(self):
        ctx = _ctx(is_unknown=True)
        assert ctx.is_registered is False


# ---------------------------------------------------------------------------
# Config parsing tests for command/object ACLs
# ---------------------------------------------------------------------------

class TestConfigParsingCommands:
    """TOML parsing of commands and objects ACL fields (§5.3)."""

    def test_load_config_with_command_patterns(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[server]
origin = "test.local"

[[acl]]
name = "local"
match.origin = "test.local"
commands = ["BOARD_LIST", "POST_GET"]
read = true
write = true
""")
            f.flush()
            path = f.name
        try:
            config = Config.load(path)
            assert len(config.acls) == 1
            acl = config.acls[0]
            assert acl.command_patterns == ["BOARD_LIST", "POST_GET"]
            assert acl.command_matches("BOARD_LIST") is True
            assert acl.command_matches("POST_GET") is True
            assert acl.command_matches("POST_CREATE") is False
        finally:
            os.unlink(path)

    def test_load_config_with_object_patterns(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[server]
origin = "test.local"

[[acl]]
name = "mod-export"
match.origin = "test.local"
objects = ["reports", "punishments"]
read = true
""")
            f.flush()
            path = f.name
        try:
            config = Config.load(path)
            assert len(config.acls) == 1
            acl = config.acls[0]
            assert acl.object_patterns == ["reports", "punishments"]
            assert acl.object_matches("reports") is True
            assert acl.object_matches("punishments") is True
            assert acl.object_matches("users") is False
        finally:
            os.unlink(path)

    def test_load_config_with_match_unknown(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[server]
origin = "test.local"

[[acl]]
name = "unknown-reg"
match.unknown = true
commands = ["REGISTER"]
write = true
""")
            f.flush()
            path = f.name
        try:
            config = Config.load(path)
            assert len(config.acls) == 1
            acl = config.acls[0]
            assert acl.matcher.unknown is True
            assert acl.command_patterns == ["REGISTER"]
        finally:
            os.unlink(path)

    def test_load_config_commands_string(self):
        """commands as a string is parsed as a single-element list."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[server]
origin = "test.local"

[[acl]]
name = "local"
match.origin = "test.local"
commands = "REGISTER"
write = true
""")
            f.flush()
            path = f.name
        try:
            config = Config.load(path)
            assert config.acls[0].command_patterns == ["REGISTER"]
        finally:
            os.unlink(path)

    def test_public_commands_silently_ignored(self):
        """public_commands in TOML is parsed but has no authorization effect (§5.7)."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[server]
origin = "test.local"
public_commands = ["BOARD_LIST", "POST_CREATE"]

[[acl]]
name = "local"
match.origin = "test.local"
commands = ["BOARD_LIST"]
read = true
""")
            f.flush()
            path = f.name
        try:
            config = Config.load(path)
            # Config loads without error
            # public_commands has no effect — POST_CREATE is not in any command ACL
            assert config.check_command_permission("POST_CREATE", "write", b"\x11" * 32, "test.local") is False
            # BOARD_LIST is in command ACL → granted
            assert config.check_command_permission("BOARD_LIST", "read", b"\x11" * 32, "test.local") is True
        finally:
            os.unlink(path)
