# -*- coding: utf-8 -*-
"""Tests for the report registry (Phase 4, §9/§17.7).

Covers:
  - Canonical report record encoding/decoding round-trip
  - Report registry key computation
  - ReportRegistryStore: store/retrieve heads, records, state
  - ReportRegistryService: snapshot construction, backfill, mutation callback
  - Reporter signing creates rollover rather than mutating (§9.3)
  - Report registry protocol command round-trip via HTTP
  - Object ACL for reports export
  - Import allowlist for report registry sync
"""

import os
import sys
import struct
import tempfile

import pytest
import pytest_asyncio
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.crypto import Identity
from core.config import Config, Matcher, ACLEntry
from core.commands import COMMAND_SPECS
from core.report_registry import (
    report_registry_key,
    encode_report_record,
    decode_report_record,
    compute_report_value_hash,
    ReportRegistryStore,
    ReportRegistryService,
    sign_report_head,
    verify_report_head,
    decode_report_head,
    encode_head,
    REGISTRY_TYPE_REPORTS,
)
from core.merkle_registry import MerkleRegistryStore, ZERO_HASH
from engine.ume import Ume
from engine.ame import Ame
from engine.keibatsu import Keibatsu
from engine.facade import BonnetEngine
from net.commands import CommandHandler
from net.context import CommandContext
from core.orm import Database
from tests.helpers import default_test_acls, permissive_import_allowlist


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _init_rules(reports_path):
    with Database(reports_path).open() as ctx:
        ctx.execute("""
            CREATE TABLE IF NOT EXISTS rules (
                rule_num INTEGER PRIMARY KEY,
                rule_name TEXT UNIQUE NOT NULL,
                description TEXT NOT NULL
            )
        """)


def _make_setup(temp_dir, origin="local.test"):
    ident = Identity.generate()
    config = Config(
        origin=origin,
        ame_path=os.path.join(temp_dir, "boards"),
        data_dir=temp_dir,
        nav_db_path=os.path.join(temp_dir, "nav.db"),
        reports_db_path=os.path.join(temp_dir, "reports.db"),
        punishments_db_path=os.path.join(temp_dir, "punishments.db"),
        log_dir=os.path.join(temp_dir, "logs"),
        acls=default_test_acls(origin),
        anonymous_read=True,
        import_allowlist=permissive_import_allowlist([origin, "peer.test"]),
    )
    ume = Ume(os.path.join(temp_dir, "userfile"))
    ame = Ame(config.ame_path, origin=origin, signing_key=ident.signing_key,
              nav_db_path=config.nav_db_path)
    _init_rules(config.reports_db_path)
    keibatsu = Keibatsu(config.reports_db_path, config.punishments_db_path,
                        ume=ume, signing_key=ident.signing_key, origin=origin)
    engine = BonnetEngine(ume, ame, keibatsu, config, ident)
    report_store = ReportRegistryStore(os.path.join(temp_dir, "report_registry.db"))
    report_svc = ReportRegistryService(report_store, keibatsu, ident, origin)
    keibatsu.register_mutation_callback(report_svc.mark_dirty)
    engine.report_registry_store = report_store
    engine.report_registry_service = report_svc
    return {
        "ident": ident, "config": config, "ume": ume, "ame": ame,
        "keibatsu": keibatsu, "engine": engine,
        "report_store": report_store, "report_svc": report_svc,
    }


def _make_handler(setup):
    """Create a CommandHandler, cancelling its sync worker task."""
    handler = CommandHandler(setup["engine"])
    task = handler._sync_mgr._worker_task
    if task and not task.done():
        task.cancel()
    return handler


# ---------------------------------------------------------------------------
# Canonical record encoding
# ---------------------------------------------------------------------------

class TestReportRecordEncoding:
    def test_round_trip(self):
        raw = encode_report_record(
            origin="o.test", report_num=1, rollover=0, rule_num=5,
            culprit_pubkey=b"\x11" * 32, culprit_board="general",
            culprit_post_num=42, reporter_pubkey=b"\x22" * 32,
            report_time=1700000000, description="spam",
            origin_sig="abc123", reporter_sig="def456",
        )
        decoded = decode_report_record(raw)
        assert decoded["origin"] == "o.test"
        assert decoded["report_num"] == 1
        assert decoded["rollover"] == 0
        assert decoded["rule_num"] == 5
        assert decoded["culprit_pubkey"] == b"\x11" * 32
        assert decoded["culprit_board"] == "general"
        assert decoded["culprit_post_num"] == 42
        assert decoded["reporter_pubkey"] == b"\x22" * 32
        assert decoded["report_time"] == 1700000000
        assert decoded["description"] == "spam"
        assert decoded["origin_sig"] == "abc123"
        assert decoded["reporter_sig"] == "def456"

    def test_round_trip_no_signatures(self):
        raw = encode_report_record(
            origin="o.test", report_num=2, rollover=0, rule_num=1,
            culprit_pubkey=b"\x33" * 32, culprit_board=None,
            culprit_post_num=0, reporter_pubkey=b"\x44" * 32,
            report_time=1700000001, description="test",
            origin_sig=None, reporter_sig=None,
        )
        decoded = decode_report_record(raw)
        assert decoded["origin_sig"] is None
        assert decoded["reporter_sig"] is None
        assert decoded["culprit_board"] is None

    def test_value_hash_deterministic(self):
        raw = encode_report_record(
            origin="o.test", report_num=1, rollover=0, rule_num=5,
            culprit_pubkey=b"\x11" * 32, culprit_board="g",
            culprit_post_num=42, reporter_pubkey=b"\x22" * 32,
            report_time=1700000000, description="spam",
            origin_sig=None, reporter_sig=None,
        )
        h1 = compute_report_value_hash(raw)
        h2 = compute_report_value_hash(raw)
        assert h1 == h2
        assert len(h1) == 32

    def test_value_hash_differs_on_one_byte(self):
        r1 = encode_report_record(
            origin="o.test", report_num=1, rollover=0, rule_num=5,
            culprit_pubkey=b"\x11" * 32, culprit_board="g",
            culprit_post_num=42, reporter_pubkey=b"\x22" * 32,
            report_time=1700000000, description="spam",
            origin_sig=None, reporter_sig=None,
        )
        r2 = encode_report_record(
            origin="o.test", report_num=1, rollover=0, rule_num=5,
            culprit_pubkey=b"\x11" * 32, culprit_board="g",
            culprit_post_num=42, reporter_pubkey=b"\x22" * 32,
            report_time=1700000000, description="spaM",  # one byte diff
            origin_sig=None, reporter_sig=None,
        )
        assert compute_report_value_hash(r1) != compute_report_value_hash(r2)


# ---------------------------------------------------------------------------
# Registry key
# ---------------------------------------------------------------------------

class TestReportRegistryKey:
    def test_key_is_32_bytes(self):
        key = report_registry_key("o.test", 1, 0)
        assert len(key) == 32

    def test_key_differs_by_report_num(self):
        k1 = report_registry_key("o.test", 1, 0)
        k2 = report_registry_key("o.test", 2, 0)
        assert k1 != k2

    def test_key_differs_by_rollover(self):
        k1 = report_registry_key("o.test", 1, 0)
        k2 = report_registry_key("o.test", 1, 1)
        assert k1 != k2

    def test_key_differs_by_origin(self):
        k1 = report_registry_key("o.test", 1, 0)
        k2 = report_registry_key("other.test", 1, 0)
        assert k1 != k2


# ---------------------------------------------------------------------------
# ReportRegistryStore
# ---------------------------------------------------------------------------

class TestReportRegistryStore:
    @pytest.fixture
    def store(self, tmp_path):
        s = ReportRegistryStore(str(tmp_path / "report_reg.db"))
        yield s
        s.close()

    def test_empty_store_has_no_state(self, store):
        assert store.get_state("o.test") is None

    def test_mark_dirty_creates_state(self, store):
        store.mark_dirty("o.test")
        state = store.get_state("o.test")
        assert state is not None
        assert state["dirty_generation"] == 1

    def test_store_and_retrieve_head(self, store, tmp_path):
        ident = Identity.generate()
        head = sign_report_head("o.test", 1, 1700000000, 5, b"\xAA" * 32, ZERO_HASH, ident)
        store.store_authoritative_head("o.test", head, [], [])
        retrieved = store.get_head("o.test")
        assert retrieved is not None
        assert retrieved.registry_seq == 1
        assert retrieved.registry_type == "reports"


# ---------------------------------------------------------------------------
# ReportRegistryService — snapshot construction
# ---------------------------------------------------------------------------

class TestReportRegistryService:
    @pytest_asyncio.fixture
    async def setup(self, tmp_path):
        s = _make_setup(str(tmp_path))
        yield s
        s["ame"].shutdown()
        s["keibatsu"].shutdown()

    def test_first_bootstrap_creates_seq_1(self, setup):
        svc = setup["report_svc"]
        head = svc.build_snapshot()
        assert head.registry_seq == 1
        assert head.origin == "local.test"
        assert head.registry_type == "reports"
        assert head.previous_head_hash == ZERO_HASH
        assert verify_report_head(head, setup["ident"].public_key)

    def test_empty_report_registry_has_empty_root(self, setup):
        from core.merkle_registry import get_empty_root
        svc = setup["report_svc"]
        head = svc.build_snapshot()
        assert head.leaf_count == 0
        assert head.merkle_root == get_empty_root("reports")

    def test_report_create_advances_registry(self, setup):
        svc = setup["report_svc"]
        keibatsu = setup["keibatsu"]
        h1 = svc.build_snapshot()
        # Create a report
        rule = keibatsu.create_rule("No Spam", "spam").result(timeout=5)
        keibatsu.create_report(
            rule.rule_num, b"\x11" * 32, b"\x22" * 32, "spam",
            "board1", 1,
        ).result(timeout=5)
        h2 = svc.build_snapshot()
        assert h2.registry_seq == h1.registry_seq + 1
        assert h2.leaf_count == 1
        assert h2.merkle_root != h1.merkle_root

    def test_no_mutation_returns_same_head(self, setup):
        svc = setup["report_svc"]
        h1 = svc.build_snapshot()
        h2 = svc.build_snapshot()
        assert h1.head_hash == h2.head_hash

    def test_mutation_callback_marks_dirty(self, setup):
        keibatsu = setup["keibatsu"]
        svc = setup["report_svc"]
        h1 = svc.build_snapshot()
        rule = keibatsu.create_rule("Test", "desc").result(timeout=5)
        keibatsu.create_report(rule.rule_num, b"\x11" * 32, b"\x22" * 32, "x").result(timeout=5)
        # The mutation callback should have marked dirty
        h2 = svc.build_snapshot()
        assert h2.registry_seq > h1.registry_seq


# ---------------------------------------------------------------------------
# Reporter signing creates rollover (§9.3)
# ---------------------------------------------------------------------------

class TestReporterSignRollover:
    @pytest_asyncio.fixture
    async def setup(self, tmp_path):
        s = _make_setup(str(tmp_path))
        yield s
        s["ame"].shutdown()
        s["keibatsu"].shutdown()

    def test_sign_creates_new_rollover(self, setup):
        keibatsu = setup["keibatsu"]
        rule = keibatsu.create_rule("No Spam", "spam").result(timeout=5)
        report = keibatsu.create_report(
            rule.rule_num, b"\x11" * 32, b"\x22" * 32, "spam",
        ).result(timeout=5)

        assert report.rollover == 0
        assert report.reporter_sig is None

        # Sign the report — should create rollover 1
        sig = b"\xAA" * 64
        signed = keibatsu.sign_report(report.origin, report.report_num, sig).result(timeout=5)

        assert signed.rollover == 1
        assert signed.reporter_sig is not None

        # Original rollover 0 still exists
        r0 = keibatsu.get_report(report.origin, report.report_num, 0).result(timeout=5)
        assert r0 is not None
        assert r0.rollover == 0
        assert r0.reporter_sig is None  # unchanged

        # Rollover 1 has the reporter sig
        r1 = keibatsu.get_report(report.origin, report.report_num, 1).result(timeout=5)
        assert r1 is not None
        assert r1.rollover == 1
        assert r1.reporter_sig is not None

    def test_sign_advances_report_registry(self, setup):
        keibatsu = setup["keibatsu"]
        svc = setup["report_svc"]
        rule = keibatsu.create_rule("No Spam", "spam").result(timeout=5)
        keibatsu.create_report(rule.rule_num, b"\x11" * 32, b"\x22" * 32, "spam").result(timeout=5)
        h1 = svc.build_snapshot()
        # Sign the report — creates a new rollover leaf
        keibatsu.sign_report("local.test", 1, b"\xBB" * 64).result(timeout=5)
        h2 = svc.build_snapshot()
        assert h2.registry_seq > h1.registry_seq
        assert h2.leaf_count == h1.leaf_count + 1  # new rollover leaf


# ---------------------------------------------------------------------------
# Protocol command round-trip (§12.1)
# ---------------------------------------------------------------------------

class TestReportRegistryCommands:
    @pytest_asyncio.fixture
    async def setup(self, tmp_path):
        s = _make_setup(str(tmp_path))
        s["handler"] = _make_handler(s)
        yield s
        s["ame"].shutdown()
        s["keibatsu"].shutdown()

    def test_report_registry_head_round_trip(self, setup):
        from client.protocol import build_report_registry_head, parse_report_registry_head_resp
        from core.merkle_registry import decode_head

        handler = setup["handler"]
        ident = setup["ident"]
        config = setup["config"]

        # Build a snapshot first
        setup["report_svc"].build_snapshot()

        # Build and send the command
        body = build_report_registry_head(config.origin)
        ctx = CommandContext(
            peer_public_key=ident.public_key,
            user=MagicMock(username="root", is_administrator=True, is_moderator=False,
                           record_origin=config.origin, creation_time=0),
            is_anonymous=False,
        )
        resp = handler.handle(body, ctx)
        assert resp[0] == 0x00, f"expected success, got error"
        encoded_head = parse_report_registry_head_resp(resp[1:])
        head = decode_head(encoded_head, expected_registry_type="reports")
        assert head.origin == config.origin
        assert head.registry_type == "reports"

    def test_report_registry_records_round_trip(self, setup):
        from client.protocol import build_report_registry_records, parse_report_registry_records_resp

        handler = setup["handler"]
        ident = setup["ident"]
        config = setup["config"]
        keibatsu = setup["keibatsu"]

        # Create a report and build snapshot
        rule = keibatsu.create_rule("Spam", "desc").result(timeout=5)
        keibatsu.create_report(rule.rule_num, b"\x11" * 32, b"\x22" * 32, "spam").result(timeout=5)
        setup["report_svc"].build_snapshot()

        # Fetch all records (count=0 means all)
        body = build_report_registry_records(config.origin, 0, [], include_proofs=False)
        ctx = CommandContext(
            peer_public_key=ident.public_key,
            user=MagicMock(username="root", is_administrator=True, is_moderator=False,
                           record_origin=config.origin, creation_time=0),
            is_anonymous=False,
        )
        resp = handler.handle(body, ctx)
        assert resp[0] == 0x00
        records = parse_report_registry_records_resp(resp[1:])
        assert len(records) == 1
        assert records[0]["present"] == 1
        decoded = decode_report_record(records[0]["raw_record"])
        assert decoded["report_num"] == 1
        assert decoded["description"] == "spam"

    def test_report_registry_heads_list(self, setup):
        from client.protocol import build_report_registry_heads, parse_report_registry_heads_resp

        handler = setup["handler"]
        ident = setup["ident"]
        config = setup["config"]

        setup["report_svc"].build_snapshot()

        body = build_report_registry_heads(offset=0, limit=10)
        ctx = CommandContext(
            peer_public_key=ident.public_key,
            user=MagicMock(username="root", is_administrator=True, is_moderator=False,
                           record_origin=config.origin, creation_time=0),
            is_anonymous=False,
        )
        resp = handler.handle(body, ctx)
        assert resp[0] == 0x00
        heads = parse_report_registry_heads_resp(resp[1:])
        assert len(heads) >= 1

    def test_report_registry_head_chain(self, setup):
        from client.protocol import build_report_registry_head_chain, parse_report_registry_heads_resp

        handler = setup["handler"]
        ident = setup["ident"]
        config = setup["config"]
        keibatsu = setup["keibatsu"]

        # Build two snapshots
        setup["report_svc"].build_snapshot()
        rule = keibatsu.create_rule("Spam", "desc").result(timeout=5)
        keibatsu.create_report(rule.rule_num, b"\x11" * 32, b"\x22" * 32, "spam").result(timeout=5)
        setup["report_svc"].build_snapshot()

        body = build_report_registry_head_chain(config.origin, 2, max_count=10)
        ctx = CommandContext(
            peer_public_key=ident.public_key,
            user=MagicMock(username="root", is_administrator=True, is_moderator=False,
                           record_origin=config.origin, creation_time=0),
            is_anonymous=False,
        )
        resp = handler.handle(body, ctx)
        assert resp[0] == 0x00
        heads = parse_report_registry_heads_resp(resp[1:])
        assert len(heads) == 2  # seq 2 and seq 1


# ---------------------------------------------------------------------------
# Object ACL for reports (§5.5, §12.2)
# ---------------------------------------------------------------------------

class TestReportObjectACL:
    def test_report_registry_commands_require_reports_object_read(self):
        """The 5 report registry commands have object_name='reports'."""
        for opcode in (0x55, 0x56, 0x57, 0x58, 0x59):
            spec = COMMAND_SPECS[opcode]
            assert spec.object_name == "reports"

    def test_missing_reports_object_acl_denies(self, tmp_path):
        """Without an object ACL for 'reports', the command is denied even
        with command ACL grant."""
        ident = Identity.generate()
        config = Config(
            origin="local.test",
            acls=[
                ACLEntry("local", Matcher(origin_pattern="local.test"), ["*"], True, True,
                         command_patterns=["*"]),
                # No object_patterns for "reports" — deny
            ],
            admin_bypass_acl=False,
        )
        ame = MagicMock()
        engine = BonnetEngine(MagicMock(), ame, MagicMock(), config, ident)

        from core.commands import get_spec
        spec = get_spec(0x55)  # REPORT_REGISTRY_HEAD
        user = MagicMock(record_origin="local.test", creation_time=0, publickey=ident.public_key)
        ctx = CommandContext(
            peer_public_key=ident.public_key,
            user=user,
            is_anonymous=False,
        )
        assert engine.check_command_permission(spec, ctx) is True  # command ACL grants
        assert engine.check_object_permission("read", "reports", ctx) is False  # no object ACL


# ---------------------------------------------------------------------------
# Domain separation: report head can't be replayed as user head
# ---------------------------------------------------------------------------

class TestReportDomainSeparation:
    def test_report_head_not_replayable_as_user(self, tmp_path):
        from core.user_registry import UserRegistryStore
        ident = Identity.generate()
        report_head = sign_report_head("o.test", 1, 1700000000, 5, b"\xAA" * 32, ZERO_HASH, ident)
        assert verify_report_head(report_head, ident.public_key)

        # Try to accept a report head into a user registry store
        user_store = UserRegistryStore(str(tmp_path / "user_reg.db"))
        result = user_store.accept_remote_head("o.test", report_head, ident.public_key, [], [])
        assert not result.accepted
        assert "registry_type mismatch" in result.reason
        user_store.close()

    def test_report_head_has_reports_type(self):
        ident = Identity.generate()
        head = sign_report_head("o.test", 1, 1700000000, 5, b"\xAA" * 32, ZERO_HASH, ident)
        assert head.registry_type == "reports"


# ---------------------------------------------------------------------------
# Backfill (§17.7: existing reports backfill into seq 1)
# ---------------------------------------------------------------------------

class TestReportBackfill:
    @pytest_asyncio.fixture
    async def setup(self, tmp_path):
        s = _make_setup(str(tmp_path))
        yield s
        s["ame"].shutdown()
        s["keibatsu"].shutdown()

    def test_existing_reports_backfill_into_seq_1(self, setup):
        keibatsu = setup["keibatsu"]
        svc = setup["report_svc"]

        # Create reports before building any snapshot
        rule = keibatsu.create_rule("Spam", "desc").result(timeout=5)
        keibatsu.create_report(rule.rule_num, b"\x11" * 32, b"\x22" * 32, "r1").result(timeout=5)
        keibatsu.create_report(rule.rule_num, b"\x33" * 32, b"\x44" * 32, "r2").result(timeout=5)

        # First snapshot should backfill all existing reports into seq 1
        head = svc.build_snapshot()
        assert head.registry_seq == 1
        assert head.leaf_count == 2

        # Records should be stored
        store = setup["report_store"]
        all_records = store.get_all_records("local.test")
        assert len(all_records) == 2
