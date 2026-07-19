# -*- coding: utf-8 -*-
"""Tests for the punishment registry and schema migration (Phase 5, §10/§11/§17.8).

Covers:
  - Canonical punishment record encoding/decoding round-trip
  - Punishment registry key computation
  - Schema migration v2->v3 (origin, rollover, origin_sig, relay)
  - Migrated signature verifies against local key
  - Per-origin ID allocation
  - Local create advances punishment registry
  - PUNISHMENT_GET requires (origin, punishment_id)
  - Object ACL for punishments
  - Domain separation: punishment head not replayable as user/report head
  - Backfill: existing punishments backfill into seq 1
  - Multi-origin effective evaluation (§11.4)
"""

import os
import sys
import struct
import json
import time

import pytest
import pytest_asyncio
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.crypto import Identity
from core.config import Config, Matcher, ACLEntry
from core.commands import COMMAND_SPECS
from core.punishment_registry import (
    punishment_registry_key,
    encode_punishment_record,
    decode_punishment_record,
    compute_punishment_value_hash,
    PunishmentRegistryStore,
    PunishmentRegistryService,
    sign_punishment_head,
    verify_punishment_head,
    decode_punishment_head,
    REGISTRY_TYPE_PUNISHMENTS,
)
from core.merkle_registry import ZERO_HASH
from engine.ume import Ume
from engine.ame import Ame
from engine.keibatsu import Keibatsu, Punishment
from engine.facade import BonnetEngine
from net.commands import CommandHandler
from net.context import CommandContext
from core.orm import Database
from tests.helpers import default_test_acls, permissive_import_allowlist


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
    pun_store = PunishmentRegistryStore(os.path.join(temp_dir, "punishment_registry.db"))
    pun_svc = PunishmentRegistryService(pun_store, keibatsu, ident, origin)
    keibatsu.register_punishment_mutation_callback(pun_svc.mark_dirty)
    engine.punishment_registry_store = pun_store
    engine.punishment_registry_service = pun_svc
    return {
        "ident": ident, "config": config, "ume": ume, "ame": ame,
        "keibatsu": keibatsu, "engine": engine,
        "pun_store": pun_store, "pun_svc": pun_svc,
    }


def _make_handler(setup):
    handler = CommandHandler(setup["engine"])
    task = handler._sync_mgr._worker_task
    if task and not task.done():
        task.cancel()
    return handler


# ---------------------------------------------------------------------------
# Canonical record encoding
# ---------------------------------------------------------------------------

class TestPunishmentRecordEncoding:
    def test_round_trip(self):
        raw = encode_punishment_record(
            punishment_id=1, rollover=0, origin="o.test",
            punished_pubkey=b"\x11" * 32, report_ids=[1, 2],
            expires_at=-1, ban_notes="banned",
            issued_by=b"\x22" * 32, created_at=1700000000,
            origin_sig="abc123",
        )
        decoded = decode_punishment_record(raw)
        assert decoded["punishment_id"] == 1
        assert decoded["rollover"] == 0
        assert decoded["origin"] == "o.test"
        assert decoded["punished_pubkey"] == b"\x11" * 32
        assert decoded["report_ids"] == [1, 2]
        assert decoded["expires_at"] == -1
        assert decoded["ban_notes"] == "banned"
        assert decoded["issued_by"] == b"\x22" * 32
        assert decoded["created_at"] == 1700000000
        assert decoded["origin_sig"] == "abc123"

    def test_round_trip_no_sig(self):
        raw = encode_punishment_record(
            punishment_id=2, rollover=0, origin="o.test",
            punished_pubkey=b"\x33" * 32, report_ids=[],
            expires_at=0, ban_notes="",
            issued_by=b'', created_at=1700000001,
            origin_sig=None,
        )
        decoded = decode_punishment_record(raw)
        assert decoded["origin_sig"] is None
        assert decoded["report_ids"] == []

    def test_value_hash_deterministic(self):
        raw = encode_punishment_record(
            punishment_id=1, rollover=0, origin="o.test",
            punished_pubkey=b"\x11" * 32, report_ids=[1],
            expires_at=-1, ban_notes="x",
            issued_by=b'', created_at=0,
            origin_sig=None,
        )
        h1 = compute_punishment_value_hash(raw)
        h2 = compute_punishment_value_hash(raw)
        assert h1 == h2
        assert len(h1) == 32


# ---------------------------------------------------------------------------
# Registry key
# ---------------------------------------------------------------------------

class TestPunishmentRegistryKey:
    def test_key_is_32_bytes(self):
        key = punishment_registry_key("o.test", 1, 0)
        assert len(key) == 32

    def test_key_differs_by_id(self):
        assert punishment_registry_key("o.test", 1, 0) != punishment_registry_key("o.test", 2, 0)

    def test_key_differs_by_rollover(self):
        assert punishment_registry_key("o.test", 1, 0) != punishment_registry_key("o.test", 1, 1)

    def test_key_differs_by_origin(self):
        assert punishment_registry_key("o.test", 1, 0) != punishment_registry_key("other.test", 1, 0)


# ---------------------------------------------------------------------------
# Schema migration
# ---------------------------------------------------------------------------

class TestPunishmentMigration:
    def test_v2_to_v3_migration(self, tmp_path):
        """v2 append-only schema migrates to v3 with origin/rollover/origin_sig."""
        reports_path = str(tmp_path / "reports.db")
        punishments_path = str(tmp_path / "punishments.db")
        origin = "test_origin"
        ident = Identity.generate()

        _init_rules(reports_path)

        # Create a v2 schema with a punishment
        with Database(punishments_path).open() as ctx:
            ctx.execute("""
                CREATE TABLE punishments (
                    punishment_id   INTEGER PRIMARY KEY AUTOINCREMENT,
                    punished_pubkey BLOB NOT NULL,
                    report_ids      TEXT NOT NULL,
                    expires_at      INTEGER NOT NULL,
                    ban_notes       TEXT,
                    issued_by       BLOB,
                    created_at      INTEGER NOT NULL
                )
            """)
            pubkey = b"\x11" * 32
            ctx.execute(
                "INSERT INTO punishments (punishment_id, punished_pubkey, report_ids, expires_at, ban_notes, issued_by, created_at) "
                "VALUES (1, ?, ?, -1, 'legacy ban', NULL, 1700000000)",
                [pubkey, "[1,2]"]
            )

        # Instantiate Keibatsu — triggers v2->v3 migration
        k = Keibatsu(reports_path, punishments_path, signing_key=ident.signing_key, origin=origin)
        try:
            # The migrated punishment should have origin and origin_sig
            punishments = k.list_punishments_by_pubkey(pubkey).result(timeout=5)
            assert len(punishments) == 1
            p = punishments[0]
            assert p.punishment_id == 1
            assert p.origin == origin
            assert p.rollover == 0
            assert p.origin_sig is not None  # generated during migration

            # Verify the origin signature
            payload = k._build_punishment_signed_payload(
                p.punishment_id, p.rollover, p.origin, p.punished_pubkey,
                p.get_report_ids(), p.expires_at, p.ban_notes, p.issued_by, p.created_at,
            )
            assert Identity.verify(ident.public_key, payload, bytes.fromhex(p.origin_sig))
        finally:
            k.shutdown()

    def test_v1_to_v3_migration(self, tmp_path):
        """v1 (pubkey PRIMARY KEY) schema migrates directly to v3."""
        reports_path = str(tmp_path / "reports.db")
        punishments_path = str(tmp_path / "punishments.db")
        origin = "test_origin"
        ident = Identity.generate()

        _init_rules(reports_path)

        pubkey = b"\x22" * 32
        with Database(punishments_path).open() as ctx:
            ctx.execute("""
                CREATE TABLE punishments (
                    punished_pubkey  BLOB PRIMARY KEY,
                    report_ids       TEXT NOT NULL,
                    expires_at       INTEGER NOT NULL,
                    ban_notes        TEXT
                )
            """)
            ctx.execute(
                "INSERT INTO punishments (punished_pubkey, report_ids, expires_at, ban_notes) VALUES (?, ?, -1, 'old ban')",
                [pubkey, "[7]"]
            )

        k = Keibatsu(reports_path, punishments_path, signing_key=ident.signing_key, origin=origin)
        try:
            punishments = k.list_punishments_by_pubkey(pubkey).result(timeout=5)
            assert len(punishments) == 1
            p = punishments[0]
            assert p.origin == origin
            assert p.rollover == 0
            assert p.get_report_ids() == [7]
            assert p.expires_at == -1
            assert p.ban_notes == "old ban"
            assert p.created_at == 0  # unknown for v1
            assert p.issued_by == b''
        finally:
            k.shutdown()


# ---------------------------------------------------------------------------
# Per-origin ID allocation
# ---------------------------------------------------------------------------

class TestPerOriginIDAllocation:
    @pytest_asyncio.fixture
    async def setup(self, tmp_path):
        s = _make_setup(str(tmp_path))
        yield s
        s["ame"].shutdown()
        s["keibatsu"].shutdown()

    def test_local_ids_increase(self, setup):
        k = setup["keibatsu"]
        pubkey = b"\x11" * 32
        p1 = k.create_punishment(pubkey, [1], -1, "first").result(timeout=5)
        p2 = k.create_punishment(pubkey, [2], -1, "second").result(timeout=5)
        assert p2.punishment_id == p1.punishment_id + 1
        assert p1.origin == setup["config"].origin
        assert p2.origin == setup["config"].origin

    def test_origin_sig_generated(self, setup):
        k = setup["keibatsu"]
        ident = setup["ident"]
        pubkey = b"\x11" * 32
        p = k.create_punishment(pubkey, [1], -1, "ban").result(timeout=5)
        assert p.origin_sig is not None
        # Verify the signature
        payload = k._build_punishment_signed_payload(
            p.punishment_id, p.rollover, p.origin, p.punished_pubkey,
            p.get_report_ids(), p.expires_at, p.ban_notes, p.issued_by, p.created_at,
        )
        assert Identity.verify(ident.public_key, payload, bytes.fromhex(p.origin_sig))


# ---------------------------------------------------------------------------
# PunishmentRegistryService — snapshot construction
# ---------------------------------------------------------------------------

class TestPunishmentRegistryService:
    @pytest_asyncio.fixture
    async def setup(self, tmp_path):
        s = _make_setup(str(tmp_path))
        yield s
        s["ame"].shutdown()
        s["keibatsu"].shutdown()

    def test_first_bootstrap_creates_seq_1(self, setup):
        svc = setup["pun_svc"]
        head = svc.build_snapshot()
        assert head.registry_seq == 1
        assert head.origin == "local.test"
        assert head.registry_type == "punishments"
        assert head.previous_head_hash == ZERO_HASH
        assert verify_punishment_head(head, setup["ident"].public_key)

    def test_empty_registry_has_empty_root(self, setup):
        from core.merkle_registry import get_empty_root
        svc = setup["pun_svc"]
        head = svc.build_snapshot()
        assert head.leaf_count == 0
        assert head.merkle_root == get_empty_root("punishments")

    def test_punishment_create_advances_registry(self, setup):
        svc = setup["pun_svc"]
        k = setup["keibatsu"]
        h1 = svc.build_snapshot()
        k.create_punishment(b"\x11" * 32, [1], -1, "ban").result(timeout=5)
        h2 = svc.build_snapshot()
        assert h2.registry_seq == h1.registry_seq + 1
        assert h2.leaf_count == 1

    def test_no_mutation_returns_same_head(self, setup):
        svc = setup["pun_svc"]
        h1 = svc.build_snapshot()
        h2 = svc.build_snapshot()
        assert h1.head_hash == h2.head_hash

    def test_mutation_callback_marks_dirty(self, setup):
        k = setup["keibatsu"]
        svc = setup["pun_svc"]
        h1 = svc.build_snapshot()
        k.create_punishment(b"\x11" * 32, [1], -1, "ban").result(timeout=5)
        h2 = svc.build_snapshot()
        assert h2.registry_seq > h1.registry_seq


# ---------------------------------------------------------------------------
# PUNISHMENT_GET requires (origin, punishment_id)
# ---------------------------------------------------------------------------

class TestPunishmentGetRewire:
    @pytest_asyncio.fixture
    async def setup(self, tmp_path):
        s = _make_setup(str(tmp_path))
        s["handler"] = _make_handler(s)
        yield s
        s["ame"].shutdown()
        s["keibatsu"].shutdown()

    def test_punishment_get_with_origin(self, setup):
        from client.protocol import build_punishment_get
        handler = setup["handler"]
        ident = setup["ident"]
        config = setup["config"]
        k = setup["keibatsu"]

        p = k.create_punishment(b"\x11" * 32, [1], -1, "ban").result(timeout=5)
        body = build_punishment_get(config.origin, p.punishment_id)
        ctx = CommandContext(
            peer_public_key=ident.public_key,
            user=MagicMock(username="root", is_administrator=True, is_moderator=False,
                           record_origin=config.origin, creation_time=0),
            is_anonymous=False,
        )
        resp = handler.handle(body, ctx)
        assert resp[0] == 0x00, f"expected success, got error"

    def test_punishment_get_wrong_origin_404(self, setup):
        from client.protocol import build_punishment_get
        handler = setup["handler"]
        ident = setup["ident"]
        config = setup["config"]

        body = build_punishment_get("nonexistent.test", 999)
        ctx = CommandContext(
            peer_public_key=ident.public_key,
            user=MagicMock(username="root", is_administrator=True, is_moderator=False,
                           record_origin=config.origin, creation_time=0),
            is_anonymous=False,
        )
        resp = handler.handle(body, ctx)
        assert resp[0] == 0x01  # ERROR
        code = struct.unpack(">H", resp[1:3])[0]
        assert code == 404


# ---------------------------------------------------------------------------
# Object ACL for punishments
# ---------------------------------------------------------------------------

class TestPunishmentObjectACL:
    def test_punishment_registry_commands_require_punishments_object(self):
        for opcode in (0x65, 0x66, 0x67, 0x68, 0x69):
            spec = COMMAND_SPECS[opcode]
            assert spec.object_name == "punishments"


# ---------------------------------------------------------------------------
# Domain separation
# ---------------------------------------------------------------------------

class TestPunishmentDomainSeparation:
    def test_punishment_head_has_punishments_type(self):
        ident = Identity.generate()
        head = sign_punishment_head("o.test", 1, 1700000000, 5, b"\xAA" * 32, ZERO_HASH, ident)
        assert head.registry_type == "punishments"

    def test_punishment_head_not_replayable_as_user(self, tmp_path):
        from core.user_registry import UserRegistryStore
        ident = Identity.generate()
        head = sign_punishment_head("o.test", 1, 1700000000, 5, b"\xAA" * 32, ZERO_HASH, ident)
        assert verify_punishment_head(head, ident.public_key)

        user_store = UserRegistryStore(str(tmp_path / "user_reg.db"))
        result = user_store.accept_remote_head("o.test", head, ident.public_key, [], [])
        assert not result.accepted
        assert "registry_type mismatch" in result.reason
        user_store.close()

    def test_punishment_head_not_replayable_as_report(self, tmp_path):
        from core.report_registry import ReportRegistryStore
        ident = Identity.generate()
        head = sign_punishment_head("o.test", 1, 1700000000, 5, b"\xAA" * 32, ZERO_HASH, ident)

        report_store = ReportRegistryStore(str(tmp_path / "report_reg.db"))
        result = report_store.accept_remote_head("o.test", head, ident.public_key, [], [])
        assert not result.accepted
        assert "registry_type mismatch" in result.reason
        report_store.close()


# ---------------------------------------------------------------------------
# Backfill
# ---------------------------------------------------------------------------

class TestPunishmentBackfill:
    @pytest_asyncio.fixture
    async def setup(self, tmp_path):
        s = _make_setup(str(tmp_path))
        yield s
        s["ame"].shutdown()
        s["keibatsu"].shutdown()

    def test_existing_punishments_backfill_into_seq_1(self, setup):
        k = setup["keibatsu"]
        svc = setup["pun_svc"]

        k.create_punishment(b"\x11" * 32, [1], -1, "ban1").result(timeout=5)
        k.create_punishment(b"\x22" * 32, [2], -1, "ban2").result(timeout=5)

        head = svc.build_snapshot()
        assert head.registry_seq == 1
        assert head.leaf_count == 2

        store = setup["pun_store"]
        all_records = store.get_all_records("local.test")
        assert len(all_records) == 2


# ---------------------------------------------------------------------------
# Multi-origin effective evaluation (§11.4)
# ---------------------------------------------------------------------------

class TestMultiOriginEvaluation:
    @pytest_asyncio.fixture
    async def setup(self, tmp_path):
        s = _make_setup(str(tmp_path))
        yield s
        s["ame"].shutdown()
        s["keibatsu"].shutdown()

    def test_local_punishment_blocks(self, setup):
        k = setup["keibatsu"]
        config = setup["config"]
        pubkey = b"\x11" * 32
        k.create_punishment(pubkey, [1], -1, "local ban").result(timeout=5)
        is_banned, notes = k.is_banned(pubkey).result(timeout=5)
        assert is_banned is True
        assert notes == "local ban"

    def test_out_of_window_denied(self, setup):
        k = setup["keibatsu"]
        pubkey = b"\x11" * 32
        p = k.create_punishment(pubkey, [1], -1, "old ban").result(timeout=5)
        # Set created_at to the past
        with k._punishments_db.open() as ctx:
            ctx.execute("UPDATE punishments SET created_at=? WHERE punishment_id=? AND origin=?",
                        [1000, p.punishment_id, p.origin])
        # Filter: only recent records
        k._record_in_window = lambda origin, t: t > 5000
        is_banned, _ = k.is_banned(pubkey).result(timeout=5)
        assert is_banned is False

    def test_expired_punishment_denied(self, setup):
        k = setup["keibatsu"]
        pubkey = b"\x11" * 32
        # Temporary ban that already expired
        k.create_punishment(pubkey, [1], int(time.time()) - 3600, "temp ban").result(timeout=5)
        is_banned, _ = k.is_banned(pubkey).result(timeout=5)
        assert is_banned is False

    def test_audit_reads_unfiltered(self, setup):
        k = setup["keibatsu"]
        pubkey = b"\x11" * 32
        p = k.create_punishment(pubkey, [1], -1, "ban").result(timeout=5)
        with k._punishments_db.open() as ctx:
            ctx.execute("UPDATE punishments SET created_at=? WHERE punishment_id=? AND origin=?",
                        [1000, p.punishment_id, p.origin])
        k._record_in_window = lambda origin, t: t > 5000
        # Audit read: list_punishments_by_pubkey returns all
        all_puns = k.list_punishments_by_pubkey(pubkey).result(timeout=5)
        assert len(all_puns) == 1  # unfiltered


# ---------------------------------------------------------------------------
# Protocol command round-trip
# ---------------------------------------------------------------------------

class TestPunishmentRegistryCommands:
    @pytest_asyncio.fixture
    async def setup(self, tmp_path):
        s = _make_setup(str(tmp_path))
        s["handler"] = _make_handler(s)
        yield s
        s["ame"].shutdown()
        s["keibatsu"].shutdown()

    def test_punishment_registry_head_round_trip(self, setup):
        from client.protocol import build_punishment_registry_head, parse_punishment_registry_head_resp
        from core.merkle_registry import decode_head

        handler = setup["handler"]
        ident = setup["ident"]
        config = setup["config"]

        setup["pun_svc"].build_snapshot()

        body = build_punishment_registry_head(config.origin)
        ctx = CommandContext(
            peer_public_key=ident.public_key,
            user=MagicMock(username="root", is_administrator=True, is_moderator=False,
                           record_origin=config.origin, creation_time=0),
            is_anonymous=False,
        )
        resp = handler.handle(body, ctx)
        assert resp[0] == 0x00
        encoded_head = parse_punishment_registry_head_resp(resp[1:])
        head = decode_head(encoded_head, expected_registry_type="punishments")
        assert head.origin == config.origin
        assert head.registry_type == "punishments"

    def test_punishment_registry_records_round_trip(self, setup):
        from client.protocol import build_punishment_registry_records, parse_punishment_registry_records_resp

        handler = setup["handler"]
        ident = setup["ident"]
        config = setup["config"]
        k = setup["keibatsu"]

        k.create_punishment(b"\x11" * 32, [1], -1, "ban").result(timeout=5)
        setup["pun_svc"].build_snapshot()

        body = build_punishment_registry_records(config.origin, 0, [], include_proofs=False)
        ctx = CommandContext(
            peer_public_key=ident.public_key,
            user=MagicMock(username="root", is_administrator=True, is_moderator=False,
                           record_origin=config.origin, creation_time=0),
            is_anonymous=False,
        )
        resp = handler.handle(body, ctx)
        assert resp[0] == 0x00
        records = parse_punishment_registry_records_resp(resp[1:])
        assert len(records) == 1
        assert records[0]["present"] == 1
        decoded = decode_punishment_record(records[0]["raw_record"])
        assert decoded["punishment_id"] == 1
        assert decoded["ban_notes"] == "ban"
