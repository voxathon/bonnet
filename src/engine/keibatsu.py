"""
Keibatsu - Punishment and Report Management System
"""

import json
import os
import time
import threading
import struct
from concurrent.futures import ThreadPoolExecutor, Future
from core.orm import Database, Table


class AsyncResult:

    def __init__(self, future):
        self._future = future
        self._result = None
        self._done = False

    def done(self) -> bool:
        if not self._done:
            self._done = self._future.done()
        return self._done

    def result(self, timeout=None) -> object:
        if not self._done:
            self._result = self._future.result(timeout=timeout)
            self._done = True
        return self._result

    def result_nowait(self) -> object:
        if self.done():
            return self.result()
        return None

    def cancel(self) -> None:
        self._future.cancel()


class Rule:

    def __init__(self):
        self.rule_num = 0
        self.rule_name = ""
        self.description = ""


class Report:

    def __init__(self):
        self.report_num = 0
        self.rule_num = 0
        self.culprit_pubkey = b''
        self.culprit_board = None
        self.culprit_post_num = 0
        self.reporter_pubkey = b''
        self.report_time = 0
        self.origin = ""
        self.relay = ""
        self.description = ""
        self.origin_sig = None
        self.reporter_sig = None
        self.rollover = 0


class Punishment:

    def __init__(self):
        self.punishment_id = 0
        self.origin = ""
        self.rollover = 0
        self.punished_pubkey = b''
        self.report_ids = "[]"
        self.expires_at = 0
        self.ban_notes = ""
        self.issued_by = b''
        self.created_at = 0
        self.relay = ""
        self.origin_sig = None

    def get_report_ids(self) -> list:
        try:
            return json.loads(self.report_ids) if self.report_ids else []
        except Exception:
            return []

    def set_report_ids(self, value) -> None:
        self.report_ids = json.dumps(value)

    def is_warning(self) -> bool:
        return self.expires_at == 0

    def is_permanent(self) -> bool:
        return self.expires_at < 0

    def is_temporary(self) -> bool:
        return self.expires_at > 0

    def is_active(self) -> bool:
        if self.expires_at == 0:
            return False
        if self.expires_at < 0:
            return True
        return self.expires_at > int(time.time())

    def time_remaining(self) -> object:
        if self.expires_at <= 0:
            return None
        remaining = self.expires_at - int(time.time())
        if remaining <= 0:
            return 0
        return remaining


class Keibatsu:

    def __init__(self, reports_path: str = "./data/reports.db",
                 punishments_path: str = "./data/punishments.db",
                 ume: object = None, signing_key: object = None, origin: str = "localhost",
                 num_workers: int = 2, record_in_window=None):
        needs_migration = False
        self._reports_path = reports_path
        self._punishments_path = punishments_path
        self._ume = ume
        self._signing_key = signing_key
        self._origin = origin
        self._record_in_window = record_in_window
        self._executor = ThreadPoolExecutor(max_workers=num_workers)
        self._lock = threading.Lock()
        self._mutation_callbacks = []
        self._punishment_callbacks = []

        reports_dir = os.path.dirname(reports_path)
        if reports_dir:
            os.makedirs(reports_dir, exist_ok=True)
        punishments_dir = os.path.dirname(punishments_path)
        if punishments_dir:
            os.makedirs(punishments_dir, exist_ok=True)

        self._reports_db = Database(reports_path)
        self._punishments_db = Database(punishments_path)

        with self._reports_db.open() as ctx:
            ctx.execute("""
            CREATE TABLE IF NOT EXISTS rules (
                rule_num     INTEGER PRIMARY KEY,
                rule_name    TEXT UNIQUE NOT NULL,
                description  TEXT NOT NULL
            )
            """)

            # Check if table exists and if it has the rollover column
            try:
                ctx.execute("SELECT rollover FROM reports LIMIT 1")
            except Exception:
                try:
                    ctx.execute("SELECT report_num FROM reports LIMIT 1")
                    needs_migration = True
                except Exception:
                    pass

            if needs_migration:
                ctx.execute("""
                CREATE TABLE reports_v2 (
                    report_num       INTEGER NOT NULL,
                    origin           TEXT NOT NULL,
                    rollover         INTEGER NOT NULL DEFAULT 0,
                    rule_num         INTEGER NOT NULL,
                    culprit_pubkey   BLOB NOT NULL,
                    culprit_board    TEXT,
                    culprit_post_num INTEGER DEFAULT 0,
                    reporter_pubkey  BLOB NOT NULL,
                    report_time      INTEGER NOT NULL,
                    relay            TEXT NOT NULL,
                    description      TEXT NOT NULL,
                    origin_sig       TEXT,
                    reporter_sig     TEXT,
                    PRIMARY KEY (origin, report_num, rollover),
                    FOREIGN KEY (rule_num) REFERENCES rules(rule_num)
                )
                """)
                ctx.execute("""
                INSERT INTO reports_v2 (report_num, origin, rollover, rule_num, culprit_pubkey, culprit_board, culprit_post_num, reporter_pubkey, report_time, relay, description, origin_sig, reporter_sig)
                SELECT report_num, origin, 0, rule_num, culprit_pubkey, culprit_board, culprit_post_num, reporter_pubkey, report_time, relay, description, origin_sig, reporter_sig FROM reports
                """)
                ctx.execute("ALTER TABLE reports RENAME TO reports_old")
                ctx.execute("ALTER TABLE reports_v2 RENAME TO reports")
                ctx.execute("DROP TABLE reports_old")
            else:
                ctx.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    report_num       INTEGER NOT NULL,
                    origin           TEXT NOT NULL,
                    rollover         INTEGER NOT NULL DEFAULT 0,
                    rule_num         INTEGER NOT NULL,
                    culprit_pubkey   BLOB NOT NULL,
                    culprit_board    TEXT,
                    culprit_post_num INTEGER DEFAULT 0,
                    reporter_pubkey  BLOB NOT NULL,
                    report_time      INTEGER NOT NULL,
                    relay            TEXT NOT NULL,
                    description      TEXT NOT NULL,
                    origin_sig       TEXT,
                    reporter_sig     TEXT,
                    PRIMARY KEY (origin, report_num, rollover),
                    FOREIGN KEY (rule_num) REFERENCES rules(rule_num)
                )
                """)

            ctx.execute("CREATE INDEX IF NOT EXISTS idx_reports_culprit ON reports(culprit_pubkey)")
            ctx.execute("CREATE INDEX IF NOT EXISTS idx_reports_rule ON reports(rule_num)")
            ctx.execute("CREATE INDEX IF NOT EXISTS idx_reports_time ON reports(report_time)")

        # Check if punishments table has the v3 schema (origin, rollover, origin_sig);
        # migrate from v2 or v1 if needed.
        needs_pun_v3_migration = False
        needs_pun_v2_migration = False
        with self._punishments_db.open() as ctx:
            # Detect v3 by presence of origin column
            try:
                ctx.execute("SELECT origin FROM punishments LIMIT 1")
            except Exception:
                # Check if v2 schema exists (punishment_id AUTOINCREMENT)
                try:
                    ctx.execute("SELECT punishment_id FROM punishments LIMIT 1")
                    needs_pun_v3_migration = True
                except Exception:
                    # Check if v1 schema exists (punished_pubkey PRIMARY KEY)
                    try:
                        ctx.execute("SELECT punished_pubkey FROM punishments LIMIT 1")
                        needs_pun_v2_migration = True
                    except Exception:
                        pass

            if needs_pun_v2_migration:
                # v1 -> v3: old schema used (punished_pubkey BLOB PRIMARY KEY, ...)
                # Migrate directly to v3 with origin=config.origin, rollover=0
                ctx.execute("""
                CREATE TABLE punishments_v3 (
                    punishment_id   INTEGER NOT NULL,
                    origin          TEXT NOT NULL,
                    rollover        INTEGER NOT NULL DEFAULT 0,
                    punished_pubkey BLOB NOT NULL,
                    report_ids      TEXT NOT NULL,
                    expires_at      INTEGER NOT NULL,
                    ban_notes       TEXT,
                    issued_by       BLOB,
                    created_at      INTEGER NOT NULL,
                    relay           TEXT NOT NULL,
                    origin_sig      TEXT,
                    PRIMARY KEY (origin, punishment_id, rollover)
                )
                """)
                # Assign monotonic IDs starting from 1
                rows = ctx.execute("SELECT punished_pubkey, report_ids, expires_at, ban_notes FROM punishments ORDER BY rowid").fetchall()
                for i, row in enumerate(rows, 1):
                    ctx.execute(
                        "INSERT INTO punishments_v3 (punishment_id, origin, rollover, punished_pubkey, report_ids, expires_at, ban_notes, issued_by, created_at, relay, origin_sig) "
                        "VALUES (?, ?, 0, ?, ?, ?, ?, NULL, 0, ?, NULL)",
                        [i, self._origin, bytes(row[0]), row[1], row[2], row[3], self._origin]
                    )
                ctx.execute("DROP TABLE punishments")
                ctx.execute("ALTER TABLE punishments_v3 RENAME TO punishments")
            elif needs_pun_v3_migration:
                # v2 -> v3: add origin, rollover, relay, origin_sig columns
                # and change PK from punishment_id AUTOINCREMENT to (origin, punishment_id, rollover)
                ctx.execute("""
                CREATE TABLE punishments_v3 (
                    punishment_id   INTEGER NOT NULL,
                    origin          TEXT NOT NULL,
                    rollover        INTEGER NOT NULL DEFAULT 0,
                    punished_pubkey BLOB NOT NULL,
                    report_ids      TEXT NOT NULL,
                    expires_at      INTEGER NOT NULL,
                    ban_notes       TEXT,
                    issued_by       BLOB,
                    created_at      INTEGER NOT NULL,
                    relay           TEXT NOT NULL,
                    origin_sig      TEXT,
                    PRIMARY KEY (origin, punishment_id, rollover)
                )
                """)
                # Migrate existing rows: origin=config.origin, rollover=0, relay=config.origin
                # Generate origin_sig for each row using the local signing key
                rows = ctx.execute(
                    "SELECT punishment_id, punished_pubkey, report_ids, expires_at, ban_notes, issued_by, created_at FROM punishments"
                ).fetchall()
                for row in rows:
                    pun_id = row[0]
                    pubkey = bytes(row[1])
                    report_ids = row[2]
                    expires_at = row[3]
                    ban_notes = row[4]
                    issued_by = bytes(row[5]) if row[5] is not None else None
                    created_at = row[6] if row[6] is not None else 0
                    origin_sig_hex = None
                    if self._signing_key is not None:
                        payload = self._build_punishment_signed_payload(
                            pun_id, 0, self._origin, pubkey,
                            json.loads(report_ids) if report_ids else [],
                            expires_at, ban_notes or "", issued_by, created_at,
                        )
                        sig = bytes(self._signing_key.sign(payload).signature)
                        origin_sig_hex = sig.hex()
                    ctx.execute(
                        "INSERT INTO punishments_v3 (punishment_id, origin, rollover, punished_pubkey, report_ids, expires_at, ban_notes, issued_by, created_at, relay, origin_sig) "
                        "VALUES (?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)",
                        [pun_id, self._origin, pubkey, report_ids, expires_at, ban_notes, issued_by, created_at, self._origin, origin_sig_hex]
                    )
                ctx.execute("DROP TABLE punishments")
                ctx.execute("ALTER TABLE punishments_v3 RENAME TO punishments")
            else:
                ctx.execute("""
                CREATE TABLE IF NOT EXISTS punishments (
                    punishment_id   INTEGER NOT NULL,
                    origin          TEXT NOT NULL,
                    rollover        INTEGER NOT NULL DEFAULT 0,
                    punished_pubkey BLOB NOT NULL,
                    report_ids      TEXT NOT NULL,
                    expires_at      INTEGER NOT NULL,
                    ban_notes       TEXT,
                    issued_by       BLOB,
                    created_at      INTEGER NOT NULL,
                    relay           TEXT NOT NULL,
                    origin_sig      TEXT,
                    PRIMARY KEY (origin, punishment_id, rollover)
                )
                """)

            ctx.execute("CREATE INDEX IF NOT EXISTS idx_punishments_pubkey ON punishments(punished_pubkey)")
            ctx.execute("CREATE INDEX IF NOT EXISTS idx_punishments_origin ON punishments(origin)")
            ctx.execute("CREATE INDEX IF NOT EXISTS idx_punishments_created ON punishments(created_at)")

        self._rules_table = self._reports_db.add_table(
            'rules',
            'rule_num rule_name description',
            proto=Rule,
            id_cols=['rule_num']
        )

        self._reports_table = self._reports_db.add_table(
            'reports',
            'report_num origin rollover rule_num culprit_pubkey culprit_board culprit_post_num reporter_pubkey report_time relay description origin_sig reporter_sig',
            proto=Report,
            id_cols=['origin', 'report_num', 'rollover']
        )

        self._punishments_table = self._punishments_db.add_table(
            'punishments',
            'punishment_id origin rollover punished_pubkey report_ids expires_at ban_notes issued_by created_at relay origin_sig',
            proto=Punishment,
            id_cols=['origin', 'punishment_id', 'rollover']
        )

    def register_mutation_callback(self, callback) -> None:
        """Register a callback invoked after local report mutations.
        The callback receives no arguments; it should mark the
        report registry dirty."""
        self._mutation_callbacks.append(callback)

    def register_punishment_mutation_callback(self, callback) -> None:
        """Register a callback invoked after local punishment mutations.
        The callback receives no arguments; it should mark the
        punishment registry dirty."""
        self._punishment_callbacks.append(callback)

    def _notify_report_mutation(self) -> None:
        for cb in self._mutation_callbacks:
            try:
                cb()
            except Exception:
                pass

    def _notify_punishment_mutation(self) -> None:
        for cb in self._punishment_callbacks:
            try:
                cb()
            except Exception:
                pass

    def _rule_exists(self, rule_num) -> bool:
        with self._reports_db.open() as ctx:
            rule = self._rules_table.select_single(
                where="rule_num=?", values=[rule_num], ctx=ctx
            )
        return rule is not None

    def _get_rule_by_name(self, rule_name) -> Rule:
        with self._reports_db.open() as ctx:
            rule = self._rules_table.select_single(
                where="rule_name=?", values=[rule_name], ctx=ctx
            )
        return rule

    def _get_rule(self, rule_num) -> Rule:
        with self._reports_db.open() as ctx:
            rule = self._rules_table.select_single(
                where="rule_num=?", values=[rule_num], ctx=ctx
            )
        return rule

    def _list_rules(self) -> list:
        with self._reports_db.open() as ctx:
            rules = list(self._rules_table.select_iter(
                orderby="rule_num ASC", ctx=ctx
            ))
        return rules

    def _create_rule(self, rule_name, description) -> Rule:
        existing = self._get_rule_by_name(rule_name)
        if existing is not None:
            raise ValueError(f"Rule '{rule_name}' already exists")
        
        with self._reports_db.open() as ctx:
            rule_num_obj = ctx.insert_record(
                self._rules_table,
                (rule_name, description),
                columns=['rule_name', 'description']
            )
        
        rule_num = rule_num_obj
        return self._get_rule(rule_num)

    def _update_rule(self, rule_num, rule_name=None, description=None) -> Rule:
        existing = self._get_rule(rule_num)
        if existing is None:
            raise ValueError(f"Rule {rule_num} does not exist")
        
        if rule_name is not None:
            name_conflict = self._get_rule_by_name(rule_name)
            if name_conflict is not None and name_conflict.rule_num != rule_num:
                raise ValueError(f"Rule name '{rule_name}' already in use")
        
        final_name = rule_name if rule_name is not None else existing.rule_name
        final_desc = description if description is not None else existing.description
        
        with self._reports_db.open() as ctx:
            ctx.execute(
                "UPDATE rules SET rule_name=?, description=? WHERE rule_num=?",
                [final_name, final_desc, rule_num]
            )
        
        return self._get_rule(rule_num)

    def _build_signed_payload(self, report) -> bytes:
        culprit_board_bytes = (report.culprit_board or "").encode('utf-8')
        origin_bytes = report.origin.encode('utf-8')
        description_bytes = report.description.encode('utf-8')
        
        return (
            struct.pack(">Q", report.report_num) +
            struct.pack(">Q", report.rule_num) +
            struct.pack("B", len(report.culprit_pubkey)) + report.culprit_pubkey +
            struct.pack("B", len(culprit_board_bytes)) + culprit_board_bytes +
            struct.pack(">Q", report.culprit_post_num) +
            struct.pack("B", len(report.reporter_pubkey)) + report.reporter_pubkey +
            struct.pack(">q", report.report_time) +
            struct.pack("B", len(origin_bytes)) + origin_bytes +
            struct.pack("B", len(description_bytes)) + description_bytes
        )

    def _get_report(self, origin, report_num, rollover=0) -> Report:
        with self._reports_db.open() as ctx:
            report = self._reports_table.select_single(
                where="origin=? AND report_num=? AND rollover=?", values=[origin, report_num, rollover], ctx=ctx
            )
        return report

    def _list_reports_by_culprit(self, pubkey) -> list:
        with self._reports_db.open() as ctx:
            reports = list(self._reports_table.select_iter(
                where="culprit_pubkey=?", values=[pubkey], ctx=ctx
            ))
        return reports

    def _list_reports_since(self, since_timestamp) -> list:
        with self._reports_db.open() as ctx:
            reports = list(self._reports_table.select_iter(
                where="report_time >= ? AND origin = ?",
                values=[since_timestamp, self._origin],
                orderby="report_time ASC",
                ctx=ctx
            ))
        return reports

    def _upsert_remote_report(self, report_num, origin, rule_num,
                                      culprit_pubkey, culprit_board, culprit_post_num,
                                      reporter_pubkey, report_time, relay,
                                      description, origin_sig, reporter_sig, peer_pubkey_resolver) -> bool:
        inserted = False
        report = Report()
        report.report_num = report_num
        report.rule_num = rule_num
        report.culprit_pubkey = culprit_pubkey
        report.culprit_board = culprit_board
        report.culprit_post_num = culprit_post_num
        report.reporter_pubkey = reporter_pubkey
        report.report_time = report_time
        report.origin = origin
        report.relay = relay
        report.description = description

        payload = self._build_signed_payload(report)
        from core.crypto import Identity

        # Verify origin signature if provided
        if origin_sig and peer_pubkey_resolver:
            origin_pubkey = peer_pubkey_resolver(origin)
            if not origin_pubkey:
                return False
            try:
                if not Identity.verify(origin_pubkey, payload, bytes.fromhex(origin_sig)):
                    return False
            except ValueError:
                return False

        # Verify reporter signature if provided
        if reporter_sig:
            try:
                if not Identity.verify(reporter_pubkey, payload, bytes.fromhex(reporter_sig)):
                    return False
            except ValueError:
                return False

        max_rollover = -1
        duplicate = False

        with self._reports_db.open() as ctx:
            existings = list(self._reports_table.select_iter(
                where="origin=? AND report_num=?", values=[origin, report_num], ctx=ctx
            ))

            for ext in existings:
                if ext.rollover > max_rollover:
                    max_rollover = ext.rollover
                if ext.origin_sig == origin_sig and ext.reporter_sig == reporter_sig and ext.description == description:
                    duplicate = True
                    break

            if not duplicate:
                ctx.insert_record(
                    self._reports_table,
                    (report_num, origin, max_rollover + 1, rule_num, culprit_pubkey, culprit_board, culprit_post_num,
                     reporter_pubkey, report_time, relay, description, origin_sig, reporter_sig),
                    columns=['report_num', 'origin', 'rollover', 'rule_num', 'culprit_pubkey', 'culprit_board',
                             'culprit_post_num', 'reporter_pubkey', 'report_time', 'relay',
                             'description', 'origin_sig', 'reporter_sig']
                )
                inserted = True
        return inserted

    def _create_report(self, rule_num, culprit_pubkey, 
                               reporter_pubkey, description,
                               culprit_board=None, culprit_post_num=0,
                               origin=None, relay=None) -> Report:
        report_time = int(time.time())
        
        if not self._rule_exists(rule_num):
            raise ValueError(f"Rule {rule_num} does not exist")
        
        if origin is None:
            origin = self._origin
        if relay is None:
            relay = self._origin
        
        with self._reports_db.open() as ctx:
            max_num = ctx.execute("SELECT MAX(report_num) FROM reports WHERE origin=?", [origin]).fetchone()[0]
            if max_num is None:
                report_num = 1
            else:
                report_num = max_num + 1
            
            ctx.insert_record(
                self._reports_table,
                (report_num, origin, 0, rule_num, culprit_pubkey, culprit_board, culprit_post_num,
                 reporter_pubkey, report_time, relay, description, None, None),
                columns=['report_num', 'origin', 'rollover', 'rule_num', 'culprit_pubkey', 'culprit_board', 'culprit_post_num',
                         'reporter_pubkey', 'report_time', 'relay', 'description',
                         'origin_sig', 'reporter_sig']
            )
        
        report = self._get_report(origin, report_num)
        
        if self._signing_key is not None:
            signed_payload = self._build_signed_payload(report)
            signature = bytes(self._signing_key.sign(signed_payload).signature)
            origin_sig = signature.hex()
            
            with self._reports_db.open() as ctx:
                ctx.execute(
                    "UPDATE reports SET origin_sig=? WHERE origin=? AND report_num=?",
                    [origin_sig, origin, report_num]
                )
            
            report.origin_sig = origin_sig
        
        self._notify_report_mutation()
        return report

    def _sign_report(self, origin, report_num, signature) -> Report:
        """Add a reporter signature as a new rollover version (§9.3).

        Instead of mutating the existing report's reporter_sig in place,
        create a new rollover leaf with the reporter signature. The old
        version remains for audit history. This preserves the append-only
        registry invariant.
        """
        # Get the current max rollover for this (origin, report_num)
        with self._reports_db.open() as ctx:
            max_ro = ctx.execute(
                "SELECT MAX(rollover) FROM reports WHERE origin=? AND report_num=?",
                [origin, report_num],
            ).fetchone()[0]
            if max_ro is None:
                raise ValueError(f"Report {origin}:{report_num} does not exist")
            new_rollover = max_ro + 1

            # Fetch the current report (at max rollover) to copy its fields
            existing = self._reports_table.select_single(
                where="origin=? AND report_num=? AND rollover=?",
                values=[origin, report_num, max_ro],
                ctx=ctx,
            )
            if existing is None:
                raise ValueError(f"Report {origin}:{report_num} rollover {max_ro} not found")

            reporter_sig = signature.hex()

            # Insert a new rollover row with the reporter signature added
            ctx.insert_record(
                self._reports_table,
                (report_num, origin, new_rollover, existing.rule_num,
                 existing.culprit_pubkey, existing.culprit_board, existing.culprit_post_num,
                 existing.reporter_pubkey, existing.report_time, existing.relay,
                 existing.description, existing.origin_sig, reporter_sig),
                columns=['report_num', 'origin', 'rollover', 'rule_num',
                         'culprit_pubkey', 'culprit_board', 'culprit_post_num',
                         'reporter_pubkey', 'report_time', 'relay', 'description',
                         'origin_sig', 'reporter_sig'],
            )

        report = self._get_report(origin, report_num, new_rollover)
        self._notify_report_mutation()
        return report
        return report

    def _build_punishment_signed_payload(self, punishment_id, rollover, origin,
                                          punished_pubkey, report_ids, expires_at,
                                          ban_notes, issued_by, created_at) -> bytes:
        """Canonical signed payload for a punishment (§10.4).

        Includes: punishment_id, rollover, origin, punished_pubkey, ordered
        report ID list, expires_at, ban_notes, issued_by, created_at.
        Excludes relay (receiver-local) and origin_sig (the signature itself).
        """
        origin_b = origin.encode("utf-8")
        notes_b = (ban_notes or "").encode("utf-8")
        issued_by_b = issued_by or b''
        report_ids_json = json.dumps(report_ids)

        return (
            struct.pack(">Q", punishment_id)
            + struct.pack(">Q", rollover)
            + struct.pack(">H", len(origin_b)) + origin_b
            + struct.pack("B", len(punished_pubkey)) + punished_pubkey
            + struct.pack(">H", len(report_ids_json)) + report_ids_json.encode("utf-8")
            + struct.pack(">q", expires_at)
            + struct.pack(">H", len(notes_b)) + notes_b
            + struct.pack("B", len(issued_by_b)) + issued_by_b
            + struct.pack(">q", created_at)
        )

    def _get_punishment_by_id(self, punishment_id, origin=None, rollover=0) -> Punishment:
        with self._punishments_db.open() as ctx:
            if origin is not None:
                punishment = self._punishments_table.select_single(
                    where="origin=? AND punishment_id=? AND rollover=?",
                    values=[origin, punishment_id, rollover], ctx=ctx
                )
            else:
                # Fallback: return the first match by punishment_id (backward compat)
                rows = ctx.execute(
                    "SELECT punishment_id, origin, rollover, punished_pubkey, report_ids, "
                    "expires_at, ban_notes, issued_by, created_at, relay, origin_sig "
                    "FROM punishments WHERE punishment_id=? ORDER BY origin ASC, rollover ASC LIMIT 1",
                    [punishment_id]
                ).fetchone()
                if rows is None:
                    return None
                punishment = self._row_to_punishment(rows)
        if punishment is not None:
            if punishment.issued_by is None:
                punishment.issued_by = b''
            if punishment.created_at is None:
                punishment.created_at = 0
        return punishment

    @staticmethod
    def _row_to_punishment(row) -> Punishment:
        """Convert a raw DB row to a Punishment object."""
        p = Punishment()
        p.punishment_id = row[0]
        p.origin = row[1] if row[1] else ""
        p.rollover = row[2] if row[2] is not None else 0
        p.punished_pubkey = bytes(row[3]) if row[3] else b''
        p.report_ids = row[4] if row[4] else "[]"
        p.expires_at = row[5]
        p.ban_notes = row[6] if row[6] else ""
        p.issued_by = bytes(row[7]) if row[7] is not None else b''
        p.created_at = row[8] if row[8] is not None else 0
        p.relay = row[9] if row[9] else ""
        p.origin_sig = row[10]
        return p

    def _list_punishments_by_pubkey(self, pubkey) -> list:
        with self._punishments_db.open() as ctx:
            rows = ctx.execute(
                "SELECT punishment_id, origin, rollover, punished_pubkey, report_ids, "
                "expires_at, ban_notes, issued_by, created_at, relay, origin_sig "
                "FROM punishments WHERE punished_pubkey=? "
                "ORDER BY origin ASC, punishment_id ASC, rollover ASC",
                [pubkey]
            ).fetchall()
        return [self._row_to_punishment(row) for row in rows]

    def _in_window(self, creation_time: int, origin: str = None) -> bool:
        if self._record_in_window is None:
            return True
        # Use the row's origin for the temporal filter (§11.4)
        record_origin = origin if origin is not None else self._origin
        return self._record_in_window(record_origin, creation_time)

    def _get_latest_active_punishment(self, pubkey) -> Punishment:
        """Multi-origin effective evaluation (§11.4).

        Search active punishments across all origins, apply per-row temporal
        filter using each row's origin, and return the latest according to
        deterministic ordering: (created_at DESC, origin ASC, punishment_id DESC, rollover DESC).
        """
        now = int(time.time())
        with self._punishments_db.open() as ctx:
            rows = ctx.execute(
                "SELECT punishment_id, origin, rollover, punished_pubkey, report_ids, "
                "expires_at, ban_notes, issued_by, created_at, relay, origin_sig "
                "FROM punishments WHERE punished_pubkey=? AND (expires_at < 0 OR expires_at > ?) "
                "ORDER BY created_at DESC, origin ASC, punishment_id DESC, rollover DESC",
                [pubkey, now]
            ).fetchall()
        punishment = None
        for row in rows:
            p = self._row_to_punishment(row)
            if self._in_window(p.created_at, p.origin):
                punishment = p
                break
        return punishment

    def _create_punishment(self, pubkey, report_ids,
                                        expires_at, ban_notes="",
                                        issued_by=b'', sync_ume=True,
                                        origin=None) -> Punishment:
        """Create a local punishment with per-origin ID allocation (§10.3).

        IDs are allocated per origin: SELECT MAX(punishment_id) FROM punishments
        WHERE origin=?, then max+1. Origin signature is generated using the
        local signing key over the canonical payload (§10.4).
        """
        if origin is None:
            origin = self._origin
        report_ids_json = json.dumps(report_ids)
        created_at = int(time.time())
        relay = self._origin

        with self._punishments_db.open() as ctx:
            max_id = ctx.execute(
                "SELECT MAX(punishment_id) FROM punishments WHERE origin=?", [origin]
            ).fetchone()[0]
            if max_id is None:
                punishment_id = 1
            else:
                punishment_id = max_id + 1

            # Generate origin signature
            origin_sig_hex = None
            if self._signing_key is not None:
                payload = self._build_punishment_signed_payload(
                    punishment_id, 0, origin, pubkey,
                    report_ids, expires_at, ban_notes, issued_by, created_at,
                )
                sig = bytes(self._signing_key.sign(payload).signature)
                origin_sig_hex = sig.hex()

            ctx.insert_record(
                self._punishments_table,
                (punishment_id, origin, 0, pubkey, report_ids_json, expires_at,
                 ban_notes, issued_by, created_at, relay, origin_sig_hex),
                columns=['punishment_id', 'origin', 'rollover', 'punished_pubkey',
                         'report_ids', 'expires_at', 'ban_notes', 'issued_by',
                         'created_at', 'relay', 'origin_sig']
            )

        if sync_ume and self._ume is not None:
            is_active = (expires_at < 0) or (expires_at > int(time.time()))
            users = self._ume.get_all_by_publickey(pubkey)
            for user in users:
                self._ume.upd(username=user.username, new_banned=is_active)

        self._notify_punishment_mutation()
        return self._get_punishment_by_id(punishment_id, origin, 0)

    def _upsert_remote_punishment(self, punishment_id, origin, rollover,
                                   punished_pubkey, report_ids, expires_at,
                                   ban_notes, issued_by, created_at, relay,
                                   origin_sig, peer_pubkey_resolver) -> bool:
        """Import a remote punishment with conflict rollover (§10.6)."""
        # Verify origin signature
        if origin_sig and peer_pubkey_resolver:
            origin_pubkey = peer_pubkey_resolver(origin)
            if not origin_pubkey:
                return False
            try:
                payload = self._build_punishment_signed_payload(
                    punishment_id, rollover, origin, punished_pubkey,
                    report_ids, expires_at, ban_notes, issued_by, created_at,
                )
                from core.crypto import Identity
                if not Identity.verify(origin_pubkey, payload, bytes.fromhex(origin_sig)):
                    return False
            except (ValueError, Exception):
                return False

        report_ids_json = json.dumps(report_ids)
        issued_by_b = issued_by or b''

        with self._punishments_db.open() as ctx:
            # Check for exact duplicate (idempotent)
            existings = ctx.execute(
                "SELECT origin_sig, report_ids, ban_notes, expires_at, punished_pubkey, issued_by, created_at "
                "FROM punishments WHERE origin=? AND punishment_id=?",
                [origin, punishment_id]
            ).fetchall()

            max_rollover = -1
            duplicate = False
            for ext in existings:
                ext_ro = ctx.execute(
                    "SELECT rollover FROM punishments WHERE origin=? AND punishment_id=? AND origin_sig=? AND report_ids=? AND ban_notes=?",
                    [origin, punishment_id, ext[0], ext[1], ext[2]]
                ).fetchone()
                # Simpler: check all fields
                pass

            # Check for exact duplicate by comparing all fields
            all_existing = ctx.execute(
                "SELECT rollover, origin_sig, report_ids, ban_notes, expires_at, punished_pubkey, issued_by, created_at "
                "FROM punishments WHERE origin=? AND punishment_id=?",
                [origin, punishment_id]
            ).fetchall()

            for ext in all_existing:
                ext_ro = ext[0]
                if ext_ro > max_rollover:
                    max_rollover = ext_ro
                if (ext[1] == origin_sig and ext[2] == report_ids_json
                        and ext[3] == ban_notes and ext[4] == expires_at
                        and bytes(ext[5]) == punished_pubkey
                        and (bytes(ext[6]) if ext[6] else b'') == issued_by_b
                        and ext[7] == created_at):
                    duplicate = True
                    break

            if not duplicate:
                new_rollover = max_rollover + 1
                ctx.execute(
                    "INSERT INTO punishments (punishment_id, origin, rollover, punished_pubkey, "
                    "report_ids, expires_at, ban_notes, issued_by, created_at, relay, origin_sig) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [punishment_id, origin, new_rollover, punished_pubkey, report_ids_json,
                     expires_at, ban_notes, issued_by_b, created_at, relay, origin_sig]
                )
        return not duplicate

    def _is_banned(self, pubkey) -> tuple:
        punishment = self._get_latest_active_punishment(pubkey)
        if punishment is None:
            return (False, None)
        return (True, punishment.ban_notes if punishment.ban_notes else "No reason given")

    def _check_expiry(self, pubkey) -> bool:
        punishment = self._get_latest_active_punishment(pubkey)
        if punishment is None:
            return False
        if punishment.is_active():
            return False

        # The latest in-window row expired; only clear the UME ban flag when
        # no other active in-window punishment remains for this pubkey across
        # all origins (§11.4).
        now = int(time.time())
        with self._punishments_db.open() as ctx:
            rows = ctx.execute(
                "SELECT created_at, origin FROM punishments WHERE punished_pubkey=? AND (expires_at < 0 OR expires_at > ?)",
                [pubkey, now]
            ).fetchall()

        remaining_in_window = 0
        for row in rows:
            created_at = row[0] if row[0] is not None else 0
            origin = row[1] if row[1] else self._origin
            if self._in_window(created_at, origin):
                remaining_in_window += 1

        if remaining_in_window == 0 and self._ume is not None:
            users = self._ume.get_all_by_publickey(pubkey)
            for user in users:
                self._ume.upd(username=user.username, new_banned=False)

        return True

    def _list_active_punishments(self) -> list:
        """List active in-window punishments from all origins (§11.4)."""
        now = int(time.time())
        results = []
        with self._punishments_db.open() as ctx:
            rows = ctx.execute(
                "SELECT punishment_id, origin, rollover, punished_pubkey, report_ids, "
                "expires_at, ban_notes, issued_by, created_at, relay, origin_sig "
                "FROM punishments WHERE expires_at < 0 OR expires_at > ?",
                [now]
            ).fetchall()
        for row in rows:
            p = self._row_to_punishment(row)
            if not self._in_window(p.created_at, p.origin):
                continue
            results.append(p)
        return results

    def create_rule(self, rule_name: str, description: str):
        def task():
            return self._create_rule(rule_name, description)
        return AsyncResult(self._executor.submit(task))

    def get_rule(self, rule_num: int):
        def task():
            return self._get_rule(rule_num)
        return AsyncResult(self._executor.submit(task))

    def get_rule_by_name(self, rule_name: str):
        def task():
            return self._get_rule_by_name(rule_name)
        return AsyncResult(self._executor.submit(task))

    def list_rules(self):
        def task():
            return self._list_rules()
        return AsyncResult(self._executor.submit(task))

    def update_rule(self, rule_num: int, rule_name: str = None, description: str = None):
        def task():
            return self._update_rule(rule_num, rule_name, description)
        return AsyncResult(self._executor.submit(task))

    def get_report(self, origin: str, report_num: int, rollover: int = 0):
        def task():
            return self._get_report(origin, report_num, rollover)
        return AsyncResult(self._executor.submit(task))

    def list_reports_by_culprit(self, pubkey: bytes):
        def task():
            return self._list_reports_by_culprit(pubkey)
        return AsyncResult(self._executor.submit(task))

    def list_reports_since(self, since_timestamp: int):
        def task():
            return self._list_reports_since(since_timestamp)
        return AsyncResult(self._executor.submit(task))

    def upsert_remote_report(self, report_num: int, origin: str, rule_num: int,
                              culprit_pubkey: bytes, culprit_board: str, culprit_post_num: int,
                              reporter_pubkey: bytes, report_time: int, relay: str,
                              description: str, origin_sig: str, reporter_sig: str, peer_pubkey_resolver: object):
        def task():
            return self._upsert_remote_report(report_num, origin, rule_num, culprit_pubkey,
                                               culprit_board, culprit_post_num, reporter_pubkey,
                                               report_time, relay, description, origin_sig, reporter_sig, peer_pubkey_resolver)
        return AsyncResult(self._executor.submit(task))

    def create_report(self, rule_num: int, culprit_pubkey: bytes, reporter_pubkey: bytes,
                      description: str, culprit_board: str = None, culprit_post_num: int = 0,
                      origin: str = None, relay: str = None):
        def task():
            return self._create_report(rule_num, culprit_pubkey, reporter_pubkey, description,
                                       culprit_board, culprit_post_num, origin, relay)
        return AsyncResult(self._executor.submit(task))

    def sign_report(self, origin: str, report_num: int, signature: bytes):
        def task():
            return self._sign_report(origin, report_num, signature)
        return AsyncResult(self._executor.submit(task))

    def get_punishment(self, punishment_id: int, origin: str = None, rollover: int = 0):
        def task():
            return self._get_punishment_by_id(punishment_id, origin, rollover)
        return AsyncResult(self._executor.submit(task))

    def list_punishments_by_pubkey(self, pubkey: bytes):
        def task():
            return self._list_punishments_by_pubkey(pubkey)
        return AsyncResult(self._executor.submit(task))

    def create_punishment(self, pubkey: bytes, report_ids: list,
                          expires_at: int, ban_notes: str = "",
                          issued_by: bytes = b'', sync_ume: bool = True,
                          origin: str = None):
        def task():
            return self._create_punishment(pubkey, report_ids, expires_at, ban_notes, issued_by, sync_ume, origin)
        return AsyncResult(self._executor.submit(task))

    def upsert_remote_punishment(self, punishment_id: int, origin: str, rollover: int,
                                  punished_pubkey: bytes, report_ids: list, expires_at: int,
                                  ban_notes: str, issued_by: bytes, created_at: int,
                                  relay: str, origin_sig: str,
                                  origin_pubkey_resolver: object) -> bool:
        """Import a remote punishment with conflict rollover (§10.6).

        - Exact canonical duplicate: idempotent, skip.
        - Distinct valid origin-signed content: store under max(rollover)+1.
        - Invalid origin signature: reject.
        """
        def task():
            return self._upsert_remote_punishment(
                punishment_id, origin, rollover, punished_pubkey, report_ids,
                expires_at, ban_notes, issued_by, created_at, relay, origin_sig,
                origin_pubkey_resolver,
            )
        return AsyncResult(self._executor.submit(task))

    def is_banned(self, pubkey: bytes):
        def task():
            return self._is_banned(pubkey)
        return AsyncResult(self._executor.submit(task))

    def check_expiry(self, pubkey: bytes):
        def task():
            return self._check_expiry(pubkey)
        return AsyncResult(self._executor.submit(task))

    def list_active_punishments(self):
        def task():
            return self._list_active_punishments()
        return AsyncResult(self._executor.submit(task))

    def shutdown(self, wait=True) -> None:
        self._executor.shutdown(wait=wait)
