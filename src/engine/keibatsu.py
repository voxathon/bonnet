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
        self.punished_pubkey = b''
        self.report_ids = "[]"
        self.expires_at = 0
        self.ban_notes = ""

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
                 num_workers: int = 2):
        needs_migration = False
        self._reports_path = reports_path
        self._punishments_path = punishments_path
        self._ume = ume
        self._signing_key = signing_key
        self._origin = origin
        self._executor = ThreadPoolExecutor(max_workers=num_workers)
        self._lock = threading.Lock()

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

        with self._punishments_db.open() as ctx:
            ctx.execute("""
            CREATE TABLE IF NOT EXISTS punishments (
                punished_pubkey  BLOB PRIMARY KEY,
                report_ids       TEXT NOT NULL,
                expires_at       INTEGER NOT NULL,
                ban_notes        TEXT
            )
            """)

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
            'punished_pubkey report_ids expires_at ban_notes',
            proto=Punishment,
            id_cols=['punished_pubkey']
        )

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
        
        return report

    def _sign_report(self, origin, report_num, signature) -> Report:
        report = self._get_report(origin, report_num)
        if report is None:
            raise ValueError(f"Report {origin}:{report_num} does not exist")
        
        reporter_sig = signature.hex()
        
        with self._reports_db.open() as ctx:
            ctx.execute(
                "UPDATE reports SET reporter_sig=? WHERE origin=? AND report_num=?",
                [reporter_sig, origin, report_num]
            )
        
        report.reporter_sig = reporter_sig
        return report

    def _get_punishment(self, pubkey) -> Punishment:
        with self._punishments_db.open() as ctx:
            punishment = self._punishments_table.select_single(
                where="punished_pubkey=?", values=[pubkey], ctx=ctx
            )
        return punishment

    def _create_punishment(self, pubkey, report_ids,
                                        expires_at, ban_notes="",
                                        sync_ume=True) -> Punishment:
        report_ids_json = json.dumps(report_ids)

        with self._punishments_db.open() as ctx:
            ctx.execute(
                "INSERT OR REPLACE INTO punishments (punished_pubkey, report_ids, expires_at, ban_notes) VALUES (?, ?, ?, ?)",
                [pubkey, report_ids_json, expires_at, ban_notes]
            )

        if sync_ume and self._ume is not None:
            is_active = (expires_at < 0) or (expires_at > int(time.time()))
            users = self._ume.get_all_by_publickey(pubkey)
            for user in users:
                self._ume.upd(username=user.username, new_banned=is_active)

        return self._get_punishment(pubkey)

    def _is_banned(self, pubkey) -> tuple:
        punishment = self._get_punishment(pubkey)
        if punishment is None:
            return (False, None)
        if not punishment.is_active():
            return (False, None)
        return (True, punishment.ban_notes if punishment.ban_notes else "No reason given")

    def _check_expiry(self, pubkey) -> bool:
        punishment = self._get_punishment(pubkey)
        if punishment is None:
            return False
        if punishment.is_active():
            return False

        if punishment.expires_at > 0 and self._ume is not None:
            users = self._ume.get_all_by_publickey(pubkey)
            for user in users:
                self._ume.upd(username=user.username, new_banned=False)

        return True

    def _list_active_punishments(self) -> list:
        now = int(time.time())
        results = []
        with self._punishments_db.open() as ctx:
            rows = ctx.execute(
                "SELECT punished_pubkey, report_ids, expires_at, ban_notes FROM punishments WHERE expires_at < 0 OR expires_at > ?",
                [now]
            ).fetchall()
        for row in rows:
            p = Punishment()
            p.punished_pubkey = bytes(row[0])
            p.report_ids = row[1] if row[1] else "[]"
            p.expires_at = row[2]
            p.ban_notes = row[3] if row[3] else ""
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

    def get_punishment(self, pubkey: bytes):
        def task():
            return self._get_punishment(pubkey)
        return AsyncResult(self._executor.submit(task))

    def create_punishment(self, pubkey: bytes, report_ids: list,
                          expires_at: int, ban_notes: str = "",
                          sync_ume: bool = True):
        def task():
            return self._create_punishment(pubkey, report_ids, expires_at, ban_notes, sync_ume)
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
