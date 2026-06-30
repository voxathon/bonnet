# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True

"""
Keibatsu - Punishment and Report Management System
"""

import json
import os
import time
import threading
import struct
from concurrent.futures import ThreadPoolExecutor, Future
from libc.stdint cimport uint64_t, int64_t
from core.orm import Database, Table


cdef class AsyncResult:
    cdef object _future
    cdef object _result
    cdef bint _done

    def __init__(self, future):
        self._future = future
        self._result = None
        self._done = False

    cpdef bint done(self):
        if not self._done:
            self._done = self._future.done()
        return self._done

    cpdef object result(self, timeout=None):
        if not self._done:
            self._result = self._future.result(timeout=timeout)
            self._done = True
        return self._result

    cpdef object result_nowait(self):
        if self.done():
            return self.result()
        return None

    cpdef void cancel(self):
        self._future.cancel()


cdef class Rule:
    cdef public uint64_t rule_num
    cdef public str rule_name
    cdef public str description

    def __init__(self):
        self.rule_num = 0
        self.rule_name = ""
        self.description = ""


cdef class Report:
    cdef public uint64_t report_num
    cdef public uint64_t rule_num
    cdef public bytes culprit_pubkey
    cdef public str culprit_board
    cdef public uint64_t culprit_post_num
    cdef public bytes reporter_pubkey
    cdef public int64_t report_time
    cdef public str origin
    cdef public str relay
    cdef public str description
    cdef public str origin_sig
    cdef public str reporter_sig
    cdef public int rollover

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


cdef class Punishment:
    cdef public bytes punished_pubkey
    cdef public str report_ids
    cdef public int64_t expires_at
    cdef public str ban_notes

    def __init__(self):
        self.punished_pubkey = b''
        self.report_ids = "[]"
        self.expires_at = 0
        self.ban_notes = ""

    cpdef list get_report_ids(self):
        try:
            return json.loads(self.report_ids) if self.report_ids else []
        except Exception:
            return []

    cpdef void set_report_ids(self, list value):
        self.report_ids = json.dumps(value)

    cpdef bint is_warning(self):
        return self.expires_at == 0

    cpdef bint is_permanent(self):
        return self.expires_at < 0

    cpdef bint is_temporary(self):
        return self.expires_at > 0

    cpdef bint is_active(self):
        if self.expires_at == 0:
            return False
        if self.expires_at < 0:
            return True
        return self.expires_at > int(time.time())

    cpdef object time_remaining(self):
        if self.expires_at <= 0:
            return None
        cdef int64_t remaining = self.expires_at - int(time.time())
        if remaining <= 0:
            return 0
        return remaining


cdef class Keibatsu:
    cdef str _reports_path
    cdef str _punishments_path
    cdef object _reports_db
    cdef object _punishments_db
    cdef object _reports_table
    cdef object _punishments_table
    cdef object _rules_table
    cdef object _ume
    cdef object _executor
    cdef object _lock
    cdef object _signing_key
    cdef str _origin

    def __init__(self, str reports_path="/var/lib/bonnet/reports.db",
                 str punishments_path="/var/lib/bonnet/punishments.db",
                 object ume=None, object signing_key=None, str origin="localhost",
                 int num_workers=2):
        cdef bint needs_migration = False
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

    cdef bint _rule_exists(self, uint64_t rule_num):
        cdef Rule rule
        with self._reports_db.open() as ctx:
            rule = self._rules_table.select_single(
                where="rule_num=?", values=[rule_num], ctx=ctx
            )
        return rule is not None

    cdef Rule _get_rule_by_name(self, str rule_name):
        cdef Rule rule
        with self._reports_db.open() as ctx:
            rule = self._rules_table.select_single(
                where="rule_name=?", values=[rule_name], ctx=ctx
            )
        return rule

    cdef Rule _get_rule(self, uint64_t rule_num):
        cdef Rule rule
        with self._reports_db.open() as ctx:
            rule = self._rules_table.select_single(
                where="rule_num=?", values=[rule_num], ctx=ctx
            )
        return rule

    cdef list _list_rules(self):
        cdef list rules
        with self._reports_db.open() as ctx:
            rules = list(self._rules_table.select_iter(
                orderby="rule_num ASC", ctx=ctx
            ))
        return rules

    cdef Rule _create_rule(self, str rule_name, str description):
        cdef object rule_num_obj
        cdef uint64_t rule_num
        
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

    cdef Rule _update_rule(self, uint64_t rule_num, str rule_name=None, str description=None):
        cdef Rule existing = self._get_rule(rule_num)
        if existing is None:
            raise ValueError(f"Rule {rule_num} does not exist")
        
        if rule_name is not None:
            name_conflict = self._get_rule_by_name(rule_name)
            if name_conflict is not None and name_conflict.rule_num != rule_num:
                raise ValueError(f"Rule name '{rule_name}' already in use")
        
        cdef str final_name = rule_name if rule_name is not None else existing.rule_name
        cdef str final_desc = description if description is not None else existing.description
        
        with self._reports_db.open() as ctx:
            ctx.execute(
                "UPDATE rules SET rule_name=?, description=? WHERE rule_num=?",
                [final_name, final_desc, rule_num]
            )
        
        return self._get_rule(rule_num)

    cdef bytes _build_signed_payload(self, Report report):
        cdef bytes culprit_board_bytes = (report.culprit_board or "").encode('utf-8')
        cdef bytes origin_bytes = report.origin.encode('utf-8')
        cdef bytes description_bytes = report.description.encode('utf-8')
        
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

    cdef Report _get_report(self, str origin, uint64_t report_num, int rollover=0):
        cdef object report
        with self._reports_db.open() as ctx:
            report = self._reports_table.select_single(
                where="origin=? AND report_num=? AND rollover=?", values=[origin, report_num, rollover], ctx=ctx
            )
        return report

    cdef list _list_reports_by_culprit(self, bytes pubkey):
        cdef list reports
        with self._reports_db.open() as ctx:
            reports = list(self._reports_table.select_iter(
                where="culprit_pubkey=?", values=[pubkey], ctx=ctx
            ))
        return reports

    cdef list _list_reports_since(self, int64_t since_timestamp):
        cdef list reports
        with self._reports_db.open() as ctx:
            reports = list(self._reports_table.select_iter(
                where="report_time >= ? AND origin = ?",
                values=[since_timestamp, self._origin],
                orderby="report_time ASC",
                ctx=ctx
            ))
        return reports

    cdef bint _upsert_remote_report(self, uint64_t report_num, str origin, uint64_t rule_num,
                                      bytes culprit_pubkey, str culprit_board, uint64_t culprit_post_num,
                                      bytes reporter_pubkey, int64_t report_time, str relay,
                                      str description, str origin_sig, str reporter_sig, object peer_pubkey_resolver):
        cdef bint inserted = False
        cdef Report report = Report()
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

        cdef bytes payload = self._build_signed_payload(report)
        from core.crypto import Identity

        # Verify origin signature if provided
        cdef bytes origin_pubkey
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

        cdef list existings
        cdef Report ext
        cdef int max_rollover = -1
        cdef bint duplicate = False

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

    cdef Report _create_report(self, uint64_t rule_num, bytes culprit_pubkey, 
                               bytes reporter_pubkey, str description,
                               str culprit_board=None, uint64_t culprit_post_num=0,
                               str origin=None, str relay=None):
        cdef int64_t report_time = int(time.time())
        cdef object report_num_obj
        cdef uint64_t report_num
        cdef Report report
        cdef bytes signed_payload
        cdef bytes signature
        
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

    cdef Report _sign_report(self, str origin, uint64_t report_num, bytes signature):
        cdef Report report = self._get_report(origin, report_num)
        if report is None:
            raise ValueError(f"Report {origin}:{report_num} does not exist")
        
        cdef str reporter_sig = signature.hex()
        
        with self._reports_db.open() as ctx:
            ctx.execute(
                "UPDATE reports SET reporter_sig=? WHERE origin=? AND report_num=?",
                [reporter_sig, origin, report_num]
            )
        
        report.reporter_sig = reporter_sig
        return report

    cdef Punishment _get_punishment(self, bytes pubkey):
        cdef object punishment
        with self._punishments_db.open() as ctx:
            punishment = self._punishments_table.select_single(
                where="punished_pubkey=?", values=[pubkey], ctx=ctx
            )
        return punishment

    cdef Punishment _create_punishment(self, bytes pubkey, list report_ids,
                                        int64_t expires_at, str ban_notes="",
                                        bint sync_ume=True):
        cdef str report_ids_json = json.dumps(report_ids)
        cdef bint is_active
        cdef list users
        cdef str username

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

    cdef tuple _is_banned(self, bytes pubkey):
        cdef Punishment punishment = self._get_punishment(pubkey)
        if punishment is None:
            return (False, None)
        if not punishment.is_active():
            return (False, None)
        return (True, punishment.ban_notes if punishment.ban_notes else "No reason given")

    cdef bint _check_expiry(self, bytes pubkey):
        cdef Punishment punishment = self._get_punishment(pubkey)
        if punishment is None:
            return False
        if punishment.is_active():
            return False

        if punishment.expires_at > 0 and self._ume is not None:
            users = self._ume.get_all_by_publickey(pubkey)
            for user in users:
                self._ume.upd(username=user.username, new_banned=False)

        return True

    cdef list _list_active_punishments(self):
        cdef int64_t now = int(time.time())
        cdef list results = []
        cdef Punishment p
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

    def create_rule(self, str rule_name, str description):
        def task():
            return self._create_rule(rule_name, description)
        return AsyncResult(self._executor.submit(task))

    def get_rule(self, uint64_t rule_num):
        def task():
            return self._get_rule(rule_num)
        return AsyncResult(self._executor.submit(task))

    def get_rule_by_name(self, str rule_name):
        def task():
            return self._get_rule_by_name(rule_name)
        return AsyncResult(self._executor.submit(task))

    def list_rules(self):
        def task():
            return self._list_rules()
        return AsyncResult(self._executor.submit(task))

    def update_rule(self, uint64_t rule_num, str rule_name=None, str description=None):
        def task():
            return self._update_rule(rule_num, rule_name, description)
        return AsyncResult(self._executor.submit(task))

    def get_report(self, str origin, uint64_t report_num, int rollover=0):
        def task():
            return self._get_report(origin, report_num, rollover)
        return AsyncResult(self._executor.submit(task))

    def list_reports_by_culprit(self, bytes pubkey):
        def task():
            return self._list_reports_by_culprit(pubkey)
        return AsyncResult(self._executor.submit(task))

    def list_reports_since(self, int64_t since_timestamp):
        def task():
            return self._list_reports_since(since_timestamp)
        return AsyncResult(self._executor.submit(task))

    def upsert_remote_report(self, uint64_t report_num, str origin, uint64_t rule_num,
                              bytes culprit_pubkey, str culprit_board, uint64_t culprit_post_num,
                              bytes reporter_pubkey, int64_t report_time, str relay,
                              str description, str origin_sig, str reporter_sig, object peer_pubkey_resolver):
        def task():
            return self._upsert_remote_report(report_num, origin, rule_num, culprit_pubkey,
                                               culprit_board, culprit_post_num, reporter_pubkey,
                                               report_time, relay, description, origin_sig, reporter_sig, peer_pubkey_resolver)
        return AsyncResult(self._executor.submit(task))

    def create_report(self, uint64_t rule_num, bytes culprit_pubkey, bytes reporter_pubkey,
                      str description, str culprit_board=None, uint64_t culprit_post_num=0,
                      str origin=None, str relay=None):
        def task():
            return self._create_report(rule_num, culprit_pubkey, reporter_pubkey, description,
                                       culprit_board, culprit_post_num, origin, relay)
        return AsyncResult(self._executor.submit(task))

    def sign_report(self, str origin, uint64_t report_num, bytes signature):
        def task():
            return self._sign_report(origin, report_num, signature)
        return AsyncResult(self._executor.submit(task))

    def get_punishment(self, bytes pubkey):
        def task():
            return self._get_punishment(pubkey)
        return AsyncResult(self._executor.submit(task))

    def create_punishment(self, bytes pubkey, list report_ids,
                          int64_t expires_at, str ban_notes="",
                          bint sync_ume=True):
        def task():
            return self._create_punishment(pubkey, report_ids, expires_at, ban_notes, sync_ume)
        return AsyncResult(self._executor.submit(task))

    def is_banned(self, bytes pubkey):
        def task():
            return self._is_banned(pubkey)
        return AsyncResult(self._executor.submit(task))

    def check_expiry(self, bytes pubkey):
        def task():
            return self._check_expiry(pubkey)
        return AsyncResult(self._executor.submit(task))

    def list_active_punishments(self):
        def task():
            return self._list_active_punishments()
        return AsyncResult(self._executor.submit(task))

    cpdef void shutdown(self, bint wait=True):
        self._executor.shutdown(wait=wait)