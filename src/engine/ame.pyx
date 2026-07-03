# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True

from concurrent.futures import ThreadPoolExecutor, Future
import threading
import os
import time
import re
import struct
import subprocess
import json
from libc.stdint cimport uint64_t, int64_t
from core.orm import Database, Table
from core.binutil import resolve_rg


class SearchUnavailable(Exception):
    """Raised when content search cannot run (e.g. rg binary missing)."""
    pass


class SearchTimedOut(Exception):
    """Raised when a content search exceeds its timeout."""
    pass


cdef str _sanitize_board_name(str name):
    name = "".join(c for c in name if c.isalnum() or c in "-_.")
    if not name:
        raise ValueError("Invalid board name")
    if name.startswith('.') or '..' in name:
        raise ValueError("Invalid board name")
    return name


cdef class NavDB:
    cdef str _nav_path
    cdef object _db
    cdef object _lock

    def __init__(self, str nav_db_path):
        cdef list columns
        self._nav_path = nav_db_path
        self._lock = threading.Lock()
        nav_dir = os.path.dirname(nav_db_path)
        if nav_dir:
            os.makedirs(nav_dir, exist_ok=True)
        self._db = Database(self._nav_path)
        with self._db.open() as ctx:
            ctx.execute("""
            CREATE TABLE IF NOT EXISTS nav (
                board_name TEXT PRIMARY KEY,
                board_path TEXT NOT NULL,
                origin TEXT NOT NULL,
                signature BLOB NOT NULL,
                relay TEXT NOT NULL,
                owner_pubkey BLOB,
                closed INTEGER DEFAULT 0
            )
            """)
            columns = [col[1] for col in ctx.execute("PRAGMA table_info(nav)").fetchall()]
            if "owner_pubkey" not in columns:
                ctx.execute("ALTER TABLE nav ADD COLUMN owner_pubkey BLOB")
            if "closed" not in columns:
                ctx.execute("ALTER TABLE nav ADD COLUMN closed INTEGER DEFAULT 0")

    cpdef dict get(self, str board_name):
        cdef list rows
        with self._db.open() as ctx:
            rows = ctx.execute("SELECT board_name, board_path, origin, signature, relay, owner_pubkey, closed FROM nav WHERE board_name=?", [board_name]).fetchall()
        if rows:
            row = rows[0]
            return {
                'board_name': row[0],
                'board_path': row[1],
                'origin': row[2],
                'signature': bytes(row[3]) if row[3] else b'',
                'relay': row[4],
                'owner_pubkey': bytes(row[5]) if row[5] else None,
                'closed': bool(row[6]) if row[6] else False
            }
        return None

    cpdef list list_all(self):
        cdef list rows
        cdef list result = []
        with self._db.open() as ctx:
            rows = ctx.execute("SELECT board_name, board_path, origin, signature, relay, owner_pubkey, closed FROM nav").fetchall()
        for row in rows:
            result.append({
                'board_name': row[0],
                'board_path': row[1],
                'origin': row[2],
                'signature': bytes(row[3]) if row[3] else b'',
                'relay': row[4],
                'owner_pubkey': bytes(row[5]) if row[5] else None,
                'closed': bool(row[6]) if row[6] else False
            })
        return result

    cpdef void create_local(self, str board_name, str origin, bytes signature, bytes owner_pubkey=None):
        cdef str board_path = board_name
        cdef str relay = origin
        with self._db.open() as ctx:
            ctx.execute(
                "INSERT OR REPLACE INTO nav (board_name, board_path, origin, signature, relay, owner_pubkey, closed) VALUES (?, ?, ?, ?, ?, ?, 0)",
                [board_name, board_path, origin, signature, relay, owner_pubkey]
            )

    cpdef void upsert_remote(self, str board_name, str board_path, str origin, bytes signature, str relay):
        with self._db.open() as ctx:
            ctx.execute(
                "INSERT OR REPLACE INTO nav (board_name, board_path, origin, signature, relay, owner_pubkey, closed) VALUES (?, ?, ?, ?, ?, NULL, 0)",
                [board_name, board_path, origin, signature, relay]
            )

    cpdef void upsert_remote_batch(self, list entries):
        """
        Batch upsert multiple nav entries in a single transaction.
        entries: list of tuples (board_name, board_path, origin, signature, relay, closed)
        """
        with self._db.open() as ctx:
            for entry in entries:
                if len(entry) == 6:
                    board_name, board_path, origin, signature, relay, closed = entry
                else:
                    board_name, board_path, origin, signature, relay = entry
                    closed = 0
                ctx.execute(
                    "INSERT OR REPLACE INTO nav (board_name, board_path, origin, signature, relay, owner_pubkey, closed) VALUES (?, ?, ?, ?, ?, NULL, ?)",
                    [board_name, board_path, origin, signature, relay, closed]
                )

    cpdef void delete_by_origin_batch(self, str origin, list board_names_to_keep):
        """
        Delete nav entries for origin where board_name NOT in keep list.
        Used for delta sync - removes boards deleted by their origin server.
        """
        if not board_names_to_keep:
            with self._db.open() as ctx:
                ctx.execute("DELETE FROM nav WHERE origin=?", [origin])
            return
        
        cdef str placeholders = ",".join("?" * len(board_names_to_keep))
        cdef str sql = f"DELETE FROM nav WHERE origin=? AND board_name NOT IN ({placeholders})"
        with self._db.open() as ctx:
            ctx.execute(sql, [origin] + board_names_to_keep)

    cpdef bytes get_owner(self, str board_name):
        cdef list rows
        with self._db.open() as ctx:
            rows = ctx.execute("SELECT owner_pubkey FROM nav WHERE board_name=?", [board_name]).fetchall()
        if rows and rows[0][0]:
            return bytes(rows[0][0])
        return None

    cpdef void delete(self, str board_name):
        with self._db.open() as ctx:
            ctx.execute("DELETE FROM nav WHERE board_name=?", [board_name])

    cpdef void _set_board_closed(self, str board_name):
        with self._db.open() as ctx:
            ctx.execute("UPDATE nav SET closed = 1 WHERE board_name = ?", [board_name])

    cpdef list list_peers(self, str local_origin=None):
        cdef list rows
        cdef list result = []
        with self._db.open() as ctx:
            if local_origin:
                rows = ctx.execute("SELECT DISTINCT relay FROM nav WHERE relay != ? AND relay != ''", [local_origin]).fetchall()
            else:
                rows = ctx.execute("SELECT DISTINCT relay FROM nav WHERE relay != ''").fetchall()
        for row in rows:
            if row[0]:
                result.append(row[0])
        return result


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


cdef class Post:
    cdef public uint64_t post_num
    cdef public int64_t last_modified
    cdef public int64_t creation_date
    cdef public int64_t last_bumped
    cdef public bint closed
    cdef public int sticky
    cdef public str tags
    cdef public str subject
    cdef public str options
    cdef public uint64_t root
    cdef public str author
    cdef public str author_registrar
    cdef public str signature
    cdef public str content

    def __init__(self):
        self.post_num = 0
        self.last_modified = 0
        self.creation_date = 0
        self.last_bumped = 0
        self.closed = False
        self.sticky = 0
        self.tags = ""
        self.subject = ""
        self.options = ""
        self.root = 0
        self.author = ""
        self.author_registrar = ""
        self.signature = ""
        self.content = ""

cdef class Board:
    cdef str _base_path
    cdef str _name
    cdef str _db_path
    cdef str _articles_path
    cdef object _db
    cdef object _table
    cdef object _lock
    cdef object _executor
    cdef bint _closed

    def __init__(self, str base_path, str name, object executor):
        # Prevent path traversal
        name = "".join(c for c in name if c.isalnum() or c in "-_")
        if not name:
            raise ValueError("Invalid board name")

        self._base_path = base_path
        self._name = name
        self._executor = executor

        board_path = os.path.join(base_path, name)
        os.makedirs(board_path, exist_ok=True)

        self._db_path = os.path.join(board_path, "metadata.db")
        self._articles_path = board_path
        self._lock = threading.Lock()
        self._closed = False

        self._db = Database(self._db_path)

        # Setup schema if needed
        with self._db.open() as ctx:
            ctx.execute("""
            CREATE TABLE IF NOT EXISTS posts (
                post_num        INTEGER PRIMARY KEY AUTOINCREMENT,
                last_modified   INTEGER NOT NULL,
                creation_date   INTEGER NOT NULL,
                last_bumped     INTEGER NOT NULL,
                closed          INTEGER DEFAULT 0,
                sticky          INTEGER DEFAULT 0,
                tags            TEXT,
                subject         TEXT,
                options         TEXT,
                root            INTEGER DEFAULT 0,
                author          TEXT,
                author_registrar TEXT,
                signature       TEXT
            )
            """)
            ctx.execute("CREATE INDEX IF NOT EXISTS idx_posts_root ON posts(root)")
            ctx.execute("CREATE INDEX IF NOT EXISTS idx_posts_last_bumped ON posts(last_bumped DESC)")
            ctx.execute("CREATE INDEX IF NOT EXISTS idx_posts_sticky ON posts(sticky DESC)")

        self._table = self._db.add_table(
            'posts',
            'post_num last_modified creation_date last_bumped closed sticky tags subject options root author author_registrar signature',
            proto=Post,
            id_cols=['post_num']
        )


    cpdef void close(self):
        self._closed = True

    cpdef bint is_closed(self):
        return self._closed

    cdef str _read_content(self, uint64_t post_num):
        cdef str file_path = os.path.join(self._articles_path, str(post_num))
        if os.path.exists(file_path):
            with self._lock:
                with open(file_path, "r", encoding="utf-8") as f:
                    return f.read()
        return ""

    cdef void _write_content(self, uint64_t post_num, str content):
        cdef str file_path = os.path.join(self._articles_path, str(post_num))
        with self._lock:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)

    cdef void _delete_content(self, uint64_t post_num):
        cdef str file_path = os.path.join(self._articles_path, str(post_num))
        with self._lock:
            if os.path.exists(file_path):
                os.remove(file_path)

    cdef Post _get_post(self, uint64_t post_num):
        cdef object post
        with self._db.open() as ctx:
            post = self._table.select_single(where="post_num=?", values=[post_num], ctx=ctx)
        if post is None:
            return None
        post.content = self._read_content(post_num)
        return post

    cdef list _query_posts(self, str where=None, list values=None, str orderby=None, limit=None, offset=None, bint include_content=False):
        cdef list final_posts
        cdef object posts
        with self._db.open() as ctx:
            posts = self._table.select(where=where, values=values, orderby=orderby, limit=limit, offset=offset, ctx=ctx)
        final_posts = list(posts)
        cdef Post p
        if include_content:
            for p in final_posts:
                p.content = self._read_content(p.post_num)
        return final_posts

    cdef uint64_t _create_post(self, int64_t last_modified, int64_t creation_date, int64_t last_bumped, bint closed, int sticky, str tags, str subject, str options, uint64_t root, str author, str author_registrar, str signature, str content):
        if self._closed:
            raise RuntimeError("Board is closed")
        cdef object post_num_obj
        cdef uint64_t post_num
        try:
            with self._db.open() as ctx:
                post_num_obj = ctx.insert_record(self._table, (
                    last_modified, creation_date, last_bumped, closed, sticky, tags, subject, options, root, author, author_registrar, signature
                ), columns=['last_modified', 'creation_date', 'last_bumped', 'closed', 'sticky', 'tags', 'subject', 'options', 'root', 'author', 'author_registrar', 'signature'])

            post_num = post_num_obj
            self._write_content(post_num, content)
            if root != 0:
                self._update_post(root, {'last_bumped': creation_date})
            return post_num
        except Exception as e:
            raise RuntimeError(f"Post creation failed: {e}")

    cdef bint _update_post(self, uint64_t post_num, dict fields):
        if self._closed:
            raise RuntimeError("Board is closed")
        cdef list set_exprs = []
        cdef list values = []
        cdef str k
        cdef object v
        cdef bint has_db_fields = False
        cdef str content = None
        cdef set allowed_fields = {
            'last_modified', 'creation_date', 'last_bumped', 'closed',
            'sticky', 'tags', 'subject', 'options', 'root', 'author', 'signature'
        }

        for k, v in fields.items():
            if k == 'content':
                content = v
            elif k in allowed_fields:
                set_exprs.append(f"{k}=?")
                values.append(v)
                has_db_fields = True
            else:
                raise ValueError(f"Invalid field name: {k}")

        if has_db_fields:
            values.append(post_num)
            with self._db.open() as ctx:
                ctx.update(self._table, set_expr=", ".join(set_exprs), where="post_num=?", values=values)

        if content is not None:
            self._write_content(post_num, content)

        return True

    cdef bint _delete_post(self, uint64_t post_num):
        with self._db.open() as ctx:
            ctx.delete_record(self._table, where="post_num=?", values=[post_num])
        self._delete_content(post_num)
        return True

    def get_post(self, uint64_t post_num):
        def task():
            return self._get_post(post_num)
        return AsyncResult(self._executor.submit(task))

    def query(self, str where=None, list values=None, str orderby=None, limit=None, offset=None, bint include_content=False):
        cdef set valid_columns = {
            'post_num', 'last_modified', 'creation_date', 'last_bumped',
            'closed', 'sticky', 'tags', 'subject', 'options', 'root', 'author', 'author_registrar', 'signature'
        }
        cdef set valid_directions = {'ASC', 'DESC'}
        cdef set like_allowed = {'subject', 'author'}

        if where:
            # Strictly validate where clause for parameterized queries.
            # Allow "column = ?" for any valid column, and "column LIKE ?" for
            # the substring-searchable text columns (subject, author) only.
            parts = re.split(r'\s+(?i:AND|OR)\s+', where.strip())
            for part in parts:
                part = part.strip()
                match = re.match(r"^([a-zA-Z0-9_]+)\s*=\s*\?$", part)
                if match:
                    if match.group(1) not in valid_columns:
                        raise ValueError(f"Invalid column in where clause: {match.group(1)}")
                    continue
                match = re.match(r"^([a-zA-Z0-9_]+)\s+LIKE\s+\?$", part, re.IGNORECASE)
                if match:
                    if match.group(1) not in like_allowed:
                        raise ValueError(f"LIKE not allowed for column: {match.group(1)}")
                    continue
                raise ValueError("Invalid where clause format")

        if orderby:
            # Validate orderby format: only allow "column" or "column ASC/DESC"
            parts = orderby.strip().split()
            if len(parts) == 0 or len(parts) > 2:
                raise ValueError("Invalid orderby format")
            if parts[0] not in valid_columns:
                raise ValueError(f"Invalid column in orderby: {parts[0]}")
            if len(parts) == 2 and parts[1].upper() not in valid_directions:
                raise ValueError(f"Invalid direction in orderby: {parts[1]}")

        if limit is not None:
            limit = int(limit)
            if limit < 0:
                raise ValueError("Limit must be non-negative")

        if offset is not None:
            offset = int(offset)
            if offset < 0:
                raise ValueError("Offset must be non-negative")

        def task():
            return self._query_posts(where, values, orderby, limit, offset, include_content)
        return AsyncResult(self._executor.submit(task))

    cdef list _hydrate_post_summaries(self, list post_nums):
        """Hydrate a list of post_nums into Post objects (no content) preserving order."""
        if not post_nums:
            return []
        cdef list result = []
        cdef dict by_num
        cdef list rows
        cdef str placeholders = ",".join("?" * len(post_nums))
        cdef str sql = f"SELECT post_num, last_modified, creation_date, last_bumped, closed, sticky, tags, subject, options, root, author, author_registrar, signature FROM posts WHERE post_num IN ({placeholders})"
        with self._db.open() as ctx:
            rows = ctx.execute(sql, post_nums).fetchall()
        by_num = {row[0]: row for row in rows}
        cdef object p
        cdef uint64_t num
        for num in post_nums:
            row = by_num.get(num)
            if row is None:
                continue
            p = Post()
            p.post_num = row[0]
            p.last_modified = row[1]
            p.creation_date = row[2]
            p.last_bumped = row[3]
            p.closed = bool(row[4]) if row[4] else False
            p.sticky = row[5] if row[5] else 0
            p.tags = row[6] if row[6] is not None else ""
            p.subject = row[7] if row[7] is not None else ""
            p.options = row[8] if row[8] is not None else ""
            p.root = row[9] if row[9] is not None else 0
            p.author = row[10] if row[10] is not None else ""
            p.author_registrar = row[11] if row[11] is not None else ""
            p.signature = row[12] if row[12] is not None else ""
            result.append(p)
        return result

    cdef list _content_search(self, str pattern, int max_count, int timeout_seconds, int result_limit):
        """Run ripgrep over this board's post-body files and return hydrated Posts.

        Post bodies are flat files named by post_num under self._articles_path.
        `rg --json` emits newline-delimited JSON; match objects carry the file
        path whose basename is the post_num. Results are deduped by post_num
        and capped at result_limit, then hydrated from the metadata table.
        """
        cdef str rg_path = resolve_rg()
        if rg_path is None:
            raise SearchUnavailable("ripgrep (rg) binary not found")

        cdef list argv = [rg_path, "--json", "--line-buffered", "--max-count", str(max_count), "--", pattern, self._articles_path]
        cdef bytes stdout_data
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout_seconds)
            stdout_data = proc.stdout
        except subprocess.TimeoutExpired:
            raise SearchTimedOut("content search timed out")

        # rg exits 1 when there are no matches (normal); exit 2 is a real error.
        if proc.returncode not in (0, 1):
            raise RuntimeError(f"rg failed with exit code {proc.returncode}: {proc.stderr.decode('utf-8', errors='replace')}")

        cdef set seen = set()
        cdef list ordered_nums = []
        cdef uint64_t post_num
        cdef str line
        cdef object obj
        cdef str basename
        for line in stdout_data.decode('utf-8', errors='replace').splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if obj.get("type") != "match":
                continue
            try:
                path_text = obj["data"]["path"]["text"]
            except (KeyError, TypeError):
                continue
            basename = os.path.basename(path_text)
            try:
                post_num = int(basename)
            except ValueError:
                continue
            if post_num in seen:
                continue
            seen.add(post_num)
            ordered_nums.append(post_num)
            if len(ordered_nums) >= result_limit:
                break

        return self._hydrate_post_summaries(ordered_nums)

    def content_search(self, str pattern, int max_count=1000, int timeout_seconds=10, int result_limit=100):
        if not pattern:
            raise ValueError("search pattern cannot be empty")
        if self._closed:
            raise RuntimeError("Board is closed")
        def task():
            return self._content_search(pattern, max_count, timeout_seconds, result_limit)
        return AsyncResult(self._executor.submit(task))

    def create_post(self, int64_t last_modified=0, int64_t creation_date=0, int64_t last_bumped=0, bint closed=False, int sticky=0, str tags="", str subject="", str options="", uint64_t root=0, str author="", str author_registrar="", str signature="", str content=""):
        if creation_date == 0:
            creation_date = int(time.time())
        if last_modified == 0:
            last_modified = creation_date
        if last_bumped == 0:
            last_bumped = creation_date

        def task():
            cdef uint64_t post_num = self._create_post(last_modified, creation_date, last_bumped, closed, sticky, tags, subject, options, root, author, author_registrar, signature, content)
            return self._get_post(post_num)
        return AsyncResult(self._executor.submit(task))

    def update_post(self, uint64_t post_num, dict fields):
        def task():
            return self._update_post(post_num, fields)
        return AsyncResult(self._executor.submit(task))

    def delete_post(self, uint64_t post_num):
        def task():
            return self._delete_post(post_num)
        return AsyncResult(self._executor.submit(task))


cdef class Ame:
    cdef str _base_path
    cdef int _num_workers
    cdef object _executor
    cdef dict _boards
    cdef object _boards_lock
    cdef object _nav
    cdef str _origin
    cdef object _signing_key

    def __init__(self, str base_path, str origin=None, object signing_key=None, int num_workers=4, str nav_db_path=None):
        self._base_path = base_path
        self._origin = origin or "localhost"
        self._signing_key = signing_key
        self._num_workers = num_workers
        self._executor = ThreadPoolExecutor(max_workers=num_workers)
        self._boards = {}
        self._boards_lock = threading.Lock()
        os.makedirs(base_path, exist_ok=True)
        if nav_db_path is None:
            nav_db_path = "/var/lib/bonnet/nav.db"
        self._nav = NavDB(nav_db_path)

        for name in os.listdir(base_path):
            if os.path.isdir(os.path.join(base_path, name)) and not name.startswith('.'):
                self._boards[name] = Board(self._base_path, name, self._executor)

    cpdef NavDB get_nav(self):
        return self._nav

    cpdef bytes get_board_owner(self, str board_name):
        return self._nav.get_owner(board_name)

    cdef bytes _sign_board(self, str board_name):
        if self._signing_key is None:
            return b'\x00' * 64
        name_bytes = board_name.encode('utf-8')
        origin_bytes = self._origin.encode('utf-8')
        payload = struct.pack('B', len(name_bytes)) + name_bytes + struct.pack('B', len(origin_bytes)) + origin_bytes
        return bytes(self._signing_key.sign(payload).signature)

    def get_board(self, str name):
        name = "".join([c for c in name if c.isalnum() or c in "-_"])
        with self._boards_lock:
            return self._boards.get(name)

    def create_board(self, str name, bytes owner_pubkey=None):
        name = "".join([c for c in name if c.isalnum() or c in "-_"])
        if not name:
            raise ValueError("Invalid board name")
        with self._boards_lock:
            if name not in self._boards:
                self._boards[name] = Board(self._base_path, name, self._executor)
                signature = self._sign_board(name)
                self._nav.create_local(name, self._origin, signature, owner_pubkey)
            return self._boards[name]

    def close_board(self, str name):
        name = "".join([c for c in name if c.isalnum() or c in "-_"])
        with self._boards_lock:
            if name in self._boards:
                self._boards[name].close()
                # we don't have access to _db in cython class from outside unless public, so call a NavDB method
                self._nav._set_board_closed(name)

    def delete_board(self, str name):
        import shutil
        name = "".join([c for c in name if c.isalnum() or c in "-_"])
        with self._boards_lock:
            if name not in self._boards:
                raise ValueError(f"Board '{name}' not found")
            board = self._boards[name]
            if not board.is_closed():
                raise RuntimeError("Board must be closed before deletion")
            board.close()
            del self._boards[name]
            board_path = os.path.join(self._base_path, name)
            if os.path.exists(board_path):
                shutil.rmtree(board_path)
            self._nav.delete(name)

    cpdef list list_boards(self):
        with self._boards_lock:
            return [(name, board.is_closed()) for name, board in self._boards.items()]

    cpdef list list_peers(self):
        return self._nav.list_peers(local_origin=self._origin)

    cpdef void shutdown(self, bint wait=True):
        self._executor.shutdown(wait=wait)
        with self._boards_lock:
            for board in self._boards.values():
                board.close()
            self._boards.clear()
