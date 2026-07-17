
from concurrent.futures import ThreadPoolExecutor, Future
import threading
import os
import time
import re
import struct
import subprocess
import json
from core.orm import Database, Table
from core.binutil import resolve_rg


class SearchUnavailable(Exception):
    """Raised when content search cannot run (e.g. rg binary missing)."""
    pass


class SearchTimedOut(Exception):
    """Raised when a content search exceeds its timeout."""
    pass


def _sanitize_board_name(name: str) -> str:
    name = "".join(c for c in name if c.isalnum() or c in "-_.")
    if not name:
        raise ValueError("Invalid board name")
    if name.startswith('.') or '..' in name:
        raise ValueError("Invalid board name")
    return name


class NavDB:

    def __init__(self, nav_db_path: str):
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

    def get(self, board_name: str) -> dict:
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

    def list_all(self) -> list:
        result = []
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

    def create_local(self, board_name: str, origin: str, signature: bytes, owner_pubkey: bytes = None) -> None:
        board_path = board_name
        relay = origin
        with self._db.open() as ctx:
            ctx.execute(
                "INSERT OR REPLACE INTO nav (board_name, board_path, origin, signature, relay, owner_pubkey, closed) VALUES (?, ?, ?, ?, ?, ?, 0)",
                [board_name, board_path, origin, signature, relay, owner_pubkey]
            )

    def upsert_remote(self, board_name: str, board_path: str, origin: str, signature: bytes, relay: str) -> None:
        with self._db.open() as ctx:
            ctx.execute(
                "INSERT OR REPLACE INTO nav (board_name, board_path, origin, signature, relay, owner_pubkey, closed) VALUES (?, ?, ?, ?, ?, NULL, 0)",
                [board_name, board_path, origin, signature, relay]
            )

    def upsert_remote_batch(self, entries: list) -> None:
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

    def delete_by_origin_batch(self, origin: str, board_names_to_keep: list) -> None:
        """
        Delete nav entries for origin where board_name NOT in keep list.
        Used for delta sync - removes boards deleted by their origin server.
        """
        if not board_names_to_keep:
            with self._db.open() as ctx:
                ctx.execute("DELETE FROM nav WHERE origin=?", [origin])
            return
        
        placeholders = ",".join("?" * len(board_names_to_keep))
        sql = f"DELETE FROM nav WHERE origin=? AND board_name NOT IN ({placeholders})"
        with self._db.open() as ctx:
            ctx.execute(sql, [origin] + board_names_to_keep)

    def get_owner(self, board_name: str) -> bytes:
        with self._db.open() as ctx:
            rows = ctx.execute("SELECT owner_pubkey FROM nav WHERE board_name=?", [board_name]).fetchall()
        if rows and rows[0][0]:
            return bytes(rows[0][0])
        return None

    def delete(self, board_name: str) -> None:
        with self._db.open() as ctx:
            ctx.execute("DELETE FROM nav WHERE board_name=?", [board_name])

    def _set_board_closed(self, board_name: str) -> None:
        with self._db.open() as ctx:
            ctx.execute("UPDATE nav SET closed = 1 WHERE board_name = ?", [board_name])

    def list_peers(self, local_origin: str = None) -> list:
        result = []
        with self._db.open() as ctx:
            if local_origin:
                rows = ctx.execute("SELECT DISTINCT relay FROM nav WHERE relay != ? AND relay != ''", [local_origin]).fetchall()
            else:
                rows = ctx.execute("SELECT DISTINCT relay FROM nav WHERE relay != ''").fetchall()
        for row in rows:
            if row[0]:
                result.append(row[0])
        return result


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


class Post:

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

class Board:

    def __init__(self, base_path: str, name: str, executor: object):
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


    def close(self) -> None:
        self._closed = True

    def is_closed(self) -> bool:
        return self._closed

    def _read_content(self, post_num: int) -> str:
        file_path = os.path.join(self._articles_path, str(post_num))
        if os.path.exists(file_path):
            with self._lock:
                with open(file_path, "r", encoding="utf-8") as f:
                    return f.read()
        return ""

    def _write_content(self, post_num: int, content: str) -> None:
        file_path = os.path.join(self._articles_path, str(post_num))
        with self._lock:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)

    def _delete_content(self, post_num: int) -> None:
        file_path = os.path.join(self._articles_path, str(post_num))
        with self._lock:
            if os.path.exists(file_path):
                os.remove(file_path)

    def _get_post(self, post_num: int) -> Post:
        with self._db.open() as ctx:
            post = self._table.select_single(where="post_num=?", values=[post_num], ctx=ctx)
        if post is None:
            return None
        post.content = self._read_content(post_num)
        return post

    def _query_posts(self, where: str = None, values: list = None, orderby: str = None, limit=None, offset=None, include_content: bool = False) -> list:
        with self._db.open() as ctx:
            posts = self._table.select(where=where, values=values, orderby=orderby, limit=limit, offset=offset, ctx=ctx)
        final_posts = list(posts)
        if include_content:
            for p in final_posts:
                p.content = self._read_content(p.post_num)
        return final_posts

    def _create_post(self, last_modified: int, creation_date: int, last_bumped: int, closed: bool, sticky: int, tags: str, subject: str, options: str, root: int, author: str, author_registrar: str, signature: str, content: str) -> int:
        if self._closed:
            raise RuntimeError("Board is closed")
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

    def _update_post(self, post_num: int, fields: dict) -> bool:
        if self._closed:
            raise RuntimeError("Board is closed")
        set_exprs = []
        values = []
        has_db_fields = False
        content = None
        allowed_fields = {
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

    def _delete_post(self, post_num: int) -> bool:
        with self._db.open() as ctx:
            ctx.delete_record(self._table, where="post_num=?", values=[post_num])
        self._delete_content(post_num)
        return True

    def get_post(self, post_num: int):
        def task():
            return self._get_post(post_num)
        return AsyncResult(self._executor.submit(task))

    def query(self, where: str = None, values: list = None, orderby: str = None, limit=None, offset=None, include_content: bool = False):
        valid_columns = {
            'post_num', 'last_modified', 'creation_date', 'last_bumped',
            'closed', 'sticky', 'tags', 'subject', 'options', 'root', 'author', 'author_registrar', 'signature'
        }
        valid_directions = {'ASC', 'DESC'}
        like_allowed = {'subject', 'author'}

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

    def _hydrate_post_summaries(self, post_nums: list) -> list:
        """Hydrate a list of post_nums into Post objects (no content) preserving order."""
        if not post_nums:
            return []
        result = []
        placeholders = ",".join("?" * len(post_nums))
        sql = f"SELECT post_num, last_modified, creation_date, last_bumped, closed, sticky, tags, subject, options, root, author, author_registrar, signature FROM posts WHERE post_num IN ({placeholders})"
        with self._db.open() as ctx:
            rows = ctx.execute(sql, post_nums).fetchall()
        by_num = {row[0]: row for row in rows}
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

    def _content_search(self, pattern: str, max_count: int, timeout_seconds: int, result_limit: int) -> list:
        """Run ripgrep over this board's post-body files and return hydrated Posts.

        Post bodies are flat files named by post_num under self._articles_path.
        `rg --json` emits newline-delimited JSON; match objects carry the file
        path whose basename is the post_num. Results are deduped by post_num
        and capped at result_limit, then hydrated from the metadata table.
        """
        rg_path = resolve_rg()
        if rg_path is None:
            raise SearchUnavailable("ripgrep (rg) binary not found")

        argv = [rg_path, "--json", "--line-buffered", "--max-count", str(max_count), "--", pattern, self._articles_path]
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout_seconds)
            stdout_data = proc.stdout
        except subprocess.TimeoutExpired:
            raise SearchTimedOut("content search timed out")

        # rg exits 1 when there are no matches (normal); exit 2 is a real error.
        if proc.returncode not in (0, 1):
            raise RuntimeError(f"rg failed with exit code {proc.returncode}: {proc.stderr.decode('utf-8', errors='replace')}")

        seen = set()
        ordered_nums = []
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

    def content_search(self, pattern: str, max_count: int = 1000, timeout_seconds: int = 10, result_limit: int = 100):
        if not pattern:
            raise ValueError("search pattern cannot be empty")
        if self._closed:
            raise RuntimeError("Board is closed")
        def task():
            return self._content_search(pattern, max_count, timeout_seconds, result_limit)
        return AsyncResult(self._executor.submit(task))

    def create_post(self, last_modified: int = 0, creation_date: int = 0, last_bumped: int = 0, closed: bool = False, sticky: int = 0, tags: str = "", subject: str = "", options: str = "", root: int = 0, author: str = "", author_registrar: str = "", signature: str = "", content: str = ""):
        if creation_date == 0:
            creation_date = int(time.time())
        if last_modified == 0:
            last_modified = creation_date
        if last_bumped == 0:
            last_bumped = creation_date

        def task():
            post_num = self._create_post(last_modified, creation_date, last_bumped, closed, sticky, tags, subject, options, root, author, author_registrar, signature, content)
            return self._get_post(post_num)
        return AsyncResult(self._executor.submit(task))

    def update_post(self, post_num: int, fields: dict):
        def task():
            return self._update_post(post_num, fields)
        return AsyncResult(self._executor.submit(task))

    def delete_post(self, post_num: int):
        def task():
            return self._delete_post(post_num)
        return AsyncResult(self._executor.submit(task))


class Ame:

    def __init__(self, base_path: str, origin: str = None, signing_key: object = None, num_workers: int = 4, nav_db_path: str = None):
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

    def get_nav(self) -> NavDB:
        return self._nav

    def get_board_owner(self, board_name: str) -> bytes:
        return self._nav.get_owner(board_name)

    def _sign_board(self, board_name: str) -> bytes:
        if self._signing_key is None:
            return b'\x00' * 64
        name_bytes = board_name.encode('utf-8')
        origin_bytes = self._origin.encode('utf-8')
        payload = struct.pack('B', len(name_bytes)) + name_bytes + struct.pack('B', len(origin_bytes)) + origin_bytes
        return bytes(self._signing_key.sign(payload).signature)

    def get_board(self, name: str):
        name = "".join([c for c in name if c.isalnum() or c in "-_"])
        with self._boards_lock:
            return self._boards.get(name)

    def create_board(self, name: str, owner_pubkey: bytes = None):
        name = "".join([c for c in name if c.isalnum() or c in "-_"])
        if not name:
            raise ValueError("Invalid board name")
        with self._boards_lock:
            if name not in self._boards:
                self._boards[name] = Board(self._base_path, name, self._executor)
                signature = self._sign_board(name)
                self._nav.create_local(name, self._origin, signature, owner_pubkey)
            return self._boards[name]

    def close_board(self, name: str):
        name = "".join([c for c in name if c.isalnum() or c in "-_"])
        with self._boards_lock:
            if name in self._boards:
                self._boards[name].close()
                # we don't have access to _db in cython class from outside unless public, so call a NavDB method
                self._nav._set_board_closed(name)

    def delete_board(self, name: str):
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

    def list_boards(self) -> list:
        with self._boards_lock:
            return [(name, board.is_closed()) for name, board in self._boards.items()]

    def list_peers(self) -> list:
        return self._nav.list_peers(local_origin=self._origin)

    def shutdown(self, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait)
        with self._boards_lock:
            for board in self._boards.values():
                board.close()
            self._boards.clear()
