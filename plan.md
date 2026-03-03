# AME (Article Management Engine) Implementation Plan

## File Structure

```
src/
├── ame.pyx          # Main implementation
├── orm.pyx          # Existing (used internally)
└── ...
```

---

## Classes

### 1. `AsyncResult`
Wrapper for future-based async operations.

```cython
cdef class AsyncResult:
    cdef object _future        # concurrent.futures.Future
    cdef object _result
    cdef bint _done
    
    cpdef bint done(self)
    cpdef object result(self, timeout=None)    # blocking, returns result or raises
    cpdef object result_nowait(self)           # returns result or None if not done
    cpdef void cancel(self)
```

### 2. `Post`
Data class mapped from ORM.

```cython
cdef class Post:
    cdef public uint64_t post_num
    cdef public int last_modified
    cdef public int creation_date
    cdef public int last_bumped
    cdef public bint closed
    cdef public int sticky
    cdef public str tags
    cdef public str subject
    cdef public str options
    cdef public uint64_t root
    cdef public str author
    cdef public str signature
    cdef public str content      # loaded from file, not stored in DB
```

### 3. `Board`
Manages a single board's DB + article files.

```cython
cdef class Board:
    cdef str _base_path
    cdef str _name
    cdef str _db_path
    cdef str _articles_path
    cdef object _db             # orm.Database
    cdef object _table          # orm.Table
    cdef object _lock           # threading.Lock for file ops
    
    # Sync methods (called from worker thread)
    cdef Post _get_post(self, uint64_t post_num)
    cdef list _query_posts(self, ...)
    cdef uint64_t _create_post(self, ...)
    cdef bint _update_post(self, ...)
    cdef bint _delete_post(self, uint64_t post_num)
    cdef str _read_content(self, uint64_t post_num)
    cdef void _write_content(self, uint64_t post_num, str content)
    
    # Public async methods (return AsyncResult)
    cpdef AsyncResult get_post(self, uint64_t post_num)
    cpdef AsyncResult query(self, ...)
    cpdef AsyncResult create_post(self, ...)
    cpdef AsyncResult update_post(self, ...)
    cpdef AsyncResult delete_post(self, uint64_t post_num)
```

### 4. `Ame`
Main manager - thread pool + board routing.

```cython
cdef class Ame:
    cdef str _base_path
    cdef int _num_workers
    cdef object _executor      # ThreadPoolExecutor
    cdef dict _boards          # cached Board instances
    cdef object _boards_lock
    
    cpdef Board get_board(self, str name)
    cpdef Board create_board(self, str name)
    cpdef void close_board(self, str name)
    cpdef list list_boards(self)
    cpdef void shutdown(self, wait=True)
```

---

## Database Schema

```sql
CREATE TABLE posts (
    post_num      INTEGER PRIMARY KEY AUTOINCREMENT,
    last_modified INTEGER NOT NULL,
    creation_date INTEGER NOT NULL,
    last_bumped   INTEGER NOT NULL,
    closed        INTEGER DEFAULT 0,
    sticky        INTEGER DEFAULT 0,
    tags          TEXT,
    subject       TEXT,
    options       TEXT,
    root          INTEGER DEFAULT 0,
    author        TEXT,
    signature     TEXT
);

CREATE INDEX idx_posts_root ON posts(root);
CREATE INDEX idx_posts_last_bumped ON posts(last_bumped DESC);
CREATE INDEX idx_posts_sticky ON posts(sticky DESC);
```

---

## File Operations

| Path | Purpose |
|------|---------|
| `/{base_path}/{board}/metadata.db` | SQLite database |
| `/{base_path}/{board}/{post_num}` | Article content (raw text) |

---

## Key Methods

### `Board.create_post(...)`
1. Insert row into DB (auto-increment post_num)
2. Get `lastrowid` as post_num
3. Write content to `/{board}/{post_num}`
4. Return Post object

### `Board.get_post(post_num)`
1. Query DB for metadata
2. Read content from `/{board}/{post_num}`
3. Return Post or None

### `Board.query(where, orderby, limit, include_content)`
1. Query DB for matching posts
2. Optionally load content for each
3. Return list[Post]

### `Board.update_post(post_num, **fields)`
1. Update DB row
2. If `content` in fields, write to file
3. Return True/False

### `Board.delete_post(post_num)`
1. Delete from DB
2. Delete article file
3. Return True/False

---

## Dependencies

```py
from concurrent.futures import ThreadPoolExecutor, Future
import threading
import os
import time
from libc.stdint cimport uint64_t
from orm import Database, Table
```

---

## Makefile Update

Add `ame` to `MODULES`:
```makefile
MODULES := orm ame __init
```

---

## Design Decisions (from Q&A)

- **Async approach**: Thread pool with queue, returns `Future` objects
- **Post numbering**: Auto-increment per board (SQLite ROWID)
- **Base path**: Configurable via `Ame.__init__(base_path, num_workers)`
- **Article content**: Raw text files at `/{board}/{post_num}`
- **Not-found handling**: Return `None` (not exceptions)
- **Async results**: Custom `AsyncResult` wrapper for futures
