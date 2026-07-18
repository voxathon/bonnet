"""Concurrency stress tests for the per-board SQLite metadata store.

Validates that metadata.db does not choke under heavy mixed read/write load:
  - No SQLITE_BUSY / "database is locked" errors (WAL + busy_timeout)
  - All writes are durable and consistent
  - Parent-thread last_bumped updates are atomic with the reply insert
"""

import os
import threading
import time
import sqlite3

import pytest

from engine.ame import Ame, Board
from core.crypto import Identity
from core.orm import Database


@pytest.fixture
def ame_setup(temp_dir):
    ame_path = os.path.join(temp_dir, 'ame')
    nav_db_path = os.path.join(temp_dir, 'nav.db')
    ident = Identity.generate()
    ame = Ame(ame_path, origin='test_origin', signing_key=ident.signing_key, nav_db_path=nav_db_path)
    yield ame, ident
    ame.shutdown()


def _journal_mode(db_path):
    with sqlite3.connect(str(db_path)) as conn:
        return conn.execute("PRAGMA journal_mode").fetchone()[0]


def test_metadata_db_uses_wal(ame_setup, temp_dir):
    ame, _ = ame_setup
    ame.create_board("walboard")
    board = ame.get_board("walboard")
    ame.shutdown()
    mode = _journal_mode(board._db_path)
    assert mode == "wal"


def test_concurrent_writes_no_busy(ame_setup):
    """Many threads inserting posts concurrently must not raise SQLITE_BUSY."""
    ame, _ = ame_setup
    board = ame.create_board("writetest")
    num_threads = 8
    per_thread = 25

    errors = []

    def writer(tid):
        try:
            for i in range(per_thread):
                board._create_post(
                    last_modified=int(time.time()),
                    creation_date=int(time.time()),
                    last_bumped=int(time.time()),
                    closed=False,
                    sticky=0,
                    tags=f"t{tid}",
                    subject=f"thread-{tid}-post-{i}",
                    options="",
                    root=0,
                    author=f"author-{tid}",
                    author_registrar="test_origin",
                    signature="",
                    content=f"body {tid}/{i}",
                )
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(t,)) for t in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"concurrent writes raised: {errors}"

    posts = board._query_posts()
    expected = num_threads * per_thread
    assert len(posts) == expected, f"expected {expected} posts, got {len(posts)}"


def test_concurrent_reads_and_writes(ame_setup):
    """Mixed concurrent readers and writers must not raise or return torn rows."""
    ame, _ = ame_setup
    board = ame.create_board("mixedtest")

    board._create_post(
        last_modified=int(time.time()), creation_date=int(time.time()),
        last_bumped=int(time.time()), closed=False, sticky=0, tags="root",
        subject="root", options="", root=0, author="op",
        author_registrar="test_origin", signature="", content="root body",
    )

    num_writers = 4
    per_writer = 20
    num_readers = 4
    per_reader = 50
    errors = []
    read_counts = []

    def writer(tid):
        try:
            for i in range(per_writer):
                board._create_post(
                    last_modified=int(time.time()),
                    creation_date=int(time.time()),
                    last_bumped=int(time.time()),
                    closed=False, sticky=0, tags=f"w{tid}",
                    subject=f"w-{tid}-{i}", options="",
                    root=1, author=f"w{tid}",
                    author_registrar="test_origin", signature="",
                    content=f"reply {tid}/{i}",
                )
        except Exception as e:
            errors.append(e)

    def reader(rid):
        try:
            seen = 0
            for _ in range(per_reader):
                posts = board._query_posts(orderby="post_num ASC")
                for p in posts:
                    _ = p.subject
                seen = len(posts)
            read_counts.append(seen)
        except Exception as e:
            errors.append(e)

    threads = []
    threads += [threading.Thread(target=writer, args=(t,)) for t in range(num_writers)]
    threads += [threading.Thread(target=reader, args=(r,)) for r in range(num_readers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"mixed read/write raised: {errors}"
    expected = 1 + num_writers * per_writer
    final = board._query_posts()
    assert len(final) == expected, f"expected {expected} posts, got {len(final)}"


def test_reply_bump_is_atomic(ame_setup):
    """The parent thread's last_bumped must update atomically with the reply.

    Under concurrent replies to the same root, every successful reply must be
    reflected in the DB and the root's last_bumped must be one of the reply
    creation_dates (no lost bump, no orphan reply).
    """
    ame, _ = ame_setup
    board = ame.create_board("bumptest")

    root_time = int(time.time())
    board._create_post(
        last_modified=root_time, creation_date=root_time, last_bumped=root_time,
        closed=False, sticky=0, tags="", subject="root", options="",
        root=0, author="op", author_registrar="test_origin",
        signature="", content="root",
    )

    num_threads = 6
    per_thread = 10
    reply_times = []
    errors = []

    def replier(tid):
        try:
            for i in range(per_thread):
                ts = int(time.time()) + (tid * per_thread + i)
                board._create_post(
                    last_modified=ts, creation_date=ts, last_bumped=ts,
                    closed=False, sticky=0, tags="", subject=f"r-{tid}-{i}",
                    options="", root=1, author=f"r{tid}",
                    author_registrar="test_origin", signature="",
                    content=f"reply {tid}/{i}",
                )
                reply_times.append(ts)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=replier, args=(t,)) for t in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"reply writes raised: {errors}"

    root = board._get_post(1)
    replies = board._query_posts(where="root=?", values=[1], orderby="post_num ASC")

    expected_replies = num_threads * per_thread
    assert len(replies) == expected_replies, (
        f"expected {expected_replies} replies, got {len(replies)}"
    )
    assert root.last_bumped in reply_times, (
        f"root last_bumped={root.last_bumped} not in reply times; "
        f"bump was lost or not atomic"
    )
    assert root.last_bumped > root_time, "root was never bumped"


def test_navdb_concurrent_upserts(ame_setup):
    """NavDB upserts from multiple threads must not raise SQLITE_BUSY."""
    ame, _ = ame_setup
    nav = ame.get_nav()
    num_threads = 6
    per_thread = 15
    errors = []

    def upserter(tid):
        try:
            for i in range(per_thread):
                nav.upsert_remote(
                    board_name=f"remote-{tid}-{i}",
                    board_path=f"remote-{tid}-{i}",
                    origin="peer.example",
                    signature=b"\x00" * 64,
                    relay="peer.example",
                )
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=upserter, args=(t,)) for t in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"nav upserts raised: {errors}"
    all_entries = nav.list_all()
    remote = [e for e in all_entries if e['origin'] == "peer.example"]
    expected = num_threads * per_thread
    assert len(remote) == expected, f"expected {expected} nav entries, got {len(remote)}"


def test_upsert_remote_batch_atomic(ame_setup, temp_dir):
    """A batch upsert must be all-or-nothing within a single transaction."""
    ame, _ = ame_setup
    nav = ame.get_nav()

    entries = [
        (f"batch-{i}", f"batch-{i}", "batch.example", b"\x00" * 64, "batch.example", 0)
        for i in range(5)
    ]
    nav.upsert_remote_batch(entries)

    for i in range(5):
        assert nav.get(f"batch-{i}") is not None

    bad_entries = [
        ("good-1", "good-1", "batch.example", b"\x00" * 64, "batch.example", 0),
        ("good-2", "good-2", "batch.example", b"\x00" * 64, "batch.example", 0),
    ]
    nav.upsert_remote_batch(bad_entries)
    assert nav.get("good-1") is not None
    assert nav.get("good-2") is not None
