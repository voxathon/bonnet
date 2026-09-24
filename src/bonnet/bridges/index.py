# Copyright 2026 The Bonnet Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""The bridge runtime's index (design doc §5.4).

A cache, never authoritative. The `mirrors` table and the cursors are
rebuilt from the bridge origin's own log by `rebuild()`; losing them costs a
re-read of the venue, and every re-read post is recognized by its digest
and skipped. `pending` (posts deferred on an unresolved marker) is the one
piece of runtime-private state: losing it only means those posts get
mirrored when the venue next serves them, or not at all if it evicted them.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import threading
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass

from bonnet.bridges.adapter import ForeignPost
from bonnet.bridges.model import ROLE_MIRROR, BridgeMetadata, SourceKey
from bonnet.core.firehose import FirehoseStore
from bonnet.core.kinds import KIND_ARTICLE
from bonnet.core.record import ZERO_ID

_SCHEMA = """
CREATE TABLE IF NOT EXISTS mirrors (
    board TEXT NOT NULL,
    venue TEXT NOT NULL,
    channel TEXT NOT NULL,
    foreign_id TEXT NOT NULL,
    event_id BLOB NOT NULL,
    article_id BLOB NOT NULL,
    root_article_id BLOB NOT NULL,
    root_foreign_id TEXT,
    digest BLOB NOT NULL,
    revision INTEGER NOT NULL,
    PRIMARY KEY (board, venue, channel, foreign_id)
);
CREATE TABLE IF NOT EXISTS cursors (
    board TEXT PRIMARY KEY,
    cursor TEXT
);
CREATE TABLE IF NOT EXISTS relayed (
    board TEXT NOT NULL,
    article_id BLOB NOT NULL,
    foreign_id TEXT,
    failures INTEGER NOT NULL DEFAULT 0,
    done INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (board, article_id)
);
CREATE TABLE IF NOT EXISTS relay_floor (
    board TEXT PRIMARY KEY,
    article_num INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pending (
    board TEXT NOT NULL,
    venue TEXT NOT NULL,
    channel TEXT NOT NULL,
    foreign_id TEXT NOT NULL,
    post TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    reason TEXT NOT NULL,
    PRIMARY KEY (board, venue, channel, foreign_id)
);
"""


@dataclass(frozen=True)
class MirrorEntry:
    """The latest mirror of one foreign post on one bridge board."""

    event_id: bytes
    article_id: bytes
    root_article_id: bytes
    root_foreign_id: str | None
    digest: bytes
    revision: int


@dataclass(frozen=True)
class PendingPost:
    post: ForeignPost
    first_seen: int
    reason: str


def post_to_json(post: ForeignPost) -> str:
    d = asdict(post)
    d["raw"] = base64.b64encode(post.raw).decode("ascii")
    return json.dumps(d, sort_keys=True)


def post_from_json(s: str) -> ForeignPost:
    d = json.loads(s)
    d["raw"] = base64.b64decode(d["raw"])
    return ForeignPost(**d)


class RuntimeIndex:
    def __init__(self, state_dir: str):
        os.makedirs(state_dir, exist_ok=True)
        self._conn = sqlite3.connect(os.path.join(state_dir, "index.db"), check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._lock = threading.Lock()

    def close(self) -> None:
        self._conn.close()

    # -- mirrors ---------------------------------------------------------

    def mirror(self, board: str, src: SourceKey) -> MirrorEntry | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT event_id, article_id, root_article_id, root_foreign_id, digest, revision "
                "FROM mirrors WHERE board=? AND venue=? AND channel=? AND foreign_id=?",
                (board, src.venue, src.channel, src.foreign_id),
            ).fetchone()
        if row is None:
            return None
        return MirrorEntry(
            bytes(row[0]), bytes(row[1]), bytes(row[2]), row[3], bytes(row[4]), row[5]
        )

    def put_mirror(self, board: str, src: SourceKey, entry: MirrorEntry) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO mirrors VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    board,
                    src.venue,
                    src.channel,
                    src.foreign_id,
                    entry.event_id,
                    entry.article_id,
                    entry.root_article_id,
                    entry.root_foreign_id,
                    entry.digest,
                    entry.revision,
                ),
            )
            self._conn.commit()

    def mirror_count(self, board: str) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM mirrors WHERE board=?", (board,)
            ).fetchone()[0]

    # -- cursors ---------------------------------------------------------

    def cursor(self, board: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT cursor FROM cursors WHERE board=?", (board,)
            ).fetchone()
        return row[0] if row else None

    def set_cursor(self, board: str, cursor: str | None) -> None:
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO cursors VALUES (?, ?)", (board, cursor))
            self._conn.commit()

    # -- pending ---------------------------------------------------------

    def pending(self, board: str) -> list[PendingPost]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT post, first_seen, reason FROM pending WHERE board=?", (board,)
            ).fetchall()
        return [PendingPost(post_from_json(r[0]), r[1], r[2]) for r in rows]

    def pending_first_seen(self, board: str, src: SourceKey) -> int | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT first_seen FROM pending WHERE board=? AND venue=? AND channel=? AND foreign_id=?",
                (board, src.venue, src.channel, src.foreign_id),
            ).fetchone()
        return row[0] if row else None

    def add_pending(self, board: str, post: ForeignPost, now: int, reason: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO pending VALUES (?,?,?,?,?,?,?)",
                (board, post.venue, post.channel, post.foreign_id, post_to_json(post), now, reason),
            )
            self._conn.commit()

    def drop_pending(self, board: str, src: SourceKey) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM pending WHERE board=? AND venue=? AND channel=? AND foreign_id=?",
                (board, src.venue, src.channel, src.foreign_id),
            )
            self._conn.commit()

    # -- relay egress (§11.3) ------------------------------------------------

    def relay_floor(self, board: str) -> int | None:
        """Articles numbered at or below this predate relay egress: never relayed."""
        with self._lock:
            row = self._conn.execute(
                "SELECT article_num FROM relay_floor WHERE board=?", (board,)
            ).fetchone()
        return row[0] if row else None

    def set_relay_floor(self, board: str, article_num: int) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO relay_floor VALUES (?, ?)", (board, article_num)
            )
            self._conn.commit()

    def relay_state(self, board: str, article_id: bytes) -> tuple[int, bool] | None:
        """(failures, done) for one native article, or None if never tried."""
        with self._lock:
            row = self._conn.execute(
                "SELECT failures, done FROM relayed WHERE board=? AND article_id=?",
                (board, article_id),
            ).fetchone()
        return (row[0], bool(row[1])) if row else None

    def relay_failed(self, board: str, article_id: bytes) -> int:
        with self._lock:
            self._conn.execute(
                "INSERT INTO relayed (board, article_id, failures) VALUES (?, ?, 1) "
                "ON CONFLICT(board, article_id) DO UPDATE SET failures = failures + 1",
                (board, article_id),
            )
            self._conn.commit()
            return self._conn.execute(
                "SELECT failures FROM relayed WHERE board=? AND article_id=?", (board, article_id)
            ).fetchone()[0]

    def relay_done(self, board: str, article_id: bytes, foreign_id: str | None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO relayed (board, article_id, foreign_id, done) VALUES (?, ?, ?, 1) "
                "ON CONFLICT(board, article_id) DO UPDATE SET foreign_id=excluded.foreign_id, done=1",
                (board, article_id, foreign_id),
            )
            self._conn.commit()

    # -- rebuild ---------------------------------------------------------

    def rebuild(
        self,
        firehose: FirehoseStore,
        origin: str,
        boards: set[str],
        cursor_from_ids: Mapping[str, Callable[[list[str]], str | None]],
        batch: int = 1000,
    ) -> int:
        """Rebuild `mirrors` and the cursors from `origin`'s log.

        `cursor_from_ids` maps each board to its adapter's cursor function.
        Returns the number of mirror records read.
        """
        with self._lock:
            self._conn.execute("DELETE FROM mirrors")
            self._conn.execute("DELETE FROM cursors")
            self._conn.commit()
        ids: dict[str, list[str]] = {b: [] for b in boards}
        count = 0
        seq = 0
        while True:
            records = firehose.get_events_range(origin, seq + 1, batch)
            if not records:
                break
            for rec in records:
                seq = rec.origin_seq
                if rec.kind != KIND_ARTICLE or rec.board not in boards:
                    continue
                meta = BridgeMetadata.from_metadata(rec.metadata)
                src = meta.src
                if meta.bridge_role != ROLE_MIRROR or src is None:
                    continue
                count += 1
                revision = meta.mirror_revision or 0
                current = self.mirror(rec.board, src)
                if current is not None and current.revision > revision:
                    continue
                root = rec.metadata.get_bytes(5)
                self.put_mirror(
                    rec.board,
                    src,
                    MirrorEntry(
                        event_id=rec.event_id,
                        article_id=rec.article_id,
                        root_article_id=root if root and root != ZERO_ID else rec.article_id,
                        root_foreign_id=meta.foreign_root_id,
                        digest=meta.foreign_digest or b"",
                        revision=revision,
                    ),
                )
                ids[rec.board].append(src.foreign_id)
        for board, board_ids in ids.items():
            fn = cursor_from_ids.get(board)
            cursor = fn(board_ids) if fn else None
            if cursor is not None:
                self.set_cursor(board, cursor)
        return count
