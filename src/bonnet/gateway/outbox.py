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

"""The edge-egress outbox: signed frames waiting to reach a bridge origin (design doc §11.2).

A crosspost goes to the venue first and to the bridge origin second, and
either leg can fail after the other succeeded. Every frame is stored before
it's sent, so a retry sends exactly the bytes that were signed.

States:
  pending  signed without the venue's foreign_id; the venue post may or may
           not have happened (the crash window of §11.2 step 5)
  ready    re-signed with the foreign_id, waiting to be published on B
  sent     B accepted it
  refused  B refused it (admission, ban); the venue post stays unmatched
  dropped  a pending frame on a venue without idempotent posting: re-posting
           could duplicate, so it's given up and reported
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from dataclasses import dataclass

_SCHEMA = """
CREATE TABLE IF NOT EXISTS outbox (
    event_id BLOB PRIMARY KEY,
    bridge_origin TEXT NOT NULL,
    bridge_url TEXT NOT NULL,
    board TEXT NOT NULL,
    venue TEXT NOT NULL,
    channel TEXT NOT NULL,
    venue_text TEXT NOT NULL,
    reply_to TEXT,
    frame BLOB NOT NULL,
    state TEXT NOT NULL,
    detail TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
"""


@dataclass(frozen=True)
class OutboxEntry:
    event_id: bytes
    bridge_origin: str
    bridge_url: str
    board: str
    venue: str
    channel: str
    venue_text: str
    reply_to: str | None
    frame: bytes
    state: str
    detail: str | None


_COLS = (
    "event_id, bridge_origin, bridge_url, board, venue, channel, venue_text, reply_to, "
    "frame, state, detail"
)


def _entry(row) -> OutboxEntry:
    return OutboxEntry(
        event_id=bytes(row[0]),
        bridge_origin=row[1],
        bridge_url=row[2],
        board=row[3],
        venue=row[4],
        channel=row[5],
        venue_text=row[6],
        reply_to=row[7],
        frame=bytes(row[8]),
        state=row[9],
        detail=row[10],
    )


class Outbox:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._lock = threading.Lock()

    def close(self) -> None:
        self._conn.close()

    def put(self, entry: OutboxEntry) -> None:
        now = int(time.time())
        with self._lock:
            self._conn.execute(
                f"INSERT OR REPLACE INTO outbox ({_COLS}, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?, COALESCE((SELECT created_at FROM outbox "
                "WHERE event_id=?), ?), ?)",
                (
                    entry.event_id,
                    entry.bridge_origin,
                    entry.bridge_url,
                    entry.board,
                    entry.venue,
                    entry.channel,
                    entry.venue_text,
                    entry.reply_to,
                    entry.frame,
                    entry.state,
                    entry.detail,
                    entry.event_id,
                    now,
                    now,
                ),
            )
            self._conn.commit()

    def set_state(self, event_id: bytes, state: str, detail: str | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE outbox SET state=?, detail=?, updated_at=? WHERE event_id=?",
                (state, detail, int(time.time()), event_id),
            )
            self._conn.commit()

    def get(self, event_id: bytes) -> OutboxEntry | None:
        with self._lock:
            row = self._conn.execute(
                f"SELECT {_COLS} FROM outbox WHERE event_id=?", (event_id,)
            ).fetchone()
        return _entry(row) if row else None

    def by_state(self, *states: str) -> list[OutboxEntry]:
        marks = ",".join("?" * len(states))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {_COLS} FROM outbox WHERE state IN ({marks}) ORDER BY created_at",
                states,
            ).fetchall()
        return [_entry(r) for r in rows]
