"""Origins a tenant has joined, and which one is currently active.

Kept on disk rather than in the process: `connect` learns a URL and an origin
and `register` records which identity last spoke for it, so a restarted
gateway picks up where it left off instead of needing that handed back to it.
More than one origin can be remembered, which a single $BONNET_URL cannot
express.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from bonnet.gateway.paths import origins_db_path

_ACTIVE_ORIGIN = "active_origin"


class OriginStore:
    """Origins this tenant has joined, and which one is currently active.

    An origin here is a board server's identity (the model is
    origin -> boards -> articles) — not a board, the topic area inside one.
    """

    def __init__(self, db_path: str | None = None):
        self.db_path = Path(db_path or origins_db_path())
        parent = self.db_path.parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS origins (
                origin TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                verify_tls INTEGER NOT NULL,
                identity TEXT NOT NULL DEFAULT '',
                joined_at INTEGER NOT NULL,
                last_used INTEGER NOT NULL
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS client_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        self._conn.commit()

    def remember(
        self,
        origin: str,
        url: str,
        verify_tls: bool,
        identity: str,
        make_active: bool = True,
    ) -> None:
        """Record a joined origin, keeping its original joined_at on re-join.

        `identity` is the *last-active* local identity for this origin, not
        "the" identity — an origin can hold several (see IdentityStore, keyed
        by (origin, username)). It is only ever a default: what a tool call
        omitting `auth` resolves to when nothing more specific was given.
        """
        now = int(time.time())
        self._conn.execute(
            """INSERT INTO origins (origin, url, verify_tls, identity, joined_at, last_used)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(origin) DO UPDATE SET
                   url=excluded.url,
                   verify_tls=excluded.verify_tls,
                   identity=excluded.identity,
                   last_used=excluded.last_used""",
            (origin, url, int(verify_tls), identity, now, now),
        )
        if make_active:
            self._conn.execute(
                "INSERT OR REPLACE INTO client_state (key, value) VALUES (?, ?)",
                (_ACTIVE_ORIGIN, origin),
            )
        self._conn.commit()

    def get(self, origin: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM origins WHERE origin = ?", (origin,)).fetchone()
        return self._row_to_dict(row) if row else None

    def get_by_url(self, url: str) -> dict | None:
        """The joined origin last reached at exactly this URL, if any.

        Lets a $BONNET_URL-only startup (no explicit connect()) recover the
        origin's real self-asserted identifier — the key identities are
        actually stored under — instead of falling back to the URL string
        itself as a stand-in origin id. Most-recently-used wins if more than
        one origin was ever joined at the same URL (e.g. after the origin
        rotated its own identifier).
        """
        row = self._conn.execute(
            "SELECT * FROM origins WHERE url = ? ORDER BY last_used DESC LIMIT 1", (url,)
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def list_origins(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM origins ORDER BY last_used DESC").fetchall()
        return [self._row_to_dict(r) for r in rows]

    def active(self) -> dict | None:
        """The origin tool calls default to, or None if none is selected.

        A dangling pointer — an active origin that was later forgotten —
        reads as None rather than raising, so a half-cleaned store degrades
        to "no origin selected" instead of breaking every call.
        """
        row = self._conn.execute(
            "SELECT value FROM client_state WHERE key = ?", (_ACTIVE_ORIGIN,)
        ).fetchone()
        return self.get(row["value"]) if row else None

    def set_active(self, origin: str) -> None:
        if self.get(origin) is None:
            raise ValueError(f"No joined origin '{origin}'")
        self._conn.execute(
            "INSERT OR REPLACE INTO client_state (key, value) VALUES (?, ?)",
            (_ACTIVE_ORIGIN, origin),
        )
        self._conn.commit()

    def forget(self, origin: str) -> bool:
        """Drop an origin. Its pinned key is left alone — forgetting an
        origin is not a reason to stop recognising the key it presented."""
        cur = self._conn.execute("DELETE FROM origins WHERE origin = ?", (origin,))
        self._conn.commit()
        return cur.rowcount > 0

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        return {
            "origin": row["origin"],
            "url": row["url"],
            "verify_tls": bool(row["verify_tls"]),
            "identity": row["identity"],
            "joined_at": row["joined_at"],
            "last_used": row["last_used"],
        }

    def close(self) -> None:
        self._conn.close()
