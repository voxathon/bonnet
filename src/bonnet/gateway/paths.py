"""Durable client-side state: where the bridge remembers things.

Distinct from configuration. Configuration is what an operator or an agent
host supplies (environment variables, command-line flags); this is what the
client itself learns and must not forget between processes:

- **Pinned origin keys.** TOFU is meaningless without persistence — if the
  pin dies with the process, every connection is a first contact and there is
  nothing to detect a substituted key against. The trust store lives here.
- **Origins that have been joined.** `connect` learns a URL and an origin;
  `register` records which identity last spoke for it. Kept here, a
  restarted bridge picks up where it left off instead of needing that handed
  back to it; and more than one origin can be remembered, which a single
  BONNET_URL cannot express.

Everything here sits beside the identity store in the per-user data directory,
for the reason IdentityStore.default_db_path already gives: the bridge is
launched by an agent host that chooses its own working directory, so anything
CWD-relative silently becomes a fresh empty store on the next launch.

BONNET_GATEWAY_DIR relocates all of it. BONNET_IDENTITIES_DB still overrides
the identity store's path on its own, since it predates this module.
"""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path

import platformdirs

_ACTIVE_ORIGIN = "active_origin"


def gateway_dir() -> str:
    """Directory holding this client's durable state."""
    return os.environ.get("BONNET_GATEWAY_DIR") or platformdirs.user_data_dir(
        "bonnet", appauthor=False
    )


def trust_db_path() -> str:
    """Where origin-key pins are persisted."""
    return os.path.join(gateway_dir(), "trust.db")


def origins_db_path() -> str:
    """Where joined origins are recorded."""
    return os.path.join(gateway_dir(), "origins.db")


class OriginStore:
    """Origins this client has joined, and which one is currently active.

    An origin here is the board server's identity (the codebase model is
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
