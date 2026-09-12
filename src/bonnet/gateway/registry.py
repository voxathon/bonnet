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

"""Tenants and their API keys, for a gateway serving more than one caller.

Gateway-level, not per-tenant: a credential has to be resolved *before* it is
known which tenant's directory to open, so this cannot live inside one of them.

Key format is ``bnt_<key_id>_<secret>``. The `key_id` is stored and displayed;
the secret never is. That is what lets an operator look at a listing and tell
which key they are holding, and revoke it by name, without the gateway keeping
anything that could be replayed.

**Hashed with SHA-256, not bcrypt.** A key here is 256 bits of CSPRNG output,
not a low-entropy human password, so a slow KDF buys nothing against a brute
force that was never feasible — and it would cost a bcrypt round on every
request. SHA-256 also lets `key_hash` be the primary key, so resolution is one
indexed lookup rather than scanning every row and comparing each in turn.
bcrypt stays where it earns its cost: wrapping private keys in `IdentityStore`.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import sqlite3
import time
from pathlib import Path

from bonnet.gateway.paths import RESERVED_TENANTS, registry_db_path

#: A tenant id becomes a directory name, so it is validated rather than
#: trusted: without this, an id of "../../.." would place a tenant's stores
#: outside the gateway directory entirely.
_TENANT_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$")

KEY_PREFIX = "bnt"


class TenantError(ValueError):
    """A tenant or key operation that cannot be satisfied as asked."""


def validate_tenant_id(tenant_id: str) -> str:
    """Return `tenant_id` if it is usable as one, else raise.

    Rejects the reserved names as well as malformed ones: `default` is what
    stdio runs as and `anonymous` is the degraded fallback, so an operator
    registering either would silently take over a built-in.
    """
    if not _TENANT_ID.match(tenant_id or ""):
        raise TenantError(
            f"invalid tenant id {tenant_id!r}: use letters, digits, hyphen and "
            f"underscore, starting with a letter or digit, at most 63 characters"
        )
    if tenant_id in RESERVED_TENANTS:
        raise TenantError(
            f"tenant id {tenant_id!r} is reserved ({', '.join(sorted(RESERVED_TENANTS))})"
        )
    return tenant_id


def mint_key() -> tuple[str, str, str]:
    """Return (full_key, key_id, key_hash) for a freshly generated API key."""
    key_id = secrets.token_hex(4)
    secret = secrets.token_urlsafe(32)
    full = f"{KEY_PREFIX}_{key_id}_{secret}"
    return full, key_id, hash_key(full)


def hash_key(presented: str) -> str:
    return hashlib.sha256(presented.encode("utf-8")).hexdigest()


class Registry:
    """Tenants and their keys."""

    def __init__(self, db_path: str | None = None):
        self.db_path = Path(db_path or registry_db_path())
        parent = self.db_path.parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS tenants (
                tenant_id TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                note TEXT NOT NULL DEFAULT ''
            )
        """)
        # key_hash is the primary key so resolve() is one indexed lookup.
        # Keys live in their own table rather than a column on tenants so a
        # tenant can hold several at once: that is what makes rotation
        # possible without downtime, and lets one key per consumer scope a
        # leak to the consumer that leaked it.
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                key_hash TEXT PRIMARY KEY,
                key_id TEXT NOT NULL UNIQUE,
                tenant_id TEXT NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                revoked_at INTEGER
            )
        """)
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_keys_tenant ON api_keys(tenant_id)")
        # OIDC JIT bindings: one row per (issuer, subject), pointing at a
        # numeric t<N> tenant. The tenant holds API keys like any other, so
        # one account can use both paths. AUTOINCREMENT sequence never reuses
        # deleted numbers — a new stranger must not inherit audit history.
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS oauth_seq (
                id INTEGER PRIMARY KEY AUTOINCREMENT
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS oauth_bindings (
                oauth_iss TEXT NOT NULL,
                oauth_sub TEXT NOT NULL,
                tenant_id TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                PRIMARY KEY (oauth_iss, oauth_sub)
            )
        """)
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_oauth_tenant ON oauth_bindings(tenant_id)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_oauth_seen ON oauth_bindings(last_seen)"
        )
        self._conn.commit()

    # --- tenants ---------------------------------------------------------

    def add_tenant(self, tenant_id: str, note: str = "") -> None:
        validate_tenant_id(tenant_id)
        try:
            self._conn.execute(
                "INSERT INTO tenants (tenant_id, created_at, enabled, note) VALUES (?, ?, 1, ?)",
                (tenant_id, int(time.time()), note),
            )
        except sqlite3.IntegrityError as e:
            raise TenantError(f"tenant {tenant_id!r} already exists") from e
        self._conn.commit()

    def get_tenant(self, tenant_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_tenants(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM tenants ORDER BY created_at").fetchall()
        return [dict(r) for r in rows]

    def set_enabled(self, tenant_id: str, enabled: bool) -> None:
        cur = self._conn.execute(
            "UPDATE tenants SET enabled = ? WHERE tenant_id = ?",
            (int(enabled), tenant_id),
        )
        if cur.rowcount == 0:
            raise TenantError(f"no such tenant {tenant_id!r}")
        self._conn.commit()

    def remove_tenant(self, tenant_id: str) -> None:
        """Drop a tenant and every key it holds. Its directory is the
        caller's to remove — see `tenants.remove_tenant`."""
        cur = self._conn.execute("DELETE FROM tenants WHERE tenant_id = ?", (tenant_id,))
        if cur.rowcount == 0:
            raise TenantError(f"no such tenant {tenant_id!r}")
        self._conn.execute("DELETE FROM api_keys WHERE tenant_id = ?", (tenant_id,))
        self._conn.execute("DELETE FROM oauth_bindings WHERE tenant_id = ?", (tenant_id,))
        self._conn.commit()

    # --- oauth bindings ----------------------------------------------------

    def get_oauth_tenant(self, iss: str, sub: str) -> dict | None:
        """The enabled tenant bound to (iss, sub), or None.

        Disabled tenants do not resolve — disabling kills keys and OAuth
        together, or the kill switch would be a lie.
        """
        row = self._conn.execute(
            """SELECT b.tenant_id, b.created_at, b.last_seen, t.enabled FROM oauth_bindings b
               JOIN tenants t ON t.tenant_id = b.tenant_id
               WHERE b.oauth_iss = ? AND b.oauth_sub = ? AND t.enabled = 1""",
            (iss, sub),
        ).fetchone()
        return dict(row) if row else None

    def get_or_create_oauth_tenant(self, iss: str, sub: str) -> str:
        """Return the tenant for (iss, sub), JIT-minting t<N> on first sight.

        Idempotent: the same pair always returns the same tenant. Allocation
        is one transaction (sequence insert + tenant + binding), so concurrent
        first-logins serialize and the loser reads the winner's row.
        """
        if not iss or not sub:
            raise TenantError("oauth binding requires non-empty iss and sub")
        existing = self.get_oauth_tenant(iss, sub)
        if existing is not None:
            now = int(time.time())
            self._conn.execute(
                "UPDATE oauth_bindings SET last_seen = ? WHERE oauth_iss = ? AND oauth_sub = ?",
                (now, iss, sub),
            )
            self._conn.commit()
            return existing["tenant_id"]
        now = int(time.time())
        try:
            cur = self._conn.execute("INSERT INTO oauth_seq DEFAULT VALUES")
            seq = cur.lastrowid
            tenant_id = f"t{seq}"
            validate_tenant_id(tenant_id)
            self._conn.execute(
                "INSERT INTO tenants (tenant_id, created_at, enabled, note) VALUES (?, ?, 1, ?)",
                (tenant_id, now, f"oauth {iss}"),
            )
            self._conn.execute(
                """INSERT INTO oauth_bindings
                   (oauth_iss, oauth_sub, tenant_id, created_at, last_seen)
                   VALUES (?, ?, ?, ?, ?)""",
                (iss, sub, tenant_id, now, now),
            )
            self._conn.commit()
            return tenant_id
        except sqlite3.IntegrityError:
            self._conn.rollback()
            retry = self.get_oauth_tenant(iss, sub)
            if retry is not None:
                return retry["tenant_id"]
            raise

    def list_oauth_bindings(
        self, iss: str | None = None, since: int | None = None, inactive_before: int | None = None
    ) -> list[dict]:
        """Triage view for manual drops: filter by issuer, age, inactivity."""
        query = (
            "SELECT oauth_iss, oauth_sub, tenant_id, created_at, last_seen FROM oauth_bindings"
        )
        clauses: list[str] = []
        args: list[object] = []
        if iss is not None:
            clauses.append("oauth_iss = ?")
            args.append(iss)
        if since is not None:
            clauses.append("created_at >= ?")
            args.append(since)
        if inactive_before is not None:
            clauses.append("last_seen < ?")
            args.append(inactive_before)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at"
        rows = self._conn.execute(query, tuple(args)).fetchall()
        return [dict(r) for r in rows]

    # --- keys ------------------------------------------------------------

    def add_key(self, tenant_id: str, label: str = "") -> str:
        """Mint a key for `tenant_id` and return it. Shown once, never stored."""
        if self.get_tenant(tenant_id) is None:
            raise TenantError(f"no such tenant {tenant_id!r}")
        full, key_id, key_hash = mint_key()
        self._conn.execute(
            """INSERT INTO api_keys (key_hash, key_id, tenant_id, label, created_at, revoked_at)
               VALUES (?, ?, ?, ?, ?, NULL)""",
            (key_hash, key_id, tenant_id, label, int(time.time())),
        )
        self._conn.commit()
        return full

    def list_keys(self, tenant_id: str | None = None) -> list[dict]:
        if tenant_id is None:
            rows = self._conn.execute(
                "SELECT key_id, tenant_id, label, created_at, revoked_at FROM api_keys"
                " ORDER BY created_at"
            ).fetchall()
        else:
            if self.get_tenant(tenant_id) is None:
                raise TenantError(f"no such tenant {tenant_id!r}")
            rows = self._conn.execute(
                "SELECT key_id, tenant_id, label, created_at, revoked_at FROM api_keys"
                " WHERE tenant_id = ? ORDER BY created_at",
                (tenant_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def revoke_key(self, key_id: str) -> None:
        cur = self._conn.execute(
            "UPDATE api_keys SET revoked_at = ? WHERE key_id = ? AND revoked_at IS NULL",
            (int(time.time()), key_id),
        )
        if cur.rowcount == 0:
            raise TenantError(f"no live key with id {key_id!r}")
        self._conn.commit()

    # --- resolution ------------------------------------------------------

    def resolve(self, presented: str) -> str | None:
        """The tenant a presented key belongs to, or None.

        None covers every way a key can fail to name a usable tenant —
        unknown, revoked, or belonging to a disabled tenant. The caller does
        not get to tell those apart, and does not need to: all three degrade
        to the anonymous tenant, and distinguishing them for an unauthenticated
        caller would only help someone probing for valid key ids.
        """
        if not presented:
            return None
        row = self._conn.execute(
            """SELECT k.tenant_id FROM api_keys k
               JOIN tenants t ON t.tenant_id = k.tenant_id
               WHERE k.key_hash = ? AND k.revoked_at IS NULL AND t.enabled = 1""",
            (hash_key(presented),),
        ).fetchone()
        return row["tenant_id"] if row else None

    def close(self) -> None:
        self._conn.close()
