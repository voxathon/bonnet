import sqlite3
import threading
from pathlib import Path

from nacl.signing import SigningKey


class IdentityStore:
    DB_PATH = "./identities.db"

    def __init__(self, db_path: str | None = None):
        self.db_path = Path(db_path or self.DB_PATH)
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(str(self.db_path))
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self):
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS identities (
                username TEXT PRIMARY KEY,
                private_key BLOB NOT NULL,
                public_key BLOB NOT NULL,
                registered INTEGER DEFAULT 0
            )
        """)
        conn.commit()

    def get_or_create(self, username: str) -> tuple[bytes, bytes]:
        conn = self._get_conn()
        cur = conn.cursor()

        cur.execute(
            "SELECT private_key, public_key FROM identities WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()

        if row:
            return bytes(row["private_key"]), bytes(row["public_key"])

        signing_key = SigningKey.generate()
        private_key = bytes(signing_key)
        public_key = bytes(signing_key.verify_key)

        conn.execute(
            "INSERT INTO identities (username, private_key, public_key) VALUES (?, ?, ?)",
            (username, private_key, public_key),
        )
        conn.commit()

        return private_key, public_key

    def mark_registered(self, username: str):
        conn = self._get_conn()
        conn.execute(
            "UPDATE identities SET registered = 1 WHERE username = ?", (username,)
        )
        conn.commit()

    def is_registered(self, username: str) -> bool:
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT registered FROM identities WHERE username = ?", (username,))
        row = cur.fetchone()
        return bool(row and row["registered"])

    def get_pubkey(self, username: str) -> bytes | None:
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT public_key FROM identities WHERE username = ?", (username,))
        row = cur.fetchone()
        return bytes(row["public_key"]) if row else None

    def list_users(self) -> list[dict]:
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT username, public_key, registered FROM identities")
        return [
            {
                "username": row["username"],
                "public_key": bytes(row["public_key"]).hex(),
                "registered": bool(row["registered"]),
            }
            for row in cur.fetchall()
        ]

    def close(self):
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
