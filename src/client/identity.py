import sqlite3
import threading
import os
from pathlib import Path

import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib
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
                yescrypt_hash TEXT NOT NULL,
                auth_salt BLOB NOT NULL,
                key_salt BLOB NOT NULL,
                encrypted_private_key BLOB NOT NULL,
                public_key BLOB NOT NULL,
                registered INTEGER DEFAULT 0
            )
        """)
        conn.commit()

    def register(self, username: str, password: str) -> tuple[bytes, bytes]:
        conn = self._get_conn()
        cur = conn.cursor()

        cur.execute("SELECT username FROM identities WHERE username = ?", (username,))
        if cur.fetchone():
            raise ValueError("User already exists locally")

        # 1. Password storage for authentication
        auth_salt = os.urandom(16)
        # We'll use hashlib.scrypt which is a standard library strong KDF instead of passlib yescrypt
        # since yescrypt requires extra C bindings not available here.
        # We store the resulting hash as a hex string.
        yescrypt_hash = hashlib.scrypt(
            password.encode('utf-8'),
            salt=auth_salt,
            n=16384,
            r=8,
            p=1,
            maxmem=0
        ).hex()

        # 2. Keypair encryption
        key_salt = os.urandom(16)
        # bcrypt output is fixed to 60 chars string, but we want a 24-byte key for AES-192.
        # Let's derive the key using bcrypt.kdf, which is exactly for this purpose.
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            aes_key = bcrypt.kdf(
                password=password.encode('utf-8'),
                salt=key_salt,
                desired_key_bytes=24,
                rounds=16
            )

        signing_key = SigningKey.generate()
        private_key = bytes(signing_key)
        public_key = bytes(signing_key.verify_key)

        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        encrypted_private_key = nonce + aesgcm.encrypt(nonce, private_key, None)

        conn.execute(
            """INSERT INTO identities
               (username, yescrypt_hash, auth_salt, key_salt, encrypted_private_key, public_key)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (username, yescrypt_hash, auth_salt, key_salt, encrypted_private_key, public_key),
        )
        conn.commit()

        return private_key, public_key

    def get_private_key(self, username: str, password: str) -> bytes:
        if not self.verify_password(username, password):
            raise ValueError("Invalid password")

        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT key_salt, encrypted_private_key FROM identities WHERE username = ?",
            (username,)
        )
        row = cur.fetchone()
        if not row:
            raise ValueError("User not found")

        key_salt = bytes(row["key_salt"])
        encrypted = bytes(row["encrypted_private_key"])

        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            aes_key = bcrypt.kdf(
                password=password.encode('utf-8'),
                salt=key_salt,
                desired_key_bytes=24,
                rounds=16
            )

        aesgcm = AESGCM(aes_key)
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]

        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise ValueError("Failed to decrypt private key") from e

    def verify_password(self, username: str, password: str) -> bool:
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT yescrypt_hash, auth_salt FROM identities WHERE username = ?", (username,))
        row = cur.fetchone()
        if not row:
            return False

        expected_hash = row["yescrypt_hash"]
        auth_salt = bytes(row["auth_salt"])

        try:
            actual_hash = hashlib.scrypt(
                password.encode('utf-8'),
                salt=auth_salt,
                n=16384,
                r=8,
                p=1,
                maxmem=0
            ).hex()
            return actual_hash == expected_hash
        except ValueError:
            return False

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
