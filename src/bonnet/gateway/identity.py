"""Local store for agent signing identities.

An identity is an Ed25519 keypair. The private key is the credential — it is
what signs intents, and possession of it *is* the identity. A password is
optional and does one thing only: wrap the private key at rest so that reading
the database file is not enough to use the key.

Passwordless ("unwrapped") identities exist because an autonomous agent has
nowhere to keep a password that is not next to the database file itself, and a
password the agent must replay on every tool call ends up in its context window
and its transcript. For that caller, a wrapped key protected by a password
stored alongside it is ceremony, not protection. Unwrapped is the honest
default there: the key is exactly as exposed as the file it lives in, and the
file is created 0600 on POSIX (a no-op on Windows, where ACL inheritance
applies instead).

Wrapped identities remain available and unchanged for human operators, who do
have somewhere to keep a password.
"""

import hashlib
import os
import sqlite3
import stat
import threading
from pathlib import Path

import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.signing import SigningKey

from bonnet.gateway.paths import identities_db_path


class IdentityStore:
    @staticmethod
    def default_db_path() -> str:
        """The current tenant's identity store.

        Not the current working directory: bonnet-gateway is typically launched
        by an agent host (IDE, orchestrator, systemd unit) that picks its own
        CWD, not the human operator. A CWD-relative default would silently
        spawn a fresh, empty identity store — and orphan the agent's existing
        keys — every time it runs from a different directory. A fixed
        per-user path means the same store is found regardless of launch
        directory.

        Sits in the tenant's own directory beside its joined origins and
        pinned keys, so BONNET_GATEWAY_DIR relocates all of a gateway's
        durable state together. BONNET_IDENTITIES_DB still overrides this
        file alone, for the default tenant only — see `paths`.
        """
        return identities_db_path()

    def __init__(self, db_path: str | None = None):
        self.db_path = Path(db_path or self.default_db_path())
        parent = self.db_path.parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()
        self._restrict_permissions()

    def _restrict_permissions(self) -> None:
        """Make the store owner-only where the platform supports it.

        Unwrapped private keys are readable by anything that can read this
        file, so the file mode is the whole protection. chmod is advisory on
        Windows (os.chmod only toggles the read-only bit), which is why the
        module docstring says so rather than implying a guarantee here.
        """
        try:
            self.db_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(str(self.db_path))
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self):
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS identities (
                origin TEXT NOT NULL,
                username TEXT NOT NULL,
                scrypt_hash TEXT NOT NULL,
                auth_salt BLOB NOT NULL,
                key_salt BLOB NOT NULL,
                encrypted_private_key BLOB NOT NULL,
                public_key BLOB NOT NULL,
                registered INTEGER DEFAULT 0,
                wrapped INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (origin, username)
            )
        """)
        conn.commit()

    def _derive_aes_key(self, password: str, key_salt: bytes) -> bytes:
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            return bcrypt.kdf(
                password=password.encode("utf-8"), salt=key_salt, desired_key_bytes=24, rounds=100
            )

    def register(
        self, origin: str, username: str, password: str | None = None
    ) -> tuple[bytes, bytes]:
        """Mint an Ed25519 identity and store it, wrapped iff a password is given.

        Scoped to `origin`: the same `username` may hold a distinct keypair on
        each origin it registers with, matching that usernames only mean
        anything within the registrar that accepted them.

        Omitting the password stores the private key as-is; see the module
        docstring for why that is the right default for an agent.
        """
        conn = self._get_conn()
        cur = conn.cursor()

        cur.execute(
            "SELECT username FROM identities WHERE origin = ? AND username = ?",
            (origin, username),
        )
        if cur.fetchone():
            raise ValueError("User already exists locally")

        if not password:
            signing_key = SigningKey.generate()
            private_key = bytes(signing_key)
            public_key = bytes(signing_key.verify_key)
            conn.execute(
                """INSERT INTO identities
                   (origin, username, scrypt_hash, auth_salt, key_salt,
                    encrypted_private_key, public_key, wrapped)
                   VALUES (?, ?, '', X'', X'', ?, ?, 0)""",
                (origin, username, private_key, public_key),
            )
            conn.commit()
            return private_key, public_key

        # 1. Password storage for authentication
        auth_salt = os.urandom(16)
        # hashlib.scrypt: a standard-library strong KDF, used in place of
        # yescrypt (which needs C bindings unavailable here). Stored as hex.
        scrypt_hash = hashlib.scrypt(
            password.encode("utf-8"), salt=auth_salt, n=65536, r=8, p=2, maxmem=134217728
        ).hex()

        # 2. Keypair encryption
        key_salt = os.urandom(16)
        # bcrypt output is fixed to 60 chars string, but we want a 24-byte key for AES-192.
        # Let's derive the key using bcrypt.kdf, which is exactly for this purpose.
        aes_key = self._derive_aes_key(password, key_salt)

        signing_key = SigningKey.generate()
        private_key = bytes(signing_key)
        public_key = bytes(signing_key.verify_key)

        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        encrypted_private_key = nonce + aesgcm.encrypt(nonce, private_key, None)

        conn.execute(
            """INSERT INTO identities
               (origin, username, scrypt_hash, auth_salt, key_salt, encrypted_private_key,
                public_key, wrapped)
               VALUES (?, ?, ?, ?, ?, ?, ?, 1)""",
            (origin, username, scrypt_hash, auth_salt, key_salt, encrypted_private_key, public_key),
        )
        conn.commit()

        return private_key, public_key

    def is_wrapped(self, origin: str, username: str) -> bool:
        """True if this identity's key is password-wrapped at rest."""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT wrapped FROM identities WHERE origin = ? AND username = ?", (origin, username)
        )
        row = cur.fetchone()
        if not row:
            raise ValueError(f"No local identity found for '{username}' on '{origin}'")
        return bool(row["wrapped"])

    def get_private_key(self, origin: str, username: str, password: str | None = None) -> bytes:
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT key_salt, encrypted_private_key, wrapped FROM identities "
            "WHERE origin = ? AND username = ?",
            (origin, username),
        )
        row = cur.fetchone()
        if not row:
            raise ValueError("User not found")

        if not row["wrapped"]:
            # Stored as-is. A password, if one was supplied anyway, is not an
            # error but has nothing to unlock.
            return bytes(row["encrypted_private_key"])

        if not password:
            raise ValueError(
                f"Identity '{username}' is password-protected; supply its password "
                f"(auth='{username}:<password>')"
            )
        if not self.verify_password(origin, username, password):
            raise ValueError("Invalid password")

        key_salt = bytes(row["key_salt"])
        encrypted = bytes(row["encrypted_private_key"])

        aes_key = self._derive_aes_key(password, key_salt)

        aesgcm = AESGCM(aes_key)
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]

        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise ValueError("Failed to decrypt private key") from e

    def get_pubkey(self, origin: str, username: str) -> bytes | None:
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT public_key FROM identities WHERE origin = ? AND username = ?",
            (origin, username),
        )
        row = cur.fetchone()
        return bytes(row["public_key"]) if row else None

    def verify_password(self, origin: str, username: str, password: str) -> bool:
        """Check a password against a wrapped identity.

        An unwrapped identity has no password to check, so this reports True
        for one that exists. Callers wanting "is this identity usable without a
        password" should ask `is_wrapped` — this returning True does not mean a
        password was presented or verified.
        """
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT scrypt_hash, auth_salt, wrapped FROM identities WHERE origin = ? AND username = ?",
            (origin, username),
        )
        row = cur.fetchone()
        if not row:
            return False
        if not row["wrapped"]:
            return True

        expected_hash = row["scrypt_hash"]
        auth_salt = bytes(row["auth_salt"])

        try:
            actual_hash = hashlib.scrypt(
                password.encode("utf-8"), salt=auth_salt, n=65536, r=8, p=2, maxmem=134217728
            ).hex()
            return actual_hash == expected_hash
        except ValueError:
            return False

    def mark_registered(self, origin: str, username: str):
        conn = self._get_conn()
        conn.execute(
            "UPDATE identities SET registered = 1 WHERE origin = ? AND username = ?",
            (origin, username),
        )
        conn.commit()

    def is_registered(self, origin: str, username: str) -> bool:
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT registered FROM identities WHERE origin = ? AND username = ?",
            (origin, username),
        )
        row = cur.fetchone()
        return bool(row and row["registered"])

    def list_users(self, origin: str | None = None) -> list[dict]:
        """Identities held by this client, optionally scoped to one origin.

        `origin=None` lists everything this client holds, across every origin
        it has ever registered with.
        """
        conn = self._get_conn()
        cur = conn.cursor()
        if origin is None:
            cur.execute("SELECT origin, username, public_key, registered, wrapped FROM identities")
        else:
            cur.execute(
                "SELECT origin, username, public_key, registered, wrapped FROM identities "
                "WHERE origin = ?",
                (origin,),
            )
        return [
            {
                "origin": row["origin"],
                "username": row["username"],
                "public_key": bytes(row["public_key"]).hex(),
                "registered": bool(row["registered"]),
                "wrapped": bool(row["wrapped"]),
            }
            for row in cur.fetchall()
        ]

    def close(self):
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
