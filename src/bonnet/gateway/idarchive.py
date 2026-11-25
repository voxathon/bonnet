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

"""The `bonnet-identities` archive format (`.bnid`), shared with scootaloo.

A small JSON envelope around one encrypted payload:

    {"format": "bonnet-identities", "version": 1,
     "kdf": {"name": "argon2id", "salt": <b64>, "opslimit": 3, "memlimit": 268435456},
     "cipher": "xsalsa20poly1305", "nonce": <b64>, "payload": <b64 ciphertext>}

The payload, once decrypted:

    {"exported_at": "...Z", "exported_by": "<client> X.Y.Z",
     "identities": [{"origin", "username", "private_key_hex", "public_key_hex",
                     "registered", "relay": {"url", "verify_tls", "origin_key"}}]}

The identity field names match the gateway's `export_identity`. Without the
passphrase the file says only that it is a bonnet-identities archive.

Nothing in here touches a store: tools.py decides what export and import do
with the identities. Readers refuse a format they don't know and a version
newer than VERSION, ignore unknown fields inside an identity, and refuse
key-derivation settings outside MIN/MAX bounds so a hostile file can't make
them spend gigabytes. The envelope header is not itself authenticated by the
cipher; the bounds are what limit what it can ask for.
"""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from nacl.exceptions import CryptoError
from nacl.pwhash import argon2id
from nacl.secret import SecretBox
from nacl.signing import SigningKey

FORMAT = "bonnet-identities"
VERSION = 1
EXTENSION = ".bnid"

OPSLIMIT = argon2id.OPSLIMIT_MODERATE  # 3
MEMLIMIT = argon2id.MEMLIMIT_MODERATE  # 256 MiB
# What a reader will agree to spend: a hostile archive can't ask for gigabytes.
MAX_OPSLIMIT = 10
MAX_MEMLIMIT = 1024 * 1024 * 1024

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ArchiveError(ValueError):
    """The input isn't a usable archive or identity. The message says why, for the user."""


@dataclass
class Relay:
    url: str = ""
    verify_tls: bool = True
    origin_key: str = ""  # hex of the origin key that was pinned at export; "" if unknown


@dataclass
class Entry:
    origin: str
    username: str
    private_key_hex: str
    public_key_hex: str
    registered: bool = True
    relay: Relay = field(default_factory=Relay)

    @property
    def seed(self) -> bytes:
        return bytes.fromhex(self.private_key_hex)

    @property
    def intact(self) -> bool:
        """The seed re-derives exactly the stored public key."""
        try:
            return derive_public(self.private_key_hex) == self.public_key_hex
        except ArchiveError:
            return False

    @property
    def label(self) -> str:
        return f"{self.username} on {self.origin}"

    def to_json(self) -> dict:
        return {
            "origin": self.origin,
            "username": self.username,
            "private_key_hex": self.private_key_hex,
            "public_key_hex": self.public_key_hex,
            "registered": self.registered,
            "relay": {
                "url": self.relay.url,
                "verify_tls": self.relay.verify_tls,
                "origin_key": self.relay.origin_key,
            },
        }


def derive_public(private_key_hex: str) -> str:
    seed = _hex32(private_key_hex, "private_key_hex")
    return SigningKey(seed).verify_key.encode().hex()


def _hex32(value, name: str) -> bytes:
    if not isinstance(value, str) or not _HEX64.match(value.strip().lower()):
        raise ArchiveError(f"{name} must be 64 hex characters (a 32-byte key)")
    return bytes.fromhex(value.strip().lower())


def _b64d(value, name: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (TypeError, ValueError):
        raise ArchiveError(f"the archive's {name} isn't valid base64") from None


# ---------------------------------------------------------------------------
# Entries from JSON (archive payloads and the gateway's export)
# ---------------------------------------------------------------------------


def entry_from_json(d, *, need_public: bool = True) -> Entry:
    """One identity from a dict. Tolerates unknown fields; refuses missing or malformed ones."""
    if not isinstance(d, dict):
        raise ArchiveError("an identity must be a JSON object")
    origin, username = d.get("origin"), d.get("username")
    if not isinstance(origin, str) or not origin.strip():
        raise ArchiveError("an identity needs its origin")
    if not isinstance(username, str) or not username.strip():
        raise ArchiveError("an identity needs its username")
    priv = _hex32(d.get("private_key_hex"), "private_key_hex").hex()
    pub = d.get("public_key_hex")
    if pub is None and not need_public:
        pub = derive_public(priv)
    pub = _hex32(pub, "public_key_hex").hex()
    raw_relay = d.get("relay")
    relay_d: dict = raw_relay if isinstance(raw_relay, dict) else {}
    origin_key = relay_d.get("origin_key") or ""
    if origin_key:
        origin_key = _hex32(origin_key, "relay.origin_key").hex()
    url, verify_tls = relay_d.get("url"), relay_d.get("verify_tls")
    relay = Relay(
        url=url if isinstance(url, str) else "",
        verify_tls=verify_tls if isinstance(verify_tls, bool) else True,
        origin_key=origin_key,
    )
    registered = d.get("registered")
    return Entry(
        origin.strip(),
        username.strip(),
        priv,
        pub,
        registered if isinstance(registered, bool) else True,
        relay,
    )


# ---------------------------------------------------------------------------
# Archives
# ---------------------------------------------------------------------------


def _key(passphrase: str, salt: bytes, opslimit: int, memlimit: int) -> bytes:
    return argon2id.kdf(
        SecretBox.KEY_SIZE, passphrase.encode("utf-8"), salt, opslimit=opslimit, memlimit=memlimit
    )


def build(entries: list[Entry], passphrase: str, exported_by: str) -> bytes:
    """Encrypt `entries` into archive bytes (UTF-8 JSON)."""
    if not passphrase:
        raise ArchiveError("an archive needs a passphrase")
    if not entries:
        raise ArchiveError("nothing to export")
    for e in entries:
        if not e.intact:
            raise ArchiveError(
                f"{e.label}: its key doesn't match its public key; not exporting a broken identity"
            )
    payload = {
        "exported_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "exported_by": exported_by,
        "identities": [e.to_json() for e in entries],
    }
    salt = os.urandom(argon2id.SALTBYTES)
    nonce = os.urandom(SecretBox.NONCE_SIZE)
    box = SecretBox(_key(passphrase, salt, OPSLIMIT, MEMLIMIT))
    ct = box.encrypt(json.dumps(payload, sort_keys=True).encode("utf-8"), nonce).ciphertext
    envelope = {
        "format": FORMAT,
        "version": VERSION,
        "kdf": {
            "name": "argon2id",
            "salt": base64.b64encode(salt).decode(),
            "opslimit": OPSLIMIT,
            "memlimit": MEMLIMIT,
        },
        "cipher": "xsalsa20poly1305",
        "nonce": base64.b64encode(nonce).decode(),
        "payload": base64.b64encode(ct).decode(),
    }
    return (json.dumps(envelope, indent=2) + "\n").encode("utf-8")


@dataclass
class Opened:
    exported_at: str
    exported_by: str
    entries: list[Entry]
    rejected: list[tuple[str, str]]  # (what, why) for entries that couldn't be read at all


def check_envelope(data: bytes) -> dict:
    """Parse and validate the outer envelope (no passphrase needed)."""
    try:
        env = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ArchiveError("that file isn't a bonnet-identities archive (not JSON)") from None
    if not isinstance(env, dict) or env.get("format") != FORMAT:
        raise ArchiveError("that file isn't a bonnet-identities archive")
    v = env.get("version")
    if not isinstance(v, int) or v < 1:
        raise ArchiveError("the archive's version is missing or malformed")
    if v > VERSION:
        raise ArchiveError(
            f"this archive is format version {v}; this reader reads up to version {VERSION}. Update bonnet."
        )
    kdf = env.get("kdf")
    if not isinstance(kdf, dict) or kdf.get("name") != "argon2id":
        raise ArchiveError("the archive uses a key derivation this reader doesn't know")
    ops, mem = kdf.get("opslimit"), kdf.get("memlimit")
    if not isinstance(ops, int) or not isinstance(mem, int):
        raise ArchiveError("the archive's key-derivation settings are malformed")
    if not (
        argon2id.OPSLIMIT_MIN <= ops <= MAX_OPSLIMIT
        and argon2id.MEMLIMIT_MIN <= mem <= MAX_MEMLIMIT
    ):
        raise ArchiveError(
            "the archive asks for key-derivation settings outside what this reader will run"
        )
    if env.get("cipher") != "xsalsa20poly1305":
        raise ArchiveError("the archive uses a cipher this reader doesn't know")
    if len(_b64d(kdf.get("salt"), "salt")) != argon2id.SALTBYTES:
        raise ArchiveError("the archive's salt has the wrong length")
    if len(_b64d(env.get("nonce"), "nonce")) != SecretBox.NONCE_SIZE:
        raise ArchiveError("the archive's nonce has the wrong length")
    _b64d(env.get("payload"), "payload")
    return env


def open_archive(data: bytes, passphrase: str) -> Opened:
    """Decrypt and parse. A wrong passphrase and a tampered file fail the same way."""
    env = check_envelope(data)
    kdf = env["kdf"]
    key = _key(passphrase, base64.b64decode(kdf["salt"]), kdf["opslimit"], kdf["memlimit"])
    try:
        plain = SecretBox(key).decrypt(
            base64.b64decode(env["payload"]), base64.b64decode(env["nonce"])
        )
    except CryptoError:
        raise ArchiveError(
            "wrong passphrase, or the archive was changed after it was made"
        ) from None
    try:
        payload = json.loads(plain.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ArchiveError("the archive decrypted but its contents aren't valid JSON") from None
    if not isinstance(payload, dict) or not isinstance(payload.get("identities"), list):
        raise ArchiveError("the archive decrypted but holds no identity list")
    entries, rejected = [], []
    for i, d in enumerate(payload["identities"]):
        try:
            entries.append(entry_from_json(d))
        except ArchiveError as e:
            what = (
                f"{d.get('username')} on {d.get('origin')}"
                if isinstance(d, dict)
                else f"entry {i + 1}"
            )
            rejected.append((what, str(e)))
    return Opened(
        str(payload.get("exported_at", "")), str(payload.get("exported_by", "")), entries, rejected
    )
