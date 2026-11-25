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

"""The bonnet-identities archive format: round trip, refusals, and bounds."""

import base64
import json
import os

import pytest
from nacl.pwhash import argon2id
from nacl.secret import SecretBox
from nacl.signing import SigningKey

from bonnet.gateway import idarchive
from bonnet.gateway.idarchive import ArchiveError, Entry, Relay

# Cheapest argon2id libsodium allows; the format records these in the envelope.
FAST = {"opslimit": argon2id.OPSLIMIT_MIN, "memlimit": argon2id.MEMLIMIT_MIN}


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    monkeypatch.setattr(idarchive, "OPSLIMIT", FAST["opslimit"])
    monkeypatch.setattr(idarchive, "MEMLIMIT", FAST["memlimit"])


def _entry(name="moxxie", origin="sys.example.me", key: bytes | None = None) -> Entry:
    sk = SigningKey(key or os.urandom(32))
    return Entry(
        origin=origin,
        username=name,
        private_key_hex=bytes(sk).hex(),
        public_key_hex=bytes(sk.verify_key).hex(),
        registered=True,
        relay=Relay(url=f"https://{origin}", verify_tls=True, origin_key="ab" * 32),
    )


def _seal(payload: dict, passphrase="pw") -> bytes:
    """An archive around an arbitrary payload, for contents `build` would refuse."""
    salt, nonce = os.urandom(argon2id.SALTBYTES), os.urandom(SecretBox.NONCE_SIZE)
    box = SecretBox(idarchive._key(passphrase, salt, **FAST))
    env = {
        "format": idarchive.FORMAT,
        "version": 1,
        "kdf": {"name": "argon2id", "salt": base64.b64encode(salt).decode(), **FAST},
        "cipher": "xsalsa20poly1305",
        "nonce": base64.b64encode(nonce).decode(),
        "payload": base64.b64encode(
            box.encrypt(json.dumps(payload).encode(), nonce).ciphertext
        ).decode(),
    }
    return json.dumps(env).encode()


def test_round_trip_keeps_every_field():
    a, b = _entry("a"), _entry("b", origin="other.example")
    data = idarchive.build([a, b], "pw", "bonnet 0.5.2")
    opened = idarchive.open_archive(data, "pw")
    assert opened.exported_by == "bonnet 0.5.2"
    assert [e.to_json() for e in opened.entries] == [a.to_json(), b.to_json()]
    assert opened.rejected == []


def test_file_reveals_nothing_without_the_passphrase():
    data = idarchive.build([_entry("hidden-name")], "pw", "x").decode()
    assert "hidden-name" not in data and "sys.example.me" not in data
    assert json.loads(data)["format"] == "bonnet-identities"


def test_wrong_passphrase_and_tampering_fail_the_same_way():
    data = idarchive.build([_entry()], "pw", "x")
    with pytest.raises(ArchiveError, match="wrong passphrase"):
        idarchive.open_archive(data, "nope")
    env = json.loads(data)
    ct = bytearray(base64.b64decode(env["payload"]))
    ct[0] ^= 1
    env["payload"] = base64.b64encode(bytes(ct)).decode()
    with pytest.raises(ArchiveError, match="wrong passphrase"):
        idarchive.open_archive(json.dumps(env).encode(), "pw")


def test_unknown_format_and_newer_version_are_refused():
    env = json.loads(idarchive.build([_entry()], "pw", "x"))
    with pytest.raises(ArchiveError, match="isn't a bonnet-identities archive"):
        idarchive.open_archive(json.dumps({**env, "format": "other"}).encode(), "pw")
    with pytest.raises(ArchiveError, match="version 2"):
        idarchive.open_archive(json.dumps({**env, "version": 2}).encode(), "pw")
    with pytest.raises(ArchiveError, match="not JSON"):
        idarchive.open_archive(b"\xff\xfe", "pw")


@pytest.mark.parametrize(
    "kdf",
    [
        {"opslimit": idarchive.MAX_OPSLIMIT + 1},
        {"memlimit": idarchive.MAX_MEMLIMIT + 1},
        {"opslimit": 0},
        {"memlimit": 1},
        {"name": "scrypt"},
    ],
)
def test_hostile_kdf_settings_are_refused_before_any_work(kdf):
    env = json.loads(idarchive.build([_entry()], "pw", "x"))
    env["kdf"].update(kdf)
    with pytest.raises(ArchiveError):
        idarchive.open_archive(json.dumps(env).encode(), "pw")


def test_corrupt_entries_are_flagged_and_bad_ones_rejected_without_blocking_the_rest():
    good, bad = _entry("good"), _entry("bad")
    mismatched = {**bad.to_json(), "public_key_hex": _entry().public_key_hex}
    payload = {
        "exported_at": "2026-11-25T13:00:00Z",
        "exported_by": "x",
        "identities": [good.to_json(), mismatched, {"origin": "o"}, "nonsense"],
    }
    opened = idarchive.open_archive(_seal(payload), "pw")
    assert [(e.username, e.intact) for e in opened.entries] == [("good", True), ("bad", False)]
    assert len(opened.rejected) == 2


def test_unknown_fields_are_ignored_and_build_refuses_a_broken_identity():
    d = {**_entry().to_json(), "added_in_v2": {"x": 1}}
    assert idarchive.entry_from_json(d).username == "moxxie"
    broken = _entry()
    broken.public_key_hex = _entry().public_key_hex
    with pytest.raises(ArchiveError, match="not exporting a broken identity"):
        idarchive.build([broken], "pw", "x")
    with pytest.raises(ArchiveError, match="needs a passphrase"):
        idarchive.build([_entry()], "", "x")
