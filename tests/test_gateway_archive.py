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

"""export_archive / import_archive against the real ASGI server stack.

Each "machine" is its own gateway home and identity database, so an archive
exported from one is imported into a gateway that has never seen the origin.
"""

from __future__ import annotations

import json
import os

import httpx
import pytest

pytest.importorskip("fastmcp")

from nacl.pwhash import argon2id  # noqa: E402
from nacl.signing import SigningKey  # noqa: E402

from bonnet.core.trust import TrustStore  # noqa: E402
from bonnet.gateway import cursor, idarchive, tenancy, tools  # noqa: E402
from bonnet.gateway.firehose_client import FirehoseHTTPClient  # noqa: E402
from bonnet.gateway.tenancy import tenant_trust_db_path  # noqa: E402
from tests.test_firehose_http_server import ORIGIN, server_stack  # noqa: E402,F401

URL = "https://bbs.test"


@pytest.fixture
def machine(server_stack, tmp_path, monkeypatch):  # noqa: F811
    """A factory for fresh gateway state; the server behind it is shared."""
    monkeypatch.setattr(idarchive, "OPSLIMIT", argon2id.OPSLIMIT_MIN)
    monkeypatch.setattr(idarchive, "MEMLIMIT", argon2id.MEMLIMIT_MIN)
    monkeypatch.delenv("BONNET_IDENTITY", raising=False)
    monkeypatch.delenv("BONNET_URL", raising=False)
    monkeypatch.setattr(tools, "gateway_transport", "stdio")
    monkeypatch.setattr(server_stack["rate_limiter"], "_max_requests", 10_000)
    app = server_stack["server"]

    def make_client(url: str | None = None, verify=None) -> FirehoseHTTPClient:
        target = url if url is not None else tools._current_url()
        client = FirehoseHTTPClient(
            target, verify=False, trust_store_path=tenant_trust_db_path(), pin_mode="strict"
        )
        client._http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=target, timeout=30.0, verify=False
        )
        return client

    monkeypatch.setattr(tools, "_make_client", make_client)

    def switch(name: str) -> None:
        monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / name / "state"))
        monkeypatch.setenv("BONNET_IDENTITIES_DB", str(tmp_path / name / "identities.db"))
        tenancy.reset_store_cache()
        for var in (tools.current_origin_url, tools.current_origin_verify, tools.current_origin):
            var.set(None)
        tools._origin_loaded.set(False)
        tools.current_username.set(None)
        cursor.clear_board()

    yield switch
    tenancy.reset_store_cache()
    tools.current_username.set(None)
    cursor.clear_board()


async def _home_with(*names: str, password: str | None = None) -> None:
    await tools.connect(URL)
    for n in names:
        await tools.register(n, password)


def _pin() -> bytes | None:
    store = TrustStore(tenant_trust_db_path())
    try:
        return store.get_pin(ORIGIN)
    finally:
        store.close()


async def test_export_then_import_on_a_fresh_gateway(machine):
    machine("laptop")
    await _home_with("scout", "second")
    exported = await tools.export_archive("correct horse")
    assert exported["count"] == 2 and exported["skipped"] == []
    opened = idarchive.open_archive(exported["archive"].encode(), "correct horse")
    by_name = {e.username: e for e in opened.entries}
    assert set(by_name) == {"scout", "second"}
    assert by_name["scout"].registered and by_name["scout"].relay.url == URL
    laptop_pin = _pin()
    assert by_name["scout"].relay.origin_key == laptop_pin.hex()

    machine("desktop")
    assert await tools.list_identities(ORIGIN) == []
    result = await tools.import_archive(exported["archive"], "correct horse")
    assert result["imported"] == 2
    assert {r["outcome"] for r in result["results"]} == {"imported"}
    scout = next(r for r in result["results"] if r["username"] == "scout")
    assert scout["relay"]["joined"] is True and scout["relay"]["pin"] == "pinned from archive"
    assert scout["liveness"] == "active"
    assert _pin() == laptop_pin
    assert {i.username for i in await tools.list_identities(ORIGIN)} == {"scout", "second"}

    # The pinned key from the archive is what connect checks, so it connects
    # without asking, and the imported identity is the same key.
    connected = await tools.connect(URL)
    assert "pin_required" not in connected
    held = await tools.list_identities(ORIGIN)
    sk = SigningKey(by_name["scout"].seed)
    assert next(i for i in held if i.username == "scout").public_key == bytes(sk.verify_key).hex()
    exported_again = await tools.export_identity(auth="scout")
    assert exported_again["private_key_hex"] == by_name["scout"].private_key_hex

    again = await tools.import_archive(exported["archive"], "correct horse")
    assert again["imported"] == 0
    assert {r["outcome"] for r in again["results"]} == {"already_held"}


async def test_wrong_passphrase_imports_nothing(machine):
    machine("laptop")
    await _home_with("scout")
    archive = (await tools.export_archive("right"))["archive"]
    machine("desktop")
    with pytest.raises(ValueError, match="wrong passphrase"):
        await tools.import_archive(archive, "wrong")
    assert await tools.list_identities(ORIGIN) == []


async def test_only_selects_entries(machine):
    machine("laptop")
    await _home_with("scout", "second")
    archive = (await tools.export_archive("pw", identities=["second"]))["archive"]
    assert [e.username for e in idarchive.open_archive(archive.encode(), "pw").entries] == [
        "second"
    ]
    full = (await tools.export_archive("pw"))["archive"]
    machine("desktop")
    result = await tools.import_archive(full, "pw", only=[f"{ORIGIN}/second", f"{ORIGIN}/ghost"])
    assert {(r["username"], r["outcome"]) for r in result["results"]} == {
        ("second", "imported"),
        ("ghost", "not_in_archive"),
    }
    assert [i.username for i in await tools.list_identities(ORIGIN)] == ["second"]


async def test_same_name_under_another_key_is_a_conflict_and_left_alone(machine):
    machine("laptop")
    await _home_with("scout")
    original = (await tools.export_identity(auth="scout"))["public_key_hex"]
    other = SigningKey(os.urandom(32))
    entry = idarchive.Entry(ORIGIN, "scout", bytes(other).hex(), bytes(other.verify_key).hex())
    archive = idarchive.build([entry], "pw", "test").decode()
    result = await tools.import_archive(archive, "pw")
    assert result["imported"] == 0 and result["results"][0]["outcome"] == "conflict"
    assert (await tools.export_identity(auth="scout"))["public_key_hex"] == original


async def test_a_corrupt_entry_is_refused_and_does_not_block_the_rest(machine):
    machine("desktop")
    good = SigningKey(os.urandom(32))
    bad = SigningKey(os.urandom(32))
    d_good = idarchive.Entry(
        ORIGIN, "good", bytes(good).hex(), bytes(good.verify_key).hex()
    ).to_json()
    d_bad = idarchive.Entry(
        ORIGIN,
        "bad",
        bytes(bad).hex(),
        bytes(good.verify_key).hex(),  # wrong public key
    ).to_json()
    # build() refuses a broken identity, so seal the payload by hand.
    import base64

    from nacl.secret import SecretBox

    salt, nonce = os.urandom(argon2id.SALTBYTES), os.urandom(SecretBox.NONCE_SIZE)
    key = idarchive._key("pw", salt, argon2id.OPSLIMIT_MIN, argon2id.MEMLIMIT_MIN)
    payload = json.dumps({"identities": [d_bad, d_good]}).encode()
    env = {
        "format": "bonnet-identities", "version": 1,
        "kdf": {"name": "argon2id", "salt": base64.b64encode(salt).decode(),
                "opslimit": argon2id.OPSLIMIT_MIN, "memlimit": argon2id.MEMLIMIT_MIN},
        "cipher": "xsalsa20poly1305", "nonce": base64.b64encode(nonce).decode(),
        "payload": base64.b64encode(SecretBox(key).encrypt(payload, nonce).ciphertext).decode(),
    }  # fmt: skip
    result = await tools.import_archive(json.dumps(env), "pw")
    assert {r["username"]: r["outcome"] for r in result["results"]} == {
        "bad": "corrupt",
        "good": "imported",
    }


async def test_a_pin_already_held_is_never_replaced_by_the_archive(machine):
    machine("laptop")
    await _home_with("scout")
    exported = (await tools.export_archive("pw"))["archive"]
    real = _pin()
    # A desktop that already trusts a different key for this origin.
    machine("desktop")
    store = TrustStore(tenant_trust_db_path())
    store.tofu_pin(ORIGIN, bytes([7]) * 32)
    store.close()
    result = await tools.import_archive(exported, "pw")
    assert result["results"][0]["relay"]["pin"] == "differs from archive; kept"
    assert _pin() == bytes([7]) * 32 != real


async def test_wrapped_identities_need_their_password_to_export(machine):
    machine("laptop")
    await _home_with("sealed", password="hunter2")
    with pytest.raises(ValueError, match="nothing to export"):
        await tools.export_archive("pw")
    exported = await tools.export_archive("pw", passwords={"sealed": "hunter2"})
    assert exported["count"] == 1

    machine("desktop")
    result = await tools.import_archive(exported["archive"], "pw", password="new-pass")
    assert result["imported"] == 1
    (held,) = await tools.list_identities(ORIGIN)
    assert held.wrapped is True


async def test_nothing_to_export_and_empty_passphrase_are_refused(machine):
    machine("laptop")
    await tools.connect(URL)
    with pytest.raises(ValueError, match="nothing to export"):
        await tools.export_archive("pw")
    await tools.register("scout")
    with pytest.raises(ValueError, match="needs a passphrase"):
        await tools.export_archive("")
    with pytest.raises(ValueError, match="no local identity 'ghost'"):
        await tools.export_archive("pw", identities=["ghost"])
