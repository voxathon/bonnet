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

"""Tests for the operator console's permission-management commands:
grant-role, revoke-user, warn, ban, permaban, revoke-punishment.
"""

import os
import time

import pytest

from bonnet.app.console import OperatorConsole
from bonnet.core.config import FirehoseConfig


@pytest.fixture
def config(tmp_path):
    return FirehoseConfig(
        origin="bbs.test",
        hostname="bbs.test",
        data_dir=str(tmp_path / "data"),
        boards_dir=str(tmp_path / "boards"),
        events_bodies_dir=str(tmp_path / "event_bodies"),
        port=2272,
        tls_enabled=False,
    )


@pytest.fixture
def server(config):
    os.makedirs(config.data_dir, exist_ok=True)
    os.makedirs(config.boards_dir, exist_ok=True)
    os.makedirs(config.events_bodies_dir, exist_ok=True)

    from bonnet.app.server import BonnetServer

    s = BonnetServer(config)
    yield s
    try:
        s.close()
    except Exception:
        pass


@pytest.fixture
def console(server):
    return OperatorConsole(server)


def _pubkey_hex() -> str:
    return os.urandom(32).hex()


# ---------------------------------------------------------------------------
# grant-role
# ---------------------------------------------------------------------------


def test_grant_role_registers_new_user_with_role(console, server):
    pk = _pubkey_hex()
    result = console.dispatch_local_command(f"grant-role {pk} moderator newbie")
    assert "Registered" in result
    assert "moderator" in result

    user = server.users.get_user_by_pubkey("bbs.test", bytes.fromhex(pk))
    assert user is not None
    assert user["username"] == "newbie"
    assert user["flags"] & 0x02


def test_grant_role_new_user_without_username_errors(console):
    pk = _pubkey_hex()
    result = console.dispatch_local_command(f"grant-role {pk} admin")
    assert "supply a username" in result


def test_grant_role_regrant_reuses_existing_username(console, server):
    pk = _pubkey_hex()
    console.dispatch_local_command(f"grant-role {pk} moderator newbie")

    result = console.dispatch_local_command(f"grant-role {pk} admin")
    assert "Re-registered" in result
    assert "newbie" in result

    user = server.users.get_user_by_pubkey("bbs.test", bytes.fromhex(pk))
    assert user["flags"] & 0x01
    assert not (user["flags"] & 0x02)


def test_grant_role_unknown_role_errors(console):
    pk = _pubkey_hex()
    result = console.dispatch_local_command(f"grant-role {pk} superadmin newbie")
    assert "Unknown role" in result


def test_grant_role_invalid_pubkey_errors(console):
    result = console.dispatch_local_command("grant-role not-hex admin newbie")
    assert "Invalid hex pubkey" in result


# ---------------------------------------------------------------------------
# revoke-user
# ---------------------------------------------------------------------------


def test_revoke_user_revokes_registration(console, server):
    pk = _pubkey_hex()
    console.dispatch_local_command(f"grant-role {pk} moderator newbie")

    result = console.dispatch_local_command(f"revoke-user {pk}")
    assert "Revoked" in result

    user = server.users.get_user_by_pubkey("bbs.test", bytes.fromhex(pk))
    assert user["revoked"]


def test_revoke_user_unregistered_pubkey_errors(console):
    pk = _pubkey_hex()
    result = console.dispatch_local_command(f"revoke-user {pk}")
    assert "not a registered user" in result


def test_revoke_user_already_revoked_errors(console):
    pk = _pubkey_hex()
    console.dispatch_local_command(f"grant-role {pk} moderator newbie")
    console.dispatch_local_command(f"revoke-user {pk}")

    result = console.dispatch_local_command(f"revoke-user {pk}")
    assert "already revoked" in result


# ---------------------------------------------------------------------------
# warn / ban / permaban
# ---------------------------------------------------------------------------


def test_warn_issues_pending_warning(console):
    pk = _pubkey_hex()
    result = console.dispatch_local_command(f"warn {pk} spamming the general board")
    assert "Warned" in result
    assert "Event:" in result

    status = console.dispatch_local_command(f"ban-status {pk}")
    assert "warning" in status


def test_warn_requires_reason(console):
    pk = _pubkey_hex()
    result = console.dispatch_local_command(f"warn {pk}")
    assert "Usage" in result


def test_ban_with_relative_duration(console):
    pk = _pubkey_hex()
    result = console.dispatch_local_command(f"ban {pk} 7d repeated spam")
    assert "Banned" in result

    status = console.dispatch_local_command(f"ban-status {pk}")
    assert "ban" in status


def test_ban_with_absolute_timestamp(console):
    pk = _pubkey_hex()
    future = int(time.time()) + 3600
    result = console.dispatch_local_command(f"ban {pk} {future} spam")
    assert "Banned" in result


def test_ban_invalid_duration_errors(console):
    pk = _pubkey_hex()
    result = console.dispatch_local_command(f"ban {pk} not-a-duration spam")
    assert "Invalid duration" in result


def test_permaban_issues_permanent_ban(console):
    pk = _pubkey_hex()
    result = console.dispatch_local_command(f"permaban {pk} abuse")
    assert "Permabanned" in result

    status = console.dispatch_local_command(f"ban-status {pk}")
    assert "permaban" in status


def test_warn_ban_permaban_invalid_pubkey_errors(console):
    assert "Invalid hex pubkey" in console.dispatch_local_command("warn zz reason")
    assert "Invalid hex pubkey" in console.dispatch_local_command("ban zz 1d reason")
    assert "Invalid hex pubkey" in console.dispatch_local_command("permaban zz reason")


def test_warn_custom_board(console):
    pk = _pubkey_hex()
    result = console.dispatch_local_command(f"warn {pk} being rude --board=off-topic")
    assert "/off-topic" in result


# ---------------------------------------------------------------------------
# revoke-punishment
# ---------------------------------------------------------------------------


def test_revoke_punishment_clears_ban(console):
    pk = _pubkey_hex()
    ban_result = console.dispatch_local_command(f"ban {pk} 7d spam")
    event_id = ban_result.split("Event: ")[1].strip()

    status_before = console.dispatch_local_command(f"ban-status {pk}")
    assert "ban" in status_before

    revoke_result = console.dispatch_local_command(f"revoke-punishment {event_id} appeal granted")
    assert "Revoked punishment" in revoke_result

    status_after = console.dispatch_local_command(f"ban-status {pk}")
    assert status_after == "No pending punishments."


def test_revoke_punishment_invalid_event_id_errors(console):
    result = console.dispatch_local_command("revoke-punishment not-hex")
    assert "Invalid event ID hex" in result

    result = console.dispatch_local_command("revoke-punishment " + "ab" * 10)
    assert "must be 32 bytes" in result
