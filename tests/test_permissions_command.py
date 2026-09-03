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

"""PERMISSIONS (0x06): what may this principal do.

The point of the opcode is that the answer comes from the same ACLEvaluator
the enforcing paths use, so it cannot drift from what a real request gets.
These tests check that correspondence directly — for each principal class,
what PERMISSIONS reports must match what the command actually does.
"""

import pytest

from bonnet.core.acl import ACLRule, PrincipalMatcher
from bonnet.core.crypto import Identity
from bonnet.net.firehose_wire import (
    ProtocolError,
    build_board_list,
    build_permissions,
    parse_board_list_response,
    parse_permissions_response,
)
from tests.test_firehose_http_server import (  # noqa: F401
    ORIGIN,
    SERVER_IDENTITY,
    server_stack,
)


async def _perms(client, board: str = ""):
    return parse_permissions_response(await client._send_command(build_permissions(board)))


async def test_anonymous_sees_its_own_grants(server_stack):  # noqa: F811
    client = server_stack["client"]
    await client.connect_anonymous()

    perms = await _perms(client)

    assert perms.principal == "anonymous"
    assert "BOARD_LIST" in perms.commands
    assert "PUBLISH_RECORD" not in perms.commands


async def test_admin_sees_write_and_kinds(server_stack):  # noqa: F811
    client = server_stack["client"]
    await client.connect(SERVER_IDENTITY)

    perms = await _perms(client)

    assert "PUBLISH_RECORD" in perms.commands
    assert "bonnet.article" in perms.kinds


async def test_kinds_are_empty_without_publish(server_stack):  # noqa: F811
    """Enumerating kinds for a principal that cannot publish at all would be
    noise; the field is only meaningful alongside PUBLISH_RECORD."""
    client = server_stack["client"]
    await client.connect_anonymous()

    assert (await _perms(client)).kinds == []


async def test_report_matches_enforcement(server_stack):  # noqa: F811
    """The correspondence that justifies the opcode: if PERMISSIONS says a
    command is allowed, issuing it must not return 0x0004 — and vice versa."""
    client = server_stack["client"]
    await client.connect_anonymous()
    perms = await _perms(client)

    assert "BOARD_LIST" in perms.commands
    # Parsed, not just sent: _send_command returns the raw frame, so an error
    # response only surfaces when something decodes it.
    assert parse_board_list_response(await client._send_command(build_board_list(ORIGIN))) == []

    assert "PERMISSIONS" in perms.commands  # it reports itself, having answered


async def test_a_denied_command_disappears_and_stays_denied(server_stack):  # noqa: F811
    """Both halves of the correspondence, against the same rule change: a
    command that becomes denied must drop out of the report *and* start
    returning 0x0004. Either one alone would let the report drift from what
    the enforcing path actually does."""
    client = server_stack["client"]
    await client.connect_anonymous()
    assert "BOARD_LIST" in (await _perms(client)).commands

    server_stack["command_handler"]._acl.add_rule(
        ACLRule(
            effect="deny",
            matcher=PrincipalMatcher(anonymous=True),
            actions=["read"],
            commands=["BOARD_LIST"],
            boards=["*"],
        )
    )

    assert "BOARD_LIST" not in (await _perms(client)).commands
    with pytest.raises(ProtocolError, match="error 4"):
        parse_board_list_response(await client._send_command(build_board_list(ORIGIN)))


async def test_board_scope_distinguishes_boards(server_stack):  # noqa: F811
    """ACL rules carry a board dimension, so the same identity can publish to
    one board and not another. A board-independent answer cannot express that,
    which is why the request takes a board at all."""
    actor = Identity.from_private_key(bytes(range(70, 102)))
    server_stack["command_handler"]._acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(pubkey=actor.public_key),
            actions=["read", "write"],
            commands=["PUBLISH_RECORD", "PERMISSIONS"],
            kinds=["bonnet.article"],
            boards=["open"],
        )
    )
    client = server_stack["client"]
    await client.connect(actor)

    assert "PUBLISH_RECORD" in (await _perms(client, "open")).commands
    assert "PUBLISH_RECORD" not in (await _perms(client, "locked")).commands


async def test_role_is_reported(server_stack):  # noqa: F811
    """Role drives ACL matching, so a caller checking why it can or cannot do
    something needs to see the role the relay assigned it."""
    client = server_stack["client"]
    await client.connect_anonymous()

    assert (await _perms(client)).role == ""


def test_request_round_trips():
    assert build_permissions("general")[0] == 0x06
    assert build_permissions() == bytes([0x06, 0x00, 0x00])
