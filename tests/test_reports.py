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

"""The report system, end to end.

`bonnet.report` had a validator, a dispatcher route and a projection table,
but no producer and no reader — records arriving over federation were stored
and then seen by nobody. These tests cover the piping that closed that loop,
and pin the property that motivates the kind existing separately from
punishments: a report is an accusation, and filing one grants no authority.
"""

import pytest

from bonnet.core.acl import ACLRule, PrincipalMatcher
from bonnet.core.crypto import Identity
from bonnet.core.record import ZERO_ID
from bonnet.net.firehose_wire import ProtocolError, build_report_list
from tests.test_firehose_http_server import (  # noqa: F401
    ORIGIN,
    SERVER_IDENTITY,
    server_stack,
)

REPORTER = Identity.from_private_key(bytes(range(100, 132)))
CULPRIT = Identity.from_private_key(bytes(range(130, 162)))


def _allow_reports(stack, matcher):
    """Grant permission to *file* reports, and only that.

    Deliberately write-only. ACL dimensions are evaluated independently across
    every matching rule, so a rule granting `read` with `boards = ["*"]` would
    also satisfy the board dimension of a REPORT_LIST check — silently
    defeating any board-scoped restriction on the queue. `_check_dimension`
    filters rules by action first, so a write-only grant cannot leak into a
    read check.
    """
    stack["command_handler"]._acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=matcher,
            actions=["write"],
            commands=["PUBLISH_RECORD"],
            kinds=["bonnet.report"],
            boards=["*"],
        )
    )


async def test_a_report_is_stored_and_readable(server_stack):  # noqa: F811
    """The whole point: it round-trips. Before this, apply_report wrote a row
    that nothing could ever select."""
    _allow_reports(server_stack, PrincipalMatcher(pubkey=REPORTER.public_key))
    client = server_stack["client"]
    await client.connect(REPORTER)

    await client.publish_report(culprit_pubkey=CULPRIT.public_key, reason="spam")

    rows = server_stack["policy"].list_reports()
    assert len(rows) == 1
    assert rows[0]["culprit_pubkey"] == CULPRIT.public_key
    assert rows[0]["body_size"] == len(b"spam")


async def test_article_target_round_trips(server_stack):  # noqa: F811
    """The article tuple is what makes a report evidence rather than a bare
    accusation, so it has to survive storage intact."""
    _allow_reports(server_stack, PrincipalMatcher(pubkey=REPORTER.public_key))
    client = server_stack["client"]
    await client.connect(REPORTER)
    article_id = bytes(range(32))

    await client.publish_report(
        culprit_pubkey=CULPRIT.public_key,
        reason="off topic",
        target_origin=ORIGIN,
        target_board="general",
        target_article_id=article_id,
    )

    row = server_stack["policy"].list_reports()[0]
    assert row["target_origin"] == ORIGIN
    assert row["target_board"] == "general"
    assert row["target_article_id"] == article_id
    assert row["target_event_id"] == ZERO_ID


async def test_a_partial_target_is_rejected(server_stack):  # noqa: F811
    """The validator allows an article tuple, an event, or nothing — never a
    mixture. A half-filled tuple must fail loudly rather than store a report
    pointing at nothing in particular."""
    _allow_reports(server_stack, PrincipalMatcher(pubkey=REPORTER.public_key))
    client = server_stack["client"]
    await client.connect(REPORTER)

    with pytest.raises(ProtocolError, match="Validation error"):
        await client.publish_report(
            culprit_pubkey=CULPRIT.public_key,
            reason="incomplete",
            target_origin=ORIGIN,  # board and article_id omitted
        )


async def test_filing_a_report_grants_no_authority(server_stack):  # noqa: F811
    """The property that justifies report and punishment being separate kinds.
    A reporter who may file must still be refused a punishment."""
    _allow_reports(server_stack, PrincipalMatcher(pubkey=REPORTER.public_key))
    client = server_stack["client"]
    await client.connect(REPORTER)
    await client.publish_report(culprit_pubkey=CULPRIT.public_key, reason="spam")

    with pytest.raises(ProtocolError, match="error 4"):
        await client.publish_punishment_ban(
            board="moderation.actions",
            punished_pubkey=CULPRIT.public_key,
            reason="taking matters into my own hands",
            expires_at=2**31,
        )


async def test_reports_can_be_filtered_by_culprit(server_stack):  # noqa: F811
    _allow_reports(server_stack, PrincipalMatcher(pubkey=REPORTER.public_key))
    client = server_stack["client"]
    await client.connect(REPORTER)
    other = Identity.generate()

    await client.publish_report(culprit_pubkey=CULPRIT.public_key, reason="a")
    await client.publish_report(culprit_pubkey=other.public_key, reason="b")

    named = server_stack["policy"].list_reports(culprit_pubkey=CULPRIT.public_key)
    assert len(named) == 1
    assert named[0]["culprit_pubkey"] == CULPRIT.public_key
    assert len(server_stack["policy"].list_reports()) == 2


async def test_reporting_requires_the_kind_to_be_granted(server_stack):  # noqa: F811
    """Reports are ACL-gated like any other publish, so an operator can turn
    them off — and a caller with no grant cannot file one."""
    client = server_stack["client"]
    await client.connect(REPORTER)

    with pytest.raises(ProtocolError, match="error 4"):
        await client.publish_report(culprit_pubkey=CULPRIT.public_key, reason="nope")


def test_default_config_lets_users_report_but_not_punish():
    """The shipped split: anyone registered may accuse, nobody may judge
    without an explicit rule."""
    from bonnet.core.acl import AuthContext
    from bonnet.core.config import FirehoseConfig

    acl = FirehoseConfig.load("config.example.toml").acl
    ctx = AuthContext(is_registered=True)

    def may(kind):
        return acl.check(ctx, "write", command="PUBLISH_RECORD", kind=kind, board="general")

    assert may("bonnet.report")
    assert not may("bonnet.punishment.ban")
    assert not may("bonnet.punishment.permaban")


# --- REPORT_LIST: the queue as a command, not a client-side scan -----------


def _allow_queue(stack, matcher, boards=None):
    stack["command_handler"]._acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=matcher,
            actions=["read"],
            commands=["REPORT_LIST"],
            boards=boards if boards is not None else ["*"],
        )
    )


async def test_queue_requires_its_own_grant(server_stack):  # noqa: F811
    """The reason this is an opcode: an operator can withhold it. A caller
    with every ordinary read permission still cannot enumerate accusations."""
    client = server_stack["client"]
    await client.connect_anonymous()

    with pytest.raises(ProtocolError, match="error 4"):
        await client.list_reports()


async def test_queue_returns_reports_when_granted(server_stack):  # noqa: F811
    """Also pins where the reporter comes from. The reports projection stores
    no reporter column — the handler reads actor_pubkey back off the record,
    where it is covered by the actor signature and the hash chain. This
    assertion passing means that lookup works; a projection copy would have
    been unsigned derived state saying the same thing less credibly.
    """
    _allow_reports(server_stack, PrincipalMatcher(pubkey=REPORTER.public_key))
    _allow_queue(server_stack, PrincipalMatcher(pubkey=REPORTER.public_key))
    client = server_stack["client"]
    await client.connect(REPORTER)
    await client.publish_report(
        culprit_pubkey=CULPRIT.public_key,
        reason="spam",
        target_origin=ORIGIN,
        target_board="general",
        target_article_id=bytes(range(32)),
    )

    reports = await client.list_reports()

    assert len(reports) == 1
    assert reports[0].culprit_pubkey == CULPRIT.public_key.hex()
    assert reports[0].reporter_pubkey == REPORTER.public_key.hex()
    assert reports[0].target_kind == "article"
    assert reports[0].target_board == "general"


async def test_board_scoped_acl_filters_the_queue(server_stack):  # noqa: F811
    """The check a client-side scan over EVENT_RANGE cannot make. A caller
    granted the queue for one board must not see accusations made in another
    — otherwise a `boards = [...]` rule is a no-op here, exactly what
    _board_read_allowed exists to prevent."""
    _allow_reports(server_stack, PrincipalMatcher(pubkey=REPORTER.public_key))
    client = server_stack["client"]
    await client.connect(REPORTER)
    for board in ("open", "secret"):
        await client.publish_report(
            culprit_pubkey=CULPRIT.public_key,
            reason=f"about {board}",
            target_origin=ORIGIN,
            target_board=board,
            target_article_id=bytes(range(32)),
        )
    _allow_queue(server_stack, PrincipalMatcher(pubkey=REPORTER.public_key), boards=["open"])

    reports = await client.list_reports()

    assert [r.target_board for r in reports] == ["open"]


async def test_untargeted_reports_need_only_the_command_grant(server_stack):  # noqa: F811
    """A report with no board carries nothing to check per board, so the
    command grant governs it alone — it must not be silently dropped."""
    _allow_reports(server_stack, PrincipalMatcher(pubkey=REPORTER.public_key))
    _allow_queue(server_stack, PrincipalMatcher(pubkey=REPORTER.public_key), boards=["open"])
    client = server_stack["client"]
    await client.connect(REPORTER)
    await client.publish_report(culprit_pubkey=CULPRIT.public_key, reason="general concern")

    reports = await client.list_reports()

    assert len(reports) == 1
    assert reports[0].target_kind == "none"


async def test_queue_filters_by_culprit(server_stack):  # noqa: F811
    _allow_reports(server_stack, PrincipalMatcher(pubkey=REPORTER.public_key))
    _allow_queue(server_stack, PrincipalMatcher(pubkey=REPORTER.public_key))
    client = server_stack["client"]
    await client.connect(REPORTER)
    other = Identity.generate()
    await client.publish_report(culprit_pubkey=CULPRIT.public_key, reason="a")
    await client.publish_report(culprit_pubkey=other.public_key, reason="b")

    named = await client.list_reports(CULPRIT.public_key)

    assert len(named) == 1
    assert named[0].culprit_pubkey == CULPRIT.public_key.hex()


def test_request_round_trips():
    assert build_report_list()[0] == 0x23
