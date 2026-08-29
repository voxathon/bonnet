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
from bonnet.net.firehose_wire import ProtocolError
from tests.test_firehose_http_server import (  # noqa: F401
    ORIGIN,
    SERVER_IDENTITY,
    server_stack,
)

REPORTER = Identity.from_private_key(bytes(range(100, 132)))
CULPRIT = Identity.from_private_key(bytes(range(130, 162)))


def _allow_reports(stack, matcher):
    stack["command_handler"]._acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=matcher,
            actions=["read", "write"],
            commands=["PUBLISH_RECORD", "PERMISSIONS"],
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
