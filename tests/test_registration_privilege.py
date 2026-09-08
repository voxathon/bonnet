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

"""Registration is not a privilege-granting operation.

`config.example.toml` grants unknown principals `PUBLISH_RECORD` for
`bonnet.user.register` so the documented first-run flow works without editing
config. Two things then have to hold, or that grant hands out the server:

  - an ordinary registration names its own signer, never a third party's key,
    and
  - `flags` — which `firehose_http_server` reads back as `role` — cannot be
    set by the principal it would privilege.

Both are lifted for administrators, because provisioning is a real operator
task: `console.grant-role` registers someone else's key with a role. So the
rules are authorization, not schema, and they live in `_cmd_publish` rather
than in `KindValidator`.

These tests load the ACL from `config.example.toml` itself rather than
constructing a permissive one, because the claim under test is about what the
shipped default allows. A test ACL would prove nothing about it.
"""

import os
import struct
import tomllib

import pytest

from bonnet.core.acl import ACLEvaluator, ACLRule, PrincipalMatcher
from bonnet.core.crypto import Identity
from bonnet.core.kind_validator import KindValidator
from bonnet.core.record import (
    Intent,
    MetadataMap,
    encode_intent,
    metadata_bytes,
    metadata_text,
    metadata_u64,
    sign_intent,
)
from bonnet.net.firehose_commands import FirehoseContext
from bonnet.net.firehose_wire import OP_PUBLISH_RECORD
from tests.test_commands_and_sync import firehose, stack  # noqa: F401  (fixtures)

ORIGIN = "bbs.test"


@pytest.fixture
def shipped_acl():
    """The ACL exactly as config.example.toml ships it."""
    with open("config.example.toml", "rb") as f:
        return ACLEvaluator.from_toml(tomllib.load(f))


def _register_request(identity, username, subject_pubkey, flags):
    intent = Intent(
        event_id=os.urandom(32),
        kind="bonnet.user.register",
        origin=ORIGIN,
        actor_pubkey=identity.public_key,
        actor_username=username,
        metadata=MetadataMap(
            fields=[
                metadata_text(1, username),
                metadata_bytes(2, subject_pubkey),
                metadata_u64(3, flags),
            ]
        ),
    )
    encoded = encode_intent(intent)
    req = struct.pack(">B", OP_PUBLISH_RECORD)
    req += struct.pack(">I", len(encoded)) + encoded
    req += sign_intent(identity, encoded)
    req += struct.pack(">I", 0)
    return req


def _unknown_ctx(identity):
    return FirehoseContext(peer_pubkey=identity.public_key, is_unknown=True, origin=ORIGIN)


# ---------------------------------------------------------------------------
# flags
# ---------------------------------------------------------------------------


def test_unknown_principal_cannot_register_itself_as_administrator(stack, shipped_acl):  # noqa: F811
    stack["handler"]._acl = shipped_acl
    mallory = Identity.generate()

    resp = stack["handler"].handle(
        _register_request(mallory, "mallory", mallory.public_key, 0x01),
        _unknown_ctx(mallory),
    )

    assert resp[0] == 1
    assert b"administrator" in resp

    stack["dispatcher"].dispatch_origin(ORIGIN)
    assert stack["users"].get_user_by_pubkey(ORIGIN, mallory.public_key) is None


def test_unknown_principal_cannot_register_itself_as_moderator(stack, shipped_acl):  # noqa: F811
    stack["handler"]._acl = shipped_acl
    mallory = Identity.generate()

    resp = stack["handler"].handle(
        _register_request(mallory, "mallory", mallory.public_key, 0x02),
        _unknown_ctx(mallory),
    )

    assert resp[0] == 1


def test_ordinary_registration_still_works(stack, shipped_acl):  # noqa: F811
    """The documented first-run flow must be untouched: flags=0 is what the
    gateway's register tool publishes."""
    stack["handler"]._acl = shipped_acl
    alice = Identity.generate()

    resp = stack["handler"].handle(
        _register_request(alice, "alice", alice.public_key, 0x00),
        _unknown_ctx(alice),
    )

    assert resp[0] == 0, resp[:120]
    stack["dispatcher"].dispatch_origin(ORIGIN)
    row = stack["users"].get_user_by_pubkey(ORIGIN, alice.public_key)
    assert row is not None and row["username"] == "alice" and row["flags"] == 0


def test_an_administrator_may_still_set_flags(stack, shipped_acl):  # noqa: F811
    """The gate is on who sets privilege, not on privilege existing.

    Note what reaching this case requires. The shipped ACL grants
    `bonnet.user.register` to `match.unknown` alone, and the matchers are
    mutually exclusive, so on the default config *no* principal can both hold
    the administrator role and publish a registration — the flags path is shut
    entirely. An operator who wants to provision privileged users has to say so
    with a rule, exactly as config.example.toml's commented moderation examples
    do. That rule is what this test adds.
    """
    stack["handler"]._acl = shipped_acl
    shipped_acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(role="administrator"),
            actions=["write"],
            commands=["PUBLISH_RECORD"],
            kinds=["bonnet.user.register"],
        )
    )
    admin = Identity.generate()
    ctx = FirehoseContext(
        peer_pubkey=admin.public_key,
        is_registered=True,
        role="administrator",
        origin=ORIGIN,
    )

    resp = stack["handler"].handle(_register_request(admin, "admin", admin.public_key, 0x01), ctx)

    assert resp[0] == 0, resp[:120]


def test_shipped_config_grants_no_one_both_the_role_and_the_kind(shipped_acl):
    """Pins the property the test above depends on: on the default config the
    privileged-registration path is unreachable, not merely gated."""
    admin_ctx = FirehoseContext(
        peer_pubkey=b"\x01" * 32, is_registered=True, role="administrator", origin=ORIGIN
    ).to_auth_context()

    assert not shipped_acl.check(
        admin_ctx, "write", command="PUBLISH_RECORD", kind="bonnet.user.register"
    )


def test_a_pre_armed_admin_flag_does_not_survive_to_defeat_a_ban(stack, shipped_acl):  # noqa: F811
    """The escalation mattered because administrators skip the punishment
    gate, so a key registered with flags=0x01 was permanently unbannable.
    Registration is refused, so the exemption is never acquired."""
    stack["handler"]._acl = shipped_acl
    spammer = Identity.generate()

    refused = stack["handler"].handle(
        _register_request(spammer, "spammer", spammer.public_key, 0x01),
        _unknown_ctx(spammer),
    )
    assert refused[0] == 1

    stack["dispatcher"].dispatch_origin(ORIGIN)
    row = stack["users"].get_user_by_pubkey(ORIGIN, spammer.public_key)
    assert row is None or row["flags"] == 0


# ---------------------------------------------------------------------------
# subject key
# ---------------------------------------------------------------------------


def test_cannot_register_a_username_onto_another_key(stack, shipped_acl):  # noqa: F811
    stack["handler"]._acl = shipped_acl
    mallory = Identity.generate()
    victim = Identity.generate()

    resp = stack["handler"].handle(
        _register_request(mallory, "treasurer", victim.public_key, 0x00),
        _unknown_ctx(mallory),
    )

    assert resp[0] == 1
    stack["dispatcher"].dispatch_origin(ORIGIN)
    assert stack["users"].get_user_by_pubkey(ORIGIN, victim.public_key) is None


def test_an_administrator_may_register_another_key(stack, shipped_acl):  # noqa: F811
    """The operator-provisioning case, which `console.grant-role` relies on:
    it registers a third party's key with a role over the local connection,
    and that connection authenticates as administrator."""
    stack["handler"]._acl = shipped_acl
    shipped_acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(role="administrator"),
            actions=["write"],
            commands=["PUBLISH_RECORD"],
            kinds=["bonnet.user.register"],
        )
    )
    operator = Identity.generate()
    newcomer = Identity.generate()
    ctx = FirehoseContext(
        peer_pubkey=operator.public_key,
        is_registered=True,
        role="administrator",
        origin=ORIGIN,
    )

    resp = stack["handler"].handle(
        _register_request(operator, "newcomer", newcomer.public_key, 0x02), ctx
    )

    assert resp[0] == 0, resp[:120]
    stack["dispatcher"].dispatch_origin(ORIGIN)
    row = stack["users"].get_user_by_pubkey(ORIGIN, newcomer.public_key)
    assert row is not None and row["flags"] == 0x02


def test_the_validator_stays_schema_only(stack):  # noqa: F811
    """Both rules are authorization, not schema: an intent naming a third
    party's key is well-formed, and the validator must not be the thing that
    rejects it — otherwise the administrator exemption above is unreachable."""
    mallory = Identity.generate()
    victim = Identity.generate()
    intent = Intent(
        event_id=os.urandom(32),
        kind="bonnet.user.register",
        origin=ORIGIN,
        actor_pubkey=mallory.public_key,
        metadata=MetadataMap(
            fields=[
                metadata_text(1, "treasurer"),
                metadata_bytes(2, victim.public_key),
                metadata_u64(3, 0x01),
            ]
        ),
    )

    KindValidator().validate(intent)


# ---------------------------------------------------------------------------
# idempotency: same key + same name + same flags is a duplicate
# ---------------------------------------------------------------------------


def _registered_ctx(identity, role=""):
    return FirehoseContext(
        peer_pubkey=identity.public_key, is_registered=True, role=role, origin=ORIGIN
    )


def test_same_key_same_name_same_flags_is_refused_as_duplicate(stack, shipped_acl):  # noqa: F811
    """Repeat connect+register loops must not spam the log: the second
    identical registration is refused so the gateway maps it to
    already_registered instead of appending a new seq."""
    stack["handler"]._acl = shipped_acl
    # The shipped default grants user.register to unknown only, so a second
    # publish as a registered principal would stop at the ACL ("Not
    # permitted") before reaching dedupe. Deployments with a permissive
    # wildcard rule (and the gateway's already_registered mapping) hit the
    # handler itself — grant that here so the dedupe is what's under test.
    shipped_acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(registered=True),
            actions=["write"],
            commands=["PUBLISH_RECORD"],
            kinds=["bonnet.user.register"],
        )
    )
    alice = Identity.generate()

    first = stack["handler"].handle(
        _register_request(alice, "alice", alice.public_key, 0x00),
        _unknown_ctx(alice),
    )
    assert first[0] == 0, first[:120]
    stack["dispatcher"].dispatch_origin(ORIGIN)
    head_before = stack["firehose"].get_head(ORIGIN).event_count

    second = stack["handler"].handle(
        _register_request(alice, "alice", alice.public_key, 0x00),
        _registered_ctx(alice),
    )
    assert second[0] == 1
    assert b"already registered to this key" in second
    stack["dispatcher"].dispatch_origin(ORIGIN)
    assert stack["firehose"].get_head(ORIGIN).event_count == head_before


def test_same_key_same_name_changed_flags_still_allows_admin_role_update(stack, shipped_acl):  # noqa: F811
    """The carve-out grant-role relies on: same (name, key) with different
    flags is a role update, not a duplicate, and stays allowed for admins."""
    stack["handler"]._acl = shipped_acl
    shipped_acl.add_rule(
        ACLRule(
            effect="allow",
            matcher=PrincipalMatcher(role="administrator"),
            actions=["write"],
            commands=["PUBLISH_RECORD"],
            kinds=["bonnet.user.register"],
        )
    )
    operator = Identity.generate()
    newcomer = Identity.generate()
    ctx = FirehoseContext(
        peer_pubkey=operator.public_key,
        is_registered=True,
        role="administrator",
        origin=ORIGIN,
    )

    # Operator provisions newcomer with no role, then grants admin. The
    # actor fields stay the operator's; the subject (metadata) is newcomer.
    first = stack["handler"].handle(
        _register_request(operator, "newcomer", newcomer.public_key, 0x00), ctx
    )
    assert first[0] == 0, first[:120]
    stack["dispatcher"].dispatch_origin(ORIGIN)

    grant = stack["handler"].handle(
        _register_request(operator, "newcomer", newcomer.public_key, 0x01), ctx
    )
    assert grant[0] == 0, grant[:120]
    stack["dispatcher"].dispatch_origin(ORIGIN)
    row = stack["users"].get_user_by_pubkey(ORIGIN, newcomer.public_key)
    assert row is not None and row["flags"] == 0x01

    # Repeating the identical grant is now a duplicate, not a new record.
    head_before = stack["firehose"].get_head(ORIGIN).event_count
    again = stack["handler"].handle(
        _register_request(operator, "newcomer", newcomer.public_key, 0x01), ctx
    )
    assert again[0] == 1
    assert b"already registered to this key" in again
    stack["dispatcher"].dispatch_origin(ORIGIN)
    assert stack["firehose"].get_head(ORIGIN).event_count == head_before


def test_register_subject_helper_distinguishes_grant_from_self_register():
    """The gateway display fix: actor=root + subject=lanternfly must not
    read as a root re-register."""
    import time

    from bonnet.core.record import ZERO_ID, Record
    from bonnet.gateway.tools import _register_subject

    self_reg = Record(
        origin=ORIGIN,
        origin_seq=1,
        event_id=os.urandom(32),
        kind="bonnet.user.register",
        schema_version=1,
        created_at=int(time.time()),
        actor_pubkey=b"\x01" * 32,
        actor_username="root",
        actor_registrar=ORIGIN,
        board="",
        article_id=ZERO_ID,
        article_num=0,
        target_origin="",
        target_board="",
        target_article_id=ZERO_ID,
        target_event_id=ZERO_ID,
        metadata=MetadataMap(
            fields=[
                metadata_text(1, "root"),
                metadata_bytes(2, b"\x01" * 32),
                metadata_u64(3, 0),
            ]
        ),
        body_hash=ZERO_ID,
        body_size=0,
        actor_signature=b"\x00" * 64,
        origin_signature=b"\x00" * 64,
    )
    assert _register_subject(self_reg) == ("root", "01" * 32, 0)

    grant = Record(
        origin=ORIGIN,
        origin_seq=5,
        event_id=os.urandom(32),
        kind="bonnet.user.register",
        schema_version=1,
        created_at=int(time.time()),
        actor_pubkey=b"\x01" * 32,
        actor_username="root",
        actor_registrar=ORIGIN,
        board="",
        article_id=ZERO_ID,
        article_num=0,
        target_origin="",
        target_board="",
        target_article_id=ZERO_ID,
        target_event_id=ZERO_ID,
        metadata=MetadataMap(
            fields=[
                metadata_text(1, "lanternfly"),
                metadata_bytes(2, b"\x02" * 32),
                metadata_u64(3, 1),
            ]
        ),
        body_hash=ZERO_ID,
        body_size=0,
        actor_signature=b"\x00" * 64,
        origin_signature=b"\x00" * 64,
    )
    assert _register_subject(grant) == ("lanternfly", "02" * 32, 1)

    other = Record(
        origin=ORIGIN,
        origin_seq=6,
        event_id=os.urandom(32),
        kind="bonnet.article",
        schema_version=1,
        created_at=int(time.time()),
        actor_pubkey=b"\x01" * 32,
        actor_username="root",
        actor_registrar=ORIGIN,
        board="general",
        article_id=os.urandom(32),
        article_num=1,
        target_origin="",
        target_board="",
        target_article_id=ZERO_ID,
        target_event_id=ZERO_ID,
        metadata=MetadataMap(fields=[]),
        body_hash=ZERO_ID,
        body_size=0,
        actor_signature=b"\x00" * 64,
        origin_signature=b"\x00" * 64,
    )
    assert _register_subject(other) == ("", "", None)
