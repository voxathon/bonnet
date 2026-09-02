"""Author identity: what a name on a record means, and what it costs to lie.

Three rules, and the seam between them is the point:

  - On a record published *here*, `actor_username` and `actor_registrar` must
    be the ones this origin issued to the signing key. Refused, not rewritten,
    because both fields are inside the bytes the actor signed.
  - A username is held by one live key per origin, first writer wins.
  - On a record arriving by federation, neither can be enforced — it is another
    origin's log and it is relayed verbatim. What happens instead is that the
    claim is resolved as far as it can be locally and the answer is *recorded*
    (`author_check`), never acted on: nothing is filtered, hidden or refused.

The last one is the containment principle. A hostile origin can say what it
likes in its own log; it just cannot make this relay repeat the claim as if
this relay had established it.
"""

import os
import struct

import pytest

from bonnet.core.board_projection import (
    AUTHOR_FOREIGN,
    AUTHOR_REGISTRY,
    AUTHOR_UNCHECKED,
    AUTHOR_UNREGISTERED,
)
from bonnet.core.crypto import Identity
from bonnet.core.firehose import FirehoseStore
from bonnet.core.record import (
    Intent,
    MetadataMap,
    Record,
    compute_body_hash,
    encode_intent,
    encode_record,
    metadata_bytes,
    metadata_text,
    metadata_u64,
    sign_intent,
)
from bonnet.net.firehose_commands import FirehoseContext
from bonnet.net.firehose_sync import SyncClient, SyncManager
from bonnet.net.firehose_wire import OP_PUBLISH_RECORD
from tests.test_commands_and_sync import _create_board, firehose, stack  # noqa: F401  (fixtures)
from tests.test_federation import _OriginServer
from tests.test_registration_privilege import shipped_acl  # noqa: F401  (fixture)

ORIGIN = "bbs.test"


@pytest.fixture
def wired(stack, shipped_acl):  # noqa: F811
    """The stack under the ACL config.example.toml actually ships: unknown
    principals may register, registered ones may publish articles."""
    stack["handler"]._acl = shipped_acl
    _create_board(stack["handler"], "general")
    return stack


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _publish(handler, identity, ctx, kind="bonnet.article", **fields):
    body = fields.pop("body", b"hello")
    intent = Intent(
        event_id=os.urandom(32),
        kind=kind,
        origin=ORIGIN,
        actor_pubkey=identity.public_key,
        body_hash=compute_body_hash(body),
        body_size=len(body),
        **fields,
    )
    encoded = encode_intent(intent)
    req = struct.pack(">B", OP_PUBLISH_RECORD)
    req += struct.pack(">I", len(encoded)) + encoded
    req += sign_intent(identity, encoded)
    req += struct.pack(">I", len(body)) + body
    return handler.handle(req, ctx)


def _article_fields(subject="Test", **extra):
    return dict(
        board="general",
        article_id=os.urandom(32),
        metadata=MetadataMap([metadata_text(1, subject), metadata_text(4, "text/plain")]),
        **extra,
    )


def _register(wired, identity, username):
    intent = Intent(
        event_id=os.urandom(32),
        kind="bonnet.user.register",
        origin=ORIGIN,
        actor_pubkey=identity.public_key,
        actor_username=username,
        metadata=MetadataMap(
            [
                metadata_text(1, username),
                metadata_bytes(2, identity.public_key),
                metadata_u64(3, 0),
            ]
        ),
    )
    encoded = encode_intent(intent)
    req = struct.pack(">B", OP_PUBLISH_RECORD)
    req += struct.pack(">I", len(encoded)) + encoded
    req += sign_intent(identity, encoded)
    req += struct.pack(">I", 0)
    resp = wired["handler"].handle(
        req, FirehoseContext(peer_pubkey=identity.public_key, is_unknown=True, origin=ORIGIN)
    )
    wired["dispatcher"].dispatch_origin(ORIGIN)
    return resp


def _registered_ctx(identity):
    return FirehoseContext(peer_pubkey=identity.public_key, is_registered=True, origin=ORIGIN)


# ---------------------------------------------------------------------------
# publishing under a name
# ---------------------------------------------------------------------------


def test_a_name_the_origin_never_issued_is_refused(wired):
    """The original finding: an unregistered key published an article
    attributed to root@whitehouse.gov, and it federated that way."""
    mallory = Identity.generate()

    resp = _publish(
        wired["handler"],
        mallory,
        _registered_ctx(mallory),
        **_article_fields(
            subject="Official notice",
            actor_username="root",
            actor_registrar="whitehouse.gov",
        ),
    )

    assert resp[0] == 1
    assert b"actor_registrar" in resp


def test_a_local_record_cannot_credit_another_registrar(wired):
    alice = Identity.generate()
    _register(wired, alice, "alice")

    resp = _publish(
        wired["handler"],
        alice,
        _registered_ctx(alice),
        **_article_fields(actor_username="alice", actor_registrar="elsewhere.test"),
    )

    assert resp[0] == 1
    assert b"actor_registrar" in resp


def test_a_registered_key_cannot_publish_under_someone_elses_name(wired):
    alice = Identity.generate()
    bob = Identity.generate()
    _register(wired, alice, "alice")
    _register(wired, bob, "bob")

    resp = _publish(
        wired["handler"],
        bob,
        _registered_ctx(bob),
        **_article_fields(actor_username="alice", actor_registrar=ORIGIN),
    )

    assert resp[0] == 1
    assert b"actor_username" in resp


def test_the_registered_name_is_accepted_and_resolves(wired):
    alice = Identity.generate()
    _register(wired, alice, "alice")

    resp = _publish(
        wired["handler"],
        alice,
        _registered_ctx(alice),
        **_article_fields(actor_username="alice", actor_registrar=ORIGIN),
    )
    assert resp[0] == 0, resp[:120]

    wired["dispatcher"].dispatch_origin(ORIGIN)
    bp = wired["dispatcher"]._get_board_projection(ORIGIN, "general")
    art = bp.list_articles(ORIGIN, "general")[0]
    assert art.author_username == "alice"
    assert art.author_check == AUTHOR_REGISTRY


def test_claiming_no_name_stays_legal(wired):
    """Anonymity is honest; only a false claim is not."""
    nobody = Identity.generate()

    resp = _publish(
        wired["handler"], nobody, _registered_ctx(nobody), **_article_fields(subject="Quiet")
    )
    assert resp[0] == 0, resp[:120]

    wired["dispatcher"].dispatch_origin(ORIGIN)
    bp = wired["dispatcher"]._get_board_projection(ORIGIN, "general")
    art = bp.list_articles(ORIGIN, "general")[0]
    assert art.author_check == AUTHOR_UNCHECKED


# ---------------------------------------------------------------------------
# one live key per name
# ---------------------------------------------------------------------------


def test_a_second_key_cannot_take_a_live_name(wired):
    first = Identity.generate()
    squatter = Identity.generate()

    assert _register(wired, first, "alice")[0] == 0
    resp = _register(wired, squatter, "alice")

    assert resp[0] == 1
    assert b"already registered" in resp
    assert wired["users"].get_user_by_pubkey(ORIGIN, squatter.public_key) is None
    assert wired["users"].get_user_by_pubkey(ORIGIN, first.public_key)["username"] == "alice"


def test_the_same_key_may_re_register_its_own_name(wired):
    alice = Identity.generate()
    assert _register(wired, alice, "alice")[0] == 0
    assert _register(wired, alice, "alice")[0] == 0


def test_the_projection_enforces_it_independently_of_the_handler(wired):
    """Federated registrations never reach `_cmd_publish`, so the rule cannot
    live only there."""
    users = wired["users"]
    first, squatter = Identity.generate(), Identity.generate()

    def reg_record(identity, seq):
        return Record(
            origin="remote.test",
            origin_seq=seq,
            event_id=os.urandom(32),
            kind="bonnet.user.register",
            actor_pubkey=identity.public_key,
            metadata=MetadataMap(
                [
                    metadata_text(1, "alice"),
                    metadata_bytes(2, identity.public_key),
                    metadata_u64(3, 0),
                ]
            ),
            created_at=1,
        )

    users.apply_user_register(reg_record(first, 1))
    users.apply_user_register(reg_record(squatter, 2))

    assert users.get_user_by_pubkey("remote.test", first.public_key)["username"] == "alice"
    assert users.get_user_by_pubkey("remote.test", squatter.public_key) is None


def test_revocation_frees_the_name(wired):
    """Otherwise a squatter burns every good name permanently."""
    users = wired["users"]
    gone, newcomer = Identity.generate(), Identity.generate()

    users.apply_user_register(
        Record(
            origin="remote.test",
            origin_seq=1,
            event_id=os.urandom(32),
            kind="bonnet.user.register",
            actor_pubkey=gone.public_key,
            metadata=MetadataMap(
                [
                    metadata_text(1, "alice"),
                    metadata_bytes(2, gone.public_key),
                    metadata_u64(3, 0),
                ]
            ),
            created_at=1,
        )
    )
    assert users.username_holder("remote.test", "alice") == gone.public_key

    users.apply_user_revoke(
        Record(
            origin="remote.test",
            origin_seq=2,
            event_id=os.urandom(32),
            kind="bonnet.user.revoke",
            actor_pubkey=gone.public_key,
            target_origin="remote.test",
            metadata=MetadataMap([metadata_bytes(1, gone.public_key)]),
            created_at=2,
        )
    )
    assert users.username_holder("remote.test", "alice") is None

    users.apply_user_register(
        Record(
            origin="remote.test",
            origin_seq=3,
            event_id=os.urandom(32),
            kind="bonnet.user.register",
            actor_pubkey=newcomer.public_key,
            metadata=MetadataMap(
                [
                    metadata_text(1, "alice"),
                    metadata_bytes(2, newcomer.public_key),
                    metadata_u64(3, 0),
                ]
            ),
            created_at=3,
        )
    )
    assert users.username_holder("remote.test", "alice") == newcomer.public_key


# ---------------------------------------------------------------------------
# federation: contained, not censored
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_a_foreign_claim_is_relayed_verbatim_and_marked(tmp_path):
    """The containment principle, end to end.

    A hostile origin publishes an article crediting a reputable origin as
    registrar. Everything about the record survives: it passes ingest, it is
    stored byte-identical, and it is served on unchanged. What does *not*
    happen is this relay repeating the claim as established fact.
    """
    from bonnet.core.bodies import BodyStore
    from bonnet.core.dispatcher import Dispatcher
    from bonnet.core.global_projections import NavProjection, PolicyProjection, UserProjection

    evil = _OriginServer(tmp_path, "evil.test")
    body = b"I never wrote this."
    intent = Intent(
        event_id=os.urandom(32),
        kind="bonnet.article",
        origin="evil.test",
        actor_pubkey=evil.identity.public_key,
        actor_username="alice",
        actor_registrar="respectable.test",
        board="general",
        article_id=os.urandom(32),
        metadata=MetadataMap([metadata_text(1, "Confession"), metadata_text(4, "text/plain")]),
        body_hash=compute_body_hash(body),
        body_size=len(body),
    )
    original = evil.store.append_record(
        evil.identity, intent, sign_intent(evil.identity, encode_intent(intent)), body
    )
    original_bytes = encode_record(original)

    store = FirehoseStore(str(tmp_path / "mine.db"))
    nav = NavProjection(str(tmp_path / "nav.db"))
    users = UserProjection(str(tmp_path / "users.db"))
    policy = PolicyProjection(str(tmp_path / "policy.db"))
    bodies = BodyStore(str(tmp_path / "boards"), str(tmp_path / "event_bodies"))
    dispatcher = Dispatcher(
        firehose=store,
        nav=nav,
        users=users,
        policy=policy,
        boards_dir=str(tmp_path / "boards"),
        body_store=bodies,
        local_origin=ORIGIN,
    )

    class Peer(SyncClient):
        async def fetch_head(self, origin):
            return evil.store.get_head(origin), b""

        async def fetch_range(self, origin, start_seq, max_count):
            return [(r, []) for r in evil.store.get_events_range(origin, start_seq, max_count)]

        def peer_identity(self):
            return evil.identity.public_key, "evil.test"

        async def close(self):
            pass

    nav.apply_board_create(
        Record(
            origin="evil.test",
            origin_seq=0,
            event_id=os.urandom(32),
            kind="bonnet.board.create",
            actor_pubkey=evil.identity.public_key,
            board="general",
            metadata=MetadataMap([metadata_bytes(1, evil.identity.public_key)]),
            created_at=0,
        )
    )

    mgr = SyncManager(store, Identity.generate(), "myrelay.test", dispatcher=dispatcher)
    peer = Peer()
    mgr._clients["evil.test"] = peer
    result = await mgr._sync_once("evil.test", peer)

    # accepted, stored, and byte-identical: relay behaviour is untouched
    assert result.accepted
    stored = store.get_event_by_id("evil.test", intent.event_id)
    assert encode_record(stored) == original_bytes
    assert stored.actor_username == "alice"
    assert stored.actor_registrar == "respectable.test"

    # but the claim is recorded as unestablished, not repeated as fact
    bp = dispatcher._get_board_projection("evil.test", "general")
    art = bp.list_articles("evil.test", "general")[0]
    assert art.author_username == "alice"
    assert art.author_registrar == "respectable.test"
    assert art.author_check == AUTHOR_FOREIGN

    dispatcher.close()
    nav.close()
    users.close()
    policy.close()
    store.close()
    evil.store.close()


def test_a_same_origin_claim_with_no_registration_reads_unregistered(wired):
    """Distinct from `foreign`: here the naming origin *is* the publishing
    origin, so the question is answerable, and the answer is no."""
    ghost = Identity.generate()
    rec = Record(
        origin=ORIGIN,
        origin_seq=1,
        event_id=os.urandom(32),
        kind="bonnet.article",
        actor_pubkey=ghost.public_key,
        actor_username="phantom",
        actor_registrar=ORIGIN,
        board="general",
        article_id=os.urandom(32),
        article_num=1,
        metadata=MetadataMap([metadata_text(1, "Hi"), metadata_text(4, "text/plain")]),
        created_at=1,
    )

    assert wired["dispatcher"]._resolve_author_check(rec) == AUTHOR_UNREGISTERED


# ---------------------------------------------------------------------------
# querying by name
# ---------------------------------------------------------------------------


def _seed(bp, username, registrar, check, num):
    bp.apply_article(
        Record(
            origin=ORIGIN,
            origin_seq=num,
            event_id=os.urandom(32),
            kind="bonnet.article",
            actor_pubkey=os.urandom(32),
            actor_username=username,
            actor_registrar=registrar,
            board="general",
            article_id=os.urandom(32),
            article_num=num,
            metadata=MetadataMap([metadata_text(1, f"post {num}"), metadata_text(4, "text/plain")]),
            created_at=num,
        ),
        author_check=check,
    )


def test_a_bare_username_query_still_matches_every_registrar(wired):
    """Loose queries stay loose. Searching a name without a registrar must not
    come back empty just because the name is ambiguous."""
    bp = wired["dispatcher"]._get_board_projection(ORIGIN, "general")
    _seed(bp, "alice", ORIGIN, AUTHOR_REGISTRY, 1)
    _seed(bp, "alice", "respectable.test", AUTHOR_FOREIGN, 2)

    hits = bp.query_articles(ORIGIN, "general", [(0x02, 0x01, "alice")])
    assert len(hits) == 2


def test_adding_the_registrar_narrows_to_one_identity(wired):
    bp = wired["dispatcher"]._get_board_projection(ORIGIN, "general")
    _seed(bp, "alice", ORIGIN, AUTHOR_REGISTRY, 1)
    _seed(bp, "alice", "respectable.test", AUTHOR_FOREIGN, 2)

    hits = bp.query_articles(
        ORIGIN, "general", [(0x02, 0x01, "alice"), (0x03, 0x01, "respectable.test")]
    )
    assert len(hits) == 1
    assert hits[0].author_registrar == "respectable.test"
    assert hits[0].author_check == AUTHOR_FOREIGN
