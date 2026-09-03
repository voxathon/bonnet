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

"""Tests for server lifecycle: construction, root registration, and close."""

import os

import pytest

from bonnet.app.console import OperatorConsole
from bonnet.core.config import FirehoseConfig
from bonnet.core.record import Intent, MetadataMap, compute_body_hash, encode_intent, sign_intent


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


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_server_constructs(server):
    """Server constructs with all components wired."""
    assert server.server_identity is not None
    assert server.config.origin == "bbs.test"
    assert server.firehose is not None
    assert server.nav is not None
    assert server.users is not None
    assert server.policy is not None
    assert server.body_store is not None
    assert server.dispatcher is not None
    assert server.command_handler is not None
    assert server.http_server is not None
    assert server.replay_ledger is not None
    assert server.rate_limiter is not None


def test_server_identity_persisted(server, config):
    """Server identity is persisted to disk and stable across restarts."""
    identity_path = config.identity_path
    assert os.path.exists(identity_path)

    with open(identity_path, "rb") as f:
        saved_key = f.read()
    assert saved_key == server.server_identity.private_key


# ---------------------------------------------------------------------------
# Root registration
# ---------------------------------------------------------------------------


def test_root_user_registered(server):
    """Root user is registered on first startup."""
    user = server.users.get_user_by_pubkey("bbs.test", server.server_identity.public_key)
    assert user is not None
    assert user["username"] == "root"
    assert user.get("flags", 0) & 0x01, "root should have admin flag"


def test_root_registration_idempotent(server, config):
    """Restarting the server does not create a second root user."""
    server_identity = server.server_identity

    from bonnet.app.server import BonnetServer

    server2 = BonnetServer(config)
    try:
        user = server2.users.get_user_by_pubkey("bbs.test", server_identity.public_key)
        assert user is not None
        assert user["username"] == "root"

        all_users = server2.users.list_users("bbs.test")
        root_users = [u for u in all_users if u["username"] == "root"]
        assert len(root_users) == 1
    finally:
        server2.close()


async def test_register_user_rebinds_server_identity(server):
    """REPL register-user reuses the server identity key and REPLACES its
    existing registration row.

    This test pins current semantics: the new username replaces 'root' and
    the row carries flags=0 (no admin badge), even though the pubkey keeps
    administrator authority via the default ACL pubkey rule. Any change to
    this behavior must update this test deliberately.
    """
    result = await OperatorConsole(server)._repl_register_user(["bob"])
    assert "bob" in result.lower()
    assert "replaces" in result.lower()

    user = server.users.get_user_by_pubkey("bbs.test", server.server_identity.public_key)
    assert user is not None
    assert user["username"] == "bob"
    assert not user.get("flags", 0) & 0x01

    all_users = server.users.list_users("bbs.test")
    usernames = [u["username"] for u in all_users]
    assert usernames == ["bob"]


async def test_create_board_after_rename_succeeds(server, monkeypatch):
    """Renaming the admin identity away from 'root' must not break
    create-board/publish-article for the renamed identity.

    Regression test: these commands used to hardcode actor_username="root"
    when signing records locally, so after register-user renamed the
    server's own key, the origin's own actor-username check
    (firehose_commands.py) rejected every subsequent record it tried to
    publish.
    """
    monkeypatch.setattr("builtins.input", lambda *a, **k: "")

    console = OperatorConsole(server)
    await console._repl_register_user(["chaosb"])

    result = console._do_create_board(["testboard"])
    assert "created" in result.lower()
    assert "Error 0x0004" not in result


def test_publish_article_oversized_subject_gives_clean_error(server, monkeypatch):
    """An article subject over the wire's 4096-byte MAX_TEXT_FIELD used to
    surface only as 'Error 0x0000: Internal error' - the actual reason
    (LengthExceeded, a CodecError) fell outside the tuple of exceptions
    firehose_commands.py's dispatch loop translated into a clean 0x0006
    response, so it was swallowed into the generic internal-error branch
    and logged server-side only.
    """
    monkeypatch.setattr("builtins.input", lambda *a, **k: "")

    console = OperatorConsole(server)
    console._do_create_board(["testboard"])

    responses = iter(["x" * 5000, "", "hello", ""])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(responses))

    result = console._do_publish_article(["testboard"])
    assert "Internal error" not in result
    assert "exceeds" in result.lower()


def test_get_article_rejects_negative_article_num(server):
    """A negative article number used to reach struct.pack('>Q', ...)
    directly and raise its raw format-string error instead of a clean
    usage message."""
    console = OperatorConsole(server)
    result = console._cmd_get_article(["get-article", "testboard", "-1"])
    assert "format requires" not in result
    assert "Invalid article number" in result


def test_event_range_rejects_negative_start_and_oversized_count(server):
    """Same struct.pack bug for event-range's start (packed '>Q') and
    count (packed '>H')."""
    console = OperatorConsole(server)

    result = console._cmd_event_range(["event-range", "bbs.test", "-5", "-10"])
    assert "format requires" not in result
    assert "Invalid start" in result

    result = console._cmd_event_range(["event-range", "bbs.test", "0", "999999999"])
    assert "format requires" not in result
    assert "Invalid count" in result


def test_list_articles_rejects_negative_offset(server):
    console = OperatorConsole(server)
    result = console._cmd_list_articles(["list-articles", "testboard", "-1"])
    assert "out of range" not in result
    assert "Invalid offset" in result


def test_get_article_strips_ansi_and_bidi_from_subject_and_body(server, monkeypatch):
    """Article subject/content carry no character-class validation at
    publish time (kind_validator.py's _validate_article only checks a
    subject is present) - an embedded ANSI escape or Unicode bidi override
    used to round-trip intact and render as a live terminal control
    sequence in the REPL's own get-article/list-articles output."""
    monkeypatch.setattr("builtins.input", lambda *a, **k: "")
    console = OperatorConsole(server)
    console._do_create_board(["testboard"])

    evil_subject = "hello\x1b[31mDANGER"
    evil_body_lines = iter([evil_subject, "", "line one‮evil", ""])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(evil_body_lines))

    result = console._do_publish_article(["testboard"])
    assert "published" in result.lower()

    view = console._cmd_get_article(["get-article", "testboard", "1"])
    assert "\x1b" not in view
    assert "‮" not in view
    assert "DANGER" in view  # sanitized, not deleted wholesale
    assert "evil" in view

    listing = console._cmd_list_articles(["list-articles", "testboard"])
    assert "\x1b" not in listing


def test_publish_article_to_nonexistent_board_is_rejected(server, monkeypatch):
    """publish-article used to silently auto-create the board projection
    for any name (BoardProjection is lazily instantiated on first touch,
    with no existence check anywhere in the write path), contradicting the
    documented create-a-board-first flow."""
    monkeypatch.setattr("builtins.input", lambda *a, **k: "should not be prompted")

    console = OperatorConsole(server)
    result = console._do_publish_article(["never-created"])
    assert "does not exist" in result
    assert server.nav.get_board(server.config.origin, "never-created") is None


def test_create_board_reports_existing_name(server, monkeypatch):
    """create-board on a name that already exists used to re-report
    'created' with no signal that nothing changed."""
    monkeypatch.setattr("builtins.input", lambda *a, **k: "")

    console = OperatorConsole(server)
    first = console._do_create_board(["dup"])
    assert "created" in first.lower()

    second = console._do_create_board(["dup"])
    assert "already exists" in second.lower()


def test_list_boards_truncates_long_name_for_display(server, monkeypatch):
    """A board name has no length policy beyond the wire's 4096-byte
    MAX_TEXT_FIELD (kind_validator.py's identity_text_violation) - list-boards
    must not flood the REPL with an unreadable line for one, but the
    truncation is display-only and must not touch the stored/signed name."""
    monkeypatch.setattr("builtins.input", lambda *a, **k: "")

    console = OperatorConsole(server)
    long_name = "b" * 200  # under MAX_BOARD (255) but over the display width

    result = console._do_create_board([long_name])
    assert "created" in result.lower()

    result = console._cmd_list_boards(["list-boards"])
    assert "…" in result
    assert long_name not in result


# ---------------------------------------------------------------------------
# Close
# ---------------------------------------------------------------------------


def test_double_close_safe(server):
    """close() can be called twice without raising."""
    server.close()
    server.close()


def test_close_releases_resources(server):
    """After close, SQLite connections are closed."""
    server.close()

    with pytest.raises(Exception):
        server.firehose.get_highest_seq("bbs.test")

    with pytest.raises(Exception):
        server.nav.list_boards()


# ---------------------------------------------------------------------------
# Identity persistence across restart
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# admin_pubkey ACL wiring
# ---------------------------------------------------------------------------


def test_admin_pubkey_grants_admin_alongside_existing_acl_rules(tmp_path):
    """A FirehoseConfig built directly (not via .load()) with admin_pubkey_hex
    set AND pre-existing [[acl]] rules must still grant that key admin — the
    bug was that it only worked when acl._rules was completely empty. The
    server's own identity must still also be admin (the documented
    invariant), not replaced by the configured key."""
    from bonnet.app.server import BonnetServer
    from bonnet.core.acl import ACLEvaluator, ACLRule, PrincipalMatcher

    admin_hex = "cd" * 32
    config = FirehoseConfig(
        origin="bbs.test",
        hostname="bbs.test",
        data_dir=str(tmp_path / "data"),
        boards_dir=str(tmp_path / "boards"),
        events_bodies_dir=str(tmp_path / "event_bodies"),
        port=2272,
        tls_enabled=False,
        admin_pubkey_hex=admin_hex,
        acl=ACLEvaluator(
            [
                ACLRule(
                    effect="allow",
                    matcher=PrincipalMatcher(anonymous=True),
                    actions=["read"],
                    commands=["BOARD_LIST"],
                    boards=["*"],
                )
            ]
        ),
    )
    os.makedirs(config.data_dir, exist_ok=True)
    os.makedirs(config.boards_dir, exist_ok=True)
    os.makedirs(config.events_bodies_dir, exist_ok=True)

    s = BonnetServer(config)
    try:
        admin_bytes = bytes.fromhex(admin_hex)
        assert any(r.matcher.pubkey == admin_bytes and r.effect == "allow" for r in s.acl._rules), (
            "configured admin_pubkey must be granted admin"
        )
        assert any(
            r.matcher.pubkey == s.server_identity.public_key and r.effect == "allow"
            for r in s.acl._rules
        ), "the server's own identity must still be its own admin regardless of what's configured"
    finally:
        s.close()


def test_identity_stable_across_restart(config):
    """Server identity is the same after restart."""
    os.makedirs(config.data_dir, exist_ok=True)
    os.makedirs(config.boards_dir, exist_ok=True)
    os.makedirs(config.events_bodies_dir, exist_ok=True)

    from bonnet.app.server import BonnetServer

    s1 = BonnetServer(config)
    pubkey1 = s1.server_identity.public_key
    s1.close()

    s2 = BonnetServer(config)
    pubkey2 = s2.server_identity.public_key
    s2.close()

    assert pubkey1 == pubkey2


# ---------------------------------------------------------------------------
# Orphaned staged body recovery (internal/BUGS.md #4's crash-window half)
# ---------------------------------------------------------------------------


def _stage_body(server, board, event_id, body):
    server.body_store.stage_article_body(
        "bbs.test", board, event_id, body, compute_body_hash(body), len(body)
    )


def _append_article_record(server, board, event_id, article_id, body):
    intent = Intent(
        event_id=event_id,
        kind="bonnet.article",
        origin="bbs.test",
        actor_pubkey=server.server_identity.public_key,
        board=board,
        article_id=article_id,
        metadata=MetadataMap([]),
        body_hash=compute_body_hash(body),
        body_size=len(body),
    )
    actor_sig = sign_intent(server.server_identity, encode_intent(intent))
    return server.firehose.append_record(server.server_identity, intent, actor_sig, body)


def test_sweep_discards_orphan_with_no_matching_record(server):
    """A staged body whose event was never actually committed — the append
    crashed before the firehose transaction, not after it — is a true
    orphan and gets discarded."""
    event_id = bytes(range(1, 33))
    _stage_body(server, "general", event_id, b"never appended")

    staged = server.body_store.list_staged_article_bodies()
    assert any(e == event_id for _, _, e, _ in staged)

    server._sweep_orphaned_staged_bodies(min_age_seconds=0)

    staged = server.body_store.list_staged_article_bodies()
    assert not any(e == event_id for _, _, e, _ in staged)


def test_sweep_handles_mtime_ahead_of_wall_clock(server):
    """A staged file's mtime can read as slightly ahead of time.time() —
    clock skew between the write and the sweep's own clock read, seen on
    virtualized CI runners though not reproducible locally on demand.
    min_age_seconds=0 must still sweep it: a negative age must not read as
    'younger than every threshold including 0'."""
    event_id = bytes(range(1, 33))
    _stage_body(server, "general", event_id, b"future mtime")

    staging_path = os.path.join(
        server.config.boards_dir,
        b"bbs.test".hex(),
        b"general".hex(),
        "bodies",
        "staging",
        event_id.hex(),
    )
    future = os.path.getmtime(staging_path) + 5
    os.utime(staging_path, (future, future))

    server._sweep_orphaned_staged_bodies(min_age_seconds=0)

    staged = server.body_store.list_staged_article_bodies()
    assert not any(e == event_id for _, _, e, _ in staged)


def test_sweep_recovers_staged_body_with_committed_record(server):
    """A staged body whose record DID commit — the crash happened between
    append_record succeeding and finalize_article_body running — is
    recovered into its final path, not discarded."""
    event_id = bytes(range(1, 33))
    article_id = bytes(range(50, 82))
    body = b"crashed before finalize"
    _stage_body(server, "general", event_id, body)
    rec = _append_article_record(server, "general", event_id, article_id, body)

    server._sweep_orphaned_staged_bodies(min_age_seconds=0)

    staged = server.body_store.list_staged_article_bodies()
    assert not any(e == event_id for _, _, e, _ in staged)
    assert server.body_store.article_body_exists("bbs.test", "general", rec.article_num)
    recovered = server.body_store.get_article_body(
        "bbs.test", "general", rec.article_num, compute_body_hash(body), len(body)
    )
    assert recovered == body


def test_sweep_leaves_fresh_staged_bodies_alone(server):
    """A body staged moments ago — a request still legitimately in flight —
    must not be swept out from under it just because a sweep happens to
    run concurrently."""
    event_id = bytes(range(1, 33))
    _stage_body(server, "general", event_id, b"still in flight")

    server._sweep_orphaned_staged_bodies()  # default min_age_seconds

    staged = server.body_store.list_staged_article_bodies()
    assert any(e == event_id for _, _, e, _ in staged)


def test_restart_discards_orphaned_staged_body(config):
    """End-to-end: a body orphaned by one process's crash is cleaned up by
    the next process's startup, without anything calling the sweep by hand."""
    os.makedirs(config.data_dir, exist_ok=True)
    os.makedirs(config.boards_dir, exist_ok=True)
    os.makedirs(config.events_bodies_dir, exist_ok=True)

    from bonnet.app.server import BonnetServer

    s1 = BonnetServer(config)
    event_id = bytes(range(1, 33))
    try:
        _stage_body(s1, "general", event_id, b"orphaned by a crash")
        staging_path = os.path.join(
            config.boards_dir,
            b"bbs.test".hex(),
            b"general".hex(),
            "bodies",
            "staging",
            event_id.hex(),
        )
        old_time = os.path.getmtime(staging_path) - 7200
        os.utime(staging_path, (old_time, old_time))
    finally:
        s1.close()

    s2 = BonnetServer(config)
    try:
        staged = s2.body_store.list_staged_article_bodies()
        assert not any(e == event_id for _, _, e, _ in staged)
    finally:
        s2.close()
