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

"""Bonnet server bootstrap.

Constructs the firehose protocol components, wires them into an ASGI HTTP
server, and provides a runnable entry point.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Protocol

from bonnet.app.cli import FirehoseLocalConnection
from bonnet.app.console import OperatorConsole
from bonnet.core.acl import ACLEvaluator, default_rules_for_admin
from bonnet.core.binutil import resolve_rg, set_rg_path
from bonnet.core.bodies import BodyStore
from bonnet.core.config import FirehoseConfig
from bonnet.core.crypto import Identity
from bonnet.core.dispatcher import Dispatcher
from bonnet.core.firehose import FirehoseStore
from bonnet.core.global_projections import NavProjection, PolicyProjection, UserProjection
from bonnet.core.kind_validator import KindValidator
from bonnet.core.logging import close_logging, get_log_path, log_msg
from bonnet.core.search import SearchService
from bonnet.net.firehose_commands import FirehoseCommandHandler
from bonnet.net.firehose_http_server import FirehoseHTTPServer
from bonnet.net.firehose_sync import HttpSyncClient
from bonnet.net.firehose_sync import SyncManager as FirehoseSyncManager
from bonnet.net.rate_limiter import RateLimiter
from bonnet.net.replay import ReplayLedger


class _Closeable(Protocol):
    def close(self) -> None: ...


class BonnetServer:
    """Complete Bonnet server: all components wired and runnable."""

    def __init__(self, config: FirehoseConfig):
        self.config = config
        self._closed = False
        # Set for real once run() binds (see run()'s startup()). Declared
        # here so a signal handler racing with startup has something to
        # check rather than an AttributeError.
        self._uvicorn_server: Any = None

        os.makedirs(config.data_dir, exist_ok=True)
        os.makedirs(config.boards_dir, exist_ok=True)
        os.makedirs(config.events_bodies_dir, exist_ok=True)

        # data_dir/boards_dir/events_bodies_dir are resolved relative to the
        # process's working directory when configured as relative paths.
        # Logging the resolved absolute paths avoids ambiguity when the
        # server is launched by a service manager or from an unexpected CWD.
        log_msg(
            "INIT: storage paths — "
            f"data_dir={os.path.abspath(config.data_dir)}, "
            f"boards_dir={os.path.abspath(config.boards_dir)}, "
            f"events_bodies_dir={os.path.abspath(config.events_bodies_dir)}"
        )

        set_rg_path(config.rg_path)
        log_msg(f"INIT: rg_path={config.rg_path or '(auto-resolve)'}")

        identity_path = config.identity_path
        if os.path.exists(identity_path):
            with open(identity_path, "rb") as f:
                key_bytes = f.read()
            self.server_identity = Identity.from_private_key(key_bytes)
        else:
            self.server_identity = Identity.generate()
            with open(identity_path, "wb") as f:
                f.write(self.server_identity.private_key)
            log_msg(f"INIT: generated new server identity at {identity_path}")

        log_msg(f"INIT: server_identity pubkey={self.server_identity.public_key.hex()}")

        self.anonymous_identity = Identity.generate()
        log_msg(f"INIT: anonymous_key={self.anonymous_identity.public_key.hex()}")

        self.firehose = FirehoseStore(config.events_db_path)
        self.firehose.init_origin_key(config.origin, self.server_identity.public_key)
        log_msg(f"INIT: FirehoseStore at {config.events_db_path}")

        self.nav = NavProjection(config.nav_db_path)
        self.users = UserProjection(config.users_db_path)
        self.policy = PolicyProjection(config.policy_db_path)
        log_msg("INIT: projections initialized (nav, users, policy)")

        self.body_store = BodyStore(
            boards_dir=config.boards_dir,
            events_dir=config.events_bodies_dir,
        )
        log_msg(f"INIT: BodyStore at boards={config.boards_dir}, events={config.events_bodies_dir}")

        allowed_origins = {config.origin}
        for peer in config.peers:
            allowed_origins.add(peer.origin)

        punishment_import_policy = {
            peer.origin: peer.imported_punishment_types() for peer in config.peers
        }

        self.dispatcher = Dispatcher(
            firehose=self.firehose,
            nav=self.nav,
            users=self.users,
            policy=self.policy,
            boards_dir=config.boards_dir,
            body_store=self.body_store,
            allowed_origins=allowed_origins,
            local_origin=config.origin,
            punishment_import_policy=punishment_import_policy,
        )
        log_msg("INIT: Dispatcher initialized")

        # Tracks the one ACL rule (if any) that grants admin by the server's
        # own key because nothing else in config did — as opposed to a rule
        # an operator wrote into config.toml themselves. Only this rule is
        # safe for apply_key_rotation to mutate live: it's synthesized state
        # we own, not operator-authored config we'd silently diverge from on
        # the next restart.
        self._acl_admin_rule = None

        acl = config.acl
        if config.admin_pubkey_hex:
            # Ensure admin_pubkey_hex actually grants admin, regardless of
            # whether other [[acl]] rules exist — it used to only take
            # effect when acl._rules was completely empty, so the moment an
            # operator kept even one of the sample config's default rules
            # (the documented first-run flow: keep the three defaults,
            # uncomment admin_pubkey), the configured key silently got
            # nothing, with no error anywhere.
            admin_pubkey_bytes = bytes.fromhex(config.admin_pubkey_hex)
            has_configured_admin = any(
                r.matcher.pubkey == admin_pubkey_bytes and r.effect == "allow" for r in acl._rules
            )
            if not has_configured_admin:
                acl.add_rule(default_rules_for_admin(config.admin_pubkey_hex)[0])

        if not acl._rules:
            acl = ACLEvaluator(default_rules_for_admin(self.server_identity.public_key.hex()))
            self._acl_admin_rule = acl._rules[0]
            log_msg("INIT: no ACL rules configured, defaulting to server identity as admin")
        else:
            has_server_admin = any(
                r.matcher.pubkey == self.server_identity.public_key and r.effect == "allow"
                for r in acl._rules
                if r.matcher.pubkey is not None
            )
            if not has_server_admin:
                from bonnet.core.acl import ACLRule, PrincipalMatcher

                admin_rule = ACLRule(
                    effect="allow",
                    matcher=PrincipalMatcher(pubkey=self.server_identity.public_key),
                    actions=["read", "write"],
                    commands=["*"],
                    kinds=["*"],
                    boards=["*"],
                    objects=["*"],
                )
                acl.add_rule(admin_rule)
                self._acl_admin_rule = admin_rule
                log_msg("INIT: added server identity to ACL as admin (not in config)")

        self.acl = acl

        self.validator = KindValidator()
        self.search = SearchService(
            boards_dir=config.boards_dir,
            body_store=self.body_store,
            max_count=config.search_max_count,
            timeout_seconds=config.search_timeout_seconds,
            result_limit=config.search_result_limit,
        )

        self.sync_manager = FirehoseSyncManager(
            self.firehose,
            self.server_identity,
            config.hostname,
            dispatcher=self.dispatcher,
        )
        if config.peers:
            for peer in config.peers:
                log_msg(
                    f"INIT: configured peer '{peer.origin}' at "
                    f"{peer.scheme}://{peer.hostname}:{peer.port} (verify_tls={peer.verify_tls})"
                )

        peer_map = {peer.origin: peer for peer in config.peers}

        self.command_handler = FirehoseCommandHandler(
            firehose=self.firehose,
            server_identity=self.server_identity,
            config_origin=config.origin,
            nav=self.nav,
            users=self.users,
            policy=self.policy,
            body_store=self.body_store,
            boards_dir=config.boards_dir,
            acl=acl,
            validator=self.validator,
            search=self.search,
            hostname=config.hostname,
            dispatcher=self.dispatcher,
            sync_manager=self.sync_manager,
            peer_map=peer_map,
            allowed_origins=allowed_origins,
            max_body_size=config.max_article_body_size,
        )
        log_msg("INIT: FirehoseCommandHandler initialized")

        self.replay_ledger = ReplayLedger(
            config.replay_db_path,
            clock_skew_seconds=config.clock_skew_seconds,
        )
        self.rate_limiter = RateLimiter(
            max_requests=config.rate_limit_requests,
            window_seconds=config.rate_limit_window,
        )

        self.http_server = FirehoseHTTPServer(
            command_handler=self.command_handler,
            server_identity=self.server_identity,
            config=config,
            anonymous_identity=self.anonymous_identity,
            replay_ledger=self.replay_ledger,
            rate_limiter=self.rate_limiter,
            users_projection=self.users,
        )
        log_msg("INIT: FirehoseHTTPServer initialized")

        self.dispatcher.dispatch_origin(config.origin)
        log_msg(f"INIT: dispatched local origin '{config.origin}'")

        self._ensure_root_registered()

        for row in self.firehose._conn.execute(
            "SELECT DISTINCT origin FROM origin_state WHERE origin != ?", (config.origin,)
        ).fetchall():
            remote = row[0]
            count = self.dispatcher.dispatch_origin(remote)
            if count:
                log_msg(f"INIT: dispatched remote origin '{remote}' ({count} records)")

        self._sweep_orphaned_staged_bodies()
        self._verify_origin_tips()
        self._verify_key_epochs()

        self.local_conn = FirehoseLocalConnection(
            self.server_identity.public_key,
            config.origin,
        )

        log_msg("INIT: complete")

    def _verify_origin_tips(self) -> None:
        """Check each origin's recorded tip against the record stored at it.

        `origin_state.current_event_hash` is maintained alongside `events`
        rather than derived from it, so a crash mid-transaction or a restored
        database can leave the two disagreeing. That is worth catching on its
        own terms: sync compares an incoming record's previous_event_hash
        against this value, so a drifted tip makes every honest peer look like
        it is serving a broken chain, and the relay would blame the peer
        forever for our own inconsistency.

        One indexed lookup per origin. Only `origin_state` is rewritten —
        the events are signed and are never touched here.
        """
        for origin in self.firehose.list_origins():
            consistent, recorded, actual = self.firehose.check_tip(origin)
            if consistent:
                continue
            if actual is None:
                log_msg(
                    f"INIT: origin '{origin}' records a tip with no stored record at "
                    f"its sequence — leaving alone, this needs an operator"
                )
                continue
            self.firehose.repair_tip(origin)
            log_msg(
                f"INIT: repaired tip for origin '{origin}' "
                f"(recorded={recorded.hex()[:16] if recorded else None} "
                f"actual={actual.hex()[:16]})"
            )

    def _verify_key_epochs(self) -> None:
        """Check each origin's key epochs against the rotate records it holds.

        The same argument as `_verify_origin_tips`, for the table that decides
        which key verifies which record. `origin_key_epochs` is maintained
        alongside `events` by `_apply_rotation_locked` rather than derived from
        them, so a restored database or a crash can leave the two disagreeing —
        and a wrong key there makes every honest peer look like it is serving
        forged records, which is the same "blame the peer for our own state"
        failure the tip check exists to prevent, with a worse symptom.

        Local and free: derived from records already on disk, no network. The
        anchor (epoch 1's key) came from TOFU and cannot be re-derived, so what
        is checked is whether the rest follows from it.
        """
        for origin in self.firehose.list_origins():
            consistent, stored, derived = self.firehose.check_key_epochs(origin)
            if consistent:
                continue
            if self.firehose.repair_key_epochs(origin):
                log_msg(
                    f"INIT: repaired key epochs for origin '{origin}' "
                    f"({len(stored)} stored -> {len(derived)} derived)"
                )

    def _sweep_orphaned_staged_bodies(self, min_age_seconds: int = 3600) -> None:
        """Recover or discard article bodies a crash left in staging.

        stage_article_body writes here before the firehose transaction that
        allocates an article number; only finalize_article_body (on success)
        or delete_staged_article_body (on failure) is meant to remove the
        file afterward. A process killed in between the two leaves a file
        neither served nor cleaned up (internal/BUGS.md #4). Age-gated so a
        request that's merely still in flight isn't swept out from under it.

        Two outcomes per stale entry: if the record actually committed
        (bootstrap dispatch above would already have finalized it in the
        ordinary case, but this is independent of dispatch state and
        doesn't rely on that ordering), finalize it into place; if no such
        record exists at all, the append never happened and the file is a
        true orphan — discard it.
        """
        now = time.time()
        for origin, board, event_id, staged_at in self.body_store.list_staged_article_bodies():
            # Clamped rather than a bare subtraction: a file's mtime can
            # read as slightly ahead of this now (clock skew between the
            # write and this read, most visible on virtualized CI runners —
            # not reproduced locally). A negative age must never read as
            # "younger than every threshold including 0", or the age gate
            # silently stops gating anything at min_age_seconds=0.
            age = max(0.0, now - staged_at)
            if age < min_age_seconds:
                continue
            rec = self.firehose.get_event_by_id(origin, event_id)
            if rec is not None and rec.article_num > 0:
                if self.body_store.finalize_article_body(origin, board, event_id, rec.article_num):
                    log_msg(
                        f"INIT: recovered staged body for {origin}/{board} "
                        f"article #{rec.article_num} (event {event_id.hex()[:16]}..., "
                        f"age={int(age)}s)"
                    )
            else:
                self.body_store.delete_staged_article_body(origin, board, event_id)
                log_msg(
                    f"INIT: discarded orphaned staged body {origin}/{board} "
                    f"event {event_id.hex()[:16]}... (no matching record, age={int(age)}s)"
                )

    async def _sweep_staged_bodies_periodically(self, interval_seconds: int = 3600) -> None:
        """Re-run the startup sweep for the life of the process.

        Startup alone only covers crashes. A process that stays up accrues
        orphans from every publish that failed after stage_article_body and
        before the transaction resolved — the same window the startup sweep
        exists for, just without the restart that used to be the only thing
        clearing it.

        Off the loop thread: the sweep walks the staging tree and queries the
        firehose synchronously, the same reason firehose_http_server hands
        command dispatch to asyncio.to_thread.
        """
        while True:
            await asyncio.sleep(interval_seconds)
            try:
                await asyncio.to_thread(self._sweep_orphaned_staged_bodies)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log_msg(f"SWEEP: staged-body sweep failed: {type(e).__name__}: {e}")

    def _ensure_root_registered(self) -> None:
        """Publish a bonnet.user.register record for the server identity if not already present."""
        try:
            existing = self.users.get_user_by_pubkey(
                self.config.origin, self.server_identity.public_key
            )
            if existing is not None:
                return

            import os as _os

            from bonnet.core.record import (
                ZERO_ID,
                Intent,
                MetadataMap,
                compute_body_hash,
                encode_intent,
                metadata_bytes,
                metadata_text,
                metadata_u64,
                sign_intent,
            )

            event_id = _os.urandom(32)
            intent = Intent(
                event_id=event_id,
                kind="bonnet.user.register",
                origin=self.config.origin,
                actor_pubkey=self.server_identity.public_key,
                actor_username="root",
                actor_registrar=self.config.origin,
                board="",
                article_id=ZERO_ID,
                metadata=MetadataMap(
                    fields=[
                        metadata_text(1, "root"),
                        metadata_bytes(2, self.server_identity.public_key),
                        metadata_u64(3, 1),
                    ]
                ),
                body_hash=compute_body_hash(b""),
                body_size=0,
            )

            actor_signature = sign_intent(self.server_identity, encode_intent(intent))
            self.firehose.append_record(
                origin_identity=self.server_identity,
                intent=intent,
                actor_signature=actor_signature,
                body=b"",
            )
            self.dispatcher.dispatch_origin(self.config.origin)
            log_msg("INIT: registered root user in firehose")
        except Exception as e:
            log_msg(f"INIT: failed to register root user: {e}")

    def apply_key_rotation(self, new_identity: Identity) -> str:
        """Rotate the server's own origin signing key live — no restart.

        Publishes the bonnet.origin.key.rotate record (old key signs the
        record, new key signs the proof — the mutual-consent scheme
        firehose.py._apply_rotation_locked verifies), persists the new
        private key to identity_path (old one backed up alongside it), then
        hot-swaps every component that captured the old Identity object:
        command_handler (signs future local publishes), http_server (signs
        HTTP responses — its BonnetSigner bakes in the private key, so it
        must be rebuilt, not just repointed), sync_manager (signs relay
        witnesses for future accepted federation batches), and local_conn
        (the console's own peer_pubkey — otherwise the console itself would
        stop matching its ACL admin rule the moment that rule is updated
        below).

        The one thing this cannot safely do is rewrite an operator-authored
        config.toml. If the ACL granted this server admin access through a
        rule the operator wrote (as opposed to the automatic fallback this
        class adds when nothing else grants admin), that rule is left alone
        and the caller is told to update config.toml by hand — otherwise the
        *next* restart would reload the stale key from disk and boot without
        admin access.
        """
        from bonnet.core.record import (
            Intent,
            MetadataMap,
            encode_intent,
            metadata_bytes,
            sign_intent,
            sign_key_rotation_proof,
        )

        origin = self.config.origin
        old_identity = self.server_identity

        proof = sign_key_rotation_proof(
            new_identity, origin, old_identity.public_key, new_identity.public_key
        )
        existing = self.users.get_user_by_pubkey(origin, old_identity.public_key)
        intent = Intent(
            event_id=os.urandom(32),
            kind="bonnet.origin.key.rotate",
            origin=origin,
            actor_pubkey=old_identity.public_key,
            actor_username=existing["username"] if existing is not None else "root",
            actor_registrar=origin,
            metadata=MetadataMap(
                [
                    metadata_bytes(1, new_identity.public_key),
                    metadata_bytes(2, proof),
                ]
            ),
        )
        actor_sig = sign_intent(old_identity, encode_intent(intent))
        self.firehose.append_record(old_identity, intent, actor_sig, b"")
        self.dispatcher.dispatch_origin(origin)

        identity_path = self.config.identity_path
        backup_path = f"{identity_path}.pre-rotate-{int(time.time())}"
        os.replace(identity_path, backup_path)
        with open(identity_path, "wb") as f:
            f.write(new_identity.private_key)

        self.server_identity = new_identity
        self.command_handler.set_server_identity(new_identity)
        self.http_server.set_server_identity(new_identity)
        self.sync_manager.set_identity(new_identity)
        self.local_conn.server_pubkey = new_identity.public_key

        acl_updated = False
        if self._acl_admin_rule is not None:
            self._acl_admin_rule.matcher.pubkey = new_identity.public_key
            acl_updated = True

        log_msg(
            f"ROTATE: origin='{origin}' old={old_identity.public_key.hex()} "
            f"new={new_identity.public_key.hex()} acl_updated={acl_updated}"
        )

        lines = [
            f"Rotated origin '{origin}' from {old_identity.public_key.hex()} "
            f"to {new_identity.public_key.hex()}. Effective immediately, no restart needed.",
            f"Old identity backed up to {backup_path}.",
        ]
        if acl_updated:
            lines.append("Live ACL admin rule updated to the new key.")
        else:
            lines.append(
                "WARNING: this server's admin ACL rule was configured explicitly "
                "(not the automatic fallback), so it was left untouched. If it "
                "grants access by this server's own pubkey, update config.toml "
                "to the new key by hand, or the next restart will boot without "
                "admin access."
            )
        return "\n".join(lines)

    async def run(
        self, port: int = None, ssl_certfile: str = None, ssl_keyfile: str = None
    ) -> bool:
        """Run until shutdown. Returns False if the server never managed to start."""
        import sys

        import uvicorn

        listen_port = port or self.config.port
        if ssl_certfile is None and self.config.tls_enabled and self.config.tls_cert_path:
            ssl_certfile = self.config.tls_cert_path
        if ssl_keyfile is None and self.config.tls_enabled and self.config.tls_key_path:
            ssl_keyfile = self.config.tls_key_path

        scheme = "https" if ssl_certfile else "http"

        uv_config = uvicorn.Config(
            self.http_server,
            host=self.config.http_host,
            port=listen_port,
            ssl_certfile=ssl_certfile,
            ssl_keyfile=ssl_keyfile,
            log_level="info",
        )
        server = uvicorn.Server(uv_config)
        self._uvicorn_server = server

        # uvicorn.Server.startup() dereferences self.lifespan, which is only
        # ever set inside Server._serve() (reached via .serve()/.run(), which
        # we deliberately don't use so we can bind before printing the
        # banner below). Replicate the bit of _serve() that sets it up.
        if not uv_config.loaded:
            uv_config.load()
        server.lifespan = uv_config.lifespan_class(uv_config)

        # Bind before printing anything - a bad port or a port already in
        # use must not produce a "listening" banner (with live pubkeys) that
        # the process then contradicts by crashing or dying silently.
        try:
            await server.startup()
        except (OSError, OverflowError) as exc:
            print(
                f"error: could not listen on {self.config.http_host}:{listen_port}: {exc}",
                file=sys.stderr,
            )
            return False
        except SystemExit:
            # uvicorn's own startup() logs the real bind failure (address
            # already in use, permission denied, etc.) and calls sys.exit(1)
            # directly instead of raising OSError - caught here so it
            # doesn't look like the banner below ever had a chance to be
            # true. The specific cause is whatever uvicorn just logged above
            # this line, not guessed at here.
            print(
                f"error: could not listen on {self.config.http_host}:{listen_port} "
                "(see the uvicorn error above)",
                file=sys.stderr,
            )
            return False
        if server.should_exit or not server.started:
            print(
                f"error: server failed to start on {self.config.http_host}:{listen_port} "
                "(see logs for details)",
                file=sys.stderr,
            )
            return False

        print(f"Bonnet server listening on {scheme}://{self.config.http_host}:{listen_port}")
        print(f"Origin: {self.config.origin}")
        print(f"Hostname: {self.config.hostname}")
        print(f"Server public key: {self.server_identity.public_key.hex()}")
        print(f"Anonymous key: {self.anonymous_identity.public_key.hex()}")
        log_path = get_log_path()
        print(f"Logs: {log_path}" if log_path else "Logs: disabled")
        if not resolve_rg():
            print(
                "WARNING: ripgrep (rg) not found - ARTICLE_SEARCH will return 503 "
                "until it's installed and on PATH, or [search] rg_path is set in config.toml"
            )

        tasks = [asyncio.create_task(self._sweep_staged_bodies_periodically())]
        if sys.stdin.isatty():
            tasks.append(asyncio.create_task(OperatorConsole(self).repl_loop()))
        else:
            print("No interactive terminal on stdin - operator REPL disabled, serving only.")

        for peer in self.config.peers:
            base_url = f"{peer.scheme}://{peer.hostname}:{peer.port}"
            try:
                client = HttpSyncClient(
                    base_url, verify_tls=peer.verify_tls, allow_private_dial=peer.allow_private
                )
            except ValueError as e:
                print(
                    f"WARNING: skipping sync peer '{peer.origin}' ({base_url}): {e} "
                    "- set allow_private = true under this [[sync.peers]] entry to permit "
                    "loopback/private/LAN addresses"
                )
                log_msg(f"SYNC: skipped peer '{peer.origin}' at {base_url}: {e}")
                continue
            self.sync_manager.start_origin(peer.origin, client, self.config.sync_interval_seconds)
            log_msg(f"SYNC: started background sync for peer '{peer.origin}' from {base_url}")

        try:
            await server.main_loop()
        finally:
            for task in tasks:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            await self.sync_manager.stop_all()
            await server.shutdown()
        return True

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        first_error = None
        closers: list[_Closeable] = [
            self.command_handler,
            self.dispatcher,
            self.firehose,
            self.nav,
            self.users,
            self.policy,
            self.replay_ledger,
        ]
        for closer in closers:
            try:
                closer.close()
            except Exception as e:
                if first_error is None:
                    first_error = e
                log_msg(f"INIT: error during close: {e}")
        log_msg("INIT: shutdown complete")
        close_logging()
        if first_error is not None:
            raise first_error
