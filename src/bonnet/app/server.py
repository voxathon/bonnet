"""Bonnet Firehose Server bootstrap (PROTOCOL.md).

Constructs all firehose protocol components, wires them into an ASGI
HTTP server, and provides a runnable entry point. Replaces the old v3
Bonnet server bootstrap entirely.
"""

from __future__ import annotations

import asyncio
import os

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


class BonnetFirehoseServer:
    """Complete Bonnet firehose server: all components wired and runnable."""

    def __init__(self, config: FirehoseConfig):
        self.config = config

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

        acl = config.acl
        if not acl._rules and config.admin_pubkey_hex:
            acl = ACLEvaluator(default_rules_for_admin(config.admin_pubkey_hex))
        elif not acl._rules:
            acl = ACLEvaluator(default_rules_for_admin(self.server_identity.public_key.hex()))
            log_msg("INIT: no ACL rules configured, defaulting to server identity as admin")
        else:
            has_server_admin = any(
                r.matcher.pubkey == self.server_identity.public_key and r.effect == "allow"
                for r in acl._rules
                if r.matcher.pubkey is not None
            )
            if not has_server_admin:
                from bonnet.core.acl import ACLRule, PrincipalMatcher

                acl.add_rule(
                    ACLRule(
                        effect="allow",
                        matcher=PrincipalMatcher(pubkey=self.server_identity.public_key),
                        actions=["read", "write"],
                        commands=["*"],
                        kinds=["*"],
                        boards=["*"],
                        objects=["*"],
                    )
                )
                log_msg("INIT: added server identity to ACL as admin (not in config)")

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
                    f"INIT: configured peer '{peer.origin}' at {peer.hostname}:{peer.port} (verify_tls={peer.verify_tls})"
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

        self.local_conn = FirehoseLocalConnection(
            self.server_identity.public_key,
            config.origin,
        )

        log_msg("INIT: complete")

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

    async def run(self, port: int = None, ssl_certfile: str = None, ssl_keyfile: str = None):
        import uvicorn

        listen_port = port or self.config.port
        if ssl_certfile is None and self.config.tls_enabled and self.config.tls_cert_path:
            ssl_certfile = self.config.tls_cert_path
        if ssl_keyfile is None and self.config.tls_enabled and self.config.tls_key_path:
            ssl_keyfile = self.config.tls_key_path

        scheme = "https" if ssl_certfile else "http"
        print(
            f"Bonnet firehose server listening on {scheme}://{self.config.http_host}:{listen_port}"
        )
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

        repl_task = asyncio.create_task(OperatorConsole(self).repl_loop())

        for peer in self.config.peers:
            base_url = f"https://{peer.hostname}:{peer.port}"
            client = HttpSyncClient(base_url, verify_tls=peer.verify_tls)
            self.sync_manager.start_origin(peer.origin, client, self.config.sync_interval_seconds)
            log_msg(f"SYNC: started background sync for peer '{peer.origin}' from {base_url}")

        try:
            await server.serve()
        finally:
            repl_task.cancel()
            try:
                await repl_task
            except asyncio.CancelledError:
                pass
            await self.sync_manager.stop_all()

    def close(self):
        if hasattr(self, "_closed") and self._closed:
            return
        self._closed = True
        first_error = None
        for closer in [
            self.command_handler,
            self.dispatcher,
            self.firehose,
            self.nav,
            self.users,
            self.policy,
            self.replay_ledger,
        ]:
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
