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

"""The bridge runtime: ingest from venues onto bridge boards (design doc §5, §11.1).

One `BridgeRuntime` runs next to a `BonnetServer` in the same process and
publishes through it in-process. Each venue polls in its own task with its
own backoff, so one venue going offline leaves the others alone.

M1 is read-only: it mirrors, observes, and never posts to a venue. It never
cancels or purges either; the only lifecycle action a bridge ever takes is a
puppet superseding its own mirror when an editable venue reports an edit.
"""

from __future__ import annotations

import asyncio
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass

from bonnet.bridges import model
from bonnet.bridges.adapter import ForeignPost, VenueAdapter, VenueError, build_adapter
from bonnet.bridges.bindings import Bindings
from bonnet.bridges.config import (
    BindingConfig,
    BridgeRuntimeConfig,
    VenueConfig,
    load_daemon_identity,
    load_master_secret,
)
from bonnet.bridges.index import MirrorEntry, RuntimeIndex
from bonnet.bridges.local_publish import LocalPublisher
from bonnet.bridges.model import BridgeMetadata, SourceKey
from bonnet.bridges.puppets import PuppetError, Puppets
from bonnet.core.kinds import KIND_ARTICLE
from bonnet.core.logging import log_msg
from bonnet.core.record import (
    Intent,
    MetadataMap,
    compute_body_hash,
    metadata_bytes,
    metadata_text,
    metadata_text_list,
)
from bonnet.net.firehose_wire import ProtocolError

MAX_BACKOFF_SECONDS = 900
SUBJECT_CHARS = 80

# _consider outcomes
DONE = "done"
HOLD = "hold"


@dataclass
class _Venue:
    config: VenueConfig
    adapter: VenueAdapter
    failures: int = 0


def mirror_subject(venue_type: str, foreign_id: str, text: str) -> str:
    first = " ".join(model.normalize_foreign_text(text).split())
    if len(first) > SUBJECT_CHARS:
        first = first[: SUBJECT_CHARS - 1].rstrip() + "…"
    return f"[{venue_type} #{foreign_id}] {first}".rstrip()


class BridgeRuntime:
    def __init__(
        self,
        server,
        config: BridgeRuntimeConfig | None = None,
        adapter_factory: Callable[[VenueConfig], VenueAdapter] = build_adapter,
        clock: Callable[[], float] = time.time,
    ):
        self._server = server
        self._config = config or server.config.bridge_runtime
        if self._config is None:
            raise ValueError("config has no [bridge_runtime] table: this is not a bridge origin")
        self._origin = server.config.origin
        self._clock = clock
        self._max_raw = server.config.max_article_body_size
        self.daemon = load_daemon_identity(self._config)
        self.publisher = LocalPublisher.for_server(server)
        self.index = RuntimeIndex(self._config.state_dir)
        self.puppets = Puppets(
            self.publisher, server.users, self._origin, load_master_secret(self._config)
        )
        self.bindings = Bindings(
            self.publisher,
            server.firehose,
            server.nav,
            server.users,
            self._origin,
            self.daemon,
            self._config.daemon_username,
        )
        self.venues = [_Venue(v, adapter_factory(v)) for v in self._config.venues]

    async def close(self) -> None:
        for v in self.venues:
            try:
                await v.adapter.close()
            except Exception as e:
                log_msg(f"BRIDGE: closing {v.config.venue} adapter: {e!r}")
        self.index.close()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def setup(self) -> None:
        """Register the daemon, create bridge boards, reconcile bindings."""
        await self.bindings.ensure_daemon()
        await self.bindings.reconcile(
            self._config.venues, {v.config.type: v.adapter.capabilities for v in self.venues}
        )

    async def run(self) -> None:
        await self.setup()
        live = self._server.command_handler.live_bridge_venues
        live.update(v.config.venue for v in self.venues)
        try:
            if not self.venues:
                log_msg("BRIDGE: no venues configured; serving only")
                await asyncio.Event().wait()
            async with asyncio.TaskGroup() as tg:
                for v in self.venues:
                    tg.create_task(self._venue_loop(v))
        finally:
            live.difference_update(v.config.venue for v in self.venues)

    async def _venue_loop(self, venue: _Venue) -> None:
        interval = venue.config.poll_interval_seconds
        while True:
            try:
                await self.ingest_venue(venue)
                venue.failures = 0
                delay = interval
            except asyncio.CancelledError:
                raise
            except Exception as e:
                venue.failures += 1
                delay = min(interval * 2**venue.failures, MAX_BACKOFF_SECONDS)
                detail = "" if isinstance(e, VenueError) else "\n" + traceback.format_exc()
                log_msg(
                    f"BRIDGE: {venue.config.venue} poll failed ({e!r}); "
                    f"retrying in {delay}s{detail}"
                )
            await asyncio.sleep(delay)

    def rebuild_index(self) -> int:
        boards = {b.board for v in self.venues for b in v.config.bindings}
        cursor_fns = {
            b.board: v.adapter.cursor_from_ids for v in self.venues for b in v.config.bindings
        }
        return self.index.rebuild(self._server.firehose, self._origin, boards, cursor_fns)

    def status(self) -> list[dict]:
        out = []
        for v in self.venues:
            for b in v.config.bindings:
                out.append(
                    {
                        "venue": v.config.venue,
                        "channel": b.channel,
                        "board": b.board,
                        "ingest": b.ingest,
                        "cursor": self.index.cursor(b.board),
                        "mirrors": self.index.mirror_count(b.board),
                        "pending": len(self.index.pending(b.board)),
                        "failures": v.failures,
                    }
                )
        return out

    # ------------------------------------------------------------------
    # Ingest (§11.1)
    # ------------------------------------------------------------------

    async def ingest_venue(self, venue: _Venue) -> None:
        for binding in venue.config.bindings:
            if binding.ingest:
                await self.ingest_binding(venue, binding)

    async def ingest_binding(self, venue: _Venue, binding: BindingConfig) -> int:
        """One poll of one binding. Returns the number of posts handled."""
        board = binding.board
        now = int(self._clock())
        for pending in self.index.pending(board):
            await self._consider(venue, binding, pending.post, now)

        posts = await venue.adapter.poll(binding.channel, self.index.cursor(board))
        handled = 0
        for post in posts:
            if await self._consider(venue, binding, post, now) == HOLD:
                # Too young: stop here so it (and everything after it) is
                # read again next poll, in order.
                break
            self.index.set_cursor(board, venue.adapter.cursor_after(post))
            handled += 1
        return handled

    async def _consider(
        self, venue: _Venue, binding: BindingConfig, post: ForeignPost, now: int
    ) -> str:
        board = binding.board
        src = SourceKey(post.venue, post.channel, post.foreign_id)

        # 1. Grace window: let the venue settle (and, from M4, an edge
        #    gateway finish publishing its original) before mirroring.
        if post.created_at is not None and now - post.created_at < self._config.grace_seconds:
            return HOLD

        # 2. The relay account's own posts are observed, never mirrored (M4).
        if venue.config.relay_user and post.author_handle == venue.config.relay_user:
            return DONE

        # 3-5. A marker defers until it resolves or times out. Nothing can
        #      resolve one before crossposts exist (M4), so for now every
        #      marked post waits out the timeout and is then mirrored as an
        #      ordinary post.
        if model.find_marker(post.text) is not None:
            first_seen = self.index.pending_first_seen(board, src)
            if first_seen is None:
                self.index.add_pending(board, post, now, "marker")
                return DONE
            if now - first_seen < self._config.marker_timeout_seconds:
                return DONE
        await self._mirror(venue, binding, post)
        self.index.drop_pending(board, src)
        return DONE

    async def _mirror(self, venue: _Venue, binding: BindingConfig, post: ForeignPost) -> None:
        board = binding.board
        venue_type = venue.config.type
        src = SourceKey(post.venue, post.channel, post.foreign_id)
        digest = model.foreign_digest(post.text)
        current = self.index.mirror(board, src)
        if current is not None and current.digest == digest:
            return
        if current is not None and "edit" not in venue.adapter.capabilities:
            log_msg(
                f"BRIDGE: {post.venue} post {post.foreign_id} changed on a venue without "
                "edits; keeping the first mirror"
            )
            return
        revision = current.revision + 1 if current is not None else 0

        parent = (
            self.index.mirror(board, SourceKey(post.venue, post.channel, post.reply_to))
            if post.reply_to
            else None
        )
        root_foreign_id = (
            post.root_id
            or (parent.root_foreign_id if parent is not None else None)
            or (post.foreign_id if not post.reply_to else None)
        )

        normalized = model.normalize_foreign_text(post.text)
        full = normalized.encode("utf-8")
        truncated = len(full) > binding.max_body_bytes
        body = model.truncate_utf8(normalized, binding.max_body_bytes).encode("utf-8")
        digest16 = model.content_digest(post.text)
        article_id = model.mirror_article_id(
            self._origin, board, post.venue, post.channel, post.foreign_id, revision, digest16
        )
        event_id = model.mirror_event_id(
            self._origin, board, post.venue, post.channel, post.foreign_id, revision, digest16
        )

        try:
            puppet = await self.puppets.ensure(
                post.venue, venue_type, post.author_handle, post.author_id
            )
        except PuppetError as e:
            log_msg(f"BRIDGE: skipping {post.venue} post {post.foreign_id}: {e}")
            return

        meta = BridgeMetadata(
            bridge_role=model.ROLE_MIRROR,
            venue=post.venue,
            channel=post.channel,
            foreign_id=post.foreign_id,
            foreign_author=post.author_handle,
            foreign_author_id=post.author_id or model.ANONYMOUS_HANDLE,
            foreign_created_at=post.created_at,
            foreign_reply_to=post.reply_to,
            foreign_url=post.url,
            foreign_state=model.FOREIGN_EDITED if revision else model.FOREIGN_PRESENT,
            original_size=len(full) if truncated else None,
            truncated=True if truncated else None,
            foreign_root_id=root_foreign_id,
            foreign_digest=digest,
            mirror_revision=revision,
        )
        fields = [
            metadata_text(1, mirror_subject(venue_type, post.foreign_id, post.text)),
            metadata_text_list(2, model.bridge_tags(venue_type, src)),
            metadata_text(4, "text/plain"),
        ]
        if parent is not None:
            fields.append(metadata_bytes(5, parent.root_article_id))
            fields.append(metadata_bytes(6, parent.article_id))
        if current is not None:
            fields.append(metadata_bytes(7, current.article_id))
        intent = Intent(
            event_id=event_id,
            kind=KIND_ARTICLE,
            origin=self._origin,
            actor_pubkey=puppet.identity.public_key,
            actor_username=puppet.username,
            actor_registrar=self._origin,
            board=board,
            article_id=article_id,
            metadata=model.merge_metadata(MetadataMap(fields), meta.to_fields()),
            body_hash=compute_body_hash(body),
            body_size=len(body),
        )
        try:
            await self.publisher.publish(puppet.identity, intent, body)
        except ProtocolError as e:
            if "different content" in str(e):
                # Deterministic IDs broke: the same foreign post, revision and
                # text produced a different intent. That's a bug, not a venue
                # problem; say so loudly and move on.
                log_msg(
                    f"BRIDGE: DETERMINISM BUG mirroring {post.venue} post {post.foreign_id} "
                    f"rev {revision}: {e}"
                )
                return
            raise

        # Observe before indexing: if the process dies in between, the next
        # poll finds no index entry, re-publishes the mirror (a no-op, same
        # IDs) and observes again, instead of skipping a post whose evidence
        # never landed.
        await self._observe(
            post, event_id, model.FOREIGN_EDITED if revision else model.FOREIGN_PRESENT
        )
        self.index.put_mirror(
            board,
            src,
            MirrorEntry(
                event_id=event_id,
                article_id=article_id,
                root_article_id=parent.root_article_id if parent is not None else article_id,
                root_foreign_id=root_foreign_id,
                digest=digest,
                revision=revision,
            ),
        )

    async def _observe(self, post: ForeignPost, target_event_id: bytes, state: int) -> None:
        raw = post.raw[: self._max_raw]
        if len(raw) < len(post.raw):
            log_msg(f"BRIDGE: {post.venue} post {post.foreign_id} raw bytes cut to {self._max_raw}")
        intent = Intent(
            event_id=model.observation_event_id(
                post.venue,
                post.channel,
                post.foreign_id,
                model.content_digest(post.text),
                state,
                raw,
                self._origin,
                target_event_id,
            ),
            kind=model.KIND_BRIDGE_OBSERVATION,
            origin=self._origin,
            actor_pubkey=self.daemon.public_key,
            actor_username=self._config.daemon_username,
            actor_registrar=self._origin,
            target_origin=self._origin,
            target_event_id=target_event_id,
            metadata=MetadataMap(
                BridgeMetadata(
                    bridge_role=model.ROLE_OBSERVATION,
                    venue=post.venue,
                    channel=post.channel,
                    foreign_id=post.foreign_id,
                    foreign_content_type=post.raw_content_type,
                    foreign_state=state,
                ).to_fields()
            ),
            body_hash=compute_body_hash(raw),
            body_size=len(raw),
        )
        await self.publisher.publish(self.daemon, intent, raw)


async def serve_bridge(server, runtime: BridgeRuntime, **run_kwargs) -> bool:
    """Run the server and, once it's listening, the runtime (§5.2).

    Returns False if the server never bound its port; the runtime never
    starts in that case. A runtime failure stops the server and re-raises,
    so the process exits non-zero.
    """
    run_kwargs.setdefault("console", False)
    server_task = asyncio.create_task(server.run(**run_kwargs))
    started = asyncio.create_task(server.started.wait())
    await asyncio.wait({server_task, started}, return_when=asyncio.FIRST_COMPLETED)
    if not started.done():
        started.cancel()
        return await server_task

    runtime_task = asyncio.create_task(runtime.run())
    try:
        await asyncio.wait({server_task, runtime_task}, return_when=asyncio.FIRST_COMPLETED)
    except asyncio.CancelledError:
        runtime_task.cancel()
        server_task.cancel()
        raise
    if runtime_task.done():
        if server._uvicorn_server is not None:
            server._uvicorn_server.should_exit = True
        await server_task
        runtime_task.result()  # re-raises a runtime failure
        return True
    runtime_task.cancel()
    try:
        await runtime_task
    except asyncio.CancelledError:
        pass
    return server_task.result()
