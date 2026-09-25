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

One `BridgeRuntime` runs inside a `BonnetServer` whose config has
`[[bridges.venue]]`s, and publishes through it in-process. Bridge facts are
signed with the server's own key; puppets' keys derive from its puppet
secret. Each venue polls in its own task with its own backoff, so one venue
going offline leaves the others alone.

M1 is read-only: it mirrors, observes, and never posts to a venue. It never
cancels or purges either; the only lifecycle action a bridge ever takes is a
puppet superseding its own mirror when an editable venue reports an edit.
"""

from __future__ import annotations

import asyncio
import os
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass

from bonnet.bridges import model
from bonnet.bridges.adapter import (
    ForeignAccount,
    ForeignPost,
    VenueAdapter,
    VenueAuthError,
    VenueError,
    VenueRateLimited,
    VenueUncertain,
    build_adapter,
)
from bonnet.bridges.bindings import Bindings, signer_name
from bonnet.bridges.config import (
    BindingConfig,
    BridgeRuntimeConfig,
    VenueConfig,
    load_puppet_secret,
)
from bonnet.bridges.index import MirrorEntry, RuntimeIndex
from bonnet.bridges.local_publish import LocalPublisher
from bonnet.bridges.model import BridgeMetadata, SourceKey
from bonnet.bridges.puppets import PuppetError, Puppets
from bonnet.core.crypto import Identity
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
# How far ahead of this clock a venue's timestamp may be before it's
# treated as no timestamp at all (§11.1 step 1).
MAX_CLOCK_SKEW_SECONDS = 300
SUBJECT_CHARS = 80

# _consider outcomes
DONE = "done"
HOLD = "hold"


@dataclass
class _Venue:
    config: VenueConfig
    adapter: VenueAdapter
    failures: int = 0
    last_sweep: float = 0.0


def _relay_account(venue: VenueConfig) -> ForeignAccount | None:
    """The relay's venue account, if configured and its token file is readable."""
    if not venue.relay_user or not venue.relay_token_file:
        return None
    path = os.path.expanduser(venue.relay_token_file)
    try:
        with open(path, encoding="utf-8") as f:
            token = f.read().strip()
    except OSError as e:
        log_msg(f"BRIDGE: relay for {venue.venue} disabled, can't read token file: {e}")
        return None
    return ForeignAccount(venue.relay_user, token) if token else None


def mirror_subject(text: str) -> str:
    first = " ".join(model.normalize_foreign_text(text).split())
    if len(first) > SUBJECT_CHARS:
        first = first[: SUBJECT_CHARS - 1].rstrip() + "…"
    return first


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
            raise ValueError("this server bridges no venues ([[bridges.venue]])")
        self._origin = server.config.origin
        self._clock = clock
        self._max_raw = server.config.max_article_body_size
        self.publisher = LocalPublisher.for_server(server)
        self.index = RuntimeIndex(server.config.bridges_state_dir)
        self.puppets = Puppets(
            self.publisher,
            server.users,
            self._origin,
            load_puppet_secret(server.config.puppet_secret_path),
        )
        self.bindings = Bindings(
            self.publisher,
            server.firehose,
            server.nav,
            server.users,
            self._origin,
            lambda: self.daemon,
        )
        self.venues = [_Venue(v, adapter_factory(v)) for v in self._config.venues]
        self._relay_accounts = {v.venue: _relay_account(v) for v in self._config.venues}
        # Bindings whose relay credentials the venue rejected: relaying stops
        # there until restart, since venues lock out IPs over bad tokens.
        self._relay_stopped: set[str] = set()

    @property
    def daemon(self) -> Identity:
        """The key bridge facts are signed with: the server's own, as it is now."""
        return self._server.server_identity

    def _daemon_name(self) -> str:
        return signer_name(self._server.users, self._origin, self.daemon)

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
        """Create bridge boards and reconcile bindings."""
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
        for binding in venue.config.bindings:
            if binding.relay_egress:
                await self.relay_binding(venue, binding)
        caps = venue.adapter.capabilities
        now = self._clock()
        if ("edit" in caps or "deletion_log" in caps) and (
            now - venue.last_sweep >= venue.config.sweep_interval_seconds
        ):
            venue.last_sweep = now
            for binding in venue.config.bindings:
                if binding.ingest:
                    await self.sweep_binding(venue, binding)

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
        grace = (
            self._config.linked_grace_seconds
            if self.index.is_crossposter(post.venue, post.author_id)
            else self._config.grace_seconds
        )
        created = post.created_at
        if created is not None and created > now + MAX_CLOCK_SKEW_SECONDS:
            # A post "from the future" would hold itself, and every post
            # after it, until its timestamp came round. A marker still
            # defers it below if it needs to wait for an original.
            created = None
        if created is not None and now - created < grace:
            return HOLD

        crosspost_of = None
        prefix = model.find_marker(post.text)
        if prefix is not None:
            # 3-5. A marker is a hint: it counts only when the copy it names
            #      states this same foreign post.
            local, remote, anything = self._resolve_marker(board, prefix, post)
            if local is not None:
                # 3. Our own crosspost original or relay-linked article came
                #    back from the venue: the echo. Observe only.
                await self._observe(post, local.event_id, model.FOREIGN_PRESENT)
                if local.role == model.ROLE_CROSSPOST:
                    # Their next posts get the longer grace: an edge gateway
                    # may still be publishing the original (§11.1 step 1).
                    self.index.note_crossposter(post.venue, post.author_id)
                self.index.drop_pending(board, src)
                return DONE
            if remote is not None:
                # 4. Another origin's original: mirror it, pointing there.
                crosspost_of = (remote.origin, remote.event_id)
            elif not anything:
                # 5. Resolves nowhere yet: the original may still be on its
                #    way. Defer, then mirror as an ordinary post on timeout.
                first_seen = self.index.pending_first_seen(board, src)
                if first_seen is None:
                    self.index.add_pending(board, post, now, "marker")
                    return DONE
                if now - first_seen < self._config.marker_timeout_seconds:
                    return DONE
            # else: a copied marker naming some other post; ordinary post.

        # 2. The relay account's own posts are never mirrored; the echoes of
        #    what it relayed were handled above.
        if venue.config.relay_user and post.author_handle == venue.config.relay_user:
            self.index.drop_pending(board, src)
            return DONE

        # 6. A reply to a post still pending here waits for it: mirrored
        #    now, it would never be threaded under the parent's mirror.
        #    Pending posts are reconsidered in the order they were added,
        #    so the parent goes first.
        if post.reply_to is not None:
            parent = SourceKey(post.venue, post.channel, post.reply_to)
            if self.index.pending_first_seen(board, parent) is not None:
                self.index.add_pending(board, post, now, "parent")
                return DONE

        await self._mirror(venue, binding, post, crosspost_of=crosspost_of)
        self.index.drop_pending(board, src)
        return DONE

    def _resolve_marker(self, board: str, prefix: str, post: ForeignPost):
        """(local copy, remote copy, any hit) for a marker, matched on foreign_id."""
        bridges = getattr(self._server, "bridges", None)
        if bridges is None:
            return None, None, False
        hits = [
            c
            for c in bridges.copies_by_event_prefix(prefix)
            if c.role in (model.ROLE_CROSSPOST, model.ROLE_RELAY_LINK)
        ]
        same = [
            c
            for c in hits
            if c.src.venue == post.venue
            and c.src.channel == post.channel
            and c.src.foreign_id == post.foreign_id
        ]
        local = next((c for c in same if c.origin == self._origin and c.board == board), None)
        remote = next((c for c in same if c.origin != self._origin), None)
        return local, remote, bool(hits)

    async def _mirror(
        self,
        venue: _Venue,
        binding: BindingConfig,
        post: ForeignPost,
        crosspost_of: tuple[str, bytes] | None = None,
    ) -> None:
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
            crosspost_of_origin=crosspost_of[0] if crosspost_of else None,
            crosspost_of_event=crosspost_of[1] if crosspost_of else None,
        )
        fields = [
            metadata_text(1, mirror_subject(post.text)),
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

    # ------------------------------------------------------------------
    # Relay egress (§11.3)
    # ------------------------------------------------------------------

    RELAY_MIN_AGE_SECONDS = 60
    RELAY_MAX_FAILURES = 5
    RELAY_SCAN = 200

    async def relay_binding(self, venue: _Venue, binding: BindingConfig) -> int:
        """Carry native articles on a bridge board to the venue. Returns how many."""
        board = binding.board
        account = self._relay_accounts.get(venue.config.venue)
        if account is None or board in self._relay_stopped:
            return 0
        if "write" not in venue.adapter.capabilities:
            return 0
        bp = self._server.dispatcher._get_board_projection(self._origin, board)
        recent = bp.list_articles(self._origin, board, offset=0, limit=self.RELAY_SCAN)
        floor = self.index.relay_floor(board)
        if floor is None:
            # First time relaying this board: only what's posted from now on,
            # never a backlog that predates the operator turning this on.
            floor = max((a.article_num for a in recent), default=0)
            self.index.set_relay_floor(board, floor)
            return 0
        now = int(self._clock())
        relayed = 0
        for art in sorted(recent, key=lambda a: a.article_num):
            if art.article_num <= floor or now - art.created_at < self.RELAY_MIN_AGE_SECONDS:
                continue
            state = self.index.relay_state(board, art.article_id)
            if state is not None and (state[1] or state[0] >= self.RELAY_MAX_FAILURES):
                continue
            if not self._relayable(board, art):
                self.index.relay_done(board, art.article_id, None)
                continue
            try:
                if await self._relay_one(venue, binding, account, art):
                    relayed += 1
            except VenueAuthError as e:
                self._relay_stopped.add(board)
                log_msg(f"BRIDGE: relay for '{board}' stopped, venue rejected the account: {e}")
                return relayed
            except VenueRateLimited as e:
                # Not the article's fault: try again next pass, uncounted.
                log_msg(f"BRIDGE: relay for '{board}' paused until the next poll: {e}")
                return relayed
            except VenueError as e:
                failures = self.index.relay_failed(board, art.article_id)
                log_msg(
                    f"BRIDGE: relaying article {art.article_num} on '{board}' failed "
                    f"({failures}/{self.RELAY_MAX_FAILURES}): {e}"
                )
        return relayed

    def _relayable(self, board: str, art) -> bool:
        """Native, not a copy, and not written by the bridge's own keys."""
        if art.author_pubkey == self.daemon.public_key:
            return False
        bridges = getattr(self._server, "bridges", None)
        if bridges is not None and bridges.copy_by_article(self._origin, board, art.article_id):
            return False
        user = self._server.users.get_user_by_pubkey(self._origin, art.author_pubkey)
        policy = getattr(self._server, "bridge_policy", None)
        if user is not None and policy is not None and policy.is_puppet_name(user["username"]):
            return False
        return True

    def _attribution(self, art) -> str:
        user = self._server.users.get_user_by_pubkey(self._origin, art.author_pubkey)
        name = user["username"] if user else art.author_pubkey.hex()[:16]
        bridges = getattr(self._server, "bridges", None)
        admission = bridges.admission(self._origin, art.author_pubkey) if bridges else None
        if admission is not None and admission["active"]:
            return f"{name} ({admission['home_origin']})"
        return f"{name}@{self._origin}"

    async def _relay_one(self, venue: _Venue, binding: BindingConfig, account, art) -> bool:
        board = binding.board
        body = self._server.body_store.get_article_body(
            self._origin, board, art.article_num, art.body_hash, art.body_size
        )
        if body is None:
            return False
        text = venue.adapter.render_outbound(
            body.decode("utf-8", errors="replace"),
            model.make_marker(art.event_id),
            self._attribution(art),
        )
        parent = None
        bridges = getattr(self._server, "bridges", None)
        if art.reply_to_article_id and art.reply_to_article_id != bytes(32) and bridges:
            parent = bridges.copy_by_article(self._origin, board, art.reply_to_article_id)
        # The article's event_id is the key: a retry after a crash re-posts
        # with it, and an idempotent venue hands back the same post. Any
        # other venue could post twice, so there the article is claimed
        # before posting and relayed at most once: only a refusal, which
        # says the venue took nothing, releases the claim for a retry.
        at_most_once = "idempotent_post" not in venue.adapter.capabilities
        if at_most_once:
            self.index.relay_done(board, art.article_id, None)
        try:
            posted = await venue.adapter.post(
                account,
                binding.channel,
                text,
                parent.src.foreign_id if parent is not None else None,
                art.event_id.hex()[:32],
            )
        except VenueUncertain as e:
            if not at_most_once:
                raise
            log_msg(
                f"BRIDGE: article {art.article_num} on '{board}' may or may not have "
                f"reached {venue.config.venue} ({e}); not retrying, the venue can't "
                "take a retry without risking a duplicate"
            )
            return False
        except VenueError:
            if at_most_once:
                self.index.relay_release(board, art.article_id)
            raise
        root = None
        if parent is not None and bridges is not None:
            root = bridges.thread_root(parent.src)[0]
        meta = BridgeMetadata(
            bridge_role=model.ROLE_RELAY_LINK,
            venue=posted.venue,
            channel=posted.channel,
            foreign_id=posted.foreign_id,
            foreign_author=posted.author_handle,
            foreign_reply_to=posted.reply_to,
            foreign_url=posted.url,
            foreign_root_id=root or (posted.foreign_id if parent is None else None),
            foreign_digest=model.foreign_digest(posted.text),
        )
        await self.publisher.publish(
            self.daemon,
            Intent(
                event_id=model.link_event_id(
                    self._origin,
                    board,
                    art.article_id,
                    posted.venue,
                    posted.channel,
                    posted.foreign_id,
                ),
                kind=model.KIND_BRIDGE_LINK,
                origin=self._origin,
                actor_pubkey=self.daemon.public_key,
                actor_username=self._daemon_name(),
                actor_registrar=self._origin,
                target_origin=self._origin,
                target_board=board,
                target_article_id=art.article_id,
                metadata=MetadataMap(meta.to_fields()),
            ),
        )
        # The observation comes from ingest, when the relay's post is read
        # back as the echo of this article (§11.1 step 3).
        self.index.relay_done(board, art.article_id, posted.foreign_id)
        log_msg(
            f"BRIDGE: relayed article {art.article_num} on '{board}' as "
            f"{posted.venue} #{posted.foreign_id}"
        )
        return True

    async def _observe(self, post: ForeignPost, target_event_id: bytes, state: int) -> None:
        await self._observe_raw(
            post.venue,
            post.channel,
            post.foreign_id,
            model.content_digest(post.text),
            post.raw,
            post.raw_content_type,
            target_event_id,
            state,
        )

    async def _observe_raw(
        self,
        venue: str,
        channel: str,
        foreign_id: str,
        digest16: bytes,
        raw: bytes,
        content_type: str,
        target_event_id: bytes,
        state: int,
    ) -> None:
        if len(raw) > self._max_raw:
            log_msg(f"BRIDGE: {venue} post {foreign_id} raw bytes cut to {self._max_raw}")
            raw = raw[: self._max_raw]
        intent = Intent(
            event_id=model.observation_event_id(
                venue, channel, foreign_id, digest16, state, raw, self._origin, target_event_id
            ),
            kind=model.KIND_BRIDGE_OBSERVATION,
            origin=self._origin,
            actor_pubkey=self.daemon.public_key,
            actor_username=self._daemon_name(),
            actor_registrar=self._origin,
            target_origin=self._origin,
            target_event_id=target_event_id,
            metadata=MetadataMap(
                BridgeMetadata(
                    bridge_role=model.ROLE_OBSERVATION,
                    venue=venue,
                    channel=channel,
                    foreign_id=foreign_id,
                    foreign_content_type=content_type,
                    foreign_state=state,
                ).to_fields()
            ),
            body_hash=compute_body_hash(raw),
            body_size=len(raw),
        )
        await self.publisher.publish(self.daemon, intent, raw)

    # ------------------------------------------------------------------
    # Sweeps (§11.4)
    # ------------------------------------------------------------------

    async def sweep_binding(self, venue: _Venue, binding: BindingConfig) -> int:
        """Look back for edits and deletions on venues that report them.

        Edits (capability `edit`): re-fetch the most recent mirrors; a new
        text supersedes. Deletions (capability `deletion_log`): read the
        venue's log and observe each deletion of a mirrored post. Never
        cancels or purges, and a plain 404 means nothing (§11.4).
        """
        board = binding.board
        adapter = venue.adapter
        changed = 0
        if "edit" in adapter.capabilities:
            for src, entry in self.index.recent_mirrors(board, venue.config.sweep_window):
                got = await adapter.fetch(src.channel, src.foreign_id)
                if isinstance(got, ForeignPost) and model.foreign_digest(got.text) != entry.digest:
                    await self._mirror(venue, binding, got)
                    changed += 1
        deletions = getattr(adapter, "deletions", None)
        if "deletion_log" in adapter.capabilities and deletions is not None:
            entries, cursor = await deletions(binding.channel, self.index.deletion_cursor(board))
            for d in entries:
                mirror = self.index.mirror(
                    board, SourceKey(adapter.venue, binding.channel, d.foreign_id)
                )
                if mirror is not None:
                    await self._observe_raw(
                        adapter.venue,
                        binding.channel,
                        d.foreign_id,
                        mirror.digest[:16],
                        d.raw,
                        d.raw_content_type,
                        mirror.event_id,
                        model.FOREIGN_DELETED,
                    )
                    changed += 1
            self.index.set_deletion_cursor(board, cursor)
        return changed


async def serve_bridge(server, runtime: BridgeRuntime, **run_kwargs) -> bool:
    """Run the server and, once it's listening, the runtime (§5.2).

    Returns False if the server never bound its port; the runtime never
    starts in that case. A runtime failure stops the server and re-raises,
    so the process exits non-zero.
    """
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
