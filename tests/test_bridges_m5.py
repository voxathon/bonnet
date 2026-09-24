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

"""Bridges milestone M5: hardening (design doc §13).

Sweeps for venues that report edits or keep a deletion log (§11.4), the
longer grace window for authors who have crossposted before (§11.1 step 1),
and bridges.db committing a dispatch batch at once without letting one bad
record take the batch down with it.
"""

from __future__ import annotations

import json
import os
import sqlite3

import pytest

from bonnet.bridges import model
from bonnet.bridges.adapter import Deletion
from bonnet.bridges.adapters.flatboard import FlatboardAdapter
from bonnet.bridges.model import BridgeMetadata, SourceKey
from bonnet.bridges.runtime import BridgeRuntime
from bonnet.core.kinds import KIND_ARTICLE
from tests.bridge_fakes import (
    FLATBOARD_VENUE,
    FakeFlatboard,
    _NoLimit,
    make_config,
    runtime_config,
    venue_config,
)

ORIGIN = "bridge.test"
BOARD = "~flatboard"
NOW = 1_900_000_000


class Clock:
    def __init__(self):
        self.t = float(NOW)

    def __call__(self):
        return self.t


class EditableFlatboard(FlatboardAdapter):
    """A flatboard that allows edits and keeps a deletion log."""

    capabilities = frozenset({"read", "threads", "edit", "deletion_log"})

    def __init__(self, venue, board: FakeFlatboard):
        super().__init__(venue, http=board.client(), limiter=_NoLimit(), post_limiter=_NoLimit())
        self._board = board

    async def deletions(self, channel, cursor):
        start = int(cursor or 0)
        log = self._board.deletion_log
        return (
            [Deletion(str(d["id"]), json.dumps(d).encode()) for d in log[start:]],
            str(len(log)),
        )


class World:
    def __init__(self, tmp_path, editable: bool = True, **venue_kw):
        from bonnet.app.server import BonnetServer

        self.board = FakeFlatboard()
        self.board.deletion_log = []
        venue = venue_config()
        for k, v in venue_kw.items():
            setattr(venue, k, v)
        self.server = BonnetServer(make_config(tmp_path, ORIGIN, runtime_config(tmp_path, [venue])))
        self.clock = Clock()
        factory = (lambda v: EditableFlatboard(v, self.board)) if editable else self.board.adapter
        self.runtime = BridgeRuntime(self.server, adapter_factory=factory, clock=self.clock)

    @property
    def venue(self):
        return self.runtime.venues[0]

    async def ingest(self):
        return await self.runtime.ingest_binding(self.venue, self.venue.config.bindings[0])

    async def sweep(self):
        return await self.runtime.sweep_binding(self.venue, self.venue.config.bindings[0])

    def records(self, kind):
        return [
            r for r in self.server.firehose.get_events_range(ORIGIN, 1, 100000) if r.kind == kind
        ]

    def mirrors_of(self, foreign_id):
        return [
            r
            for r in self.records(KIND_ARTICLE)
            if BridgeMetadata.from_metadata(r.metadata).foreign_id == str(foreign_id)
        ]

    async def close(self):
        await self.runtime.close()
        self.server.close()


@pytest.fixture
async def w(tmp_path):
    world = World(tmp_path)
    await world.runtime.setup()
    yield world
    await world.close()


# ---------------------------------------------------------------------------
# Edit sweeps
# ---------------------------------------------------------------------------


async def test_an_edit_at_the_venue_supersedes_the_mirror(w):
    mid = w.board.post("first text", created=0)
    await w.ingest()
    w.board.messages[mid]["text"] = "edited text"
    assert await w.sweep() == 1

    first, second = w.mirrors_of(mid)
    meta = BridgeMetadata.from_metadata(second.metadata)
    assert meta.mirror_revision == 1 and meta.foreign_state == model.FOREIGN_EDITED
    assert second.metadata.get_bytes(7) == first.article_id
    assert second.actor_pubkey == first.actor_pubkey  # the puppet supersedes its own mirror
    bp = w.server.dispatcher._get_board_projection(ORIGIN, BOARD)
    assert bp.get_article_by_id(ORIGIN, BOARD, first.article_id).visibility == "superseded"
    assert await w.sweep() == 0  # nothing new


async def test_a_to_b_to_a_through_sweeps(w):
    mid = w.board.post("A", created=0)
    await w.ingest()
    for text in ("B", "A"):
        w.board.messages[mid]["text"] = text
        await w.sweep()
    revisions = [
        BridgeMetadata.from_metadata(r.metadata).mirror_revision for r in w.mirrors_of(mid)
    ]
    assert revisions == [0, 1, 2]


async def test_a_plain_404_is_not_a_deletion(w):
    mid = w.board.post("going away", created=0)
    await w.ingest()
    w.board.evict_below(mid + 1)
    before = w.server.firehose.get_highest_seq(ORIGIN)
    assert await w.sweep() == 0
    assert w.server.firehose.get_highest_seq(ORIGIN) == before


# ---------------------------------------------------------------------------
# Deletion logs
# ---------------------------------------------------------------------------


async def test_a_logged_deletion_is_observed_never_cancelled(w):
    mid = w.board.post("regrettable", created=0)
    await w.ingest()
    (mirror,) = w.mirrors_of(mid)
    w.board.deletion_log.append({"id": mid, "deleted_at": NOW})
    assert await w.sweep() == 1

    deletions = [
        r
        for r in w.records(model.KIND_BRIDGE_OBSERVATION)
        if BridgeMetadata.from_metadata(r.metadata).foreign_state == model.FOREIGN_DELETED
    ]
    (obs,) = deletions
    assert obs.target_event_id == mirror.event_id
    body = w.server.body_store.get_event_body(ORIGIN, obs.event_id, obs.body_hash, obs.body_size)
    assert json.loads(body) == {"id": mid, "deleted_at": NOW}
    bp = w.server.dispatcher._get_board_projection(ORIGIN, BOARD)
    assert bp.get_article_by_id(ORIGIN, BOARD, mirror.article_id).visibility == "active"

    assert await w.sweep() == 0  # the cursor moved past it
    assert w.runtime.index.deletion_cursor(BOARD) == "1"


async def test_deletions_of_unmirrored_posts_are_ignored(w):
    w.board.deletion_log.append({"id": 999})
    assert await w.sweep() == 0


async def test_sweeps_run_on_their_interval(tmp_path):
    world = World(tmp_path, sweep_interval_seconds=600)
    await world.runtime.setup()
    try:
        mid = world.board.post("v1", created=0)
        await world.runtime.ingest_venue(world.venue)  # first sweep runs here
        world.board.messages[mid]["text"] = "v2"
        await world.runtime.ingest_venue(world.venue)
        assert len(world.mirrors_of(mid)) == 1  # too soon
        world.clock.t += 601
        await world.runtime.ingest_venue(world.venue)
        assert len(world.mirrors_of(mid)) == 2
    finally:
        await world.close()


async def test_flatboard_is_never_swept(tmp_path):
    world = World(tmp_path, editable=False)
    await world.runtime.setup()
    try:
        world.board.post("immutable", created=0)
        await world.runtime.ingest_venue(world.venue)
        assert world.venue.last_sweep == 0.0
    finally:
        await world.close()


# ---------------------------------------------------------------------------
# Linked grace (§11.1 step 1)
# ---------------------------------------------------------------------------


async def test_crossposters_get_the_longer_grace(w):
    w.runtime.index.note_crossposter(FLATBOARD_VENUE, "moxxie")
    crossposter = w.board.post("mine", author="moxxie", created=NOW - 300)
    stranger = w.board.post("theirs", author="grok", created=NOW - 300)
    await w.ingest()
    assert w.mirrors_of(crossposter) == []
    assert w.mirrors_of(stranger) == []  # held behind the crossposter, in order
    w.clock.t += 301
    await w.ingest()
    assert len(w.mirrors_of(crossposter)) == 1 and len(w.mirrors_of(stranger)) == 1


async def test_ordinary_authors_keep_the_short_grace(w):
    mid = w.board.post("hi", author="grok", created=NOW - 300)
    await w.ingest()
    assert len(w.mirrors_of(mid)) == 1


# ---------------------------------------------------------------------------
# bridges.db batching
# ---------------------------------------------------------------------------


async def test_bridges_db_commits_once_per_dispatch_batch(w):
    mid = w.board.post("committed", created=0)
    await w.ingest()
    # Visible from a separate connection: the batch was committed.
    conn = sqlite3.connect(w.server.config.bridges_db_path)
    try:
        rows = conn.execute("SELECT foreign_id FROM copies").fetchall()
        seq = conn.execute("SELECT seq FROM checkpoints WHERE origin=?", (ORIGIN,)).fetchone()[0]
    finally:
        conn.close()
    assert rows == [(str(mid),)]
    assert seq == w.server.firehose.get_checkpoint(ORIGIN)
    assert not w.server.bridges._conn.in_transaction


async def test_a_failing_record_loses_only_itself(w, monkeypatch):
    """The later record fails: the earlier one in the same batch must survive."""
    projection = w.server.bridges
    real = projection._apply_article
    first = w.board.post("first", created=0)
    second = w.board.post("second", created=0)

    def fail_second(rec):
        real(rec)
        if BridgeMetadata.from_metadata(rec.metadata).foreign_id == str(second):
            raise RuntimeError("bad record")

    await w.ingest()
    monkeypatch.setattr(projection, "_apply_article", fail_second)
    # A rebuild replays the whole log through one dispatch call: one batch.
    w.server.dispatcher.rebuild_all(ORIGIN)
    assert len(projection.copies_of(SourceKey(FLATBOARD_VENUE, "", str(first)))) == 1
    assert projection.copies_of(SourceKey(FLATBOARD_VENUE, "", str(second))) == []
    assert projection.get_checkpoint(ORIGIN) == w.server.firehose.get_checkpoint(ORIGIN)


async def test_config_parses_sweep_settings(tmp_path):
    from bonnet.bridges.config import parse_bridge_runtime

    cfg, _ = parse_bridge_runtime(
        {
            "venue": [
                {
                    "type": "flatboard",
                    "venue": FLATBOARD_VENUE,
                    "url": "https://x",
                    "sweep_interval_seconds": 30,
                    "sweep_window": 5,
                    "binding": [{"board": BOARD}],
                }
            ]
        },
        str(tmp_path),
    )
    assert (cfg.venues[0].sweep_interval_seconds, cfg.venues[0].sweep_window) == (30, 5)
    assert os.path.isabs(cfg.state_dir)
