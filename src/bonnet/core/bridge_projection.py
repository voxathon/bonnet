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

"""`bridges.db`: copies of foreign posts across every origin (design doc §9).

A tracked projection (see `Dispatcher`): it sees every record from every
allowed origin, keeps its own checkpoints, and catches up from the log when
it's behind. It records facts only: which article on which origin is a copy
of which foreign post, in which thread, with which digest and state; which
boards are bound to which venues; observations; admissions.

Which copy is canonical is not a fact but this server's opinion, since it
depends on which bridge origins this server recognizes. `BridgeView` answers
that at read time from the facts plus the `[[recognize]]` preference order.
Nothing here is authoritative; `clear_origin` and a replay rebuild it.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from bonnet.bridges.model import (
    KIND_BRIDGE_BINDING,
    KIND_BRIDGE_LINK,
    KIND_BRIDGE_OBSERVATION,
    KIND_BRIDGE_UNBIND,
    ROLE_CROSSPOST,
    ROLE_MIRROR,
    ROLE_RELAY_LINK,
    BridgeMetadata,
    SourceKey,
    is_puppet_of,
    parse_src_tag,
)
from bonnet.core.kinds import (
    KIND_ARTICLE,
    KIND_ARTICLE_CANCEL,
    KIND_ARTICLE_PURGE,
    KIND_ARTICLE_RESTORE,
    KIND_BOARD_PURGE,
    KIND_USER_REGISTER,
    KIND_USER_REVOKE,
)
from bonnet.core.logging import log_msg
from bonnet.core.record import ZERO_ID, Record

_SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS copies (
    origin TEXT NOT NULL,
    event_id BLOB NOT NULL,
    venue TEXT NOT NULL,
    channel TEXT NOT NULL,
    foreign_id TEXT NOT NULL,
    root_foreign_id TEXT,
    board TEXT NOT NULL,
    article_id BLOB NOT NULL,
    article_num INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    role INTEGER NOT NULL,
    digest BLOB,
    revision INTEGER NOT NULL,
    state TEXT NOT NULL,
    PRIMARY KEY (origin, event_id)
);
CREATE INDEX IF NOT EXISTS copies_src ON copies (venue, channel, foreign_id);
CREATE INDEX IF NOT EXISTS copies_article ON copies (origin, board, article_id);
CREATE TABLE IF NOT EXISTS srcs (
    venue TEXT NOT NULL,
    channel TEXT NOT NULL,
    foreign_id TEXT NOT NULL,
    root TEXT,
    conflict INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (venue, channel, foreign_id)
);
CREATE INDEX IF NOT EXISTS srcs_root ON srcs (venue, channel, root);
CREATE TABLE IF NOT EXISTS bindings (
    origin TEXT NOT NULL,
    event_id BLOB NOT NULL,
    venue TEXT NOT NULL,
    channel TEXT NOT NULL,
    board TEXT NOT NULL,
    generation INTEGER NOT NULL,
    max_body_bytes INTEGER,
    active INTEGER NOT NULL,
    PRIMARY KEY (origin, event_id)
);
CREATE TABLE IF NOT EXISTS observations (
    origin TEXT NOT NULL,
    event_id BLOB NOT NULL,
    target_origin TEXT NOT NULL,
    target_event_id BLOB NOT NULL,
    venue TEXT,
    channel TEXT,
    foreign_id TEXT,
    foreign_state INTEGER,
    PRIMARY KEY (origin, event_id)
);
CREATE TABLE IF NOT EXISTS admissions (
    origin TEXT NOT NULL,
    pubkey BLOB NOT NULL,
    username TEXT NOT NULL,
    home_origin TEXT NOT NULL,
    home_url TEXT,
    home_username TEXT,
    reg_event_id BLOB NOT NULL,
    active INTEGER NOT NULL,
    PRIMARY KEY (origin, pubkey)
);
CREATE TABLE IF NOT EXISTS checkpoints (
    origin TEXT PRIMARY KEY,
    seq INTEGER NOT NULL
);
"""

ACTIVE = "active"
LIVE_ROLES = (ROLE_MIRROR, ROLE_CROSSPOST, ROLE_RELAY_LINK)


@dataclass(frozen=True)
class Copy:
    origin: str
    event_id: bytes
    src: SourceKey
    root_foreign_id: str | None
    board: str
    article_id: bytes
    article_num: int
    created_at: int
    role: int
    digest: bytes | None
    revision: int
    state: str


_COPY_COLS = (
    "origin, event_id, venue, channel, foreign_id, root_foreign_id, board, article_id, "
    "article_num, created_at, role, digest, revision, state"
)


def _copy(row) -> Copy:
    return Copy(
        origin=row[0],
        event_id=bytes(row[1]),
        src=SourceKey(row[2], row[3], row[4]),
        root_foreign_id=row[5],
        board=row[6],
        article_id=bytes(row[7]),
        article_num=row[8],
        created_at=row[9],
        role=row[10],
        digest=bytes(row[11]) if row[11] is not None else None,
        revision=row[12],
        state=row[13],
    )


# (origin, board, article_id) -> (event_id, article_num, created_at), or None
ArticleLookup = Callable[[str, str, bytes], "tuple[bytes, int, int] | None"]


class BridgeProjection:
    """The `bridges.db` tracked projection."""

    name = "bridges"

    def __init__(self, path: str, article_lookup: ArticleLookup | None = None):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._lock = threading.RLock()
        self._article_lookup = article_lookup

    def set_article_lookup(self, lookup: ArticleLookup) -> None:
        self._article_lookup = lookup

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- TrackedProjection ----------------------------------------------

    def get_checkpoint(self, origin: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT seq FROM checkpoints WHERE origin=?", (origin,)
            ).fetchone()
        return row[0] if row else 0

    def set_checkpoint(self, origin: str, seq: int) -> None:
        # Not committed here: the dispatcher calls flush() once per batch, so
        # the checkpoint and the rows it covers land in one transaction.
        with self._lock:
            self._begin()
            self._conn.execute("INSERT OR REPLACE INTO checkpoints VALUES (?, ?)", (origin, seq))

    def flush(self) -> None:
        """Commit everything applied since the last flush."""
        with self._lock:
            if self._conn.in_transaction:
                self._conn.commit()

    def _begin(self) -> None:
        if not self._conn.in_transaction:
            self._conn.execute("BEGIN")

    def clear_origin(self, origin: str) -> None:
        with self._lock:
            self._begin()
            for table in ("copies", "bindings", "observations", "admissions", "checkpoints"):
                self._conn.execute(f"DELETE FROM {table} WHERE origin=?", (origin,))
            # srcs are shared across origins: keep only those some copy still names.
            self._conn.execute(
                "DELETE FROM srcs WHERE NOT EXISTS (SELECT 1 FROM copies c WHERE "
                "c.venue=srcs.venue AND c.channel=srcs.channel AND c.foreign_id=srcs.foreign_id)"
            )
            self._conn.commit()

    def apply(self, rec: Record) -> None:
        """Apply one record inside the batch's transaction.

        A savepoint per record, so a failing record undoes only its own
        writes and the rest of the batch survives to the next flush().
        """
        with self._lock:
            self._begin()
            self._conn.execute("SAVEPOINT rec")
            try:
                self._apply(rec)
            except Exception:
                self._conn.execute("ROLLBACK TO rec")
                self._conn.execute("RELEASE rec")
                raise
            self._conn.execute("RELEASE rec")

    def _apply(self, rec: Record) -> None:
        kind = rec.kind
        if kind == KIND_ARTICLE:
            self._apply_article(rec)
        elif kind in (KIND_ARTICLE_CANCEL, KIND_ARTICLE_RESTORE, KIND_ARTICLE_PURGE):
            self._apply_control(rec)
        elif kind == KIND_BOARD_PURGE:
            self._conn.execute(
                "UPDATE copies SET state='purged' WHERE origin=? AND board=?",
                (rec.origin, rec.board),
            )
        elif kind == KIND_BRIDGE_BINDING:
            meta = BridgeMetadata.from_metadata(rec.metadata)
            if meta.venue is None or rec.target_origin != rec.origin:
                return
            self._conn.execute(
                "INSERT OR REPLACE INTO bindings VALUES (?,?,?,?,?,?,?,1)",
                (
                    rec.origin,
                    rec.event_id,
                    meta.venue,
                    meta.channel or "",
                    rec.target_board,
                    meta.binding_generation or 0,
                    meta.binding_max_body_bytes,
                ),
            )
            # A later generation for the same board supersedes earlier ones.
            self._conn.execute(
                "UPDATE bindings SET active=0 WHERE origin=? AND board=? AND generation<?",
                (rec.origin, rec.target_board, meta.binding_generation or 0),
            )
        elif kind == KIND_BRIDGE_UNBIND:
            self._conn.execute(
                "UPDATE bindings SET active=0 WHERE origin=? AND event_id=?",
                (rec.origin, rec.target_event_id),
            )
        elif kind == KIND_BRIDGE_OBSERVATION:
            meta = BridgeMetadata.from_metadata(rec.metadata)
            self._confirm_crosspost(rec, meta)
            self._conn.execute(
                "INSERT OR REPLACE INTO observations VALUES (?,?,?,?,?,?,?,?)",
                (
                    rec.origin,
                    rec.event_id,
                    rec.target_origin,
                    rec.target_event_id,
                    meta.venue,
                    meta.channel,
                    meta.foreign_id,
                    meta.foreign_state,
                ),
            )
        elif kind == KIND_BRIDGE_LINK:
            self._apply_link(rec)
        elif kind == KIND_USER_REGISTER:
            meta = BridgeMetadata.from_metadata(rec.metadata)
            subject = rec.metadata.get_bytes(2) or rec.actor_pubkey
            if meta.home_origin is None:
                return
            self._conn.execute(
                "INSERT OR REPLACE INTO admissions VALUES (?,?,?,?,?,?,?,1)",
                (
                    rec.origin,
                    subject,
                    rec.metadata.get_text(1) or "",
                    meta.home_origin,
                    meta.home_url,
                    meta.home_username,
                    rec.event_id,
                ),
            )
        elif kind == KIND_USER_REVOKE:
            self._conn.execute(
                "UPDATE admissions SET active=0 WHERE origin=? AND (reg_event_id=? OR pubkey=?)",
                (rec.origin, rec.target_event_id, rec.metadata.get_bytes(1) or b""),
            )

    def _confirm_crosspost(self, rec: Record, meta: BridgeMetadata) -> None:
        """An observation of one of this origin's crossposts confirms it: only
        now does the root it states count (see `observed`)."""
        if rec.target_origin != rec.origin:
            return
        row = self._conn.execute(
            "SELECT venue, channel, foreign_id, root_foreign_id FROM copies "
            "WHERE origin=? AND event_id=? AND role=?",
            (rec.origin, rec.target_event_id, ROLE_CROSSPOST),
        ).fetchone()
        if row is None or (row[0], row[1], row[2]) != (meta.venue, meta.channel, meta.foreign_id):
            return
        self._note_root(SourceKey(row[0], row[1], row[2]), row[3])

    def _insert_copy(self, c: Copy) -> None:
        self._conn.execute(
            f"INSERT OR REPLACE INTO copies ({_COPY_COLS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                c.origin,
                c.event_id,
                c.src.venue,
                c.src.channel,
                c.src.foreign_id,
                c.root_foreign_id,
                c.board,
                c.article_id,
                c.article_num,
                c.created_at,
                c.role,
                c.digest,
                c.revision,
                c.state,
            ),
        )
        if c.role != ROLE_CROSSPOST:
            # A crosspost is its author's claim until observed; a false root
            # could otherwise mark a real thread as conflicted.
            self._note_root(c.src, c.root_foreign_id)

    def _note_root(self, src: SourceKey, root: str | None) -> None:
        """Record the thread root stated for `src`, flagging disagreement."""
        row = self._conn.execute(
            "SELECT root, conflict FROM srcs WHERE venue=? AND channel=? AND foreign_id=?",
            (src.venue, src.channel, src.foreign_id),
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO srcs VALUES (?,?,?,?,0)",
                (src.venue, src.channel, src.foreign_id, root),
            )
        elif root is not None and row[0] is None:
            self._conn.execute(
                "UPDATE srcs SET root=? WHERE venue=? AND channel=? AND foreign_id=?",
                (root, src.venue, src.channel, src.foreign_id),
            )
        elif root is not None and row[0] != root and not row[1]:
            self._conn.execute(
                "UPDATE srcs SET conflict=1 WHERE venue=? AND channel=? AND foreign_id=?",
                (src.venue, src.channel, src.foreign_id),
            )

    def _apply_article(self, rec: Record) -> None:
        superseded = rec.metadata.get_bytes(7)
        if superseded and superseded != ZERO_ID:
            self._conn.execute(
                "UPDATE copies SET state='superseded' WHERE origin=? AND board=? AND article_id=?",
                (rec.origin, rec.board, superseded),
            )
        meta = BridgeMetadata.from_metadata(rec.metadata)
        src = meta.src
        if meta.bridge_role not in (ROLE_MIRROR, ROLE_CROSSPOST) or src is None:
            return
        if meta.bridge_role == ROLE_MIRROR and not is_puppet_of(rec.actor_username, src.venue):
            # Only a bridge's puppets mirror; anything else claiming to is
            # an ordinary article.
            return
        self._insert_copy(
            Copy(
                origin=rec.origin,
                event_id=rec.event_id,
                src=src,
                root_foreign_id=meta.foreign_root_id,
                board=rec.board,
                article_id=rec.article_id,
                article_num=rec.article_num,
                created_at=rec.created_at,
                role=meta.bridge_role,
                digest=meta.foreign_digest,
                revision=meta.mirror_revision or 0,
                state=ACTIVE,
            )
        )

    def _apply_control(self, rec: Record) -> None:
        # Controls from another origin are ignored, as in the board projection.
        if rec.target_origin != rec.origin:
            return
        where = "origin=? AND board=? AND article_id=?"
        args = (rec.origin, rec.target_board, rec.target_article_id)
        if rec.kind == KIND_ARTICLE_CANCEL:
            self._conn.execute(
                f"UPDATE copies SET state='cancelled' WHERE {where} AND state='active'", args
            )
        elif rec.kind == KIND_ARTICLE_RESTORE:
            self._conn.execute(
                f"UPDATE copies SET state='active' WHERE {where} AND state='cancelled'", args
            )
        else:
            self._conn.execute(f"UPDATE copies SET state='purged' WHERE {where}", args)

    def _apply_link(self, rec: Record) -> None:
        """Role 3: the targeted native article becomes a copy of the linked foreign post."""
        meta = BridgeMetadata.from_metadata(rec.metadata)
        src = meta.src
        if meta.bridge_role != ROLE_RELAY_LINK or src is None or rec.target_origin != rec.origin:
            return
        native = (
            self._article_lookup(rec.origin, rec.target_board, rec.target_article_id)
            if self._article_lookup is not None
            else None
        )
        if native is None:
            log_msg(
                f"BRIDGES: relay link {rec.event_id.hex()[:16]} targets an unknown article; skipped"
            )
            return
        event_id, article_num, created_at = native
        self._insert_copy(
            Copy(
                origin=rec.origin,
                event_id=event_id,
                src=src,
                root_foreign_id=meta.foreign_root_id,
                board=rec.target_board,
                article_id=rec.target_article_id,
                article_num=article_num,
                created_at=created_at,
                role=ROLE_RELAY_LINK,
                digest=meta.foreign_digest,
                revision=0,
                state=ACTIVE,
            )
        )

    # -- reads ------------------------------------------------------------

    def copy_by_event(self, origin: str, event_id: bytes) -> Copy | None:
        with self._lock:
            row = self._conn.execute(
                f"SELECT {_COPY_COLS} FROM copies WHERE origin=? AND event_id=?",
                (origin, event_id),
            ).fetchone()
        return _copy(row) if row else None

    def copy_by_article(self, origin: str, board: str, article_id: bytes) -> Copy | None:
        with self._lock:
            row = self._conn.execute(
                f"SELECT {_COPY_COLS} FROM copies WHERE origin=? AND board=? AND article_id=?",
                (origin, board, article_id),
            ).fetchone()
        return _copy(row) if row else None

    def copies_by_event_prefix(self, prefix_hex: str) -> list[Copy]:
        """Copies whose event_id starts with a marker's 16-hex prefix (§4.5)."""
        try:
            prefix = bytes.fromhex(prefix_hex)
        except ValueError:
            return []
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {_COPY_COLS} FROM copies WHERE substr(event_id, 1, ?) = ?",
                (len(prefix), prefix),
            ).fetchall()
        return [_copy(r) for r in rows]

    def observed(self, copy: Copy) -> bool:
        """Whether `copy`'s own origin has observed its foreign post at the venue.

        A crosspost is signed by its author, who can claim any foreign post;
        it counts as a copy only once the bridge reads the venue post back
        and finds the marker naming it.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM observations WHERE origin=? AND target_origin=? "
                "AND target_event_id=? AND venue=? AND channel=? AND foreign_id=? LIMIT 1",
                (
                    copy.origin,
                    copy.origin,
                    copy.event_id,
                    copy.src.venue,
                    copy.src.channel,
                    copy.src.foreign_id,
                ),
            ).fetchone()
        return row is not None

    def copies_of(self, src: SourceKey) -> list[Copy]:
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {_COPY_COLS} FROM copies WHERE venue=? AND channel=? AND foreign_id=?",
                (src.venue, src.channel, src.foreign_id),
            ).fetchall()
        return [_copy(r) for r in rows]

    def thread_root(self, src: SourceKey) -> tuple[str, bool]:
        """(root foreign id, conflict) for `src`: stated root, else its own id."""
        with self._lock:
            row = self._conn.execute(
                "SELECT root, conflict FROM srcs WHERE venue=? AND channel=? AND foreign_id=?",
                (src.venue, src.channel, src.foreign_id),
            ).fetchone()
        if row is None:
            return src.foreign_id, False
        return (row[0] if row[0] is not None else src.foreign_id), bool(row[1])

    def thread_copies(self, venue: str, channel: str, root: str) -> list[Copy]:
        """Every copy, on any origin, of a post in the thread rooted at `root`."""
        cols = ", ".join(f"c.{c.strip()}" for c in _COPY_COLS.split(","))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {cols} FROM copies c JOIN srcs s ON s.venue=c.venue AND "
                "s.channel=c.channel AND s.foreign_id=c.foreign_id "
                "WHERE c.venue=? AND c.channel=? AND s.conflict=0 AND "
                "COALESCE(s.root, s.foreign_id)=?",
                (venue, channel, root),
            ).fetchall()
        return [_copy(r) for r in rows]

    def article_ids_for_src(
        self, origin: str, board: str, srcs: Iterable[SourceKey]
    ) -> list[bytes]:
        out: list[bytes] = []
        with self._lock:
            for s in srcs:
                out.extend(
                    bytes(r[0])
                    for r in self._conn.execute(
                        "SELECT article_id FROM copies WHERE origin=? AND board=? AND venue=? "
                        "AND channel=? AND foreign_id=?",
                        (origin, board, s.venue, s.channel, s.foreign_id),
                    )
                )
        return out

    def article_ids_for_root(self, origin: str, board: str, root: SourceKey) -> list[bytes]:
        return [
            c.article_id
            for c in self.thread_copies(root.venue, root.channel, root.foreign_id)
            if c.origin == origin and c.board == board
        ]

    def active_bindings(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT origin, venue, channel, board, generation, max_body_bytes FROM bindings "
                "WHERE active=1 ORDER BY origin, board"
            ).fetchall()
        return [
            {
                "origin": r[0],
                "venue": r[1],
                "channel": r[2],
                "board": r[3],
                "generation": r[4],
                "max_body_bytes": r[5],
            }
            for r in rows
        ]

    def admission_for_home(self, origin: str, home_origin: str, home_username: str) -> dict | None:
        """The active admission on `origin` for one home identity, with its key."""
        with self._lock:
            row = self._conn.execute(
                "SELECT pubkey FROM admissions WHERE origin=? AND home_origin=? "
                "AND home_username=? AND active=1",
                (origin, home_origin, home_username),
            ).fetchone()
        if row is None:
            return None
        found = self.admission(origin, bytes(row[0]))
        return None if found is None else {**found, "pubkey": bytes(row[0])}

    def admission(self, origin: str, pubkey: bytes) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT username, home_origin, home_url, home_username, reg_event_id, active "
                "FROM admissions WHERE origin=? AND pubkey=?",
                (origin, pubkey),
            ).fetchone()
        if row is None:
            return None
        return {
            "username": row[0],
            "home_origin": row[1],
            "home_url": row[2],
            "home_username": row[3],
            "reg_event_id": bytes(row[4]),
            "active": bool(row[5]),
        }


# ---------------------------------------------------------------------------
# Canonical view (§9.3)
# ---------------------------------------------------------------------------


class BridgeView:
    """This server's opinion on which copy of each foreign post to show.

    `recognized` maps a venue to its recognized bridge origins in preference
    order. Copies on other origins are never deduplicated. One instance per
    read request: it caches thread rankings, so it must not outlive the
    facts it read.
    """

    def __init__(self, projection: BridgeProjection, recognized: dict[str, list[str]]):
        self._p = projection
        self._recognized = recognized
        self._shown: dict[SourceKey, set[tuple[str, bytes]] | None] = {}
        self._ranks: dict[tuple[str, str, str], list[str]] = {}
        self._observed: dict[tuple[str, bytes], bool] = {}

    def _pref(self, venue: str, origin: str) -> int | None:
        order = self._recognized.get(venue)
        if order is None or origin not in order:
            return None
        return order.index(origin)

    def _counts(self, copy: Copy) -> bool:
        """Whether `copy` takes part in dedup: live, recognized, and, for a
        crosspost, observed at the venue by its own origin."""
        if copy.state != ACTIVE or self._pref(copy.src.venue, copy.origin) is None:
            return False
        if copy.role != ROLE_CROSSPOST:
            return True
        key = (copy.origin, copy.event_id)
        if key not in self._observed:
            self._observed[key] = self._p.observed(copy)
        return self._observed[key]

    def visible(self, copy: Copy | None) -> bool:
        """Whether an aggregate read should show this row."""
        if copy is None or copy.state != ACTIVE:
            # Not a bridge copy, or one the caller asked to see despite its
            # state (cancelled, superseded): the read's own flags decide.
            return True
        if not self._counts(copy):
            return True
        shown = self._shown_for(copy.src)
        return shown is None or (copy.origin, copy.event_id) in shown

    def visible_event(self, origin: str, event_id: bytes) -> bool:
        return self.visible(self._p.copy_by_event(origin, event_id))

    def visible_article(self, origin: str, board: str, article_id: bytes) -> bool:
        return self.visible(self._p.copy_by_article(origin, board, article_id))

    def _shown_for(self, src: SourceKey) -> set[tuple[str, bytes]] | None:
        """The (origin, event_id) shown for `src`, or None to show every copy."""
        if src in self._shown:
            return self._shown[src]
        result = self._compute_shown(src)
        self._shown[src] = result
        return result

    def _compute_shown(self, src: SourceKey) -> set[tuple[str, bytes]] | None:
        live = [c for c in self._p.copies_of(src) if self._counts(c)]
        if len(live) < 2:
            return None
        # Digest check: a recognized bridge serving altered text can't hide
        # an honest one. Copies without a digest don't count against it.
        if len({c.digest for c in live if c.digest is not None}) > 1:
            return None
        root, conflict = self._p.thread_root(src)
        if conflict:
            return None
        ranking = self._rank_thread(src.venue, src.channel, root)
        by_origin: dict[str, list[Copy]] = {}
        for c in live:
            by_origin.setdefault(c.origin, []).append(c)
        for origin in ranking:
            if origin in by_origin:
                chosen = min(by_origin[origin], key=lambda c: c.event_id)
                return {(chosen.origin, chosen.event_id)}
        return None

    def _rank_thread(self, venue: str, channel: str, root: str) -> list[str]:
        """Recognized origins holding the thread, best first (§9.3). Cached per thread."""
        key = (venue, channel, root)
        if key not in self._ranks:
            self._ranks[key] = self._compute_rank(venue, channel, root)
        return self._ranks[key]

    def _compute_rank(self, venue: str, channel: str, root: str) -> list[str]:
        copies = [c for c in self._p.thread_copies(venue, channel, root) if self._counts(c)]
        per_origin: dict[str, list[Copy]] = {}
        for c in copies:
            per_origin.setdefault(c.origin, []).append(c)

        def key(origin: str):
            held = per_origin[origin]
            root_copies = [c for c in held if c.src.foreign_id == root]
            basis = root_copies or held
            authored = any(c.role in (ROLE_CROSSPOST, ROLE_RELAY_LINK) for c in basis)
            return (
                0 if root_copies else 1,  # holds a live copy of the root
                0 if authored else 1,  # rule 1: the authored post keeps its thread
                self._pref(venue, origin),  # rule 2: preference order
                min(c.created_at for c in basis),  # rule 3: earliest copy
                origin,  # rule 4
            )

        return sorted(per_origin, key=key)


def src_from_filter(value: str) -> SourceKey | None:
    """Parse an ARTICLE_QUERY src value: `venue#channel#foreign_id`, escaped like the tag."""
    return parse_src_tag("src:" + value)
