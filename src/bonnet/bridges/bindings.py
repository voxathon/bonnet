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

"""Bindings: which venue channel a bridge board mirrors (design doc §8).

Config is the source of intent and the log is the record. At startup the
runtime reconciles the two: a board whose options changed gets a new
binding generation and an unbind of the old one, and a board no longer in
config gets an unbind. An unchanged binding publishes nothing.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, replace

from bonnet.bridges.config import BindingConfig, VenueConfig
from bonnet.bridges.local_publish import LocalPublisher
from bonnet.bridges.model import (
    KIND_BRIDGE_BINDING,
    KIND_BRIDGE_UNBIND,
    ROLE_BINDING,
    BridgeMetadata,
    binding_event_id,
    unbind_event_id,
)
from bonnet.core.crypto import Identity
from bonnet.core.firehose import FirehoseStore
from bonnet.core.global_projections import NavProjection, UserProjection
from bonnet.core.kinds import KIND_BOARD_CREATE
from bonnet.core.logging import log_msg
from bonnet.core.record import (
    Intent,
    MetadataMap,
    compute_body_hash,
    metadata_bytes,
)


class BindingError(Exception):
    """A binding could not be put in place."""


def signer_name(users: UserProjection, origin: str, identity: Identity) -> str:
    """The name `origin` issued to `identity`'s key, or "" (always accepted)."""
    user = users.get_user_by_pubkey(origin, identity.public_key)
    return user["username"] if user is not None else ""


@dataclass(frozen=True)
class ActiveBinding:
    event_id: bytes
    board: str
    generation: int
    meta: BridgeMetadata


def binding_metadata(venue: VenueConfig, binding: BindingConfig, capabilities) -> BridgeMetadata:
    return BridgeMetadata(
        bridge_role=ROLE_BINDING,
        venue=venue.venue,
        channel=binding.channel,
        binding_ingest=binding.ingest,
        binding_relay_egress=binding.relay_egress,
        binding_edge_egress_default=binding.edge_egress_default,
        binding_relay_account=venue.relay_user if binding.relay_egress else None,
        binding_max_body_bytes=binding.max_body_bytes,
        binding_foreign_capabilities=tuple(sorted(capabilities)),
    )


def _scan_bindings(
    firehose: FirehoseStore, origin: str, batch: int = 1000
) -> tuple[dict[str, ActiveBinding], set[bytes]]:
    """(the highest-generation binding per board, the unbound event ids)."""
    latest: dict[str, ActiveBinding] = {}
    unbound: set[bytes] = set()
    seq = 0
    while True:
        records = firehose.get_events_range(origin, seq + 1, batch)
        if not records:
            break
        for rec in records:
            seq = rec.origin_seq
            if rec.kind == KIND_BRIDGE_BINDING:
                meta = BridgeMetadata.from_metadata(rec.metadata)
                gen = meta.binding_generation or 0
                prev = latest.get(rec.target_board)
                if prev is None or gen >= prev.generation:
                    latest[rec.target_board] = ActiveBinding(
                        rec.event_id, rec.target_board, gen, meta
                    )
            elif rec.kind == KIND_BRIDGE_UNBIND:
                unbound.add(rec.target_event_id)
    return latest, unbound


def read_bindings(
    firehose: FirehoseStore, origin: str, batch: int = 1000
) -> dict[str, ActiveBinding]:
    """Active bindings on `origin`, by board: the latest binding with no later unbind."""
    latest, unbound = _scan_bindings(firehose, origin, batch)
    return {b: a for b, a in latest.items() if a.event_id not in unbound}


class Bindings:
    def __init__(
        self,
        publisher: LocalPublisher,
        firehose: FirehoseStore,
        nav: NavProjection,
        users: UserProjection,
        origin: str,
        signer: Callable[[], Identity],
    ):
        self._publisher = publisher
        self._firehose = firehose
        self._nav = nav
        self._users = users
        self._origin = origin
        # The server's own key, read per use: it can rotate while running.
        self._signer = signer

    @property
    def _daemon(self) -> Identity:
        return self._signer()

    def _intent(self, kind: str, **fields) -> Intent:
        return Intent(
            kind=kind,
            origin=self._origin,
            actor_pubkey=self._daemon.public_key,
            actor_username=signer_name(self._users, self._origin, self._daemon),
            actor_registrar=self._origin,
            **fields,
        )

    async def ensure_board(self, board: str) -> None:
        # `~` boards are created by this origin's bridges alone (the
        # reservation in firehose_commands), so an existing one is ours,
        # whichever of the server's keys created it.
        if self._nav.get_board(self._origin, board) is not None:
            return
        await self._publisher.publish(
            self._daemon,
            self._intent(
                KIND_BOARD_CREATE,
                event_id=os.urandom(32),
                board=board,
                metadata=MetadataMap([metadata_bytes(1, self._daemon.public_key)]),
            ),
        )
        log_msg(f"BRIDGE: created board '{board}'")

    async def _unbind(self, active: ActiveBinding, reason: str) -> None:
        body = reason.encode("utf-8")
        await self._publisher.publish(
            self._daemon,
            self._intent(
                KIND_BRIDGE_UNBIND,
                event_id=unbind_event_id(active.event_id),
                target_event_id=active.event_id,
                body_hash=compute_body_hash(body),
                body_size=len(body),
            ),
            body,
        )
        log_msg(f"BRIDGE: unbound '{active.board}' ({reason})")

    async def reconcile(
        self, venues: list[VenueConfig], capabilities: dict[str, frozenset]
    ) -> None:
        """Make the log's active bindings match config. `capabilities` is by venue type."""
        latest, unbound = _scan_bindings(self._firehose, self._origin)
        active = {b: a for b, a in latest.items() if a.event_id not in unbound}
        wanted: set[str] = set()
        for venue in venues:
            for binding in venue.bindings:
                wanted.add(binding.board)
                await self.ensure_board(binding.board)
                meta = binding_metadata(venue, binding, capabilities.get(venue.type, frozenset()))
                current = active.get(binding.board)
                if current is not None and replace(current.meta, binding_generation=None) == meta:
                    continue
                # Past every generation the board ever had, unbound ones
                # included: a board re-added after removal would otherwise
                # reuse generation 0's event id, which is already unbound.
                ever = latest.get(binding.board)
                generation = ever.generation + 1 if ever is not None else 0
                fields = replace(meta, binding_generation=generation).to_fields()
                await self._publisher.publish(
                    self._daemon,
                    self._intent(
                        KIND_BRIDGE_BINDING,
                        event_id=binding_event_id(
                            venue.venue, binding.channel, self._origin, binding.board, generation
                        ),
                        target_origin=self._origin,
                        target_board=binding.board,
                        metadata=MetadataMap(fields),
                    ),
                )
                log_msg(
                    f"BRIDGE: bound '{binding.board}' to {venue.venue} (generation {generation})"
                )
                if current is not None:
                    await self._unbind(current, "options changed")
        for board, current in active.items():
            if board not in wanted:
                await self._unbind(current, "removed from config")
