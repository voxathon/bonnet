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

"""Learning bridge origins from peers' manifests (design doc §10.1, M3).

A peer's `bridges` manifest section is treated like a learned route:
advisory unless `[routing] auto_dial = "trusted-peers-only"` and the peer
that advertised it is trusted (a configured peer or in `route_trust`).
Adopting a bridge origin means recognizing it for that venue, after the
configured ones, and reading its records; if it isn't synced yet, it's
dialed through its live learned route, under the learned-route cap and
dial guards. With no route for it, it stays advisory until one arrives.

Adoptions live in memory: after a restart they're re-learned on the first
sync with the peer that carried them.
"""

from __future__ import annotations

from bonnet.bridges.config import venue_type_of
from bonnet.core.logging import log_msg
from bonnet.core.record import normalize_origin


class BridgeAdopter:
    """The `fn(via, entries)` a `SyncManager` calls after connecting to a peer."""

    def __init__(self, server):
        self._server = server
        self.adopted: dict[tuple[str, str], str] = {}  # (venue, origin) -> via
        self._noted: set[tuple[str, str, str]] = set()  # advisories already logged

    def _note(self, venue: str, origin: str, via: str, why: str) -> None:
        key = (venue, origin, why)
        if key not in self._noted:
            self._noted.add(key)
            log_msg(f"BRIDGES: {origin} for {venue} (via {via}) stays advisory: {why}")

    def __call__(self, via: str, entries: list[dict]) -> None:
        server = self._server
        sync = server.sync_manager
        auto_dial, trusted = sync.routing_policy
        if auto_dial != "trusted-peers-only" or via not in trusted:
            return
        handler = server.command_handler
        own = server.config.origin
        for entry in entries:
            # Only bindings the peer actually holds: an unsynced entry is
            # its configuration, not something it has seen.
            if entry.get("status", "bound") != "bound":
                continue
            venue = entry.get("venue")
            origins = entry.get("origins")
            if not isinstance(venue, str) or "@" not in venue or not isinstance(origins, list):
                continue
            # The venue name carries its type; a peer's `type` field that
            # disagrees with it is ignored.
            venue_type = venue_type_of(venue)
            for raw in origins:
                if not isinstance(raw, str) or not raw:
                    continue
                origin = normalize_origin(raw)
                if origin == own or origin in handler.recognized_origins(venue):
                    continue
                if not sync.is_syncing(origin):
                    route = server.routes.get_route(origin)
                    if route is None:
                        self._note(venue, origin, via, "no learned route to dial")
                        continue
                    started, reason = sync.learn_transitive_route(origin, route, via)
                    if not started and reason != "already syncing":
                        self._note(venue, origin, via, reason)
                        continue
                server.allowed_origins.add(origin)
                handler.recognize_bridge_origin(venue, origin, venue_type)
                self.adopted[(venue, origin)] = via
                log_msg(f"BRIDGES: adopted {origin} for {venue} (via {via})")
