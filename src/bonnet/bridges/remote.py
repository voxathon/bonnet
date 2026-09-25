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

"""Resolving addressed markers: fetch the event a marker names from its origin.

A `[bnt:<origin>/<event id>]` marker at a venue says where its original
lives. A bridge that hasn't synced that origin can ask it directly
(EVENT_GET) instead of waiting for the record to arrive, and mirror the
venue post with a pointer to it at once.

The marker is venue text, which anyone can write, so the origin it names is
a stranger's suggestion: dialing it goes through the same SSRF guard and
TOFU pinning as admission, with a timeout, and an origin that fails is left
alone for a while. What comes back is only a candidate; the runtime checks
it names the very venue post before pointing at it. Off unless
`[bridges] resolve_markers` is on.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Any

from bonnet.core.logging import log_msg
from bonnet.core.record import Record, normalize_origin

EVENT_NOT_FOUND = 0x0003


class RemoteEvents:
    """Fetches single events from the origins markers name."""

    def __init__(
        self,
        transport_factory: Callable[[str], Any],
        timeout_seconds: int = 5,
        backoff_seconds: int = 300,
        clock: Callable[[], float] = time.time,
    ):
        self._factory = transport_factory
        self._timeout = timeout_seconds
        self._backoff = backoff_seconds
        self._clock = clock
        self._down_until: dict[str, float] = {}
        self._absent_until: dict[tuple[str, bytes], float] = {}

    async def get(self, origin: str, event_id: bytes) -> Record | None:
        """The event as `origin` serves it, or None (absent, unreachable, backing off)."""
        now = self._clock()
        if (
            self._down_until.get(origin, 0.0) > now
            or self._absent_until.get((origin, event_id), 0.0) > now
        ):
            return None
        try:
            rec = await asyncio.wait_for(self._fetch(origin, event_id), self._timeout)
        except Exception as e:  # a hint failed to resolve: never the venue loop's problem
            log_msg(f"BRIDGE: marker origin {origin} unavailable ({e!r}); retry later")
            self._down_until[origin] = self._clock() + self._backoff
            return None
        if rec is None:
            # Not there (yet): a post waiting on its marker is reconsidered
            # every poll, and needn't ask again every poll.
            now = self._clock()
            if len(self._absent_until) >= 4096:
                self._absent_until = {k: t for k, t in self._absent_until.items() if t > now}
            self._absent_until[(origin, event_id)] = now + self._backoff
        return rec

    async def _fetch(self, origin: str, event_id: bytes) -> Record | None:
        from bonnet.net.firehose_wire import (
            ProtocolError,
            build_event_get,
            parse_event_get_response,
        )

        transport = self._factory(f"https://{origin}")
        try:
            await transport.connect_anonymous()
            served = normalize_origin(transport._server_origin or "")
            if served != origin:
                raise ValueError(f"https://{origin} says it is {served!r}")
            try:
                resp = await transport.send_command(build_event_get(origin, event_id))
                rec, _witnesses = parse_event_get_response(resp)
            except ProtocolError as e:
                if e.code == EVENT_NOT_FOUND:
                    return None
                raise
            return rec
        finally:
            await transport.close()
