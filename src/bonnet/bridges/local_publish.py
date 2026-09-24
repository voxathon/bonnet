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

"""In-process publishing for the bridge runtime (design doc §5.2).

The runtime publishes through `FirehoseCommandHandler.handle`, the same entry
the HTTP server uses, with a context derived by the same `derive_context`.
That skips RFC 9421, the replay ledger and the HTTP rate limiter, but not the
actor signature, the validator, the ACL or the chain rules.

The kind guard is an allowlist. A bridge never cancels, restores or purges,
and never touches routes, rules or punishments; those are refused here before
anything is signed, as well as by the daemon's ACL grant.
"""

from __future__ import annotations

import asyncio

from bonnet.bridges.model import BRIDGE_KIND_PREFIX
from bonnet.core.crypto import Identity
from bonnet.core.global_projections import UserProjection
from bonnet.core.kinds import KIND_ARTICLE, KIND_BOARD_CREATE, KIND_USER_REGISTER
from bonnet.core.record import Intent, encode_intent, sign_intent
from bonnet.net.firehose_commands import (
    FirehoseCommandHandler,
    FirehoseContext,
    derive_context,
)
from bonnet.net.firehose_wire import PublishResult, build_publish_record, parse_publish_response

ALLOWED_KINDS = frozenset({KIND_ARTICLE, KIND_BOARD_CREATE, KIND_USER_REGISTER})

LOCAL_REMOTE_ADDR = "bridge-runtime"


class KindRefused(ValueError):
    """The runtime tried to publish a kind outside its allowlist."""


def kind_allowed(kind: str) -> bool:
    return kind in ALLOWED_KINDS or kind.startswith(BRIDGE_KIND_PREFIX)


class LocalPublisher:
    """Publishes and reads on the bridge origin without leaving the process."""

    def __init__(
        self,
        handler: FirehoseCommandHandler,
        users: UserProjection,
        origin: str,
        anonymous_pubkey: bytes,
    ):
        self._handler = handler
        self._users = users
        self._origin = origin
        self._anonymous_pubkey = anonymous_pubkey

    @classmethod
    def for_server(cls, server) -> LocalPublisher:
        """Bind to a `BonnetServer`'s handler, users projection and keys."""
        return cls(
            server.command_handler,
            server.users,
            server.config.origin,
            server.anonymous_identity.public_key,
        )

    def context_for(self, pubkey: bytes) -> FirehoseContext:
        """The context the HTTP server would give `pubkey`, marked as the runtime's."""
        ctx = derive_context(
            self._users, self._origin, pubkey, LOCAL_REMOTE_ADDR, self._anonymous_pubkey
        )
        ctx.via_bridge_runtime = True
        return ctx

    def build_frame(self, identity: Identity, intent: Intent, body: bytes = b"") -> bytes:
        """Guard the kind, sign the intent and encode a PUBLISH_RECORD frame."""
        if not kind_allowed(intent.kind):
            raise KindRefused(f"bridge runtime may not publish '{intent.kind}'")
        if intent.actor_pubkey != identity.public_key:
            raise ValueError("intent.actor_pubkey must be the signing identity's key")
        return build_publish_record(intent, sign_intent(identity, encode_intent(intent)), body)

    async def request(self, frame: bytes, pubkey: bytes) -> bytes:
        """Run any frame through the handler as `pubkey`; returns the raw response."""
        ctx = self.context_for(pubkey)
        return await asyncio.to_thread(self._handler.handle, frame, ctx)

    async def publish(self, identity: Identity, intent: Intent, body: bytes = b"") -> PublishResult:
        """Publish `intent` signed by `identity`. Raises ProtocolError on refusal."""
        frame = self.build_frame(identity, intent, body)
        return parse_publish_response(await self.request(frame, identity.public_key))
