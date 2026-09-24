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

"""Puppets: daemon-held identities for foreign authors (design doc §4.4).

A puppet's key is derived from the master secret, so it never needs
storing. Its name is chosen once, when it registers, and read back from the
users projection ever after: retries and index rebuilds must produce
byte-identical intents, and recomputing a name could pick a different
collision suffix than the one on record.
"""

from __future__ import annotations

from dataclasses import dataclass

from bonnet.bridges.local_publish import LocalPublisher
from bonnet.bridges.model import (
    ANONYMOUS_HANDLE,
    puppet_register_event_id,
    puppet_seed,
    puppet_username,
)
from bonnet.core.crypto import Identity
from bonnet.core.global_projections import UserProjection
from bonnet.core.kinds import KIND_USER_REGISTER
from bonnet.core.logging import log_msg
from bonnet.core.record import Intent, MetadataMap, metadata_bytes, metadata_text, metadata_u64
from bonnet.net.firehose_wire import ProtocolError


@dataclass(frozen=True)
class Puppet:
    identity: Identity
    username: str


class PuppetError(Exception):
    """A puppet could not be registered."""


class Puppets:
    def __init__(
        self,
        publisher: LocalPublisher,
        users: UserProjection,
        origin: str,
        master_secret: bytes,
    ):
        self._publisher = publisher
        self._users = users
        self._origin = origin
        self._master_secret = master_secret
        self._cache: dict[tuple[str, str], Puppet] = {}

    def identity(self, venue: str, foreign_author_id: str) -> Identity:
        return Identity.from_private_key(puppet_seed(self._master_secret, venue, foreign_author_id))

    def _registered_name(self, pubkey: bytes) -> str | None:
        user = self._users.get_user_by_pubkey(self._origin, pubkey)
        if user is None or user.get("revoked") or user.get("superseded_by") is not None:
            return None
        return user["username"]

    async def ensure(
        self, venue: str, venue_type: str, handle: str, foreign_author_id: str
    ) -> Puppet:
        """The puppet for one foreign author, registering it on first use."""
        author_id = foreign_author_id or ANONYMOUS_HANDLE
        key = (venue, author_id)
        cached = self._cache.get(key)
        if cached is not None:
            return cached

        identity = self.identity(venue, author_id)
        name = self._registered_name(identity.public_key)
        if name is None:
            name = await self._register(identity, venue, venue_type, handle, author_id)
        puppet = Puppet(identity, name)
        self._cache[key] = puppet
        return puppet

    async def _register(
        self, identity: Identity, venue: str, venue_type: str, handle: str, author_id: str
    ) -> str:
        plain = puppet_username(handle, venue_type, author_id)
        holder = self._users.username_holder(self._origin, plain)
        collided = holder is not None and holder != identity.public_key
        name = puppet_username(handle, venue_type, author_id, collided=collided)
        intent = Intent(
            event_id=puppet_register_event_id(self._origin, venue, author_id),
            kind=KIND_USER_REGISTER,
            origin=self._origin,
            actor_pubkey=identity.public_key,
            actor_registrar=self._origin,
            metadata=MetadataMap(
                [
                    metadata_text(1, name),
                    metadata_bytes(2, identity.public_key),
                    metadata_u64(3, 0),
                ]
            ),
        )
        try:
            await self._publisher.publish(identity, intent)
        except ProtocolError as e:
            # "Already registered to this key" is success; anything else
            # (the name was taken between the check and the publish, say)
            # is retried on the next post by this author.
            registered = self._registered_name(identity.public_key)
            if registered is not None:
                return registered
            raise PuppetError(f"could not register puppet {name!r}: {e}") from e
        log_msg(f"BRIDGE: registered puppet '{name}' for {venue} author '{author_id}'")
        return self._registered_name(identity.public_key) or name
