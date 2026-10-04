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


"""An in-memory SwarmRelay hub, for tests: this adapter's `VenueFake`.

Serves the endpoints the adapter reads through an `httpx.MockTransport`:
channel lookups, message pages by `storedSeq` (`after` ascends from the
cursor; without it, the newest page oldest first), and the Markdown
permalink that states a message's relay position, and agent key lookups.
Envelopes carry the shape the real hub serves (`fixtures/page.json`) and
are really signed, each author with its own Ed25519 key. Tests add, hide,
tamper with and break envelopes directly; the conformance suite drives it
through the `VenueFake` methods.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from urllib.parse import unquote

import httpx
import nacl.signing

from bonnet.bridges.adapters.swarmrelay.adapter import (
    DEFAULT_CHANNEL,
    PAGE_SIZE,
    SwarmRelayAdapter,
)
from bonnet.bridges.adapters.swarmrelay.verify import agent_id, checksum, sign_string
from bonnet.bridges.venue import VenueConfig


@dataclass
class FakeSwarmRelay:
    """An in-memory hub. Tests add, hide and break envelopes directly."""

    # channel -> storedSeq -> envelope
    channels: dict[str, dict[int, dict]] = field(
        default_factory=lambda: {DEFAULT_CHANNEL: {}, "cartographers": {}}
    )
    next_seq: dict[str, int] = field(default_factory=dict)
    author_seq: dict[tuple[str, str], int] = field(default_factory=dict)
    offline: bool = False
    requests: list[str] = field(default_factory=list)
    rate_limit_reads: int = 0  # the next N requests answer HTTP 429
    no_markdown: bool = False  # the permalink route is missing (404 for all)
    keys: dict[str, nacl.signing.SigningKey] = field(default_factory=dict)  # sender ->
    unregistered: set[str] = field(default_factory=set)  # senders the hub has no key for

    def author(self, name: str = "alice") -> str:
        """The sender id of `name`'s key (made on first use)."""
        key = nacl.signing.SigningKey(hashlib.sha256(name.encode()).digest())
        sender = agent_id(bytes(key.verify_key).hex())
        self.keys[sender] = key
        return sender

    def envelope(
        self,
        text: str | None,
        sender: str | None = None,
        channel: str = DEFAULT_CHANNEL,
        reply_to: str | None = None,
        name: str | None = "alice",
        envelope_id: str | None = None,
        timestamp: int = 1_791_000_000_000,
        payload: dict | None = None,
    ) -> dict:
        """Store an envelope as the hub would; returns it, `storedSeq` included."""
        sender = sender or self.author()
        msgs = self.channels.setdefault(channel, {})
        seq = self.next_seq.get(channel, 1)
        self.next_seq[channel] = seq + 1
        author = self.author_seq.get((channel, sender), 0)
        self.author_seq[(channel, sender)] = author + 1
        if payload is None:
            payload = {"message": text}
            if name is not None:
                payload["origin"] = name
            if reply_to is not None:
                payload["inReplyTo"] = reply_to
        env = {
            "id": envelope_id or f"urn:uuid:{uuid.uuid4()}",
            "channel": channel,
            "sender": sender,
            "type": "intel",
            "sequence": author,
            "storedSeq": seq,
            "timestamp": timestamp,
            "payload": payload,
            "signature": "",
            "checksum": checksum(payload),
            "encrypted": False,
        }
        if sender in self.keys:
            env["signature"] = self.keys[sender].sign(sign_string(env)).signature.hex()
        msgs[seq] = env
        return env

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(str(request.url))
        if self.offline:
            raise httpx.ConnectError("hub is down", request=request)
        if self.rate_limit_reads:
            self.rate_limit_reads -= 1
            return httpx.Response(429, json={"error": "slow down"}, headers={"retry-after": "7"})
        parts = request.url.raw_path.decode().split("?")[0].strip("/").split("/")
        if parts[:2] == ["v1", "agents"] and len(parts) == 3:
            sender = unquote(parts[2])
            if sender not in self.keys or sender in self.unregistered:
                return httpx.Response(404, json={"error": "Agent not found"})
            key = bytes(self.keys[sender].verify_key).hex()
            return httpx.Response(200, json={"agent": {"agentId": sender, "publicKey": key}})
        if parts[:2] == ["v1", "channels"] and len(parts) == 3:
            channel = unquote(parts[2])
            if channel not in self.channels:
                return httpx.Response(404, json={"error": "Channel not found"})
            return httpx.Response(200, json={"channel": {"name": channel, "isPrivate": False}})
        if parts[:2] == ["v1", "channels"] and len(parts) == 4 and parts[3] == "messages":
            return self._handle_messages(unquote(parts[2]), request.url.params)
        if parts[0] == "channels" and len(parts) == 5 and parts[4] == "index.md":
            return self._handle_markdown(unquote(parts[1]), unquote(parts[3]))
        return httpx.Response(404, json={"error": f"Route GET {request.url.path} not found"})

    def _handle_messages(self, channel: str, params) -> httpx.Response:
        try:
            limit = int(params.get("limit", "50"))
            after = int(params["after"]) if "after" in params else None
        except ValueError:
            return httpx.Response(400, json={"error": "bad query"})
        if not 1 <= limit <= PAGE_SIZE:
            return httpx.Response(400, json={"error": "limit must be an integer from 1 to 200"})
        # An unknown channel is just empty here, as on the real hub.
        msgs = self.channels.get(channel, {})
        seqs = sorted(msgs)
        if after is not None:
            chosen = [s for s in seqs if s > after][:limit]
        else:
            chosen = seqs[-limit:]
        page = [msgs[s] for s in chosen]
        return httpx.Response(200, json={"channel": channel, "messages": page, "count": len(page)})

    def _handle_markdown(self, channel: str, envelope_id: str) -> httpx.Response:
        if self.no_markdown:
            return httpx.Response(404, text="# Public record not found")
        for seq, env in self.channels.get(channel, {}).items():
            if env["id"] == envelope_id:  # exact: the hub doesn't fold id forms
                body = (
                    f"## Message {envelope_id}\n\n"
                    f"[Source JSON (check message ID)](https://hub.test/v1/channels/{channel}"
                    f"/messages?after={seq - 1}&limit=1)\n\n"
                    f"Author sequence: {env['sequence']}. Unsigned relay position: {seq}.\n"
                )
                return httpx.Response(200, text=body, headers={"content-type": "text/markdown"})
        return httpx.Response(404, text="# Public record not found")

    # -- VenueFake (bonnet.bridges.conformance) ---------------------------

    def venue_config(self) -> VenueConfig:
        return VenueConfig(type="swarmrelay", venue="swarmrelay@hub.test", url="https://hub.test")

    def _channel(self, channel: str) -> str:
        return channel or DEFAULT_CHANNEL

    def native_post(self, text: str, author: str = "alice", reply_to: str | None = None) -> str:
        msgs = self.channels[DEFAULT_CHANNEL]
        parent = msgs[int(reply_to)]["id"] if reply_to else None
        env = self.envelope(text, sender=self.author(author), reply_to=parent, name=author)
        return str(env["storedSeq"])

    def remove(self, foreign_id: str) -> None:
        # Envelopes are never deleted; a hub can stop serving one.
        self.channels[DEFAULT_CHANNEL].pop(int(foreign_id), None)

    def venue_posts(self) -> list[str]:
        return [str(s) for s in sorted(self.channels[DEFAULT_CHANNEL])]

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self._handle))

    def adapter(self, venue: VenueConfig) -> SwarmRelayAdapter:
        return SwarmRelayAdapter(venue, http=self.client(), limiter=_NoLimit())


class _NoLimit:
    deferred: float = 0.0

    async def wait(self) -> None:
        return None

    def defer(self, seconds: float) -> None:
        self.deferred = seconds
