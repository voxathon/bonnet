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

"""SwarmRelay adapter (OpenAgentForum and other SwarmRelay hubs).

A hub holds named channels of signed envelopes that are never edited or
deleted. Each envelope the hub stores gets an unsigned, per-channel
`storedSeq` in arrival order; that is this adapter's foreign id and cursor,
since `GET /v1/channels/<c>/messages?after=<seq>` pages forward from it and
`?after=<seq - 1>&limit=1` reads one envelope back exactly.

Replies name their parent by envelope `id` (`payload.inReplyTo`, inside the
signed payload), not by `storedSeq`, so a parent is translated: from the
same poll, from what this adapter has already seen, or else from the hub's
Markdown permalink, which states the parent's relay position. That page is
only a hint: the position is confirmed against the JSON record before use.

Every envelope is verified here (`verify.py`) against the key the hub serves
for its sender, and its mirror is tagged with the verdict: `sig:verified`,
`sig:checksum-mismatch`, `sig:invalid` or `sig:no-key`.

Posting: an account is an Ed25519 key the hub knows, and its "token" is the
private key. `register` mints one and claims the name with a v2 signed
profile; `post` signs an envelope with it. The envelope id is derived from
the idempotency key, and the hub binds an id to one envelope, so a retry
whose first attempt landed is refused and reads that one back instead.

API reference: `/agent.md` and `/llms-full.txt` on the hub. See README.md.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
import uuid
from collections import OrderedDict
from urllib.parse import quote, urlsplit

import httpx
import nacl.signing

from bonnet.bridges.adapter import (
    ForeignAccount,
    ForeignPost,
    Gone,
    RateLimits,
    ReadLimiter,
    VenueAuthError,
    VenueError,
    VenueNameTaken,
    VenueRateLimited,
    VenueUncertain,
)
from bonnet.bridges.adapters.swarmrelay import verify
from bonnet.bridges.model import normalize_foreign_text, truncate_utf8
from bonnet.bridges.venue import VenueConfig

PAGE_SIZE = 200  # the hub's maximum `limit`
# Pages walked forward per poll once a cursor exists: 2000 new envelopes
# between polls before the rest waits for the next one.
MAX_CATCHUP_PAGES = 10
# The binding channel "" (the conformance suite's) means the hub's default.
DEFAULT_CHANNEL = "general"
# The hub blocks default client signatures at its edge and asks for a
# descriptive one.
USER_AGENT = "bonnet-bridge/swarmrelay (+https://github.com/voxathon/bonnet)"
# Envelope id -> storedSeq translations kept per adapter.
MAX_KNOWN_IDS = 50_000
ENCRYPTED_TEXT = "[encrypted SwarmRelay envelope]"
SIG_TAG = "sig:"  # + a verify verdict
# The hub sets no text limit; this keeps posts the size its residents write.
MAX_TEXT_BYTES = 4000
# Nor a post rate: one every 10 s per adapter is a considerate resident.
POST_INTERVAL_SECONDS = 10.0
# Pages scanned, from a channel's start, for an author's last sequence.
MAX_SEQUENCE_SCAN_PAGES = 100
# Post envelope ids: uuid5 of sender|channel|idempotency key in this space.
ID_NAMESPACE = uuid.UUID("6f1c3a52-9b0e-4d8e-a1f5-2c7b5e0d9a41")
REGISTRATION_DOMAIN = b"openagentforum:registration:v2\n"
# A PKCS#8 DER Ed25519 private key is this prefix, then the 32-byte seed.
_PKCS8_PREFIX = "302e020100300506032b657004220420"
_HEX = re.compile(r"[0-9a-f]+")

_URN = "urn:uuid:"
_POSITION = re.compile(r"Unsigned relay position: (\d+)\.")
_SOURCE_JSON = re.compile(r"/messages\?after=(\d+)&limit=1\b")


def _seq(value) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def _id_key(envelope_id: str) -> str:
    """Envelope ids appear both bare and as `urn:uuid:` URNs, and replies
    don't always use the form their parent was stored under."""
    return envelope_id.strip().lower().removeprefix(_URN)


def _id_forms(envelope_id: str) -> list[str]:
    """The stored id `envelope_id` may be under: as given, then the other form."""
    bare = envelope_id.strip().removeprefix(_URN)
    other = bare if envelope_id.strip().startswith(_URN) else _URN + bare
    return [envelope_id.strip(), other]


def _canonical(envelope: dict) -> bytes:
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _text(envelope: dict) -> str:
    if envelope.get("encrypted") is True:
        return ENCRYPTED_TEXT
    payload = envelope.get("payload")
    message = payload.get("message") if isinstance(payload, dict) else None
    if isinstance(message, str):
        return message
    # Not every payload carries a `message` string (a structured message,
    # an `insight`, or none at all): show the payload itself.
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)


def _handle(envelope: dict, sender: str) -> str:
    """The name the author signed into this envelope, else its key id.

    Self-chosen and unchecked: the identity is `sender`, the key fingerprint.
    """
    payload = envelope.get("payload")
    if isinstance(payload, dict):
        for key in ("name", "origin"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return sender


def _error_code(resp: httpx.Response) -> str | None:
    try:
        body = resp.json()
    except ValueError:
        return None
    error = body.get("error") if isinstance(body, dict) else None
    return error if isinstance(error, str) else None


def _signing_key(token: str) -> nacl.signing.SigningKey | None:
    """The key a token holds: the 32-byte seed, or PKCS#8 DER, as hex."""
    token = (token or "").strip().lower()
    if token.startswith(_PKCS8_PREFIX) and len(token) == len(_PKCS8_PREFIX) + 64:
        token = token[len(_PKCS8_PREFIX) :]
    if len(token) != 64 or not _HEX.fullmatch(token):
        return None
    return nacl.signing.SigningKey(bytes.fromhex(token))


def _retry_after(resp: httpx.Response) -> float | None:
    try:
        seconds = float(resp.headers.get("retry-after", ""))
    except ValueError:
        return None
    return seconds if seconds >= 0 else None


class SwarmRelayAdapter:
    protocol = 1
    type = "swarmrelay"
    # Envelopes are never edited or deleted: no "edit", no "deletion_log".
    capabilities = frozenset(
        {"read", "threads", "write", "idempotent_post", "signup", "self_register"}
    )
    # The hub publishes no limits; it asks clients to respect 429/503.
    limits = RateLimits(reads_per_minute=60, posts_min_interval_seconds=POST_INTERVAL_SECONDS)
    options: frozenset[str] = frozenset()

    def __init__(
        self,
        venue: VenueConfig,
        http: httpx.AsyncClient | None = None,
        limiter=None,
        post_limiter=None,
    ):
        self.venue = venue.venue
        self._base = venue.url.rstrip("/")
        self._backfill_pages = venue.backfill_pages
        self._http = http or httpx.AsyncClient(timeout=30.0)
        self._owns_http = http is None
        self._limiter = limiter or ReadLimiter(self.limits.reads_per_minute)
        self._post_limiter = post_limiter or ReadLimiter(int(60 / POST_INTERVAL_SECONDS))
        # (sender, channel) -> the next sequence that sender signs there.
        self._next_sequence: dict[tuple[str, str], int] = {}
        self._sequence_locks: dict[tuple[str, str], asyncio.Lock] = {}
        # (channel, id key) -> storedSeq, or None for a parent the hub
        # doesn't have in that channel.
        self._known: OrderedDict[tuple[str, str], int | None] = OrderedDict()
        self._checked_channels: set[str] = set()
        # sender -> the public key the hub serves for it (None: none). Keys
        # are never replaced or deleted, so a lookup holds for good.
        self._keys: dict[str, str | None] = {}

    async def close(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    # -- HTTP -------------------------------------------------------------

    async def _get(self, path: str, params: dict | None = None) -> httpx.Response:
        await self._limiter.wait()
        try:
            resp = await self._http.get(
                f"{self._base}{path}", params=params, headers={"user-agent": USER_AGENT}
            )
        except httpx.HTTPError as e:
            raise VenueError(f"swarmrelay {self._base}{path}: {e or type(e).__name__}") from e
        if resp.status_code in (429, 503):
            retry = _retry_after(resp)
            defer = getattr(self._limiter, "defer", None)
            if retry is not None and defer is not None:
                defer(retry)
            raise VenueError(f"swarmrelay {path}: HTTP {resp.status_code}")
        return resp

    @staticmethod
    def _slug(channel: str) -> str:
        return channel or DEFAULT_CHANNEL

    def _path(self, channel: str) -> str:
        return f"/v1/channels/{quote(self._slug(channel), safe='')}"

    async def _check_channel(self, channel: str) -> None:
        """Refuse a channel the hub doesn't have: its message list would just
        come back empty forever, and a typo would never show."""
        if channel in self._checked_channels:
            return
        resp = await self._get(self._path(channel))
        if resp.status_code == 404:
            try:
                body = resp.json()
            except ValueError:
                body = None
            if isinstance(body, dict) and body.get("error") == "Channel not found":
                raise VenueError(f"swarmrelay: no channel {self._slug(channel)!r} on {self._base}")
        # Anything else (a hub without the route, say) proves nothing either
        # way; don't ask again.
        self._checked_channels.add(channel)

    async def _messages(self, channel: str, after: int | None, limit: int) -> list[dict]:
        params: dict = {"limit": limit}
        if after is not None:
            params["after"] = after
        resp = await self._get(f"{self._path(channel)}/messages", params)
        where = f"swarmrelay #{self._slug(channel)}"
        if resp.status_code != 200:
            raise VenueError(f"{where}: HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as e:
            raise VenueError(f"{where}: bad JSON: {e}") from e
        messages = data.get("messages") if isinstance(data, dict) else None
        if not isinstance(messages, list):
            raise VenueError(f"{where}: no message list")
        out = [
            m
            for m in messages
            if isinstance(m, dict)
            and _seq(m.get("storedSeq")) is not None
            and isinstance(m.get("id"), str)
            and m["id"].strip()
        ]
        for m in out:
            self._remember(channel, m["id"], m["storedSeq"])
        return out

    async def _envelope(self, channel: str, seq: int) -> dict | None:
        """The envelope stored at `seq`, or None if the hub doesn't serve one."""
        for m in await self._messages(channel, seq - 1, 1):
            if m["storedSeq"] == seq:
                return m
        return None

    # -- reply translation ------------------------------------------------

    def _remember(self, channel: str, envelope_id: str, seq: int | None) -> None:
        key = (channel, _id_key(envelope_id))
        self._known[key] = seq
        self._known.move_to_end(key)
        while len(self._known) > MAX_KNOWN_IDS:
            self._known.popitem(last=False)

    async def _parent_seq(self, channel: str, envelope_id: str) -> int | None:
        key = (channel, _id_key(envelope_id))
        if key in self._known:
            self._known.move_to_end(key)
            return self._known[key]
        seq = await self._lookup(channel, envelope_id)
        self._remember(channel, envelope_id, seq)
        return seq

    async def _lookup(self, channel: str, envelope_id: str) -> int | None:
        """Where the hub stored `envelope_id` in `channel`, if it did."""
        want = _id_key(envelope_id)
        seq = None
        for form in _id_forms(envelope_id):
            resp = await self._get(
                f"/channels/{quote(self._slug(channel), safe='')}"
                f"/messages/{quote(form, safe='')}/index.md"
            )
            if resp.status_code == 404:
                continue
            if resp.status_code != 200:
                raise VenueError(f"swarmrelay parent lookup: HTTP {resp.status_code}")
            hint = _POSITION.search(resp.text)
            if hint:
                candidate = int(hint.group(1))
            elif source := _SOURCE_JSON.search(resp.text):
                candidate = int(source.group(1)) + 1
            else:
                break
            # The page is a rendering, not the record: confirm it.
            envelope = await self._envelope(channel, candidate) if candidate > 0 else None
            if envelope is not None and _id_key(envelope["id"]) == want:
                seq = candidate
            break
        return seq

    # -- signatures -------------------------------------------------------

    async def _public_key(self, sender: str) -> str | None:
        if sender in self._keys:
            return self._keys[sender]
        resp = await self._get(f"/v1/agents/{quote(sender, safe='')}")
        if resp.status_code == 404:
            key = None
        elif resp.status_code == 200:
            try:
                body = resp.json()
            except ValueError as e:
                raise VenueError(f"swarmrelay agent {sender}: bad JSON: {e}") from e
            agent = body.get("agent") if isinstance(body, dict) else None
            key = agent.get("publicKey") if isinstance(agent, dict) else None
            if not isinstance(key, str):
                raise VenueError(f"swarmrelay agent {sender}: no public key in the answer")
        else:
            # A failed lookup isn't a verdict: mirrors are written once, so
            # fail the poll and look again next time.
            raise VenueError(f"swarmrelay agent {sender}: HTTP {resp.status_code}")
        self._keys[sender] = key
        return key

    async def _verdict(self, envelope: dict) -> str:
        sender = envelope.get("sender")
        if not isinstance(sender, str) or not verify.SENDER.fullmatch(sender):
            return verify.INVALID
        return verify.verify(envelope, await self._public_key(sender))

    # -- posts ------------------------------------------------------------

    def _post(
        self, channel: str, envelope: dict, reply_to: int | None, verdict: str
    ) -> ForeignPost:
        seq = envelope["storedSeq"]
        foreign_id = str(seq)
        sender = envelope.get("sender")
        sender = sender if isinstance(sender, str) else ""
        timestamp = envelope.get("timestamp")
        created = (
            timestamp // 1000
            if isinstance(timestamp, int) and not isinstance(timestamp, bool) and timestamp > 0
            else None
        )
        return ForeignPost(
            venue=self.venue,
            channel=channel,
            foreign_id=foreign_id,
            author_handle=_handle(envelope, sender),
            author_id=sender,
            created_at=created,
            reply_to=str(reply_to) if reply_to else None,
            # A top-level post is its own root; for a reply the runtime's
            # index knows the root.
            root_id=None if reply_to else foreign_id,
            text=_text(envelope),
            raw=_canonical(envelope),
            raw_content_type="application/json",
            url=(
                f"{self._base}/channels/{quote(self._slug(channel), safe='')}"
                f"/messages/{quote(envelope['id'], safe='')}/"
            ),
            tags=(SIG_TAG + verdict,),
        )

    async def _posts(self, channel: str, envelopes: list[dict]) -> list[ForeignPost]:
        out = []
        for m in envelopes:
            payload = m.get("payload")
            # Only the signed `inReplyTo` threads; the top-level `replyToId`
            # is unsigned and the hub itself doesn't treat it as a link.
            ref = payload.get("inReplyTo") if isinstance(payload, dict) else None
            parent = None
            if isinstance(ref, str) and ref.strip():
                parent = await self._parent_seq(channel, ref)
                if parent is not None and parent >= m["storedSeq"]:
                    parent = None  # a parent can't arrive after its reply
            out.append(self._post(channel, m, parent, await self._verdict(m)))
        return out

    async def _walk(
        self, channel: str, after: int, pages: int, until: int | None = None
    ) -> list[dict]:
        """Envelopes after `after`, oldest first: up to `pages` pages, or
        until reaching `until`."""
        out: list[dict] = []
        for _ in range(pages):
            page = [
                m for m in await self._messages(channel, after, PAGE_SIZE) if m["storedSeq"] > after
            ]
            out += page
            if len(page) < PAGE_SIZE:
                break
            after = max(m["storedSeq"] for m in page)
            if until is not None and after >= until:
                break
        return out

    async def poll(self, channel: str, cursor: str | None) -> list[ForeignPost]:
        await self._check_channel(channel)
        if cursor:
            envelopes = await self._walk(channel, int(cursor), MAX_CATCHUP_PAGES)
        else:
            # No cursor: the newest page (the hub serves it oldest first),
            # and with `backfill_pages`, as many pages before it.
            envelopes = await self._messages(channel, None, PAGE_SIZE)
            if self._backfill_pages > 1 and len(envelopes) == PAGE_SIZE:
                first = min(m["storedSeq"] for m in envelopes)
                start = max(0, first - 1 - PAGE_SIZE * (self._backfill_pages - 1))
                older = await self._walk(channel, start, self._backfill_pages - 1, until=first)
                envelopes = older + envelopes
        by_seq = {m["storedSeq"]: m for m in envelopes}
        return await self._posts(channel, [by_seq[s] for s in sorted(by_seq)])

    def cursor_after(self, post: ForeignPost) -> str:
        return post.foreign_id

    def cursor_from_ids(self, foreign_ids: list[str]) -> str | None:
        ids = [int(i) for i in foreign_ids if i.isdigit()]
        return str(max(ids)) if ids else None

    async def fetch(self, channel: str, foreign_id: str) -> ForeignPost | Gone:
        if not foreign_id.isdigit() or int(foreign_id) <= 0:
            return Gone(foreign_id, "unknown")
        envelope = await self._envelope(channel, int(foreign_id))
        if envelope is None:
            # Envelopes are never deleted, but a hub may stop serving one.
            return Gone(foreign_id, "unknown")
        return (await self._posts(channel, [envelope]))[0]

    # -- accounts ---------------------------------------------------------

    def _origin(self) -> str:
        parts = urlsplit(self._base)
        return f"{parts.scheme}://{parts.netloc}"

    def signup_instructions(self) -> str:
        return (
            f"An account at {self._origin()} is an Ed25519 key the hub knows, with a "
            "name claimed by a signed profile. Make one with the hub's own client "
            "(`npx swarmrelay hello --name NAME`) or any Ed25519 tool, following "
            f"{self._origin()}/agent.md. Then link it by calling register again with "
            "venue_user=NAME and venue_token=<the private key: its 32-byte seed as 64 "
            "hex characters, or PKCS#8 DER as hex>. The token is the key itself: "
            "everything posted as you is signed with it, and the hub never replaces a key."
        )

    async def register(self, user: str) -> ForeignAccount:
        """Mint a key and claim `user` for it with a v2 signed profile."""
        seed = os.urandom(32)
        key = nacl.signing.SigningKey(seed)
        issued = int(time.time() * 1000) - 10_000  # the hub allows 30 s of skew
        doc = {
            "proofVersion": 2,
            "action": "register-profile",
            "hub": self._origin(),
            "publicKey": bytes(key.verify_key).hex(),
            "expectedRevision": 0,
            "issuedAt": issued,
            "expiresAt": issued + 240_000,  # at most 5 minutes after issuedAt
            "profile": {
                "name": user,
                "x25519PublicKey": None,
                "capabilities": [],
                "metadata": {"via": "bonnet"},
                "endpoint": None,
            },
        }
        signed = REGISTRATION_DOMAIN + verify.canonical(doc).encode("utf-8")
        proof = {**doc, "signature": key.sign(signed).signature.hex()}
        lost = (
            f"swarmrelay registration of {user!r}: no answer arrived; the name may now "
            "belong to a key nobody kept"
        )
        # The hub answers an exact replay of a proof from its receipt, so an
        # answer that never arrived earns one retry of the same bytes.
        resp: httpx.Response | None = None
        for _ in range(2):
            await self._post_limiter.wait()
            try:
                resp = await self._http.post(
                    f"{self._base}/v1/agents/register",
                    json=proof,
                    headers={"user-agent": USER_AGENT},
                )
            except httpx.HTTPError:
                resp = None
                continue
            if resp.status_code < 500:
                break
        if resp is None or resp.status_code >= 500:
            raise VenueUncertain(lost)
        error = _error_code(resp)
        if resp.status_code == 409 and error == "display_name_claimed":
            raise VenueNameTaken(f"swarmrelay name {user!r} is taken")
        if resp.status_code == 429:
            raise VenueRateLimited("swarmrelay registration: rate limited", _retry_after(resp))
        if resp.status_code != 200:
            raise VenueError(
                f"swarmrelay registration of {user!r} refused: HTTP {resp.status_code} "
                f"{error or ''}".rstrip()
            )
        try:
            body = resp.json()
        except ValueError:
            raise VenueUncertain(lost) from None
        agent = body.get("agent") if isinstance(body, dict) else None
        name = agent.get("name") if isinstance(agent, dict) else None
        return ForeignAccount(name if isinstance(name, str) and name else user, seed.hex())

    # -- write ------------------------------------------------------------

    def max_text_bytes(self) -> int:
        return MAX_TEXT_BYTES

    def render_outbound(self, text: str, marker: str, attribution: str | None) -> str:
        head = f"{attribution}: " if attribution else ""
        tail = f"\n{marker}"
        budget = MAX_TEXT_BYTES - len((head + tail).encode("utf-8"))
        body = truncate_utf8(normalize_foreign_text(text), max(budget, 0)).rstrip()
        return f"{head}{body}{tail}"

    async def _sequence(self, channel: str, sender: str) -> int:
        """The next sequence `sender` signs in `channel`.

        Authors number their envelopes per channel (0, 1, 2, ...), and a
        skipped number reads as a withheld message, so the count comes from
        the hub: scanned from the channel once per adapter, then kept here.
        """
        slot = (sender, self._slug(channel))
        if slot in self._next_sequence:
            return self._next_sequence[slot]
        last, after = -1, 0
        for _ in range(MAX_SEQUENCE_SCAN_PAGES):
            page = await self._messages(channel, after, PAGE_SIZE)
            for m in page:
                seq = m.get("sequence")
                if m.get("sender") == sender and isinstance(seq, int) and not isinstance(seq, bool):
                    last = max(last, seq)
            if len(page) < PAGE_SIZE:
                self._next_sequence[slot] = last + 1
                return last + 1
            after = max(m["storedSeq"] for m in page)
        raise VenueError(f"swarmrelay #{slot[1]}: too long to count {sender}'s envelopes")

    async def _stored(self, channel: str, envelope_id: str) -> ForeignPost | None:
        """The post the hub stored under `envelope_id`, if it did."""
        seq = await self._lookup(channel, envelope_id)
        envelope = await self._envelope(channel, seq) if seq else None
        return (await self._posts(channel, [envelope]))[0] if envelope else None

    async def post(
        self,
        account: ForeignAccount,
        channel: str,
        text: str,
        reply_to: str | None,
        idempotency_key: str,
        subject: str | None = None,  # envelopes have no titles
    ) -> ForeignPost:
        key = _signing_key(account.token)
        if key is None:
            raise VenueAuthError(f"swarmrelay token for {account.user!r} is not an Ed25519 key")
        sender = verify.agent_id(bytes(key.verify_key).hex())
        slug = self._slug(channel)
        # The hub creates a channel it lacks on the first post to it.
        await self._check_channel(channel)
        # The same key always makes the same id, and the hub binds an id to
        # one envelope: a retry whose first attempt landed gets a 409 below.
        envelope_id = f"urn:uuid:{uuid.uuid5(ID_NAMESPACE, f'{sender}|{slug}|{idempotency_key}')}"
        payload: dict = {"message": text}
        if account.user:
            payload["origin"] = account.user
        if reply_to:
            parent = await self._envelope(channel, int(reply_to)) if reply_to.isdigit() else None
            if parent is None:
                raise VenueError(f"swarmrelay #{slug}: the parent {reply_to} is gone")
            payload["inReplyTo"] = parent["id"]
        slot = (sender, slug)
        async with self._sequence_locks.setdefault(slot, asyncio.Lock()):
            sequence = await self._sequence(channel, sender)
            envelope = {
                "id": envelope_id,
                "channel": slug,
                "sender": sender,
                "type": "intel",
                "sequence": sequence,
                "timestamp": int(time.time() * 1000),
                "payload": payload,
                "checksum": verify.checksum(payload),
                "encrypted": False,
            }
            envelope["signature"] = key.sign(verify.sign_string(envelope)).signature.hex()
            await self._post_limiter.wait()
            try:
                resp = await self._http.post(
                    f"{self._base}{self._path(channel)}/messages",
                    json=envelope,
                    headers={"user-agent": USER_AGENT},
                )
            except httpx.HTTPError as e:
                # It may have landed under this sequence: count again next time.
                self._next_sequence.pop(slot, None)
                raise VenueUncertain(f"swarmrelay post: {type(e).__name__}") from None
            if resp.status_code >= 500:
                self._next_sequence.pop(slot, None)
                raise VenueUncertain(f"swarmrelay post: HTTP {resp.status_code}")
            if resp.status_code == 401:
                raise VenueAuthError(f"swarmrelay doesn't know the key of {account.user!r}")
            if resp.status_code == 429:
                raise VenueRateLimited("swarmrelay post: rate limited", _retry_after(resp))
            if resp.status_code == 409:
                # The id is taken: by an earlier attempt with this key, which
                # landed without our hearing (same id, older bytes)?
                if (already := await self._stored(channel, envelope_id)) is not None:
                    return already
                raise VenueError("swarmrelay post: the envelope id is bound to another envelope")
            if resp.status_code != 200:
                raise VenueError(
                    f"swarmrelay post refused: HTTP {resp.status_code} "
                    f"{_error_code(resp) or ''}".rstrip()
                )
            self._next_sequence[slot] = sequence + 1
            try:
                body = resp.json()
            except ValueError:
                body = None
        saved = body.get("envelope") if isinstance(body, dict) else None
        if not isinstance(saved, dict) or _seq(saved.get("storedSeq")) is None:
            # It landed, but the answer doesn't say where: read it back.
            if (stored := await self._stored(channel, envelope_id)) is not None:
                return stored
            raise VenueUncertain("swarmrelay post: no envelope in the answer")
        self._remember(channel, envelope_id, saved["storedSeq"])
        return (await self._posts(channel, [saved]))[0]
