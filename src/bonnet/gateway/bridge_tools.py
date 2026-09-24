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

"""Gateway tools for bridges (design doc §9.5, §11.2).

  list_bridges  the bridges an origin advertises in its discovery document
  crosspost     post on a bridge board on a bridge origin, signed with your
                home key; with a venue account configured, the gateway posts
                to the venue as you first (edge egress)
  flush_outbox  retry crossposts that reached the venue but not the bridge
  corroborate   find every recognized bridge's copy of a bridged article

Venue accounts live in the tenant's `bridge_accounts.toml` (or the file
$BONNET_BRIDGE_ACCOUNTS names), managed by the operator, never passed through
a tool call:

    [[account]]
    venue = "flatboard@tools.nyrds.net"
    type = "flatboard"
    url = "https://tools.nyrds.net"
    user = "lanternfly"
    token_file = "~/.bonnet/flatboard.token"

Plain functions: `bonnet.gateway.tools` registers them as MCP tools (and
declares their Needs) at its end, so this module never touches `mcp` and
there is no import cycle to type through.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
import tomllib
from dataclasses import dataclass

from bonnet.bridges import model
from bonnet.bridges.adapter import (
    ForeignAccount,
    ReadLimiter,
    VenueAuthError,
    VenueError,
    VenueRateLimited,
    VenueUncertain,
    build_adapter,
)
from bonnet.bridges.config import VenueConfig, check_venue, venue_type_of
from bonnet.bridges.model import BridgeMetadata, SourceKey
from bonnet.core.crypto import Identity
from bonnet.core.kinds import KIND_ARTICLE
from bonnet.core.record import (
    Intent,
    MetadataMap,
    compute_body_hash,
    encode_intent,
    metadata_bytes,
    metadata_text,
    metadata_text_list,
    normalize_origin,
    sign_intent,
)
from bonnet.gateway import paths
from bonnet.gateway.outbox import Outbox, OutboxEntry
from bonnet.net.firehose_transport import FirehoseClientError
from bonnet.net.firehose_wire import ProtocolError, build_publish_record, parse_publish_response

# ---------------------------------------------------------------------------
# Accounts, outbox, seams
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VenueAccountSpec:
    venue: str
    type: str
    url: str
    account: ForeignAccount


def accounts_path() -> str:
    return os.environ.get("BONNET_BRIDGE_ACCOUNTS") or os.path.join(
        paths.tenant_dir(), "bridge_accounts.toml"
    )


def load_accounts() -> dict[str, VenueAccountSpec]:
    """Venue -> account, from the tenant's accounts file. Missing file = none."""
    path = accounts_path()
    if not os.path.exists(path):
        return {}
    with open(path, "rb") as f:
        data = tomllib.load(f)
    out = {}
    for i, a in enumerate(data.get("account", [])):
        try:
            with open(os.path.expanduser(a["token_file"]), encoding="utf-8") as tf:
                token = tf.read().strip()
            check_venue(a["type"], a["venue"], f"account[{i}]")
            out[a["venue"]] = VenueAccountSpec(
                venue=a["venue"],
                type=a["type"],
                url=a["url"],
                account=ForeignAccount(a["user"], token),
            )
        except (KeyError, OSError, TypeError, ValueError) as e:
            raise ValueError(f"{path}: account[{i}] is unusable: {e!r}") from e
    return out


def _outbox() -> Outbox:
    return Outbox(os.path.join(paths.tenant_dir(), "outbox.db"))


def _t():
    """bonnet.gateway.tools, imported late: it imports this module at its end."""
    from bonnet.gateway import tools

    return tools


def _client_for(url: str):
    return _t()._make_client(url)


def _adapter_for(spec: VenueAccountSpec):
    return build_adapter(VenueConfig(type=spec.type, venue=spec.venue, url=spec.url))


# ---------------------------------------------------------------------------
# Posting as a venue account
# ---------------------------------------------------------------------------

# Every call builds a fresh adapter, so an adapter's own post spacing never
# outlives one call. Posts are spaced here instead, per account, for as long
# as this gateway process runs.
_gates: dict[tuple[str, str], ReadLimiter] = {}
_clock = time.monotonic
_sleep = asyncio.sleep

# A venue's retry-after up to this long is waited out and the post retried
# once; longer, and the call reports the venue error.
MAX_RATE_WAIT_SECONDS = 20.0


def _gate(spec: VenueAccountSpec, adapter) -> ReadLimiter:
    key = (spec.venue, spec.account.user)
    gate = _gates.get(key)
    if gate is None:
        interval = adapter.limits.posts_min_interval_seconds
        gate = _gates[key] = ReadLimiter(
            60.0 / interval if interval > 0 else 0,
            clock=lambda: _clock(),
            sleep=lambda d: _sleep(d),
        )
    return gate


def _auth_failures_path() -> str:
    return os.path.join(paths.tenant_dir(), "bridge_auth_failures.json")


def _credential_digest(spec: VenueAccountSpec) -> str:
    raw = f"{spec.venue}\0{spec.account.user}\0{spec.account.token}".encode()
    return hashlib.sha256(raw).hexdigest()


def _read_auth_failures() -> dict:
    try:
        with open(_auth_failures_path(), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_auth_failures(data: dict) -> None:
    path = _auth_failures_path()
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def _auth_blocked(spec: VenueAccountSpec) -> str | None:
    """Why posting as `spec` is refused without asking the venue, if it is.

    A venue that rejected these exact credentials is never sent them again:
    flatboard locks every account on an IP out after 10 bad tokens an hour,
    and a shared gateway holds many tenants' accounts. The block lifts when
    the token (or user) in the accounts file changes.
    """
    record = _read_auth_failures().get(spec.venue)
    if not isinstance(record, dict) or record.get("digest") != _credential_digest(spec):
        return None
    when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.get("at", 0)))
    return (
        f"{spec.venue} rejected the credentials for {spec.account.user!r} at {when}; "
        "not sending them again: replace the token in the accounts file"
    )


def _note_auth(spec: VenueAccountSpec, failed: bool) -> None:
    data = _read_auth_failures()
    if failed:
        data[spec.venue] = {"digest": _credential_digest(spec), "at": int(time.time())}
    elif spec.venue in data:
        del data[spec.venue]
    else:
        return
    _write_auth_failures(data)


async def _venue_post(spec: VenueAccountSpec, adapter, channel, text, reply_to, key):
    """Post as `spec`: spaced per account, never with rejected credentials.

    Retried once, with the same key, when that's safe: after a short rate
    limit (the venue took nothing), or after an uncertain failure on a venue
    with idempotent posting (the key lands on the same post either way).
    """
    blocked = _auth_blocked(spec)
    if blocked is not None:
        raise VenueAuthError(blocked)
    gate = _gate(spec, adapter)
    for attempt in range(2):
        await gate.wait()
        try:
            posted = await adapter.post(spec.account, channel, text, reply_to, key)
        except VenueAuthError:
            _note_auth(spec, failed=True)
            raise
        except VenueUncertain:
            if attempt or "idempotent_post" not in adapter.capabilities:
                raise
            continue
        except VenueRateLimited as e:
            wait = e.retry_after
            if wait is not None:
                gate.defer(wait)
            if attempt or wait is None or wait > MAX_RATE_WAIT_SECONDS:
                raise
            continue
        _note_auth(spec, failed=False)
        return posted
    raise AssertionError("unreachable")


def _home(auth: str | None) -> tuple[Identity, str, str]:
    """(home identity, home origin, home url) for the calling identity."""
    t = _t()
    username, password = t._resolve_auth(auth)
    home_origin = t._default_origin()
    key = t._get_identity_store().get_private_key(home_origin, username, password)
    return Identity.from_private_key(key), home_origin, t._current_url()


def _bridge_url(bridge_origin: str, bridge_url: str) -> str:
    if bridge_url:
        return bridge_url
    joined = _t()._get_origin_store().get(bridge_origin)
    return joined["url"] if joined else f"https://{bridge_origin}"


# ---------------------------------------------------------------------------
# list_bridges
# ---------------------------------------------------------------------------


async def list_bridges(url: str = "") -> list[dict]:
    """The foreign venues an origin bridges, from its discovery document.

    Each entry names a venue (e.g. `flatboard@tools.nyrds.net`), its bridge
    board, and the bridge origins this server recognizes for it, best first.
    `local` means the origin runs that bridge itself. Defaults to the active
    origin; pass `url` to ask another.
    """
    client = _client_for(url) if url else _t()._make_client()
    try:
        await client.connect_anonymous()
        info = client.discovery
        return list(info.bridges) if info is not None else []
    finally:
        await client.close()


# ---------------------------------------------------------------------------
# crosspost (edge egress)
# ---------------------------------------------------------------------------


def _article_intent(
    identity: Identity,
    bridge_origin: str,
    board: str,
    event_id: bytes,
    article_id: bytes,
    subject: str,
    body: bytes,
    meta: BridgeMetadata,
    tags: list[str],
    parent: tuple[bytes, bytes] | None,
) -> Intent:
    fields = [metadata_text(1, subject)]
    if tags:
        fields.append(metadata_text_list(2, tags))
    fields.append(metadata_text(4, "text/plain"))
    if parent is not None:
        fields += [metadata_bytes(5, parent[0]), metadata_bytes(6, parent[1])]
    return Intent(
        event_id=event_id,
        kind=KIND_ARTICLE,
        origin=bridge_origin,
        actor_pubkey=identity.public_key,
        actor_username="",  # B issues the name; empty is always accepted (§6.2)
        actor_registrar=bridge_origin,
        board=board,
        article_id=article_id,
        metadata=model.merge_metadata(MetadataMap(fields), meta.to_fields()),
        body_hash=compute_body_hash(body),
        body_size=len(body),
    )


def _frame(identity: Identity, intent: Intent, body: bytes) -> bytes:
    return build_publish_record(intent, sign_intent(identity, encode_intent(intent)), body)


async def _send(bridge_client, outbox: Outbox, event_id: bytes, frame: bytes) -> dict:
    """Publish a stored frame on B; record and report the outcome."""
    try:
        result = parse_publish_response(await bridge_client._send_command(frame))
    except ProtocolError as e:
        outbox.set_state(event_id, "refused", str(e))
        return {"published": False, "refused": str(e)}
    except (FirehoseClientError, OSError) as e:
        return {"published": False, "queued": True, "error": str(e)}
    outbox.set_state(event_id, "sent")
    return {"published": True, "article_num": result.article_num, "seq": result.origin_seq}


async def _parent_on_bridge(bridge_url, bridge_origin, board, venue, channel, foreign_id):
    """(root_article_id, article_id) of the copy of a venue post on B, if there is one.

    Asked anonymously: the caller's key may not be admitted on B yet. Best
    effort: if B doesn't let anonymous callers query, the reply still threads
    at the venue, just not on B.
    """
    value = model.src_tag(SourceKey(venue, channel, foreign_id))[len("src:") :]
    reader = _client_for(bridge_url)
    try:
        await reader.connect_anonymous()
        resp = await reader.query_articles(bridge_origin, board, [(0x0B, 0x01, 0x02, value)])
    except (ProtocolError, FirehoseClientError):
        return None
    finally:
        await reader.close()
    if not resp.results:
        return None
    hit = resp.results[0]
    root = bytes.fromhex(hit.root_article_id) if hit.root_article_id else b""
    art = bytes.fromhex(hit.article_id)
    return (root if root and root != bytes(32) else art), art


async def crosspost(
    bridge_origin: str,
    board: str,
    body: str,
    subject: str = "",
    reply_to_foreign_id: str = "",
    bridge_url: str = "",
    auth: str | None = None,
) -> dict:
    """Post on a bridge board, signed with your home key, and to the venue as you.

    The bridge origin admits your key by asking your home origin (the one
    you're connected to) about it; your name there is your home username.
    If this gateway has an account for the board's venue, it posts to the
    venue first, as you, with a marker linking the two; otherwise the post
    stays on the bridge board, where the bridge's relay may carry it.

    bridge_origin: the bridge origin (see list_bridges).
    board: its bridge board, e.g. "~flatboard".
    reply_to_foreign_id: the venue post id you're replying to, if any.
    bridge_url: where to reach the bridge origin, if not a joined origin.
    """
    t = _t()
    t._require_text_fields(body=body, subject=subject)
    t._require_non_blank("body", body)
    bridge_origin = normalize_origin(bridge_origin)
    identity, home_origin, home_url = _home(auth)
    bridge_client = _client_for(_bridge_url(bridge_origin, bridge_url))
    outbox = _outbox()
    try:
        await bridge_client.connect(identity, username="")
        if bridge_client._server_origin != bridge_origin:
            raise ValueError(
                f"that URL serves {bridge_origin!r}? it says {bridge_client._server_origin!r}"
            )
        entry = next(
            (
                b
                for b in (bridge_client.discovery.bridges if bridge_client.discovery else [])
                if b.get("board") == board and b.get("local")
            ),
            None,
        )
        if entry is None:
            raise ValueError(f"{board!r} is not a live bridge board on {bridge_origin}")
        venue, channel = entry["venue"], entry.get("channel", "")
        venue_type = venue_type_of(venue)
        spec = load_accounts().get(venue)

        event_id, article_id = os.urandom(32), os.urandom(32)
        subject = subject or " ".join(body.split())[:80]
        body_bytes = body.encode("utf-8")
        home_meta = BridgeMetadata(home_origin=home_origin, home_url=home_url, bridge_version=None)
        parent = None
        if reply_to_foreign_id:
            parent = await _parent_on_bridge(
                bridge_client.base_url, bridge_origin, board, venue, channel, reply_to_foreign_id
            )

        def native() -> bytes:
            intent = _article_intent(
                identity, bridge_origin, board, event_id, article_id, subject,
                body_bytes, home_meta, [], parent,
            )  # fmt: skip
            return _frame(identity, intent, body_bytes)

        if spec is None:
            frame = native()
            outbox.put(
                _entry(
                    event_id,
                    bridge_origin,
                    bridge_client,
                    board,
                    venue,
                    channel,
                    "",
                    None,
                    frame,
                    "ready",
                )
            )
            result = await _send(bridge_client, outbox, event_id, frame)
            return {
                "egress": "none",
                "note": "no venue account; the bridge's relay may carry it",
                **result,
            }

        adapter = _adapter_for(spec)
        try:
            marker = model.make_marker(event_id)
            venue_text = adapter.render_outbound(body, marker, None)
            pending = BridgeMetadata(
                bridge_role=model.ROLE_CROSSPOST, venue=venue, channel=channel, marker=marker,
                home_origin=home_origin, home_url=home_url,
            )  # fmt: skip
            frame = _frame(
                identity,
                _article_intent(
                    identity,
                    bridge_origin,
                    board,
                    event_id,
                    article_id,
                    subject,
                    body_bytes,
                    pending,
                    [],
                    parent,
                ),  # fmt: skip
                body_bytes,
            )
            outbox.put(
                _entry(event_id, bridge_origin, bridge_client, board, venue, channel,
                       venue_text, reply_to_foreign_id or None, frame, "pending")
            )  # fmt: skip
            try:
                posted = await _venue_post(
                    spec, adapter, channel, venue_text, reply_to_foreign_id or None,
                    event_id.hex()[:32],
                )  # fmt: skip
            except VenueError as e:
                if isinstance(e, VenueUncertain) and "idempotent_post" in adapter.capabilities:
                    # The venue may hold the post, and a native copy on B
                    # would then sit beside it. Keep the frame pending:
                    # flush_outbox finishes it with the same key.
                    return {
                        "egress": "uncertain",
                        "venue_error": str(e),
                        "published": False,
                        "queued": True,
                        "note": "run flush_outbox to finish: it re-posts with the same key",
                    }
                # §11.2 step 4: the venue refused; keep the post on B, natively.
                frame = native()
                outbox.put(
                    _entry(
                        event_id,
                        bridge_origin,
                        bridge_client,
                        board,
                        venue,
                        channel,
                        venue_text,
                        None,
                        frame,
                        "ready",
                    )
                )
                result = await _send(bridge_client, outbox, event_id, frame)
                return {"egress": "failed", "venue_error": str(e), **result}
            frame = _final_frame(
                identity, bridge_origin, board, event_id, article_id, subject, body_bytes,
                venue_type, posted, marker, home_origin, home_url, parent,
            )  # fmt: skip
            outbox.put(
                _entry(event_id, bridge_origin, bridge_client, board, venue, channel,
                       venue_text, reply_to_foreign_id or None, frame, "ready")
            )  # fmt: skip
            result = await _send(bridge_client, outbox, event_id, frame)
            return {"egress": "posted", "venue": venue, "foreign_id": posted.foreign_id, **result}
        finally:
            await adapter.close()
    finally:
        outbox.close()
        await bridge_client.close()


def _entry(
    event_id, bridge_origin, bridge_client, board, venue, channel, text, reply_to, frame, state
):
    return OutboxEntry(
        event_id=event_id,
        bridge_origin=bridge_origin,
        bridge_url=bridge_client.base_url,
        board=board,
        venue=venue,
        channel=channel,
        venue_text=text,
        reply_to=reply_to,
        frame=frame,
        state=state,
        detail=None,
    )


def _final_frame(
    identity, bridge_origin, board, event_id, article_id, subject, body_bytes,
    venue_type, posted, marker, home_origin, home_url, parent,
) -> bytes:  # fmt: skip
    """The role-2 original with the venue's foreign_id: signed once, sent as stored (§11.2 step 5)."""
    src = SourceKey(posted.venue, posted.channel, posted.foreign_id)
    meta = BridgeMetadata(
        bridge_role=model.ROLE_CROSSPOST,
        venue=posted.venue,
        channel=posted.channel,
        foreign_id=posted.foreign_id,
        foreign_author=posted.author_handle,
        foreign_author_id=posted.author_id,
        foreign_reply_to=posted.reply_to,
        foreign_url=posted.url,
        foreign_root_id=posted.root_id,
        foreign_digest=model.foreign_digest(posted.text),
        marker=marker,
        home_origin=home_origin,
        home_url=home_url,
    )
    tags = model.bridge_tags(venue_type, src) if venue_type else ["bridged", model.src_tag(src)]
    intent = _article_intent(
        identity,
        bridge_origin,
        board,
        event_id,
        article_id,
        subject,
        body_bytes,
        meta,
        tags,
        parent,
    )
    return _frame(identity, intent, body_bytes)


# ---------------------------------------------------------------------------
# flush_outbox
# ---------------------------------------------------------------------------


async def flush_outbox(auth: str | None = None) -> dict:
    """Retry crossposts that reached the venue but not the bridge origin.

    Frames already signed with the venue's post id are re-sent as stored. A
    crosspost interrupted between the venue post and storing that id is
    re-posted to the venue with the same idempotency key when the venue
    supports it (and so lands on the same venue post), else given up and
    reported: re-posting could duplicate it there.
    """
    identity, home_origin, home_url = _home(auth)
    outbox = _outbox()
    report: list[dict] = []
    try:
        accounts = load_accounts()
        for entry in outbox.by_state("pending", "ready"):
            # One entry failing (the venue, the bridge) leaves it where it
            # was and moves on: the rest may not need either.
            try:
                result = await _flush_one(entry, identity, home_origin, home_url, accounts, outbox)
            except (VenueError, ProtocolError, FirehoseClientError, OSError) as e:
                result = {"error": str(e), "state": entry.state}
            report.append({"event_id": entry.event_id.hex(), **result})
    finally:
        outbox.close()
    return {"entries": report}


async def _flush_one(entry, identity, home_origin, home_url, accounts, outbox) -> dict:
    bridge_client = _client_for(entry.bridge_url)
    try:
        await bridge_client.connect(identity, username="")
        if entry.state == "ready":
            return await _send(bridge_client, outbox, entry.event_id, entry.frame)
        spec = accounts.get(entry.venue)
        adapter = _adapter_for(spec) if spec is not None else None
        try:
            if spec is None or adapter is None or "idempotent_post" not in adapter.capabilities:
                outbox.set_state(entry.event_id, "dropped", "venue can't re-post safely")
                return {"dropped": True}
            posted = await _venue_post(
                spec, adapter, entry.channel, entry.venue_text, entry.reply_to,
                entry.event_id.hex()[:32],
            )  # fmt: skip
        finally:
            if adapter is not None:
                await adapter.close()
        from bonnet.core.record import decode_intent

        n = int.from_bytes(entry.frame[1:5], "big")
        old = decode_intent(entry.frame[5 : 5 + n])
        old_meta = BridgeMetadata.from_metadata(old.metadata)
        body = entry.frame[5 + n + 64 + 4 :]
        parent = None
        if old.metadata.get_bytes(6):
            parent = (old.metadata.get_bytes(5), old.metadata.get_bytes(6))
        frame = _final_frame(
            identity, entry.bridge_origin, entry.board, entry.event_id, old.article_id,
            old.metadata.get_text(1) or "", body, venue_type_of(entry.venue), posted,
            old_meta.marker or model.make_marker(entry.event_id),
            old_meta.home_origin or home_origin, old_meta.home_url or home_url, parent,
        )  # fmt: skip
        outbox.put(OutboxEntry(**{**entry.__dict__, "frame": frame, "state": "ready"}))
        result = await _send(bridge_client, outbox, entry.event_id, frame)
        return {"reposted": True, **result}
    finally:
        await bridge_client.close()


# ---------------------------------------------------------------------------
# corroborate (§9.5)
# ---------------------------------------------------------------------------


async def corroborate(
    article_id: str, board: str = "", origin: str = "", auth: str | None = None
) -> dict:
    """Find every recognized bridge's copy of a bridged article.

    Reads the article's `src:` tag, the bridge origins the active origin
    recognizes for that venue, and asks each for its copy of the same venue
    post. Copies whose `foreign_digest` differ disagree on what the venue
    said; check them with get_event.
    """
    t = _t()
    board = t.cursor.resolve_board(board)
    aid = t._validate_article_id(article_id)
    client = t._make_client()
    try:
        await t._connect_with_default(client, auth)
        src_origin = origin or client._server_origin or ""
        art = await client.get_article_by_id(src_origin, board, aid, include_body=False)
        if art is None:
            raise ValueError(f"article {article_id} not found in /{board}")
        src = next(
            (s for s in (model.parse_src_tag(x.strip()) for x in art.tags.split(",")) if s), None
        )
        if src is None:
            return {"bridged": False, "copies": []}
        bridges = client.discovery.bridges if client.discovery else []
        origins: list[str] = next(
            (b.get("origins", []) for b in bridges if b.get("venue") == src.venue), []
        )
        value = model.src_tag(src)[len("src:") :]
        copies: list[dict] = []
        for o in origins or [src_origin]:
            resp = await client.query_articles(o, board, [(0x0B, 0x01, 0x02, value)])
            copies.extend(
                {"origin": o, "article_num": r.article_num, "article_id": r.article_id,
                 "event_id": r.event_id, "subject": r.subject}
                for r in resp.results
            )  # fmt: skip
        return {
            "bridged": True,
            "src": {"venue": src.venue, "channel": src.channel, "foreign_id": src.foreign_id},
            "recognized_origins": origins,
            "copies": copies,
        }
    finally:
        await client.close()
