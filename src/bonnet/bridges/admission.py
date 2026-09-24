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

"""Admission: crossposters sign on a bridge origin with their home key (design doc §6).

Server code on the bridge origin B, hooked into the publish path after
validation and before the ACL check. A key unknown on B that publishes on a
`~` board with `home_origin`/`home_url` gets checked against its home: B
dials the home, asks USER_GET about the key, and if it's live there,
registers it on B as the origin identity, pinning the home. Later writes by
the key re-check the home every `recheck_seconds`, and fail open for at
most `max_staleness_seconds` when the home is unreachable.

The handler is synchronous and runs in a worker thread, so every home check
is submitted to the server's event loop and awaited with a timeout (§6.6).
Never under a board stripe or `_identity_lock`: the network I/O happens
first, and the lock is taken only for the no-I/O name pick and append.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import threading
import time
import unicodedata
from collections.abc import Callable
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from bonnet.bridges.config import AdmissionConfig
from bonnet.bridges.model import F_HOME_ORIGIN, F_HOME_URL, F_HOME_USERNAME, BridgeMetadata
from bonnet.core.crypto import Identity
from bonnet.core.kinds import KIND_ARTICLE, KIND_USER_REGISTER, KIND_USER_REVOKE
from bonnet.core.logging import log_msg
from bonnet.core.record import (
    Intent,
    MetadataMap,
    encode_intent,
    metadata_bytes,
    metadata_text,
    metadata_u64,
    normalize_origin,
    sign_intent,
)


@dataclass(frozen=True)
class HomeStatus:
    """What the home origin says about a key. `None` from a lookup = not registered."""

    username: str
    revoked: bool
    superseded_by: bytes | None


class AdmissionRefused(Exception):
    """Admission said no; the message is the reason the client sees."""


class HomeUnreachable(Exception):
    """The home origin couldn't be asked (down, timed out, wrong origin, unsafe)."""


# ---------------------------------------------------------------------------
# Home client
# ---------------------------------------------------------------------------


def default_transport_factory(
    trust_store_path: str, verify_tls: bool, allow_private_dial: bool
) -> Callable[[str], Any]:
    from bonnet.net.firehose_sync import is_safe_dial_target
    from bonnet.net.firehose_transport import FirehoseTransport

    def make(home_url: str):
        parsed = urlparse(home_url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme not in ("https", "http") or not is_safe_dial_target(
            parsed.hostname, port, allow_private=allow_private_dial
        ):
            raise HomeUnreachable(f"unsafe or unsupported home_url {home_url!r}")
        return FirehoseTransport(home_url, verify=verify_tls, trust_store_path=trust_store_path)

    return make


class AdmissionClient:
    """Asks a home origin about one key: discovery (pinned like a peer), then USER_GET."""

    def __init__(self, transport_factory: Callable[[str], Any]):
        self._factory = transport_factory
        self._transports: dict[tuple[str, str], Any] = {}

    async def lookup(self, home_origin: str, home_url: str, pubkey: bytes) -> HomeStatus | None:
        from bonnet.net.firehose_transport import FirehoseClientError
        from bonnet.net.firehose_wire import (
            ProtocolError,
            build_user_get,
            parse_user_get_response,
        )

        key = (home_origin, home_url)
        transport = self._transports.get(key)
        try:
            if transport is None:
                transport = self._factory(home_url)
                await transport.connect_anonymous()
                if normalize_origin(transport._server_origin or "") != home_origin:
                    raise HomeUnreachable(
                        f"{home_url} says it is {transport._server_origin!r}, not {home_origin!r}"
                    )
                self._transports[key] = transport
            resp = await transport.send_command(build_user_get(home_origin, pubkey))
        except (FirehoseClientError, OSError) as e:
            self._transports.pop(key, None)
            raise HomeUnreachable(f"{home_origin}: {e}") from e
        try:
            info = parse_user_get_response(resp)
        except ProtocolError as e:
            if e.code == 0x0001:  # USER_GET's "User not found"
                return None
            raise HomeUnreachable(f"{home_origin}: {e}") from e
        return HomeStatus(
            username=info.username,
            revoked=info.revoked,
            superseded_by=bytes.fromhex(info.superseded_by) if info.superseded_by else None,
        )


# ---------------------------------------------------------------------------
# Admission
# ---------------------------------------------------------------------------


def _hex(home_origin: str) -> str:
    return hashlib.sha256(home_origin.encode("utf-8")).hexdigest()


def base_name(home_username: str) -> str:
    """The home username as a name on B: NFC, `~` → `-` (§6.2 step 5)."""
    s = unicodedata.normalize("NFC", home_username).replace("~", "-")
    s = "".join(c for c in s if ord(c) >= 0x20 and c not in '<>:"/\\|?*').strip()
    return s or "user"


class Admission:
    def __init__(
        self,
        handler,
        config: AdmissionConfig,
        origin_identity: Callable[[], Identity],
        client: AdmissionClient,
        loop_getter: Callable[[], asyncio.AbstractEventLoop | None],
        clock: Callable[[], float] = time.time,
    ):
        self._h = handler
        self._config = config
        self._origin_identity = origin_identity
        self._client = client
        self._loop = loop_getter
        self._clock = clock
        self._slots = threading.BoundedSemaphore(config.max_concurrent_checks)
        self._last_ok: dict[bytes, float] = {}

    # -- entry point ---------------------------------------------------------

    def check(self, intent: Intent, ctx):
        """None: carry on unchanged. A context: carry on as this (newly admitted)
        principal. Raises AdmissionRefused to refuse the publish."""
        h = self._h
        pin = h._bridges.admission(h._origin, ctx.peer_pubkey) if h._bridges else None
        if ctx.is_unknown:
            if intent.kind != KIND_ARTICLE or not intent.board.startswith("~"):
                return None
            meta = BridgeMetadata.from_metadata(intent.metadata)
            if not meta.home_origin or not meta.home_url:
                return None
            return self._first_contact(intent, meta, ctx)
        if pin is None or not pin["active"] or not ctx.is_registered:
            return None
        if intent.kind == KIND_ARTICLE:
            meta = BridgeMetadata.from_metadata(intent.metadata)
            if meta.home_origin != pin["home_origin"] or meta.home_url != pin["home_url"]:
                raise AdmissionRefused("home_origin does not match this key's admission")
        self._recheck(ctx.peer_pubkey, pin)
        return None

    # -- home checks -----------------------------------------------------------

    def _ask(self, home_origin: str, home_url: str, pubkey: bytes) -> HomeStatus | None:
        """Run one home lookup on the server loop from this worker thread."""
        loop = self._loop()
        if loop is None or not loop.is_running():
            raise HomeUnreachable("admission is not running (no server loop)")
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            # Waiting here would block the loop the lookup needs: refuse.
            raise AdmissionRefused("admission cannot run on the event loop thread")
        if not self._slots.acquire(blocking=False):
            raise AdmissionRefused("admission busy; retry")
        try:
            future = asyncio.run_coroutine_threadsafe(
                self._client.lookup(home_origin, home_url, pubkey), loop
            )
            try:
                return future.result(timeout=self._config.timeout_seconds)
            except FutureTimeout:
                future.cancel()
                raise HomeUnreachable(f"{home_origin} did not answer in time") from None
        finally:
            self._slots.release()

    def _require_live(self, status: HomeStatus | None) -> HomeStatus:
        if status is None:
            raise AdmissionRefused("not registered at home")
        if status.revoked:
            raise AdmissionRefused("key revoked at home")
        if status.superseded_by is not None:
            raise AdmissionRefused("key rotated at home; publish with the successor")
        return status

    def _recheck(self, pubkey: bytes, pin: dict) -> None:
        now = self._clock()
        last = self._last_ok.get(pubkey)
        if last is None:
            # The admission itself was a successful check.
            user = self._h._users.get_user_by_pubkey(self._h._origin, pubkey)
            last = float(user["created_at"]) if user else 0.0
        if now - last < self._config.recheck_seconds:
            return
        try:
            status = self._ask(pin["home_origin"], pin["home_url"], pubkey)
        except HomeUnreachable as e:
            if now - last < self._config.max_staleness_seconds:
                log_msg(f"ADMISSION: {pin['home_origin']} unreachable ({e}); failing open")
                return
            raise AdmissionRefused("home origin unreachable") from e
        try:
            self._require_live(status)
        except AdmissionRefused:
            self._last_ok.pop(pubkey, None)
            raise
        self._last_ok[pubkey] = now

    # -- first contact ------------------------------------------------------------

    def _first_contact(self, intent: Intent, meta: BridgeMetadata, ctx):
        h = self._h
        home_origin = normalize_origin(meta.home_origin or "")
        home_url = meta.home_url or ""
        pubkey = ctx.peer_pubkey
        if home_origin == h._origin:
            raise AdmissionRefused("register here first")
        if home_origin != meta.home_origin:
            raise AdmissionRefused("home_origin must be a normalized origin name")
        try:
            status = self._require_live(self._ask(home_origin, home_url, pubkey))
        except HomeUnreachable as e:
            raise AdmissionRefused(f"home origin unreachable: {e}") from e

        prior = h._bridges.admission_for_home(h._origin, home_origin, status.username)
        if prior is not None and prior["pubkey"] != pubkey:
            # Rotation at home (§6.4): the name moves only to the chain's head.
            head = self._chain_head(home_origin, home_url, prior["pubkey"])
            if head != pubkey:
                raise AdmissionRefused("this key does not succeed the admitted key at home")
            if self._banned(prior["pubkey"]):
                raise AdmissionRefused(
                    "the key this one succeeds is banned here; rotating at home does not lift it"
                )

        with h._identity_lock:
            if h._users.get_user_by_pubkey(h._origin, pubkey) is not None:
                # A concurrent first contact got there first.
                return self._context(ctx)
            current = h._bridges.admission_for_home(h._origin, home_origin, status.username)
            if current is not None and current["pubkey"] != pubkey:
                if prior is None or current["pubkey"] != prior["pubkey"]:
                    raise AdmissionRefused("admission changed concurrently; retry")
                self._append_revoke(current)
                name = current["username"]
            else:
                name = self._pick_name(status.username, home_origin)
            self._append_register(pubkey, name, home_origin, home_url, status.username)
        self._last_ok[pubkey] = self._clock()
        log_msg(f"ADMISSION: admitted {pubkey.hex()[:16]} as '{name}' (home {home_origin})")
        return self._context(ctx)

    def _chain_head(self, home_origin: str, home_url: str, start: bytes) -> bytes | None:
        key = start
        for _ in range(self._config.max_chain_hops):
            try:
                status = self._ask(home_origin, home_url, key)
            except HomeUnreachable as e:
                raise AdmissionRefused(f"home origin unreachable: {e}") from e
            if status is None or status.revoked:
                return None
            if status.superseded_by is None:
                return key
            key = status.superseded_by
        raise AdmissionRefused("rotation chain too long")

    def _banned(self, pubkey: bytes) -> bool:
        h = self._h
        try:
            pending = h._policy.list_pending_for_pubkey(pubkey, allowed_origins={h._origin})
        except Exception:
            return False
        return any(p["type"] in ("ban", "permaban") for p in pending)

    def _pick_name(self, home_username: str, home_origin: str) -> str:
        users = self._h._users
        origin = self._h._origin
        base = base_name(home_username)
        if users.username_holder(origin, base) is None:
            return base
        digest = _hex(home_origin)
        for n in range(4, len(digest) + 1, 4):
            candidate = f"{base}-{digest[:n]}"
            if users.username_holder(origin, candidate) is None:
                return candidate
        raise AdmissionRefused("no free name for this user")

    def _context(self, ctx):
        from bonnet.net.firehose_commands import FirehoseContext

        return FirehoseContext(
            peer_pubkey=ctx.peer_pubkey,
            is_anonymous=False,
            is_unknown=False,
            is_registered=True,
            role="",
            origin=ctx.origin,
            remote_addr=ctx.remote_addr,
        )

    # -- appends as the origin identity (the _ensure_root_registered path) --------

    def _append(self, intent: Intent) -> None:
        h = self._h
        identity = self._origin_identity()
        intent.actor_pubkey = identity.public_key
        h._firehose.append_record(
            identity, intent, sign_intent(identity, encode_intent(intent)), b""
        )
        if h._dispatcher is not None:
            h._dispatcher.dispatch_origin(h._origin)

    def _append_register(
        self, pubkey: bytes, name: str, home_origin: str, home_url: str, home_username: str
    ) -> None:
        origin = self._h._origin
        self._append(
            Intent(
                event_id=os.urandom(32),
                kind=KIND_USER_REGISTER,
                origin=origin,
                actor_registrar=origin,
                metadata=MetadataMap(
                    [
                        metadata_text(1, name),
                        metadata_bytes(2, pubkey),
                        metadata_u64(3, 0),
                        metadata_text(F_HOME_ORIGIN, home_origin),
                        metadata_text(F_HOME_URL, home_url),
                        metadata_text(F_HOME_USERNAME, home_username),
                    ]
                ),
            )
        )

    def _append_revoke(self, admission: dict) -> None:
        origin = self._h._origin
        self._append(
            Intent(
                event_id=os.urandom(32),
                kind=KIND_USER_REVOKE,
                origin=origin,
                actor_registrar=origin,
                target_origin=origin,
                target_event_id=admission["reg_event_id"],
                metadata=MetadataMap([metadata_bytes(1, admission["pubkey"])]),
            )
        )
        self._last_ok.pop(admission["pubkey"], None)
