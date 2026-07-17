"""Shared rate limiter for command dispatch.

Replaces the per-connection _request_timestamps deque in CommandHandler.
The old approach stored timestamps on the Connection object, but since each
v1 connection handles exactly one request, the limit never accumulated.

This limiter is keyed by identity (for authenticated users) or address
(for anonymous users), and is shared across all connections/requests.

PROTOCOL_RENOVATION_PLAN §10:
  Authenticated keys use:  identity:<ed25519-public-key-hex>
  Anonymous clients use:   address:<normalized-remote-address>
"""

from __future__ import annotations

import time
import threading
import collections
from typing import Optional


class RateLimiter:
    def __init__(self, max_requests: int = 100, window_seconds: int = 1):
        self._max_requests = max_requests
        self._window = float(window_seconds)
        self._buckets: dict[str, collections.deque] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> bool:
        """Return True if the request is allowed, False if rate-limited."""
        now = time.time()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = collections.deque()
                self._buckets[key] = bucket

            while bucket and now - bucket[0] >= self._window:
                bucket.popleft()

            if len(bucket) >= self._max_requests:
                return False

            bucket.append(now)
            return True

    def identity_key(self, peer_public_key: bytes) -> str:
        return f"identity:{peer_public_key.hex()}"

    def address_key(self, remote_addr: str) -> str:
        return f"address:{remote_addr}"

    def cleanup(self) -> None:
        """Remove expired buckets to bound memory."""
        now = time.time()
        with self._lock:
            stale = [k for k, v in self._buckets.items() if not v or now - v[0] >= self._window]
            for k in stale:
                del self._buckets[k]
