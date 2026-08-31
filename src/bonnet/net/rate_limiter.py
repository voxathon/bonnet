"""Shared rate limiter for command dispatch.

Shared across all connections rather than stored per-connection: a
connection handles exactly one request, so a per-connection counter could
never accumulate a rate to limit.

Bucket keys:
  authenticated:  identity:<ed25519-public-key-hex>
  anonymous:      address:<normalized-remote-address>
"""

from __future__ import annotations

import collections
import threading
import time


class RateLimiter:
    def __init__(self, max_requests: int = 100, window_seconds: int = 1):
        self._max_requests = max_requests
        self._window = float(window_seconds)
        self._buckets: dict[str, collections.deque] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> bool:
        """Return True if the request is allowed, False if rate-limited."""
        now = time.monotonic()
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
        now = time.monotonic()
        with self._lock:
            stale = [k for k, v in self._buckets.items() if not v or now - v[0] >= self._window]
            for k in stale:
                del self._buckets[k]
