"""Per-identity concurrency + rate limiting for content search.

The command handler is synchronous and runs inline on the event loop, but the
actual ripgrep work runs in Board's ThreadPoolExecutor. SearchLimiter gates
entry into that work per identity (the connection's peer_public_key hex, or
"anonymous"), enforcing both an in-flight concurrency cap and a token-bucket
rate limit. It is fully thread-safe (it lives behind the executor tasks plus
the sync handler) and uses only threading primitives -- no asyncio.
"""

import threading
import time


class _IdentityState:
    __slots__ = ("lock", "in_flight", "max_concurrency", "condition",
                 "tokens", "capacity", "refill_rate", "last_refill")

    def __init__(self, max_concurrency, capacity, refill_rate):
        self.lock = threading.Lock()
        self.in_flight = 0
        self.max_concurrency = max_concurrency
        self.condition = threading.Condition(self.lock)
        # token bucket: start full
        self.tokens = float(capacity)
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self.last_refill = time.monotonic()


class SearchLimiter:
    """Thread-safe per-identity concurrency + token-bucket rate limiter."""

    def __init__(self, per_identity_concurrency=1, rate_limit=10, rate_window_seconds=60):
        if per_identity_concurrency < 1:
            per_identity_concurrency = 1
        if rate_limit < 1:
            rate_limit = 1
        if rate_window_seconds < 1:
            rate_window_seconds = 1
        self._default_concurrency = per_identity_concurrency
        # refill_rate = tokens added per second
        self._refill_rate = rate_limit / float(rate_window_seconds)
        self._capacity = float(rate_limit)
        self._states = {}
        self._states_lock = threading.Lock()

    def _get_state(self, identity_key):
        with self._states_lock:
            state = self._states.get(identity_key)
            if state is None:
                state = _IdentityState(self._default_concurrency, self._capacity, self._refill_rate)
                self._states[identity_key] = state
            return state

    def _refill(self, state):
        now = time.monotonic()
        elapsed = now - state.last_refill
        if elapsed > 0:
            state.tokens = min(state.capacity, state.tokens + elapsed * state.refill_rate)
            state.last_refill = now

    def acquire(self, identity_key, timeout=10.0):
        """Try to admit one content search for ``identity_key``.

        Returns True if admitted (caller MUST later call :meth:`release`),
        False if the rate limit is exhausted or the concurrency slot could not
        be obtained within ``timeout``.
        """
        state = self._get_state(identity_key)
        deadline = time.monotonic() + timeout if timeout is not None else None

        with state.condition:
            # Rate check first (non-blocking): must have a token.
            self._refill(state)
            if state.tokens < 1.0:
                return False
            # Concurrency check: wait for a slot up to the deadline.
            while state.in_flight >= state.max_concurrency:
                if deadline is None:
                    return False
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                if not state.condition.wait(timeout=remaining):
                    if time.monotonic() >= deadline:
                        return False
            # Admit: consume a token and take a slot.
            state.tokens -= 1.0
            state.in_flight += 1
            return True

    def release(self, identity_key):
        """Release a concurrency slot for ``identity_key``."""
        state = self._get_state(identity_key)
        with state.condition:
            if state.in_flight > 0:
                state.in_flight -= 1
            state.condition.notify()
