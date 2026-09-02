"""The rate limiter must measure elapsed time on a monotonic clock.

Its buckets hold timestamps it generated itself and compares only against
each other — nothing here is ever checked against a value from the wire.
`time.time()` can therefore only hurt: an NTP correction or a manual clock
set moves it, and the window moves with it.

Contrast `net/replay.py`, which compares against signed `expires` values
from the request itself. That one must stay on the wall clock.
"""

import bonnet.net.rate_limiter as rate_limiter
from bonnet.net.rate_limiter import RateLimiter


class _SteppedClock:
    """Wall clock that jumps backwards; monotonic that never does."""

    def __init__(self):
        self._mono = 1000.0
        self._wall = 5000.0

    def advance(self, seconds):
        self._mono += seconds
        self._wall += seconds

    def step_wall_back(self, seconds):
        self._wall -= seconds

    def time(self):
        return self._wall

    def monotonic(self):
        return self._mono


def test_window_survives_a_backwards_clock_step(monkeypatch):
    """A backwards wall-clock step must not freeze the window.

    Bucket entries stamped before the step sit in the future relative to
    `now`, so `now - bucket[0]` goes negative, nothing is ever evicted, and
    the caller stays blocked long past the window it was promised.
    """
    clock = _SteppedClock()
    monkeypatch.setattr(rate_limiter, "time", clock)

    rl = RateLimiter(max_requests=2, window_seconds=1)

    assert rl.check("k")
    assert rl.check("k")
    assert not rl.check("k"), "third request inside the window must be limited"

    # Operator corrects a clock that had run fast.
    clock.step_wall_back(10.0)
    # Well past the 1s window in real elapsed time.
    clock.advance(2.0)

    assert rl.check("k"), "window did not reopen after the window elapsed"


def test_cleanup_survives_a_backwards_clock_step(monkeypatch):
    """cleanup() compares against the same stamps check() wrote.

    It has to read the same clock, or it evicts live buckets and retains
    dead ones.
    """
    clock = _SteppedClock()
    monkeypatch.setattr(rate_limiter, "time", clock)

    rl = RateLimiter(max_requests=2, window_seconds=1)
    assert rl.check("k")

    clock.step_wall_back(10.0)
    clock.advance(5.0)

    rl.cleanup()
    assert "k" not in rl._buckets, "a bucket older than the window was retained"
