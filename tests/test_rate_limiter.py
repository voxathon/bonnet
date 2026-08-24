"""Tests for src/bonnet/net/rate_limiter.py — sliding-window rate limiter."""

import threading
import time

from bonnet.net.rate_limiter import RateLimiter

# ---------------------------------------------------------------------------
# Basic check
# ---------------------------------------------------------------------------


def test_allows_under_limit():
    rl = RateLimiter(max_requests=5, window_seconds=60)
    for _ in range(5):
        assert rl.check("key1") is True


def test_denies_over_limit():
    rl = RateLimiter(max_requests=3, window_seconds=60)
    for _ in range(3):
        assert rl.check("key1") is True
    assert rl.check("key1") is False


def test_different_keys_independent():
    rl = RateLimiter(max_requests=2, window_seconds=60)
    assert rl.check("key1") is True
    assert rl.check("key1") is True
    assert rl.check("key1") is False
    assert rl.check("key2") is True


# ---------------------------------------------------------------------------
# Window expiry
# ---------------------------------------------------------------------------


def test_window_expiry_allows_after_window():
    rl = RateLimiter(max_requests=1, window_seconds=0.1)
    assert rl.check("key1") is True
    assert rl.check("key1") is False
    time.sleep(0.15)
    assert rl.check("key1") is True


def test_window_boundary():
    rl = RateLimiter(max_requests=2, window_seconds=0.1)
    assert rl.check("key1") is True
    assert rl.check("key1") is True
    assert rl.check("key1") is False
    time.sleep(0.1)
    assert rl.check("key1") is True


# ---------------------------------------------------------------------------
# Key construction
# ---------------------------------------------------------------------------


def test_identity_key():
    rl = RateLimiter()
    key = rl.identity_key(bytes(range(32)))
    assert key.startswith("identity:")
    assert len(key) == len("identity:") + 64


def test_address_key():
    rl = RateLimiter()
    key = rl.address_key("192.168.1.1")
    assert key == "address:192.168.1.1"


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------


def test_cleanup_removes_stale_buckets():
    rl = RateLimiter(max_requests=10, window_seconds=0.1)
    rl.check("key1")
    rl.check("key2")
    assert len(rl._buckets) == 2

    time.sleep(0.15)
    rl.cleanup()
    assert len(rl._buckets) == 0


def test_cleanup_preserves_active_buckets():
    rl = RateLimiter(max_requests=10, window_seconds=60)
    rl.check("key1")
    rl.cleanup()
    assert "key1" in rl._buckets


def test_cleanup_removes_expired_buckets():
    rl = RateLimiter(max_requests=1, window_seconds=0.05)
    rl.check("key1")
    rl.check("key2")
    assert len(rl._buckets) == 2

    time.sleep(0.1)
    rl.cleanup()
    assert len(rl._buckets) == 0


# ---------------------------------------------------------------------------
# High cardinality
# ---------------------------------------------------------------------------


def test_high_cardinality_cleanup():
    rl = RateLimiter(max_requests=1, window_seconds=0.05)
    for i in range(100):
        rl.check(f"key{i}")
    assert len(rl._buckets) == 100

    time.sleep(0.1)
    rl.cleanup()
    assert len(rl._buckets) == 0


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


def test_concurrent_checks_safe():
    rl = RateLimiter(max_requests=100, window_seconds=60)
    results = []
    barrier = threading.Barrier(4)

    def worker():
        barrier.wait()
        for _ in range(25):
            results.append(rl.check("shared"))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert sum(results) == 100
    assert results.count(False) == 0
