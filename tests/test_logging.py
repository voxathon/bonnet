"""Tests for the logging module lifecycle (init, close, idempotency)."""

import os
import time

from bonnet.core.logging import (
    close_logging,
    get_log_path,
    init_logging,
    log_msg,
)


def _read_text_with_retry(path: str, attempts: int = 20, delay: float = 0.05) -> str:
    """Read a just-closed file, tolerating Windows CI's momentary AV/indexer lock.

    A file handle closed on the previous line can still be briefly invisible
    to a fresh open() on GitHub's windows-latest runners (Defender/Search
    Indexer holding it for a beat) even though nothing in this process still
    has it open. Retry instead of asserting on a race we don't control.
    """
    last_error: OSError | None = None
    for _ in range(attempts):
        try:
            with open(path, encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError as e:
            last_error = e
            time.sleep(delay)
    assert last_error is not None
    raise last_error


def test_init_creates_log_file_and_close_closes_it(tmp_path):
    log_dir = tmp_path / "logs"
    init_logging(str(log_dir))
    try:
        path = get_log_path()
        assert path is not None
        assert os.path.exists(path)
        log_msg("shutdown-marker-12345")
    finally:
        close_logging()

    assert get_log_path() is None
    content = _read_text_with_retry(os.path.join(str(log_dir), os.path.basename(path)))
    assert "shutdown-marker-12345" in content


def test_close_logging_is_idempotent():
    close_logging()
    close_logging()


def test_double_init_is_single_initialization(tmp_path):
    init_logging(str(tmp_path / "a"))
    try:
        first_path = get_log_path()
        init_logging(str(tmp_path / "b"))
        assert get_log_path() == first_path
        assert os.path.dirname(first_path).endswith("a")
    finally:
        close_logging()


def test_log_msg_after_close_is_noop():
    close_logging()
    log_msg("after close")
