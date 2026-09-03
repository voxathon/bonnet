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

import logging
import os
from datetime import datetime

_log_file_path = None
_log_file = None
_log = None
_initialized = False


class TimestampFormatter(logging.Formatter):
    def format(self, record):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        return f"[{ts}] {record.getMessage()}"


def init_logging(log_dir: str = None) -> None:
    """
    Initialize logging to timestamped file in log_dir.
    Raises OSError if directory creation or file open fails.
    Must be called before any logging will occur.
    """
    global _log_file_path, _log_file, _log, _initialized

    if _initialized:
        return

    if log_dir is None:
        log_dir = "./logs"

    os.makedirs(log_dir, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    _log_file_path = os.path.join(log_dir, f"bonnet-{ts}.log")
    _log_file = open(_log_file_path, "w", encoding="utf-8", errors="replace")

    handler = logging.StreamHandler(_log_file)
    handler.setFormatter(TimestampFormatter())

    _log = logging.getLogger("bonnet")
    _log.setLevel(logging.DEBUG)
    _log.addHandler(handler)

    _initialized = True


def log_msg(msg: str) -> None:
    """Log a text message. No-op if init_logging() not called."""
    global _log, _initialized
    if not _initialized or _log is None:
        return
    _log.debug(msg)


def close_logging() -> None:
    """Flush and close the log file. Safe to call repeatedly and when uninitialized."""
    global _log_file_path, _log_file, _log, _initialized

    if not _initialized:
        return

    if _log is not None:
        for handler in list(_log.handlers):
            _log.removeHandler(handler)
            handler.close()
        _log = None

    if _log_file is not None and not _log_file.closed:
        try:
            _log_file.flush()
        finally:
            _log_file.close()

    _log_file = None
    _log_file_path = None
    _initialized = False


def get_log_path() -> str | None:
    """Return current log file path, or None if logging is not initialized."""
    return _log_file_path
