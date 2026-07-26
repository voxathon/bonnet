import logging
import os
from datetime import datetime

_log_file_path = None
_log_file = None
_log = None
_initialized = False


class TimestampFormatter(logging.Formatter):
    def format(self, record):
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
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
        log_dir = './logs'

    os.makedirs(log_dir, exist_ok=True)

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    _log_file_path = os.path.join(log_dir, f'bonnet-{ts}.log')
    _log_file = open(_log_file_path, 'w', encoding='utf-8', errors='replace')

    handler = logging.StreamHandler(_log_file)
    handler.setFormatter(TimestampFormatter())

    _log = logging.getLogger('bonnet')
    _log.setLevel(logging.DEBUG)
    _log.addHandler(handler)

    _initialized = True


def log_msg(msg: str) -> None:
    """Log a text message. No-op if init_logging() not called."""
    global _log, _initialized
    if not _initialized or _log is None:
        return
    _log.debug(msg)


def log_hex(label: str, data: bytes) -> None:
    """Log binary data as full hex dump. No-op if init_logging() not called."""
    global _log_file, _initialized
    if not _initialized or _log_file is None:
        return

    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    _log_file.write(f"[{ts}] {label} ({len(data)} bytes):\n")
    hex_str = data.hex()
    for i in range(0, len(hex_str), 64):
        _log_file.write(f"  {hex_str[i:i+64]}\n")
    _log_file.flush()


def log_dict(label: str, d: dict) -> None:
    """Log dictionary with truncation for long strings. No-op if init_logging() not called."""
    global _log_file, _initialized
    if not _initialized or _log_file is None:
        return

    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    _log_file.write(f"[{ts}] {label}:\n")
    for k, v in d.items():
        if isinstance(v, str) and len(v) > 100:
            _log_file.write(f"  {k}: {v[:100]}... ({len(v)} chars)\n")
        else:
            _log_file.write(f"  {k}: {v}\n")
    _log_file.flush()


def get_log_path() -> str:
    """Return current log file path. None if not initialized."""
    global _log_file_path
    return _log_file_path


def is_initialized() -> bool:
    """Return True if logging initialized."""
    global _initialized
    return _initialized
