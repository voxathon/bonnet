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

import contextvars
import glob
import logging
import logging.handlers
import os
from datetime import datetime

_log_file_path = None
_log = None
_initialized = False

_req_id: contextvars.ContextVar[str] = contextvars.ContextVar("bonnet_req_id", default="")
_tenant: contextvars.ContextVar[str] = contextvars.ContextVar("bonnet_tenant", default="")
_log_origin: contextvars.ContextVar[str] = contextvars.ContextVar("bonnet_origin", default="")
_log_actor: contextvars.ContextVar[str] = contextvars.ContextVar("bonnet_actor", default="")

_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
}


def bind_context(req_id: str = "", tenant: str = "", origin: str = "", actor: str = "") -> None:
    """Bind per-request correlation fields for subsequent log records."""
    if req_id:
        _req_id.set(req_id[-8:] if len(req_id) > 8 else req_id)
    if tenant:
        _tenant.set(tenant)
    if origin:
        _log_origin.set(origin)
    if actor:
        _log_actor.set(actor[:16] if len(actor) > 16 else actor)


def clear_context() -> None:
    """Clear per-request correlation fields."""
    _req_id.set("")
    _tenant.set("")
    _log_origin.set("")
    _log_actor.set("")


def _context_suffix() -> str:
    parts = []
    rid = _req_id.get()
    ten = _tenant.get()
    org = _log_origin.get()
    act = _log_actor.get()
    if rid:
        parts.append(f"req={rid}")
    if ten:
        parts.append(f"tenant={ten}")
    if org:
        parts.append(f"origin={org}")
    if act:
        parts.append(f"actor={act}")
    return (" " + " ".join(parts)) if parts else ""


def _fields_suffix(fields: dict) -> str:
    if not fields:
        return ""
    safe = {}
    for k, v in fields.items():
        if k in ("private_key", "api_key", "password"):
            safe[k] = "(redacted)"
        else:
            safe[k] = v
    return " " + " ".join(f"{k}={v}" for k, v in safe.items())


class TimestampFormatter(logging.Formatter):
    def format(self, record):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        return f"[{ts}] [{record.levelname}] {record.getMessage()}"


def _resolve_level(explicit: str | None) -> int:
    raw = explicit or os.environ.get("BONNET_LOG_LEVEL", "DEBUG")
    return _LEVELS.get(str(raw).upper(), logging.DEBUG)


def _prune_old_logs(log_dir: str, keep: int = 20) -> None:
    try:
        files = sorted(glob.glob(os.path.join(log_dir, "bonnet-*.log*")))
        for stale in files[:-keep] if len(files) > keep else []:
            try:
                os.remove(stale)
            except OSError:
                pass
    except Exception:
        pass


def init_logging(
    log_dir: str = None,
    level: str | None = None,
    mirror_stderr: bool = False,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
    keep_files: int = 20,
) -> None:
    """
    Initialize logging to timestamped rotating file in log_dir.
    Raises OSError if directory creation or file open fails.
    Must be called before any logging will occur.
    """
    global _log_file_path, _log, _initialized

    if _initialized:
        return

    if log_dir is None:
        log_dir = "./logs"

    os.makedirs(log_dir, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    _log_file_path = os.path.join(log_dir, f"bonnet-{ts}.log")

    handler = logging.handlers.RotatingFileHandler(
        _log_file_path,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
        errors="replace",
    )
    handler.setFormatter(TimestampFormatter())

    _log = logging.getLogger("bonnet")
    _log.setLevel(_resolve_level(level))
    _log.handlers.clear()
    _log.addHandler(handler)
    if mirror_stderr:
        err_handler = logging.StreamHandler()
        err_handler.setFormatter(TimestampFormatter())
        _log.addHandler(err_handler)
    _log.propagate = False

    _prune_old_logs(log_dir, keep=keep_files)

    _initialized = True


def _emit(level: int, msg: str, fields: dict | None = None) -> None:
    global _log, _initialized
    if not _initialized or _log is None:
        return
    if not _log.isEnabledFor(level):
        return
    suffix = _context_suffix() + _fields_suffix(fields or {})
    _log.log(level, f"{msg}{suffix}")


def log_msg(msg: str) -> None:
    """Log a text message. No-op if init_logging() not called."""
    _emit(logging.INFO, msg)


def log_debug(msg: str, **fields) -> None:
    """Debug-level log with optional structured k=v fields."""
    _emit(logging.DEBUG, msg, fields)


def log_info(msg: str, **fields) -> None:
    """Info-level log with optional structured k=v fields."""
    _emit(logging.INFO, msg, fields)


def log_warning(msg: str, **fields) -> None:
    """Warning-level log with optional structured k=v fields."""
    _emit(logging.WARNING, msg, fields)


def log_error(msg: str, **fields) -> None:
    """Error-level log with optional structured k=v fields."""
    _emit(logging.ERROR, msg, fields)


def set_level(level: str) -> None:
    """Change the active log level at runtime (e.g. 'INFO'). No-op if uninitialized."""
    global _log
    if _log is not None:
        _log.setLevel(_resolve_level(level))


def close_logging() -> None:
    """Flush and close the log file. Safe to call repeatedly and when uninitialized."""
    global _log_file_path, _log, _initialized

    if not _initialized:
        return

    if _log is not None:
        for handler in list(_log.handlers):
            _log.removeHandler(handler)
            try:
                handler.flush()
            except Exception:
                pass
            handler.close()
        _log = None

    _log_file_path = None
    _initialized = False
    clear_context()


def get_log_path() -> str | None:
    """Return current log file path, or None if logging is not initialized."""
    return _log_file_path
