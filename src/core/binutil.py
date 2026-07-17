"""Runtime resolution of bundled external binaries (e.g. ripgrep)."""

import os
import shutil
import sys

_rg_path = None
_rg_checked = False
_rg_explicit = None

_RG_ENV_VAR = "BONNET_RG_PATH"


def set_rg_path(path):
    """Set an explicit ripgrep binary path (e.g. from config).

    When set, :func:`resolve_rg` will prefer this path over PATH lookup
    and the frozen-bundle fallback.  Pass ``None`` to clear a previously
    set explicit path and revert to automatic resolution.
    """
    global _rg_explicit, _rg_path, _rg_checked
    _rg_explicit = path if path else None
    _rg_path = None
    _rg_checked = False


def _validate_binary(candidate):
    """Return *candidate* if it is an existing, executable file, else ``None``."""
    if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    return None


def resolve_rg():
    """Return the path to the ripgrep (`rg`) binary, or None if unavailable.

    Lookup order (first hit wins):
      1. Explicit path set via :func:`set_rg_path` (typically from config).
      2. ``BONNET_RG_PATH`` environment variable.
      3. When frozen by PyInstaller, ``sys._MEIPASS`` points at the bundled
         extraction directory; look for ``rg`` there.
      4. Otherwise search ``PATH`` via :func:`shutil.which`.

    The result is cached for the lifetime of the process (or until
    :func:`set_rg_path` / :func:`reset_resolve_cache` is called).
    """
    global _rg_path, _rg_checked
    if _rg_checked:
        return _rg_path
    _rg_checked = True

    # 1. Explicit path from set_rg_path()
    if _rg_explicit:
        found = _validate_binary(_rg_explicit)
        if found:
            _rg_path = found
            return _rg_path

    # 2. Environment variable
    env_path = os.environ.get(_RG_ENV_VAR)
    if env_path:
        found = _validate_binary(env_path)
        if found:
            _rg_path = found
            return _rg_path

    # 3. Frozen / PyInstaller bundle
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        candidate = os.path.join(sys._MEIPASS, "rg")
        found = _validate_binary(candidate)
        if found:
            _rg_path = found
            return _rg_path

    # 4. PATH lookup
    found = shutil.which("rg")
    if found:
        _rg_path = found
    return _rg_path


def reset_resolve_cache():
    """Clear the cached binary resolution (used by tests)."""
    global _rg_path, _rg_checked, _rg_explicit
    _rg_path = None
    _rg_checked = False
    _rg_explicit = None
