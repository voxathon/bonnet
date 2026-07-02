"""Runtime resolution of bundled external binaries (e.g. ripgrep)."""

import os
import shutil
import sys

_rg_path = None
_rg_checked = False


def resolve_rg():
    """Return the path to the ripgrep (`rg`) binary, or None if unavailable.

    Lookup order:
      1. When frozen by PyInstaller, ``sys._MEIPASS`` points at the bundled
         extraction directory; look for ``rg`` there first.
      2. Otherwise search ``PATH`` via :func:`shutil.which`.

    The result is cached for the lifetime of the process.
    """
    global _rg_path, _rg_checked
    if _rg_checked:
        return _rg_path
    _rg_checked = True

    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        candidate = os.path.join(sys._MEIPASS, "rg")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            _rg_path = candidate
            return _rg_path

    found = shutil.which("rg")
    if found:
        _rg_path = found
    return _rg_path


def reset_resolve_cache():
    """Clear the cached binary resolution (used by tests)."""
    global _rg_path, _rg_checked
    _rg_path = None
    _rg_checked = False
