"""Protocol v1 WebSocket client — REMOVED in Phase 8 demolition.

All WebSocket client functionality has been replaced by:
  src/client/http.py — BonnetHTTPClient (async HTTP + RFC 9421 signatures)

This file is kept as a thin compatibility shim so existing imports
(src/client/__init__.py, tools.py, simple.py) can be updated gradually.
"""

from client.http import BonnetHTTPClient as BonnetClient
from client.http import BonnetHTTPError as BonnetError


class EncryptedSession:
    """Deprecated — protocol v2 uses TLS, not application-level encryption."""
    pass
