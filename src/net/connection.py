"""Protocol v1 Connection class — REMOVED in Phase 8 demolition.

All WebSocket connection handling has been replaced by:
  - src/net/http_server.py (server-side ASGI app)
  - src/client/http.py (client-side BonnetHTTPClient)
  - src/net/context.py (transport-neutral CommandContext)

ConnectionError is kept as a thin exception class because some
legacy code and tests still reference it.
"""


class ConnectionError(Exception):
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")
