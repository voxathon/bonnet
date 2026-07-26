"""Local REPL connection for the Bonnet firehose server.

Produces a FirehoseContext for local command dispatch, bypassing HTTP
signature verification. The local admin identity is the server's own key.
"""

from __future__ import annotations

from net.firehose_commands import FirehoseContext


class FirehoseLocalConnection:
    """Local REPL principal — produces FirehoseContext for local dispatch."""

    def __init__(self, server_pubkey: bytes, origin: str, role: str = "administrator"):
        self.server_pubkey = server_pubkey
        self.origin = origin
        self.role = role

    def to_context(self) -> FirehoseContext:
        return FirehoseContext(
            peer_pubkey=self.server_pubkey,
            is_anonymous=False,
            is_unknown=False,
            is_registered=True,
            role=self.role,
            origin=self.origin,
            remote_addr="localhost",
        )
