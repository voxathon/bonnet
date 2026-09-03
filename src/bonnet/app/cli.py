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

"""Local REPL connection for the Bonnet server.

Produces a FirehoseContext for local command dispatch, bypassing HTTP
signature verification. The local admin identity is the server's own key.
"""

from __future__ import annotations

from bonnet.net.firehose_commands import FirehoseContext


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
