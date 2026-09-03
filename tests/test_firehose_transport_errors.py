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

"""Network failures against an unreachable origin must surface as a clean
FirehoseClientError, not a raw httpx traceback with an empty message.

Regression coverage for the bug where an unreachable BONNET_URL dumped a full
ConnectError traceback to stderr and returned `ToolError: ... ` with nothing
after the colon — every other error path in this codebase raises a
one-line, non-empty message.
"""

import socket

import pytest

from bonnet.net.firehose_transport import FirehoseClientError, FirehoseTransport


def _closed_local_port() -> int:
    """A TCP port on localhost nothing is listening on.

    Bound and immediately released: the OS won't hand the port back out
    right away, so a connection to it is refused rather than accepted by
    some unrelated service.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.mark.asyncio
async def test_discover_against_unreachable_origin_raises_clean_error():
    port = _closed_local_port()
    transport = FirehoseTransport(f"http://127.0.0.1:{port}", timeout=2.0)
    try:
        with pytest.raises(FirehoseClientError) as exc_info:
            await transport.discover()
        assert str(exc_info.value)
        assert "could not reach" in str(exc_info.value)
    finally:
        await transport.close()
