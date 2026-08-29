"""Signature verification must use the scheme the client actually dialed.

The client signs `@target-uri` over its own base URL. The server rebuilds that
URI to recompute the signature base, so if it assumes a scheme the client did
not use, every authenticated request fails with 401 — and `tls.enabled = false`
is the shipped default, so that is the out-of-the-box configuration.
"""

import httpx
import pytest

from bonnet.client.firehose_client import FirehoseHTTPClient
from bonnet.net.firehose_wire import build_board_list, parse_board_list_response
from tests.test_firehose_http_server import (  # noqa: F401
    ORIGIN,
    SERVER_IDENTITY,
    server_stack,
)


def _client_for(app, base_url: str) -> FirehoseHTTPClient:
    client = FirehoseHTTPClient(base_url, verify=False)
    client._http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url=base_url,
        timeout=30.0,
        verify=False,
    )
    return client


@pytest.mark.parametrize("scheme", ["http", "https"])
async def test_authenticated_request_verifies_under_either_scheme(server_stack, scheme):  # noqa: F811
    """Both schemes must work. https alone passing is exactly the bug: a
    plaintext listener is the default `--create-config` produces."""
    client = _client_for(server_stack["server"], f"{scheme}://bbs.test")
    try:
        # The server's own key: an admin under the fixture's ACL, so an
        # authorization failure cannot masquerade as a signature failure.
        await client.connect(SERVER_IDENTITY)

        resp = await client._send_command(build_board_list(ORIGIN))

        assert parse_board_list_response(resp) == []
    finally:
        await client.close()


async def test_anonymous_request_verifies_over_plaintext(server_stack):  # noqa: F811
    """Anonymous requests are signed too — with a shared key, but the same
    covered components — so they fail the same way."""
    client = _client_for(server_stack["server"], "http://bbs.test")
    try:
        await client.connect_anonymous()

        resp = await client._send_command(build_board_list(ORIGIN))

        assert parse_board_list_response(resp) == []
    finally:
        await client.close()
