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

"""The body-redirect hop: a dial target chosen by someone else.

When a relay does not hold a remote article's body it answers with the
origin's location so the caller can ask the party that does. That makes it the
one path where a *relay* picks a host this client then connects to, and it
runs in the gateway - on the user's machine, beside their identity store.

Two rules follow, and neither existed before: the target goes through the same
SSRF check federation dials already used, and the TLS policy for the hop is
this client's, not a field in the relay's reply.
"""

import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("cryptography")

from bonnet.gateway import firehose_client as fc
from bonnet.gateway.firehose_client import FirehoseClientError, FirehoseHTTPClient
from bonnet.net.firehose_wire import BodyRedirectError


def test_the_redirect_no_longer_carries_a_tls_setting():
    """Removing the field *is* the fix: how carefully to check a certificate
    is not something to accept from the party that chose the destination."""
    redirect = BodyRedirectError("origin.test", "origin.test", 2272)
    assert not hasattr(redirect, "verify_tls")


@pytest.fixture
def redirecting(monkeypatch):
    """A client whose next command comes back as a redirect to `target`."""

    def build(base_url, target_host, target_port=2272):
        client = FirehoseHTTPClient(base_url, verify=True)
        client._server_origin = "relay.test"

        async def fake_send(cmd):
            raise BodyRedirectError("origin.test", target_host, target_port)

        monkeypatch.setattr(client, "_send_command", fake_send)
        return client

    return build


@pytest.mark.anyio
@pytest.mark.parametrize(
    "target",
    ["127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1"],
)
async def test_a_public_relay_cannot_redirect_us_inward(redirecting, target):
    """169.254.169.254 is the cloud metadata address; the rest are ordinary
    private ranges. A relay on the public internet has no business sending
    anyone to any of them."""
    client = redirecting("https://relay.test", target)
    with pytest.raises(FirehoseClientError, match="unsafe target"):
        await client.get_article_body("origin.test", "general", 1)
    await client.close()


@pytest.mark.anyio
async def test_a_loopback_client_may_still_be_redirected_locally(redirecting, monkeypatch):
    """A local test federation legitimately redirects between loopback ports.
    The allowance tracks what this client is itself talking to, which is the
    same seam `is_loopback` already draws for TLS defaults and pin prompts."""
    captured = {}

    class _Stub(FirehoseHTTPClient):
        def __init__(self, base_url, **kwargs):
            captured["base_url"] = base_url
            captured.update(kwargs)
            super().__init__(base_url, **kwargs)

        async def connect_anonymous(self):
            return None

        async def get_article_body(self, *a, **kw):
            return b"body from the origin"

    monkeypatch.setattr(fc, "FirehoseHTTPClient", _Stub)

    client = redirecting("https://localhost:2272", "127.0.0.1", 2273)
    body = await client.get_article_body("origin.test", "general", 1)

    assert body == b"body from the origin"
    assert captured["base_url"] == "https://127.0.0.1:2273"
    await client.close()


@pytest.mark.anyio
async def test_the_hop_inherits_this_client_s_scheme(redirecting, monkeypatch):
    """Hardcoding https on the hop breaks a plaintext federation: the redirect
    target speaks whatever this client's own connection speaks, not TLS
    unconditionally, since BodyRedirectError never carries a scheme."""
    captured = {}

    class _Stub(FirehoseHTTPClient):
        def __init__(self, base_url, **kwargs):
            captured["base_url"] = base_url
            super().__init__(base_url, **kwargs)

        async def connect_anonymous(self):
            return None

        async def get_article_body(self, *a, **kw):
            return b"x"

    monkeypatch.setattr(fc, "FirehoseHTTPClient", _Stub)

    client = redirecting("http://localhost:2272", "127.0.0.1", 2273)
    await client.get_article_body("origin.test", "general", 1)

    assert captured["base_url"] == "http://127.0.0.1:2273"
    await client.close()


@pytest.mark.anyio
async def test_the_hop_inherits_this_client_s_tls_policy(redirecting, monkeypatch):
    """Previously the relay's reply chose it, so a relay could name a host
    *and* tell the client not to check that host's certificate."""
    captured = {}

    class _Stub(FirehoseHTTPClient):
        def __init__(self, base_url, **kwargs):
            captured.update(kwargs)
            super().__init__(base_url, **kwargs)

        async def connect_anonymous(self):
            return None

        async def get_article_body(self, *a, **kw):
            return b"x"

    monkeypatch.setattr(fc, "FirehoseHTTPClient", _Stub)

    client = redirecting("https://localhost:2272", "127.0.0.1", 2273)
    client._verify = True
    await client.get_article_body("origin.test", "general", 1)

    assert captured["verify"] is True
    await client.close()
