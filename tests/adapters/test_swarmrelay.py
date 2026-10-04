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


"""SwarmRelay's own adapter tests, beyond the conformance suite.

`fixtures/` holds responses captured from openagentforum.com: they pin the
adapter's parsing to what the hub really serves, and the fake's shape to
the hub's, so neither drifts unnoticed.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import nacl.signing
import pytest

from bonnet.bridges.adapter import (
    ForeignAccount,
    ForeignPost,
    Gone,
    VenueAuthError,
    VenueError,
    VenueNameTaken,
    VenueUncertain,
)
from bonnet.bridges.adapters import swarmrelay
from bonnet.bridges.adapters.swarmrelay import PAGE_SIZE, SwarmRelayAdapter, verify
from bonnet.bridges.adapters.swarmrelay.adapter import ENCRYPTED_TEXT, USER_AGENT
from bonnet.bridges.adapters.swarmrelay.fake import FakeSwarmRelay, _NoLimit

FIXTURES = Path(swarmrelay.__file__).parent / "fixtures"


def fixture(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _agent(request: httpx.Request) -> httpx.Response:
    """Agent records captured from the hub, for the senders in the fixtures."""
    record = fixture("agents.json").get(request.url.path.rsplit("/", 1)[-1])
    if record is None:
        return httpx.Response(404, json={"error": "Agent not found"})
    return httpx.Response(200, json=record)


def _routes(routes: dict):
    """A hub that answers by path prefix (a fixed response, or a function of
    the request), knows the captured agents, and records what it was asked."""
    seen: list[httpx.Request] = []
    routes = {"/v1/agents/": _agent, **routes}

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        key = request.url.raw_path.decode()
        for prefix, resp in routes.items():
            if key.startswith(prefix):
                return resp(request) if callable(resp) else resp
        return httpx.Response(404, json={"error": "Route not found"})

    return handle, seen


def _adapter(handler, backfill_pages: int = 1) -> SwarmRelayAdapter:
    cfg = FakeSwarmRelay().venue_config()
    cfg.backfill_pages = backfill_pages
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return SwarmRelayAdapter(cfg, http=http, limiter=_NoLimit())


# ---------------------------------------------------------------------------
# Fixtures: what the hub really serves
# ---------------------------------------------------------------------------


async def test_parses_a_captured_page_and_threads_both_ways():
    page = fixture("page.json")
    markdown = (FIXTURES / "message.md").read_text(encoding="utf-8")
    older, newer = page["messages"]
    # The older message replies to a parent outside the page: the adapter
    # asks the permalink for its position, then confirms it on the record.
    parent = dict(newer, id=older["payload"]["inReplyTo"], storedSeq=1300)
    handler, seen = _routes(
        {
            "/v1/channels/general/messages?limit=1&after=1299": httpx.Response(
                200, json={"channel": "general", "messages": [parent], "count": 1}
            ),
            "/v1/channels/general/messages": httpx.Response(200, json=page),
            "/v1/channels/general": httpx.Response(200, json={"channel": {"name": "general"}}),
            "/channels/general/messages/": httpx.Response(
                200, text=markdown.replace("1378", "1300").replace("1377", "1299")
            ),
        }
    )
    adapter = _adapter(handler)
    try:
        posts = await adapter.poll("", None)
    finally:
        await adapter.close()
    assert [p.foreign_id for p in posts] == ["1377", "1378"]
    first, second = posts
    assert first.reply_to == "1300" and first.root_id is None
    # Same page: no lookup needed, and the id forms differ (URN vs bare).
    assert second.reply_to == "1377"
    assert second.author_id == "agent_5ca69fcc029e2f1f"
    assert second.author_handle == "Mesh"
    assert second.created_at == 1791092849
    assert second.text.startswith("bridgefone")
    assert second.url == (
        "https://hub.test/channels/general/messages/caec80fc-28f1-4e0a-8dbd-3e8ab207b621/"
    )
    assert json.loads(second.raw) == newer
    # Both captured envelopes really verify; the parent stand-in, a copy of
    # `newer` under another id, doesn't (and isn't mirrored here anyway).
    assert first.tags == second.tags == ("sig:verified",)
    assert all(r.headers["user-agent"] == USER_AGENT for r in seen)
    lookups = [r for r in seen if r.url.path.endswith("index.md")]
    assert len(lookups) == 1 and "urn%3Auuid%3Ac891a640" in str(lookups[0].url)


async def test_fetch_reads_one_captured_envelope_back():
    single = fixture("single.json")
    handler, seen = _routes(
        {
            "/v1/channels/general/messages": httpx.Response(200, json=single),
            "/channels/": httpx.Response(404, text="# Public record not found"),
        }
    )
    adapter = _adapter(handler)
    try:
        post = await adapter.fetch("", "1378")
    finally:
        await adapter.close()
    assert isinstance(post, ForeignPost) and post.foreign_id == "1378"
    assert seen[0].url.params["after"] == "1377" and seen[0].url.params["limit"] == "1"
    # The parent's permalink is missing: the reply stays unthreaded, not wrong.
    assert post.reply_to is None and post.root_id == "1378"


async def test_an_empty_answer_is_gone():
    handler, _ = _routes(
        {"/v1/channels/general/messages": httpx.Response(200, json=fixture("empty.json"))}
    )
    adapter = _adapter(handler)
    try:
        assert await adapter.fetch("", "999999") == Gone("999999", "unknown")
        assert await adapter.fetch("", "not-a-seq") == Gone("not-a-seq", "unknown")
    finally:
        await adapter.close()


async def test_a_missing_channel_is_an_error_not_silence():
    handler, _ = _routes(
        {"/v1/channels/nope": httpx.Response(404, json=fixture("channel_missing.json"))}
    )
    adapter = _adapter(handler)
    try:
        with pytest.raises(VenueError, match="no channel 'nope'"):
            await adapter.poll("nope", None)
    finally:
        await adapter.close()


# ---------------------------------------------------------------------------
# Against the fake
# ---------------------------------------------------------------------------


async def test_poll_walks_forward_from_the_cursor():
    hub = FakeSwarmRelay()
    for i in range(450):
        hub.envelope(f"m{i}")
    adapter = hub.adapter(hub.venue_config())
    try:
        first = await adapter.poll("", None)  # backfill: the newest page
        assert [int(p.foreign_id) for p in first] == list(range(251, 451))
        for i in range(450):
            hub.envelope(f"n{i}")
        more = await adapter.poll("", "450")
        assert [int(p.foreign_id) for p in more] == list(range(451, 901))
    finally:
        await adapter.close()


async def test_backfill_pages_reach_further_back():
    hub = FakeSwarmRelay()
    for i in range(500):
        hub.envelope(f"m{i}")
    cfg = hub.venue_config()
    cfg.backfill_pages = 2
    adapter = SwarmRelayAdapter(cfg, http=hub.client(), limiter=_NoLimit())
    try:
        posts = await adapter.poll("", None)
    finally:
        await adapter.close()
    assert [int(p.foreign_id) for p in posts] == list(range(500 - 2 * PAGE_SIZE + 1, 501))


async def test_hidden_envelopes_leave_gaps_not_errors():
    hub = FakeSwarmRelay()
    ids = [hub.envelope(f"m{i}")["storedSeq"] for i in range(5)]
    del hub.channels["general"][ids[2]]
    adapter = hub.adapter(hub.venue_config())
    try:
        posts = await adapter.poll("", "1")
        assert [p.foreign_id for p in posts] == ["2", "4", "5"]
        # `after=2&limit=1` serves seq 4; that isn't seq 3.
        assert await adapter.fetch("", "3") == Gone("3", "unknown")
    finally:
        await adapter.close()


async def test_parents_resolve_across_id_forms_and_polls():
    hub = FakeSwarmRelay()
    root = hub.envelope("root", envelope_id="urn:uuid:11111111-2222-3333-4444-555555555555")
    adapter = hub.adapter(hub.venue_config())
    try:
        await adapter.poll("", None)
        # Replies name the parent in the other form; the first one comes in
        # a later poll, so it resolves from what the adapter already saw.
        hub.envelope("bare", reply_to="11111111-2222-3333-4444-555555555555")
        (reply,) = await adapter.poll("", "1")
        assert reply.reply_to == str(root["storedSeq"])
        assert not [u for u in hub.requests if "index.md" in u]
    finally:
        await adapter.close()


async def test_a_cold_adapter_finds_old_parents_through_the_permalink():
    hub = FakeSwarmRelay()
    root = hub.envelope("root", envelope_id="urn:uuid:11111111-2222-3333-4444-555555555555")
    hub.envelope("reply", reply_to="11111111-2222-3333-4444-555555555555")
    adapter = hub.adapter(hub.venue_config())
    try:
        (reply,) = await adapter.poll("", "1")
        assert reply.reply_to == str(root["storedSeq"])
        # Bare form first (404: the hub matches ids exactly), then the URN.
        assert len([u for u in hub.requests if "index.md" in u]) == 2
        again = await adapter.fetch("", reply.foreign_id)
        assert isinstance(again, ForeignPost) and again.reply_to == reply.reply_to
        assert len([u for u in hub.requests if "index.md" in u]) == 2, "lookups are cached"
    finally:
        await adapter.close()


async def test_a_permalink_that_points_elsewhere_is_not_trusted():
    hub = FakeSwarmRelay()
    hub.envelope("root", envelope_id="urn:uuid:aaaaaaaa-0000-0000-0000-000000000000")
    hub.envelope("other")
    hub.envelope("reply", reply_to="urn:uuid:aaaaaaaa-0000-0000-0000-000000000000")
    real = hub._handle_markdown

    def lying(channel, envelope_id):
        resp = real(channel, envelope_id)
        if resp.status_code == 200:
            return httpx.Response(200, text=resp.text.replace("position: 1.", "position: 2."))
        return resp

    hub._handle_markdown = lying  # type: ignore[method-assign]
    adapter = hub.adapter(hub.venue_config())
    try:
        (reply,) = await adapter.poll("", "2")
        assert reply.reply_to is None and reply.root_id == reply.foreign_id
    finally:
        await adapter.close()


async def test_unusual_payloads_still_render():
    hub = FakeSwarmRelay()
    hub.envelope(None, payload={"insight": {"k": 1}, "origin": "x"})
    hub.envelope(None, payload={"message": None})
    enc = hub.envelope("ciphertext", payload={"message": "c2VjcmV0"})
    enc["encrypted"] = True
    hub.envelope("no name", name=None)
    adapter = hub.adapter(hub.venue_config())
    try:
        posts = await adapter.poll("", None)
    finally:
        await adapter.close()
    assert posts[0].text == '{"insight": {"k": 1}, "origin": "x"}'
    assert posts[1].text == '{"message": null}'
    assert posts[2].text == ENCRYPTED_TEXT
    assert posts[3].author_handle == posts[3].author_id.strip() != ""


async def test_rate_limits_defer_the_next_read():
    hub = FakeSwarmRelay()
    hub.envelope("x")
    hub.rate_limit_reads = 1
    limiter = _NoLimit()
    adapter = SwarmRelayAdapter(hub.venue_config(), http=hub.client(), limiter=limiter)
    try:
        with pytest.raises(VenueError, match="429"):
            await adapter.poll("", None)
        assert limiter.deferred == 7
        assert [p.text for p in await adapter.poll("", None)] == ["x"]
    finally:
        await adapter.close()


async def test_channels_are_independent():
    hub = FakeSwarmRelay()
    hub.envelope("in general")
    hub.envelope("mapped", channel="cartographers")
    adapter = hub.adapter(hub.venue_config())
    try:
        (post,) = await adapter.poll("cartographers", None)
    finally:
        await adapter.close()
    assert post.channel == "cartographers" and post.text == "mapped"
    assert post.foreign_id == "1"  # storedSeq counts per channel


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vector", fixture("canonical-json-v1.json")["vectors"], ids=lambda v: v["name"]
)
def test_canonical_json_matches_the_hubs_vectors(vector):
    payload = json.loads(vector["payloadJson"])
    assert verify.canonical(payload) == vector["canonical"]
    assert verify.canonical(payload).encode("utf-8", "surrogatepass").hex() == vector["utf8Hex"]
    assert verify.checksum(payload) == vector["sha256"]


@pytest.mark.parametrize(
    ("value", "text"),
    [
        (0, "0"),
        (-0.0, "0"),
        (1.0, "1"),
        (1e21, "1e+21"),
        (1e20, "100000000000000000000"),
        (1e-7, "1e-7"),
        (0.000001, "0.000001"),
        (123.456, "123.456"),
        (-1.5e-10, "-1.5e-10"),
        (2**53 + 1, "9007199254740992"),  # rounded through binary64, as in JS
        (12345678901234567890, "12345678901234567000"),
    ],
)
def test_numbers_print_as_javascript_does(value, text):
    assert verify.js_number(value) == text


def test_agent_ids_derive_from_the_keys_hex():
    for sender, record in fixture("agents.json").items():
        assert verify.agent_id(record["agent"]["publicKey"]) == sender


def test_a_captured_legacy_row_is_a_checksum_mismatch_not_a_forgery():
    (env,) = fixture("legacy_checksum.json")["messages"]
    key = fixture("agents.json")[env["sender"]]["agent"]["publicKey"]
    assert verify.verify(env, key) == verify.CHECKSUM_MISMATCH


async def _verdicts(hub: FakeSwarmRelay) -> list[str]:
    adapter = hub.adapter(hub.venue_config())
    try:
        return [p.tags[0] for p in await adapter.poll("", None)]
    finally:
        await adapter.close()


async def test_every_verdict_reaches_the_tags():
    hub = FakeSwarmRelay()
    hub.envelope("good")
    edited = hub.envelope("original")
    edited["payload"]["message"] = "edited after signing"
    resealed = hub.envelope("original")
    resealed["payload"]["message"] = "edited, checksum redone"
    resealed["checksum"] = verify.checksum(resealed["payload"])
    stolen = hub.envelope("claims alice", sender=hub.author("alice"))
    stolen["signature"] = (
        hub.keys[hub.author("mallory")].sign(verify.sign_string(stolen)).signature.hex()
    )
    hub.envelope("nobody knows me", sender=hub.author("ghost"))
    hub.unregistered.add(hub.author("ghost"))
    hub.envelope("malformed", sender="not-an-agent")
    assert await _verdicts(hub) == [
        "sig:verified",
        "sig:checksum-mismatch",
        "sig:invalid",
        "sig:invalid",
        "sig:no-key",
        "sig:invalid",
    ]


async def test_a_key_the_hub_serves_for_someone_else_is_not_trusted():
    hub = FakeSwarmRelay()
    alice, mallory = hub.author("alice"), hub.author("mallory")
    # Mallory signs as alice, and the hub answers alice with mallory's key:
    # the signature checks out, but that key's id isn't alice.
    hub.keys[alice] = hub.keys[mallory]
    hub.envelope("hello", sender=alice)
    assert await _verdicts(hub) == ["sig:invalid"]


async def test_keys_are_looked_up_once_per_sender():
    hub = FakeSwarmRelay()
    for i in range(5):
        hub.envelope(f"m{i}", sender=hub.author("alice" if i % 2 else "bob"))
    await _verdicts(hub)
    assert len([u for u in hub.requests if "/v1/agents/" in u]) == 2


async def test_a_failed_key_lookup_fails_the_poll_instead_of_branding_the_post():
    hub = FakeSwarmRelay()
    hub.envelope("hello")
    real = hub._handle

    def flaky(request):
        if "/v1/agents/" in str(request.url):
            return httpx.Response(500, text="boom")
        return real(request)

    adapter = SwarmRelayAdapter(
        hub.venue_config(),
        http=httpx.AsyncClient(transport=httpx.MockTransport(flaky)),
        limiter=_NoLimit(),
    )
    try:
        with pytest.raises(VenueError, match="agent"):
            await adapter.poll("", None)
    finally:
        await adapter.close()
    assert await _verdicts(hub) == ["sig:verified"]


# ---------------------------------------------------------------------------
# Posting and accounts
# ---------------------------------------------------------------------------


def _stored(hub: FakeSwarmRelay, channel: str = "general") -> list[dict]:
    return [hub.channels[channel][s] for s in sorted(hub.channels[channel])]


async def test_posts_are_signed_verified_and_counted_per_author():
    hub = FakeSwarmRelay()
    account = hub.account("lanternfly")
    adapter = hub.adapter(hub.venue_config())
    try:
        first = await adapter.post(account, "", "hello mesh", None, "k1")
        second = await adapter.post(account, "", "again", None, "k2")
    finally:
        await adapter.close()
    one, two = _stored(hub)
    assert [one["sequence"], two["sequence"]] == [0, 1]
    assert one["payload"] == {"message": "hello mesh", "origin": "lanternfly"}
    assert first.tags == second.tags == ("sig:verified",)
    assert first.foreign_id == "1" and second.foreign_id == "2"
    # The second post knew its sequence without scanning the channel again.
    assert len([u for u in hub.requests if "messages?limit=200&after=0" in u]) == 1


async def test_an_authors_count_continues_from_the_hub():
    hub = FakeSwarmRelay()
    account = hub.account("lanternfly")
    key = nacl.signing.SigningKey(bytes.fromhex(account.token))
    sender = verify.agent_id(bytes(key.verify_key).hex())
    for i in range(PAGE_SIZE + 5):  # past one page, so the scan pages too
        hub.envelope(f"noise {i}")
    hub.envelope("mine, earlier", sender=sender)  # unsigned here, but counted
    hub.channels["general"][max(hub.channels["general"])]["sequence"] = 6
    adapter = hub.adapter(hub.venue_config())
    try:
        await adapter.post(account, "", "next one", None, "k")
    finally:
        await adapter.close()
    assert _stored(hub)[-1]["sequence"] == 7


async def test_replies_name_the_parents_envelope_id():
    hub = FakeSwarmRelay()
    parent = hub.envelope("parent", envelope_id="5f0e0b7c-0000-4000-8000-000000000001")
    adapter = hub.adapter(hub.venue_config())
    try:
        reply = await adapter.post(hub.account(), "", "a reply", str(parent["storedSeq"]), "k")
        assert reply.reply_to == str(parent["storedSeq"])
        assert _stored(hub)[-1]["payload"]["inReplyTo"] == parent["id"]
        with pytest.raises(VenueError, match="parent 99 is gone"):
            await adapter.post(hub.account(), "", "orphan", "99", "k2")
    finally:
        await adapter.close()


async def test_posting_never_creates_a_channel():
    hub = FakeSwarmRelay()
    adapter = hub.adapter(hub.venue_config())
    try:
        with pytest.raises(VenueError, match="no channel 'genral'"):
            await adapter.post(hub.account(), "genral", "typo", None, "k")
    finally:
        await adapter.close()
    assert hub.created_channels == []


async def test_a_lost_answer_is_uncertain_and_the_retry_finds_the_post():
    hub = FakeSwarmRelay()
    hub.lose_post_responses = 1
    account = hub.account()
    adapter = hub.adapter(hub.venue_config())
    try:
        with pytest.raises(VenueUncertain):
            await adapter.post(account, "", "landed anyway", None, "same-key")
        again = await adapter.post(account, "", "landed anyway", None, "same-key")
        assert [e["storedSeq"] for e in _stored(hub)] == [int(again.foreign_id)]
        # The count is read again, so the next post doesn't reuse sequence 0.
        await adapter.post(account, "", "next", None, "other-key")
    finally:
        await adapter.close()
    assert [e["sequence"] for e in _stored(hub)] == [0, 1]


async def test_a_failed_post_leaves_no_gap_in_the_count():
    hub = FakeSwarmRelay()
    hub.fail_posts = 1
    account = hub.account()
    adapter = hub.adapter(hub.venue_config())
    try:
        with pytest.raises(VenueUncertain):
            await adapter.post(account, "", "first try", None, "k")
        await adapter.post(account, "", "first try", None, "k")
    finally:
        await adapter.close()
    assert [e["sequence"] for e in _stored(hub)] == [0]


@pytest.mark.parametrize("token", ["", "zz" * 32, "ab" * 31])
async def test_a_token_that_isnt_a_key_is_an_auth_error_and_posts_nothing(token):
    hub = FakeSwarmRelay()
    adapter = hub.adapter(hub.venue_config())
    try:
        with pytest.raises(VenueAuthError):
            await adapter.post(ForeignAccount("x", token), "", "hi", None, "k")
    finally:
        await adapter.close()
    assert hub.requests == []


async def test_a_pkcs8_token_works_like_its_seed():
    hub = FakeSwarmRelay()
    account = hub.account()
    pkcs8 = ForeignAccount(account.user, "302e020100300506032b657004220420" + account.token)
    adapter = hub.adapter(hub.venue_config())
    try:
        post = await adapter.post(pkcs8, "", "hello", None, "k")
    finally:
        await adapter.close()
    assert post.tags == ("sig:verified",)


async def test_register_mints_a_key_and_claims_the_name():
    hub = FakeSwarmRelay()
    adapter = hub.adapter(hub.venue_config())
    try:
        account = await adapter.register("lanternfly")
        post = await adapter.post(account, "", "first words", None, "k")
        with pytest.raises(VenueNameTaken):
            await adapter.register("LanternFly")  # names compare folded
    finally:
        await adapter.close()
    assert account.user == "lanternfly" and len(account.token) == 64
    assert hub.names["lanternfly"] == post.author_id
    assert post.tags == ("sig:verified",)


async def test_register_retries_a_lost_answer_once_with_the_same_proof():
    hub = FakeSwarmRelay()
    hub.lose_register_responses = 1
    adapter = hub.adapter(hub.venue_config())
    try:
        account = await adapter.register("lanternfly")
        hub.lose_register_responses = 2
        with pytest.raises(VenueUncertain, match="nobody kept"):
            await adapter.register("someone-else")
    finally:
        await adapter.close()
    assert account.user == "lanternfly"
    assert len(hub.registered) == 2  # both applied; only the first one's key came back
