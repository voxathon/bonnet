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


"""The adapter conformance suite: what every venue adapter must do.

Each check drives an adapter against a fake of its venue and raises
AssertionError when the adapter breaks something the runtime relies on:
resumable polling, ordering and threading, index rebuilds, `Gone` for
removed posts, the error types backoff and lockout protection key on,
outbound text that fits and carries its marker, and idempotent posting.
Checks for a capability the adapter doesn't claim are skipped.

Shipped, not test-only, so an adapter outside this repo can run it too:

    from bonnet.bridges.conformance import CHECKS, run
    for check in CHECKS:
        await run(check, MyFakeVenue)   # raises on failure, returns False if skipped

The built-in adapters run it in `tests/adapters/test_conformance.py`; one
can't merge without passing. Never pointed at a live venue.
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from typing import Protocol

from bonnet.bridges import model
from bonnet.bridges.adapter import (
    ForeignAccount,
    ForeignPost,
    Gone,
    VenueAdapter,
    VenueAuthError,
    VenueError,
    VenueNameTaken,
    VenueRateLimited,
    adapter_problems,
)
from bonnet.bridges.venue import VenueConfig

CHANNEL = ""


class VenueFake(Protocol):
    """An in-memory venue its adapter can be pointed at."""

    offline: bool  # every request fails as a network error while set

    def venue_config(self) -> VenueConfig: ...
    def adapter(self, venue: VenueConfig) -> VenueAdapter: ...

    def native_post(self, text: str, author: str = "alice", reply_to: str | None = None) -> str:
        """A post made at the venue itself; returns its foreign id."""
        ...

    def remove(self, foreign_id: str) -> None:
        """The venue loses the post: deleted, evicted, whatever it does."""
        ...

    def venue_posts(self) -> list[str]:
        """Foreign ids the venue holds, oldest first."""
        ...

    # With "write":
    #   def good_account(self) -> ForeignAccount   an account the venue accepts
    #   def bad_account(self) -> ForeignAccount    one whose credentials it rejects
    #   def rate_limit_next_post(self) -> None     the next post is refused for rate
    # With "edit":
    #   def edit(self, foreign_id: str, text: str) -> None
    # With "self_register":
    #   def take_name(self, name: str) -> None      someone else holds `name`


Check = Callable[[VenueFake, VenueAdapter], Awaitable[None]]
# check -> the capability it needs, if any
_NEEDS: dict[Check, str] = {}


def _needs(capability: str):
    def mark(fn: Check) -> Check:
        _NEEDS[fn] = capability
        return fn

    return mark


async def _poll_all(adapter: VenueAdapter) -> list[ForeignPost]:
    return await adapter.poll(CHANNEL, None)


# ---------------------------------------------------------------------------
# Every adapter
# ---------------------------------------------------------------------------


async def interface(fake: VenueFake, adapter: VenueAdapter) -> None:
    """The class declares the protocol, capabilities and methods it uses."""
    problems = adapter_problems(type(adapter), fake.venue_config().type)
    assert not problems, "; ".join(problems)


async def poll_is_ordered_and_resumable(fake: VenueFake, adapter: VenueAdapter) -> None:
    ids = [fake.native_post(f"post {i}") for i in range(3)]
    posts = await _poll_all(adapter)
    assert [p.foreign_id for p in posts] == ids, "poll must return posts oldest first"
    assert all(p.venue == adapter.venue and p.channel == CHANNEL for p in posts)
    assert [p.text for p in posts] == ["post 0", "post 1", "post 2"]
    cursor = adapter.cursor_after(posts[-1])
    assert await adapter.poll(CHANNEL, cursor) == [], "polling past the last post found more"
    newer = fake.native_post("post 3")
    again = await adapter.poll(CHANNEL, cursor)
    assert [p.foreign_id for p in again] == [newer], "a resumed poll must return only new posts"


async def cursor_rebuilds_from_ids(fake: VenueFake, adapter: VenueAdapter) -> None:
    for i in range(3):
        fake.native_post(f"post {i}")
    posts = await _poll_all(adapter)
    shuffled = [p.foreign_id for p in reversed(posts)]
    assert adapter.cursor_from_ids(shuffled) == adapter.cursor_after(posts[-1]), (
        "cursor_from_ids must give the cursor after the newest id, in any order"
    )
    assert adapter.cursor_from_ids([]) is None


async def fetch_is_stable(fake: VenueFake, adapter: VenueAdapter) -> None:
    fid = fake.native_post("fetch me")
    first = await adapter.fetch(CHANNEL, fid)
    second = await adapter.fetch(CHANNEL, fid)
    assert isinstance(first, ForeignPost) and isinstance(second, ForeignPost)
    assert first.foreign_id == fid and first.text == "fetch me"
    # Mirrors are derived from these bytes: two reads must agree exactly.
    assert first.raw == second.raw, "fetch returned different raw bytes for the same post"
    assert first.raw_content_type


async def removed_posts_are_gone(fake: VenueFake, adapter: VenueAdapter) -> None:
    fid = fake.native_post("soon gone")
    fake.remove(fid)
    result = await adapter.fetch(CHANNEL, fid)
    assert isinstance(result, Gone) and result.foreign_id == fid, (
        f"fetch of a removed post must return Gone, got {result!r}"
    )


async def outages_raise_venue_error(fake: VenueFake, adapter: VenueAdapter) -> None:
    fid = fake.native_post("hello")
    fake.offline = True
    try:
        for attempt in (_poll_all(adapter), adapter.fetch(CHANNEL, fid)):
            try:
                await attempt
            except VenueError:
                continue
            raise AssertionError("an unreachable venue must raise VenueError")
    finally:
        fake.offline = False


# ---------------------------------------------------------------------------
# By capability
# ---------------------------------------------------------------------------


@_needs("threads")
async def replies_point_at_their_parent(fake: VenueFake, adapter: VenueAdapter) -> None:
    parent = fake.native_post("parent")
    child = fake.native_post("child", reply_to=parent)
    by_id = {p.foreign_id: p for p in await _poll_all(adapter)}
    assert by_id[child].reply_to == parent
    assert by_id[parent].reply_to is None
    assert by_id[parent].root_id in (None, parent)


@_needs("write")
async def outbound_text_fits_and_ends_with_the_marker(
    fake: VenueFake, adapter: VenueAdapter
) -> None:
    marker = model.make_marker(os.urandom(32))
    for text in ("short", "x" * (adapter.max_text_bytes() * 2)):
        for attribution in (None, "someone"):
            out = adapter.render_outbound(text, marker, attribution)
            assert len(out.encode("utf-8")) <= adapter.max_text_bytes(), "outbound text too long"
            assert out.endswith(marker), "the marker must come last, whole"


@_needs("write")
async def posts_land_and_read_back(fake: VenueFake, adapter: VenueAdapter) -> None:
    account = fake.good_account()  # type: ignore[attr-defined]
    text = adapter.render_outbound("hello venue", model.make_marker(os.urandom(32)), None)
    posted = await adapter.post(account, CHANNEL, text, None, os.urandom(16).hex())
    assert posted.foreign_id in fake.venue_posts()
    polled = {p.foreign_id: p for p in await _poll_all(adapter)}
    assert polled[posted.foreign_id].text == posted.text


@_needs("write")
async def bad_credentials_raise_auth_error(fake: VenueFake, adapter: VenueAdapter) -> None:
    bad: ForeignAccount = fake.bad_account()  # type: ignore[attr-defined]
    before = fake.venue_posts()
    try:
        await adapter.post(bad, CHANNEL, "nope", None, os.urandom(16).hex())
    except VenueAuthError:
        assert fake.venue_posts() == before
        return
    raise AssertionError("rejected credentials must raise VenueAuthError")


@_needs("write")
async def rate_limits_raise_rate_limited(fake: VenueFake, adapter: VenueAdapter) -> None:
    account = fake.good_account()  # type: ignore[attr-defined]
    fake.rate_limit_next_post()  # type: ignore[attr-defined]
    before = fake.venue_posts()
    try:
        await adapter.post(account, CHANNEL, "slow down", None, os.urandom(16).hex())
    except VenueRateLimited:
        assert fake.venue_posts() == before, "a rate-limited post must take nothing"
        return
    raise AssertionError("a rate-limited post must raise VenueRateLimited")


@_needs("idempotent_post")
async def same_key_posts_once(fake: VenueFake, adapter: VenueAdapter) -> None:
    account = fake.good_account()  # type: ignore[attr-defined]
    key = os.urandom(16).hex()
    first = await adapter.post(account, CHANNEL, "once", None, key)
    second = await adapter.post(account, CHANNEL, "once", None, key)
    assert first.foreign_id == second.foreign_id
    assert fake.venue_posts().count(first.foreign_id) == 1
    assert len(fake.venue_posts()) == 1, "a retried key must not post twice"


@_needs("edit")
async def edits_show_through_fetch(fake: VenueFake, adapter: VenueAdapter) -> None:
    fid = fake.native_post("before")
    fake.edit(fid, "after")  # type: ignore[attr-defined]
    result = await adapter.fetch(CHANNEL, fid)
    assert isinstance(result, ForeignPost) and result.text == "after"


@_needs("deletion_log")
async def deletions_are_logged(fake: VenueFake, adapter: VenueAdapter) -> None:
    fid = fake.native_post("to delete")
    fake.remove(fid)
    entries, cursor = await adapter.deletions(CHANNEL, None)  # type: ignore[attr-defined]
    assert fid in [d.foreign_id for d in entries]
    more, _ = await adapter.deletions(CHANNEL, cursor)  # type: ignore[attr-defined]
    assert fid not in [d.foreign_id for d in more], "resuming from the cursor repeated entries"


@_needs("signup")
async def signup_instructions_say_how(fake: VenueFake, adapter: VenueAdapter) -> None:
    text = adapter.signup_instructions()  # type: ignore[attr-defined]
    assert isinstance(text, str) and text.strip(), "signup instructions must say something"
    account = fake.good_account()  # type: ignore[attr-defined]
    assert account.token not in text, "signup instructions must never carry a credential"


@_needs("self_register")
async def registered_accounts_can_post(fake: VenueFake, adapter: VenueAdapter) -> None:
    account = await adapter.register("newcomer")  # type: ignore[attr-defined]
    assert isinstance(account, ForeignAccount) and account.user and account.token
    text = adapter.render_outbound("first post", model.make_marker(os.urandom(32)), None)
    posted = await adapter.post(account, CHANNEL, text, None, os.urandom(16).hex())
    assert posted.foreign_id in fake.venue_posts()


@_needs("self_register")
async def taken_names_raise_name_taken(fake: VenueFake, adapter: VenueAdapter) -> None:
    fake.take_name("occupied")  # type: ignore[attr-defined]
    try:
        await adapter.register("occupied")  # type: ignore[attr-defined]
    except VenueNameTaken:
        return
    raise AssertionError("claiming a taken name must raise VenueNameTaken")


CHECKS: list[Check] = [
    interface,
    poll_is_ordered_and_resumable,
    cursor_rebuilds_from_ids,
    fetch_is_stable,
    removed_posts_are_gone,
    outages_raise_venue_error,
    replies_point_at_their_parent,
    outbound_text_fits_and_ends_with_the_marker,
    posts_land_and_read_back,
    bad_credentials_raise_auth_error,
    rate_limits_raise_rate_limited,
    same_key_posts_once,
    edits_show_through_fetch,
    deletions_are_logged,
    signup_instructions_say_how,
    registered_accounts_can_post,
    taken_names_raise_name_taken,
]


def needs(check: Check) -> str | None:
    """The capability `check` needs, or None if every adapter must pass it."""
    return _NEEDS.get(check)


async def run(check: Check, fake_factory: Callable[[], VenueFake]) -> bool:
    """Run one check on a fresh fake. False if the adapter lacks its capability."""
    fake = fake_factory()
    adapter = fake.adapter(fake.venue_config())
    try:
        need = needs(check)
        if need is not None and need not in adapter.capabilities:
            return False
        await check(fake, adapter)
        return True
    finally:
        await adapter.close()
