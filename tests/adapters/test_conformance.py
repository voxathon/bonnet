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


"""Every built-in adapter against the conformance suite, and the loader's checks.

An adapter can't merge without passing here: add its fake to
`bonnet.bridges.adapters.BUILTIN_FAKES` and every check runs against it.
"""

from __future__ import annotations

import importlib

import pytest

from bonnet.bridges import conformance
from bonnet.bridges.adapter import (
    CAPABILITIES,
    PROTOCOL,
    AdapterInvalid,
    adapter_problems,
    load_adapter_class,
)
from bonnet.bridges.adapters import BUILTIN_ADAPTERS, BUILTIN_FAKES
from bonnet.bridges.adapters.flatboard import FlatboardAdapter
from bonnet.bridges.adapters.flatboard.fake import FakeFlatboard


def _load(ref: str):
    module, _, attr = ref.partition(":")
    return getattr(importlib.import_module(module), attr)


def test_every_builtin_adapter_ships_a_fake():
    assert set(BUILTIN_FAKES) == set(BUILTIN_ADAPTERS)


@pytest.mark.parametrize("check", conformance.CHECKS, ids=lambda c: c.__name__)
@pytest.mark.parametrize("venue_type", sorted(BUILTIN_FAKES))
async def test_conformance(venue_type, check):
    ran = await conformance.run(check, _load(BUILTIN_FAKES[venue_type]))
    cls = load_adapter_class(venue_type)
    if not ran:
        assert conformance.needs(check) not in cls.capabilities
        pytest.skip(f"{venue_type} lacks {conformance.needs(check)!r}")


def test_every_capability_has_a_check_or_needs_none():
    checked = {conformance.needs(c) for c in conformance.CHECKS} - {None}
    # "read" is every check without a capability; "signup" is reserved.
    assert checked | {"read", "signup"} == CAPABILITIES


# ---------------------------------------------------------------------------
# The suite has teeth
# ---------------------------------------------------------------------------


class _NewestFirst(FlatboardAdapter):
    async def poll(self, channel, cursor):
        return list(reversed(await super().poll(channel, cursor)))


class _NeverGone(FlatboardAdapter):
    async def fetch(self, channel, foreign_id):
        result = await super().fetch(channel, foreign_id)
        if not hasattr(result, "raw"):
            raise RuntimeError("gone")
        return result


class _MarkerFirst(FlatboardAdapter):
    def render_outbound(self, text, marker, attribution):
        return f"{marker}\n{text}"[: self.max_text_bytes()]


def _faking(adapter_cls):
    class Fake(FakeFlatboard):
        def adapter(self, venue):
            real = super().adapter(venue)
            broken = adapter_cls.__new__(adapter_cls)
            broken.__dict__.update(real.__dict__)
            return broken

    return Fake


@pytest.mark.parametrize(
    "adapter_cls, check",
    [
        (_NewestFirst, conformance.poll_is_ordered_and_resumable),
        (_NeverGone, conformance.removed_posts_are_gone),
        (_MarkerFirst, conformance.outbound_text_fits_and_ends_with_the_marker),
    ],
)
async def test_the_suite_catches_broken_adapters(adapter_cls, check):
    with pytest.raises((AssertionError, RuntimeError)):
        await conformance.run(check, _faking(adapter_cls))


# ---------------------------------------------------------------------------
# The loader's interface checks
# ---------------------------------------------------------------------------


def _adapter(**over):
    attrs = {name: getattr(FlatboardAdapter, name) for name in dir(FlatboardAdapter)
             if not name.startswith("__")}  # fmt: skip
    attrs.update(over)
    return type("Custom", (), attrs)


def test_flatboard_passes_the_loader():
    assert FlatboardAdapter.protocol == PROTOCOL
    assert adapter_problems(FlatboardAdapter, "flatboard") == []


@pytest.mark.parametrize(
    "over, problem",
    [
        ({"protocol": 2}, "implements adapter protocol 2"),
        ({"type": "other"}, ".type is 'other'"),
        ({"capabilities": frozenset({"read", "idempotent_posts"})}, "unknown capabilities"),
        ({"capabilities": frozenset({"threads"})}, "must have the 'read' capability"),
        ({"capabilities": frozenset({"read", "idempotent_post"})}, "without 'write'"),
        ({"capabilities": frozenset({"read", "deletion_log"})}, "lacks deletions"),
        ({"post": None}, "lacks post"),
        ({"capabilities": {"read"}}, "must be a frozenset"),
        ({"limits": None}, "limits must be a RateLimits"),
    ],
)
def test_the_loader_names_what_is_wrong(over, problem):
    problems = adapter_problems(_adapter(**over), "flatboard")
    assert any(problem in p for p in problems), problems


def test_an_invalid_installed_adapter_is_refused(monkeypatch):
    from bonnet.bridges import adapter as adapter_module

    monkeypatch.setitem(adapter_module.BUILTIN_ADAPTERS, "flatboard", f"{__name__}:_Broken")
    with pytest.raises(AdapterInvalid, match="protocol"):
        load_adapter_class("flatboard")


_Broken = _adapter(protocol=0)
