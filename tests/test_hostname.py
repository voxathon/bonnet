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

"""Shared hostname normalization: one spelling per host.

`normalize_hostname` is the single canonical place (lower, one trailing
dot, UTS46/WHATWG IDNA) used by signing, config, dial safety, loopback
checks, and origin lookups. `normalize_origin` extends it to origin names.
"""

import pytest

from bonnet.core.hostname import normalize_hostname
from bonnet.core.record import normalize_origin


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("h.example", "h.example"),
        ("H.EXAMPLE", "h.example"),
        ("h.example.", "h.example"),
        ("H.EXAMPLE.:443", "h.example.:443"),  # ports are not this helper's job
        ("  h.example  ", "h.example"),
        ("münchen.de", "xn--mnchen-3ya.de"),
        ("München.DE.", "xn--mnchen-3ya.de"),
        ("xn--mnchen-3ya.de", "xn--mnchen-3ya.de"),
        ("[::1]", "[::1]"),
        ("10.0.0.15", "10.0.0.15"),
        ("", ""),
    ],
)
def test_normalize_hostname(raw, expected):
    assert normalize_hostname(raw) == expected


def test_normalize_hostname_never_raises():
    # Invalid labels fail closed to the lowered input instead of raising,
    # so both signing sides still converge.
    assert normalize_hostname("bad_underscore-.example") == "bad_underscore-.example"


def test_normalize_origin_covers_idna():
    assert normalize_origin("münchen.de") == "xn--mnchen-3ya.de"
    assert normalize_origin("BBS.Example.") == "bbs.example"


def test_loopback_spellings():
    from bonnet.gateway.firehose_client import is_loopback

    assert is_loopback("https://localhost:2272")
    assert is_loopback("https://localhost.:2272")
    assert is_loopback("https://LOCALHOST/")
    assert not is_loopback("https://bbs.example")


def test_safe_dial_target_dot_equivalence():
    from bonnet.net.firehose_sync import is_safe_dial_target

    assert is_safe_dial_target("localhost.", 2272, allow_private=True)
    assert not is_safe_dial_target("localhost.", 2272)
    assert not is_safe_dial_target(None, 2272)


def test_origin_store_finds_canonical_spellings(tmp_path):
    from bonnet.gateway.origins import OriginStore

    store = OriginStore(str(tmp_path / "origins.db"))
    try:
        store.remember("bbs.test", "https://bbs.test", True, "scout")
        assert store.get_by_url("https://bbs.test:443")["origin"] == "bbs.test"
        assert store.get_by_url("https://BBS.TEST.")["origin"] == "bbs.test"
        assert store.get_by_url("https://elsewhere.example") is None
    finally:
        store.close()
