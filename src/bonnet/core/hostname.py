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

"""Shared hostname normalization: lower, trailing-dot, UTS46/WHATWG IDNA.

Single canonical place so signing (`net.http_auth`), config validation
(`core.config`), dial safety (`net.firehose_sync`), loopback checks, and
origin lookups (`core.record.normalize_origin`) all agree on what a name
means. Never raises — IDNA failures and missing `uts46` fall closed to the
lowered, dot-stripped input so both sides still converge.
"""

from __future__ import annotations

import functools


@functools.lru_cache(maxsize=1024)
def normalize_hostname(host: str) -> str:
    """Canonical form of a hostname: stripped, lowercased, no trailing dot, A-label.

    `H.Example.` → `h.example`; `münchen.de` → its punycode A-label.
    IPv6 literals (`[...]`) and IP/dot-quad strings pass through lowercased.
    On any IDNA failure (or missing `uts46` package) falls closed to the
    lowered, dot-stripped input.
    """
    lowered = host.strip().lower()
    if lowered.startswith("["):
        return lowered
    stripped = lowered[:-1] if lowered.endswith(".") and len(lowered) > 1 else lowered
    try:
        from uts46.whatwg import domain_to_ascii
    except ImportError:
        return stripped
    try:
        return domain_to_ascii(stripped, be_strict=True, transitional=False)
    except Exception:
        return stripped
