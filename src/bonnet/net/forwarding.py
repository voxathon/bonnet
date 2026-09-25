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

"""Which client a request came from, when a proxy stands in front.

One rule for the server and the gateway alike. Forwarded headers are
believed only from a socket peer on the operator's `trusted_forwarders`
list; anyone else's are ignored and the peer itself is the client. Both
servers run uvicorn with `proxy_headers=False`, so the peer is the real
socket and not a value uvicorn already rewrote from these same headers
under its own default trust of 127.0.0.1.

From a trusted peer, precedence is CF-Connecting-IP (the Cloudflare edge
overwrites it), then X-Real-IP, then the *rightmost* X-Forwarded-For entry:
proxies append, so the rightmost is the one the trusted peer added, and
everything to its left came from whoever connected to that peer.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping


def canonical_ip(value: str) -> str:
    """`value` as ipaddress spells it, so `::1` and `0:0::1` compare equal.

    Anything that isn't an IP comes back stripped and otherwise untouched.
    """
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


def parse_trusted(values: Iterable[str]) -> frozenset[str]:
    """The canonical set of trusted forwarder IPs; ValueError on a non-IP."""
    out = set()
    for value in values:
        if not isinstance(value, str):
            raise ValueError(f"trusted_forwarders entries must be strings, got {value!r}")
        try:
            out.add(str(ipaddress.ip_address(value.strip())))
        except ValueError:
            raise ValueError(f"trusted_forwarders entry {value!r} is not a valid IP address")
    return frozenset(out)


def forwarded_client(headers: Mapping[str, str]) -> str:
    """The client IP forwarded headers name, or "". Lower-case header keys.

    Data only: callers apply it only when the socket peer is trusted.
    """
    cf = (headers.get("cf-connecting-ip") or "").strip()
    if cf:
        return cf
    real = (headers.get("x-real-ip") or "").strip()
    if real:
        return real
    xff = (headers.get("x-forwarded-for") or "").strip()
    if xff:
        return xff.split(",")[-1].strip()
    return ""


def client_ip(peer: str, headers: Mapping[str, str], trusted: frozenset[str]) -> str:
    """The client a request is from: the forwarded one if `peer` is trusted."""
    if peer and canonical_ip(peer) in trusted:
        return forwarded_client(headers) or peer
    return peer
