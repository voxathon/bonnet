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

"""Record vocabulary for bridges (design doc §4).

Everything here is pure: field IDs, roles and kinds, the deterministic ID
function `H()` and the IDs built on it, text normalization and digests,
marker and `src:` tag codecs, puppet key seeds and names, and the
`BridgeMetadata` block that rides on bridge-written records.

Nothing in this module reads clocks, randomness or state. Deterministic IDs
are only crash-safe if every intent is a pure function of the foreign post,
the current revision and config (§4.3).
"""

from __future__ import annotations

import hashlib
import re
import struct
import unicodedata
from dataclasses import dataclass, fields

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from bonnet.core.kind_validator import identity_text_violation
from bonnet.core.record import (
    MAX_TEXT_FIELD,
    MetadataField,
    MetadataMap,
    metadata_bool,
    metadata_bytes,
    metadata_i64,
    metadata_text,
    metadata_text_list,
    metadata_u64,
)

# ---------------------------------------------------------------------------
# Kinds and roles (§4.2)
# ---------------------------------------------------------------------------

KIND_BRIDGE_LINK = "bonnet.bridge.link"
KIND_BRIDGE_OBSERVATION = "bonnet.bridge.observation"
KIND_BRIDGE_BINDING = "bonnet.bridge.binding"
KIND_BRIDGE_UNBIND = "bonnet.bridge.unbind"
BRIDGE_KIND_PREFIX = "bonnet.bridge."

BRIDGE_VERSION = 1

ROLE_MIRROR = 1
ROLE_CROSSPOST = 2
ROLE_RELAY_LINK = 3
ROLE_OBSERVATION = 4
ROLE_BINDING = 5
ROLE_EVIDENCE_LINK = 6

FOREIGN_PRESENT = 0
FOREIGN_DELETED = 1
FOREIGN_EDITED = 2

# ---------------------------------------------------------------------------
# Metadata field IDs (§4.1, §8). Reserved range 0x0100–0x01FF.
# ---------------------------------------------------------------------------

BRIDGE_FIELD_MIN = 0x0100
BRIDGE_FIELD_MAX = 0x01FF

F_BRIDGE_VERSION = 0x0100
F_BRIDGE_ROLE = 0x0101
F_VENUE = 0x0102
F_CHANNEL = 0x0103
F_FOREIGN_ID = 0x0104
F_FOREIGN_AUTHOR = 0x0105
F_FOREIGN_AUTHOR_ID = 0x0106
F_FOREIGN_CREATED_AT = 0x0107
F_FOREIGN_REPLY_TO = 0x0108
F_FOREIGN_URL = 0x0109
F_FOREIGN_CONTENT_TYPE = 0x010A
F_FOREIGN_STATE = 0x010B
F_MARKER = 0x010C
F_ORIGINAL_SIZE = 0x010D
F_TRUNCATED = 0x010E
F_CROSSPOST_OF_ORIGIN = 0x010F
F_CROSSPOST_OF_EVENT = 0x0110
F_FOREIGN_ROOT_ID = 0x0111
F_FOREIGN_DIGEST = 0x0112
F_MIRROR_REVISION = 0x0113
F_HOME_ORIGIN = 0x0114
F_HOME_URL = 0x0115
F_HOME_USERNAME = 0x0116

F_BINDING_GENERATION = 0x0120
F_BINDING_INGEST = 0x0121
F_BINDING_RELAY_EGRESS = 0x0122
F_BINDING_EDGE_EGRESS_DEFAULT = 0x0123
F_BINDING_RELAY_ACCOUNT = 0x0124
F_BINDING_MAX_BODY_BYTES = 0x0125
F_BINDING_FOREIGN_CAPABILITIES = 0x0126

# ---------------------------------------------------------------------------
# Text normalization and digests
# ---------------------------------------------------------------------------


def normalize_foreign_text(text: str) -> str:
    """NFC, `\\r\\n` → `\\n`, trailing whitespace stripped (§4.1)."""
    return unicodedata.normalize("NFC", text).replace("\r\n", "\n").rstrip()


def foreign_digest(text: str) -> bytes:
    """`sha256(normalized full foreign text)`, taken before any truncation."""
    return hashlib.sha256(normalize_foreign_text(text).encode("utf-8")).digest()


def content_digest(text: str) -> bytes:
    """The 16-byte digest that goes into mirror and observation IDs (§4.3)."""
    return foreign_digest(text)[:16]


def truncate_utf8(text: str, max_bytes: int) -> str:
    """Longest prefix of `text` whose UTF-8 encoding fits in `max_bytes`."""
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


# ---------------------------------------------------------------------------
# Deterministic identifiers (§4.3)
# ---------------------------------------------------------------------------

_H_DOMAIN = b"bonnet.bridge.v1\x00"


def u64(n: int) -> bytes:
    """Big-endian u64 part for `H()`. Integers never go in as text."""
    return struct.pack(">Q", n)


def _part(p: str | bytes) -> bytes:
    raw = p.encode("utf-8") if isinstance(p, str) else bytes(p)
    if len(raw) > 0xFFFF:
        raise ValueError(f"H() part too long: {len(raw)} bytes")
    return struct.pack(">H", len(raw)) + raw


def H(label: bytes, *parts: str | bytes) -> bytes:
    """`sha256(domain + len16(label) + label + Σ len16(part) + part)`.

    Length prefixes keep the encoding unambiguous even when a part contains
    `\\x00` or is empty. Text parts are UTF-8; callers pass values as they
    appear in records, so no normalization happens here.
    """
    out = _H_DOMAIN + _part(label)
    for p in parts:
        out += _part(p)
    return hashlib.sha256(out).digest()


def mirror_article_id(
    bridge_origin: str,
    bridge_board: str,
    venue: str,
    channel: str,
    foreign_id: str,
    revision: int,
    digest16: bytes,
) -> bytes:
    return H(
        b"mirror.article",
        bridge_origin,
        bridge_board,
        venue,
        channel,
        foreign_id,
        u64(revision),
        digest16,
    )


def mirror_event_id(
    bridge_origin: str,
    bridge_board: str,
    venue: str,
    channel: str,
    foreign_id: str,
    revision: int,
    digest16: bytes,
) -> bytes:
    return H(
        b"mirror.event",
        bridge_origin,
        bridge_board,
        venue,
        channel,
        foreign_id,
        u64(revision),
        digest16,
    )


def observation_event_id(
    venue: str,
    channel: str,
    foreign_id: str,
    digest16: bytes,
    foreign_state: int,
    raw: bytes,
    target_origin: str,
    target_event_id: bytes,
) -> bytes:
    return H(
        b"observation",
        venue,
        channel,
        foreign_id,
        digest16,
        u64(foreign_state),
        hashlib.sha256(raw).digest(),
        target_origin,
        target_event_id,
    )


def link_event_id(
    bridge_origin: str,
    target_board: str,
    target_article_id: bytes,
    venue: str,
    channel: str,
    foreign_id: str,
) -> bytes:
    return H(
        b"relay.link",
        bridge_origin,
        target_board,
        target_article_id,
        venue,
        channel,
        foreign_id,
    )


def binding_event_id(
    venue: str, channel: str, bridge_origin: str, bridge_board: str, generation: int
) -> bytes:
    return H(b"binding", venue, channel, bridge_origin, bridge_board, u64(generation))


def unbind_event_id(binding_event_id: bytes) -> bytes:
    return H(b"unbind", binding_event_id)


def puppet_register_event_id(bridge_origin: str, venue: str, foreign_author_id: str) -> bytes:
    return H(b"puppet.register", bridge_origin, venue, foreign_author_id)


# ---------------------------------------------------------------------------
# Puppets (§4.4)
# ---------------------------------------------------------------------------

PUPPET_HANDLE_MAX_BYTES = 24
ANONYMOUS_HANDLE = "anonymous"


def puppet_seed(master_secret: bytes, venue: str, foreign_author_id: str) -> bytes:
    """32-byte Ed25519 seed for one foreign author's puppet."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"bonnet.bridge.puppet.v1",
        info=venue.encode("utf-8") + b"\x00" + foreign_author_id.encode("utf-8"),
    ).derive(master_secret)


def _author_hex(foreign_author_id: str, n: int) -> str:
    return hashlib.sha256(foreign_author_id.encode("utf-8")).hexdigest()[:n]


def sanitize_handle(handle: str) -> str:
    """NFC, `~` → `-`, C0 controls and reserved characters dropped, trimmed."""
    s = unicodedata.normalize("NFC", handle).replace("~", "-")
    s = "".join(c for c in s if ord(c) >= 0x20 and c not in '<>:"/\\|?*')
    return s.strip()


def puppet_username(
    handle: str, venue_type: str, foreign_author_id: str, *, collided: bool = False
) -> str:
    """The name a puppet registers under: `<sanitized handle>~<type>`.

    The `~<type>` suffix is the only `~` in the result. Handles longer than
    24 bytes are cut and end in `-<4 hex>` of the author id. `collided=True`
    (the plain name was invalid or held by another key) inserts
    `-<6 hex>` before the suffix. Chosen once at registration; the runtime
    reads the registered name back afterwards and never calls this again
    for the same puppet.
    """
    base = sanitize_handle(handle) or ANONYMOUS_HANDLE
    if len(base.encode("utf-8")) > PUPPET_HANDLE_MAX_BYTES:
        tail = "-" + _author_hex(foreign_author_id, 4)
        base = truncate_utf8(base, PUPPET_HANDLE_MAX_BYTES - len(tail)).rstrip() + tail
    if collided:
        base += "-" + _author_hex(foreign_author_id, 6)
    name = f"{base}~{venue_type}"
    if not collided and identity_text_violation(name) is not None:
        return puppet_username(handle, venue_type, foreign_author_id, collided=True)
    return name


# ---------------------------------------------------------------------------
# Marker (§4.5)
# ---------------------------------------------------------------------------

_MARKER_RE = re.compile(r"\[bnt:([0-9a-f]{16})\]")


def make_marker(event_id: bytes) -> str:
    return f"[bnt:{event_id.hex()[:16]}]"


def find_marker(text: str) -> str | None:
    """The 16-hex prefix of the last marker in `text`, or None.

    A marker is a hint, never proof: anyone at the venue can copy one.
    """
    found = _MARKER_RE.findall(text)
    return found[-1] if found else None


# ---------------------------------------------------------------------------
# Source keys and tags (§4.1, §4.6)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceKey:
    """`(venue, channel, foreign_id)`: "the same foreign post" everywhere."""

    venue: str
    channel: str
    foreign_id: str


_SRC_ESCAPES = {"%": "%25", "#": "%23", ",": "%2C"}
_SRC_UNESCAPE_RE = re.compile(r"%(25|23|2C)", re.IGNORECASE)
_SRC_UNESCAPES = {"25": "%", "23": "#", "2C": ","}


def _src_escape(s: str) -> str:
    return "".join(_SRC_ESCAPES.get(c, c) for c in s)


def _src_unescape(s: str) -> str:
    return _SRC_UNESCAPE_RE.sub(lambda m: _SRC_UNESCAPES[m.group(1).upper()], s)


def src_tag(src: SourceKey) -> str:
    """`src:<venue>#<channel>#<foreign_id>`, each component escaped."""
    return "src:" + "#".join(_src_escape(p) for p in (src.venue, src.channel, src.foreign_id))


def parse_src_tag(tag: str) -> SourceKey | None:
    if not tag.startswith("src:"):
        return None
    parts = tag[4:].split("#")
    if len(parts) != 3:
        return None
    return SourceKey(*(_src_unescape(p) for p in parts))


def bridge_tags(venue_type: str, src: SourceKey) -> list[str]:
    return ["bridged", f"venue:{venue_type}", src_tag(src)]


# ---------------------------------------------------------------------------
# Metadata block
# ---------------------------------------------------------------------------


def _text(field_id: int, value: str) -> MetadataField:
    """TEXT field, NFC and capped at 4096 bytes. Truncate, never fail an import."""
    return metadata_text(
        field_id, truncate_utf8(unicodedata.normalize("NFC", value), MAX_TEXT_FIELD)
    )


# attribute name -> (field id, encoder)
_FIELD_SPECS: dict[str, tuple[int, object]] = {
    "bridge_version": (F_BRIDGE_VERSION, metadata_u64),
    "bridge_role": (F_BRIDGE_ROLE, metadata_u64),
    "venue": (F_VENUE, _text),
    "channel": (F_CHANNEL, _text),
    "foreign_id": (F_FOREIGN_ID, _text),
    "foreign_author": (F_FOREIGN_AUTHOR, _text),
    "foreign_author_id": (F_FOREIGN_AUTHOR_ID, _text),
    "foreign_created_at": (F_FOREIGN_CREATED_AT, metadata_i64),
    "foreign_reply_to": (F_FOREIGN_REPLY_TO, _text),
    "foreign_url": (F_FOREIGN_URL, _text),
    "foreign_content_type": (F_FOREIGN_CONTENT_TYPE, _text),
    "foreign_state": (F_FOREIGN_STATE, metadata_u64),
    "marker": (F_MARKER, _text),
    "original_size": (F_ORIGINAL_SIZE, metadata_u64),
    "truncated": (F_TRUNCATED, metadata_bool),
    "crosspost_of_origin": (F_CROSSPOST_OF_ORIGIN, _text),
    "crosspost_of_event": (F_CROSSPOST_OF_EVENT, metadata_bytes),
    "foreign_root_id": (F_FOREIGN_ROOT_ID, _text),
    "foreign_digest": (F_FOREIGN_DIGEST, metadata_bytes),
    "mirror_revision": (F_MIRROR_REVISION, metadata_u64),
    "home_origin": (F_HOME_ORIGIN, _text),
    "home_url": (F_HOME_URL, _text),
    "home_username": (F_HOME_USERNAME, _text),
    "binding_generation": (F_BINDING_GENERATION, metadata_u64),
    "binding_ingest": (F_BINDING_INGEST, metadata_bool),
    "binding_relay_egress": (F_BINDING_RELAY_EGRESS, metadata_bool),
    "binding_edge_egress_default": (F_BINDING_EDGE_EGRESS_DEFAULT, metadata_bool),
    "binding_relay_account": (F_BINDING_RELAY_ACCOUNT, _text),
    "binding_max_body_bytes": (F_BINDING_MAX_BODY_BYTES, metadata_u64),
    "binding_foreign_capabilities": (F_BINDING_FOREIGN_CAPABILITIES, metadata_text_list),
}


@dataclass(frozen=True)
class BridgeMetadata:
    """The 0x0100+ field block. `None` means the field is absent."""

    bridge_version: int | None = BRIDGE_VERSION
    bridge_role: int | None = None
    venue: str | None = None
    channel: str | None = None
    foreign_id: str | None = None
    foreign_author: str | None = None
    foreign_author_id: str | None = None
    foreign_created_at: int | None = None
    foreign_reply_to: str | None = None
    foreign_url: str | None = None
    foreign_content_type: str | None = None
    foreign_state: int | None = None
    marker: str | None = None
    original_size: int | None = None
    truncated: bool | None = None
    crosspost_of_origin: str | None = None
    crosspost_of_event: bytes | None = None
    foreign_root_id: str | None = None
    foreign_digest: bytes | None = None
    mirror_revision: int | None = None
    home_origin: str | None = None
    home_url: str | None = None
    home_username: str | None = None
    binding_generation: int | None = None
    binding_ingest: bool | None = None
    binding_relay_egress: bool | None = None
    binding_edge_egress_default: bool | None = None
    binding_relay_account: str | None = None
    binding_max_body_bytes: int | None = None
    binding_foreign_capabilities: tuple[str, ...] | None = None

    def to_fields(self) -> list[MetadataField]:
        """Encoded fields in ascending ID order."""
        out = []
        for f in fields(self):
            value = getattr(self, f.name)
            if value is None:
                continue
            field_id, encode = _FIELD_SPECS[f.name]
            if f.name == "binding_foreign_capabilities":
                value = list(value)
            out.append(encode(field_id, value))  # type: ignore[operator]
        out.sort(key=lambda m: m.field_id)
        return out

    @classmethod
    def from_metadata(cls, m: MetadataMap) -> BridgeMetadata:
        """Read the bridge block back; wrongly typed fields read as absent."""
        values: dict[str, object] = {}
        for name, (field_id, encode) in _FIELD_SPECS.items():
            if encode is _text:
                values[name] = m.get_text(field_id)
            elif encode is metadata_u64:
                values[name] = m.get_u64(field_id)
            elif encode is metadata_i64:
                values[name] = m.get_i64(field_id)
            elif encode is metadata_bool:
                values[name] = m.get_bool(field_id)
            elif encode is metadata_bytes:
                values[name] = m.get_bytes(field_id)
            else:
                texts = m.get_text_list(field_id)
                values[name] = tuple(texts) if texts is not None else None
        return cls(**values)  # type: ignore[arg-type]

    @property
    def src(self) -> SourceKey | None:
        if self.venue is None or self.foreign_id is None:
            return None
        return SourceKey(self.venue, self.channel or "", self.foreign_id)


def merge_metadata(base: MetadataMap, extra: list[MetadataField]) -> MetadataMap:
    """`base` plus `extra`, in ascending field-ID order.

    Raises ValueError if an ID appears twice: silently letting one side win
    would sign something the caller didn't ask for.
    """
    merged = list(base.fields) + list(extra)
    merged.sort(key=lambda f: f.field_id)
    for a, b in zip(merged, merged[1:]):
        if a.field_id == b.field_id:
            raise ValueError(f"metadata field 0x{a.field_id:04x} given twice")
    return MetadataMap(merged)


# ---------------------------------------------------------------------------
# Server-side reservations (§8)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BridgePolicy:
    """What a bridge origin's server needs to know to enforce §8.

    Held by the command handler only on origins with `[bridge_runtime]`.
    """

    daemon_pubkey: bytes
    venue_types: frozenset[str]

    def is_puppet_name(self, name: str) -> bool:
        """`<handle>~<type>` for a type this origin runs, with exactly one `~`."""
        handle, sep, venue_type = name.rpartition("~")
        return bool(sep) and bool(handle) and "~" not in handle and venue_type in self.venue_types
