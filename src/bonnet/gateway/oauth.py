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

"""OIDC JWT verifier for the gateway's http transport.

Verifier-only: this never runs an OAuth flow, stores no upstream refresh
tokens, and shows no login pages. It validates JWT access tokens someone else
minted, via OIDC discovery against any https issuer (open discovery), then
returns the (iss, sub) pair the caller binds to a numeric t<N> tenant.

Trust model: the whitelist question is answered by cryptography + admission,
not pre-registration. Any issuer's signature verifies via its own discovered
JWKS, but a token only becomes *its own* tenant — (iss, sub), never email
alone — so evil.com minting victim@gmail.com stays isolated. `blocked_iss`
amputates one bad issuer without flipping the whole thing off; `enabled=false`
(or BONNET_OAUTH=off) makes zero network fetches.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import time
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

_ALLOWED_ALGS = frozenset({"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"})

# Per-issuer discovery + JWKS cache. Small and process-local like the rest of
# the gateway's caches; entries expire, failures carry a short negative TTL so
# one bad issuer cannot pin the verifier into refetching on every request.
_discovery_cache: dict[str, tuple[float, dict]] = {}
_jwks_cache: dict[str, tuple[float, dict]] = {}
_discovery_failures: dict[str, float] = {}
_DISCOVERY_TTL = 3600.0
_JWKS_TTL = 3600.0
_NEGATIVE_TTL = 300.0


def reset_cache() -> None:
    """Drop all cached discovery/JWKS. Tests only."""
    _discovery_cache.clear()
    _jwks_cache.clear()
    _discovery_failures.clear()


def oauth_disabled() -> bool:
    """Kill switch: file config or env. Env wins, mirroring BONNET_GATING=off."""
    import os

    env = (os.environ.get("BONNET_OAUTH") or "").strip().lower()
    if env in ("off", "0", "false", "no"):
        return True
    try:
        from bonnet.gateway import gateway_config, paths

        cfg = gateway_config.load(paths.config_path())
        if cfg is None or cfg.oauth is None:
            return True  # disabled by default: no config means no OAuth
        return not cfg.oauth.enabled
    except Exception:
        return True


def _oauth_config():
    from bonnet.gateway import gateway_config, paths

    cfg = gateway_config.load(paths.config_path())
    return cfg.oauth if cfg is not None else None


def _is_public_https_iss(iss: str, allow_private: bool) -> bool:
    try:
        parsed = urlsplit(iss.strip())
    except Exception:
        return False
    if parsed.scheme != "https" or not parsed.netloc:
        return False
    if parsed.query or parsed.fragment:
        return False
    if "@" in parsed.netloc or any(c.isspace() for c in iss):
        return False
    host = parsed.hostname or ""
    if not host or host.startswith(".") or host.endswith("."):
        return False
    if allow_private:
        return True
    if host in ("localhost",):
        return False
    if host.endswith(".local"):
        return False
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return not (
            ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
        )
    except ValueError:
        pass
    return True


def _http_get_json(url: str, timeout: float = 10.0) -> dict:
    req = Request(url, headers={"Accept": "application/json"})
    with urlopen(req, timeout=timeout) as resp:  # noqa: S310 — URL validated by caller
        body = resp.read(1 << 20)
    data = json.loads(body.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("expected JSON object")
    return data


def _discover(iss: str) -> dict:
    now = time.time()
    cached = _discovery_cache.get(iss)
    if cached and cached[0] > now:
        return cached[1]
    if _discovery_failures.get(iss, 0) > now:
        raise ValueError(f"issuer temporarily failed: {iss}")
    doc = _http_get_json(iss.rstrip("/") + "/.well-known/openid-configuration")
    if not isinstance(doc.get("jwks_uri"), str) or not doc["jwks_uri"].startswith("https://"):
        raise ValueError("discovery missing https jwks_uri")
    _discovery_cache[iss] = (now + _DISCOVERY_TTL, doc)
    return doc


def _jwks(jwks_uri: str) -> dict:
    now = time.time()
    cached = _jwks_cache.get(jwks_uri)
    if cached and cached[0] > now:
        return cached[1]
    doc = _http_get_json(jwks_uri)
    if not isinstance(doc.get("keys"), list):
        raise ValueError("jwks missing keys")
    _jwks_cache[jwks_uri] = (now + _JWKS_TTL, doc)
    return doc


def _b64url(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def parse_unverified(token: str) -> tuple[dict, dict]:
    """Split a compact JWT without verifying. Raises ValueError, never crypto."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("not a compact JWT")
    try:
        header = json.loads(_b64url(parts[0]).decode("utf-8"))
        payload = json.loads(_b64url(parts[1]).decode("utf-8"))
    except Exception as e:
        raise ValueError("malformed JWT") from e
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("malformed JWT")
    return header, payload


def verify_token(token: str) -> tuple[str, str]:
    """Verify a JWT and return (iss, sub). Raises ValueError on any failure.

    Fail-closed on: non-JWT shape, disallowed alg (incl. none), private/non-https
    iss, blocked iss, discovery/JWKS fetch failure, bad signature, missing iss /
    sub / aud, aud mismatch, expiry. Email is never read.
    """
    import jwt

    if oauth_disabled():
        raise ValueError("oauth disabled")
    cfg = _oauth_config()
    if cfg is None or not cfg.enabled:
        raise ValueError("oauth disabled")
    header, payload = parse_unverified(token)
    alg = header.get("alg")
    if alg not in _ALLOWED_ALGS:
        raise ValueError(f"disallowed alg {alg!r}")
    iss = payload.get("iss")
    sub = payload.get("sub")
    if not isinstance(iss, str) or not iss or not isinstance(sub, str) or not sub:
        raise ValueError("JWT missing iss/sub")
    if not _is_public_https_iss(iss, cfg.allow_private_iss):
        raise ValueError("non-public issuer")
    if iss.rstrip("/") in {b.rstrip("/") for b in (cfg.blocked_iss or [])}:
        raise ValueError("issuer blocked")
    if not cfg.allow_all:
        # allow_all=false with no per-issuer table means closed: blocked list
        # is the only admission signal, so nothing else verifies.
        raise ValueError("issuer not allowlisted")
    aud = payload.get("aud")
    expected = (cfg.audience or "").strip()
    if not expected or aud is None:
        raise ValueError("aud required")
    auds = aud if isinstance(aud, list) else [aud]
    if expected not in auds:
        raise ValueError("aud mismatch")
    try:
        doc = _discover(iss)
        keys = _jwks(doc["jwks_uri"])
    except ValueError:
        raise
    except Exception as e:
        _discovery_failures[iss] = time.time() + _NEGATIVE_TTL
        raise ValueError(f"issuer fetch failed: {type(e).__name__}") from e
    try:
        key = _key_for(keys, header.get("kid"))
        decoded = jwt.decode(
            token,
            key=key,
            algorithms=[alg],
            audience=expected,
            issuer=iss,
            options={"require": ["iss", "sub", "aud", "exp"]},
        )
    except Exception as e:
        raise ValueError(f"JWT verification failed: {type(e).__name__}") from e
    out_iss, out_sub = decoded.get("iss"), decoded.get("sub")
    if not isinstance(out_iss, str) or not isinstance(out_sub, str):
        raise ValueError("JWT missing iss/sub after verify")
    try:
        from bonnet.core.logging import log_debug

        digest = hashlib.sha256(f"{out_iss}|{out_sub}".encode()).hexdigest()[:12]
        log_debug("OAUTH verify ok", iss=out_iss, sub_hash=digest)
    except Exception:
        pass
    return out_iss, out_sub


def _key_for(jwks: dict, kid: str | None):
    from jwt import PyJWK

    keys = jwks.get("keys") or []
    candidates = (
        [e for e in keys if isinstance(e, dict) and e.get("kid") == kid] if kid else []
    )
    if not candidates and len(keys) == 1 and isinstance(keys[0], dict) and not kid:
        candidates = keys
    if not candidates:
        raise ValueError("no matching JWK")
    return PyJWK(candidates[0]).key
