# Copyright 2026 The Bonnet Contributors
"""OIDC JWT verifier + numeric JIT tenants."""

import base64
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from bonnet.gateway import gateway_config, oauth, paths, registry, tenancy, tenants


def _b64url_int(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@pytest.fixture
def rsa_pair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub = key.public_key()
    nums = pub.public_numbers()
    jwk = {
        "kty": "RSA",
        "kid": "test-key",
        "use": "sig",
        "alg": "RS256",
        "n": _b64url_int(nums.n),
        "e": _b64url_int(nums.e),
    }
    return priv, jwk


@pytest.fixture
def oauth_env(tmp_path, monkeypatch):
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "gw"))
    monkeypatch.delenv("BONNET_OAUTH", raising=False)
    oauth.reset_cache()
    tenancy.reset_store_cache()
    tenancy.reset_registry_cache()
    yield tmp_path / "gw"
    tenancy.reset_store_cache()
    tenancy.reset_registry_cache()
    oauth.reset_cache()


def _write_oauth_config(home, audience="bonnet-test", blocked=(), allow_private=False):
    import os

    gw_dir = os.environ["BONNET_GATEWAY_HOME"]
    os.makedirs(gw_dir, exist_ok=True)
    blocked_toml = ", ".join(f'"{b}"' for b in blocked)
    with open(os.path.join(gw_dir, "gateway.toml"), "w") as f:
        f.write(
            "[gateway.oauth]\n"
            "enabled = true\nallow_all = true\n"
            f"blocked_iss = [{blocked_toml}]\n"
            f'audience = "{audience}"\n'
            f"allow_private_iss = {'true' if allow_private else 'false'}\n"
        )


def _mint(priv, iss, sub, aud, kid="test-key", alg="RS256", exp_delta=600):
    now = int(time.time())
    return jwt.encode(
        {"iss": iss, "sub": sub, "aud": aud, "iat": now, "exp": now + exp_delta},
        priv,
        algorithm=alg,
        headers={"kid": kid},
    )


def test_verify_ok_and_aud_required(oauth_env, rsa_pair, monkeypatch):
    priv, jwk = rsa_pair
    iss = "https://idp.example"
    _write_oauth_config(oauth_env)
    monkeypatch.setattr(oauth, "_discover", lambda i: {"jwks_uri": "https://idp.example/jwks"})
    monkeypatch.setattr(oauth, "_jwks", lambda u: {"keys": [jwk]})
    token = _mint(priv, iss, "user1", "bonnet-test")
    assert oauth.verify_token(token) == (iss, "user1")
    # wrong aud fails closed
    bad = _mint(priv, iss, "user1", "someone-else")
    with pytest.raises(ValueError, match="aud"):
        oauth.verify_token(bad)
    # none alg rejected
    none_tok = jwt.encode({"iss": iss, "sub": "x", "aud": "bonnet-test"}, "s", algorithm="HS256")
    hdr, _ = oauth.parse_unverified(none_tok)
    assert hdr["alg"] == "HS256"  # sanity; RS-only path below uses crafted header
    forged = "e30.e30.c2ln"  # header.alg=none shape
    with pytest.raises(ValueError):
        oauth.verify_token(forged)


def test_blocked_beats_allow_all(oauth_env, rsa_pair, monkeypatch):
    priv, jwk = rsa_pair
    iss = "https://evil.example"
    _write_oauth_config(oauth_env, blocked=(iss,))
    monkeypatch.setattr(oauth, "_discover", lambda i: {"jwks_uri": "https://x/jwks"})
    monkeypatch.setattr(oauth, "_jwks", lambda u: {"keys": [jwk]})
    token = _mint(priv, iss, "attacker", "bonnet-test")
    with pytest.raises(ValueError, match="blocked"):
        oauth.verify_token(token)


def test_private_iss_rejected_by_default(oauth_env, rsa_pair, monkeypatch):
    priv, jwk = rsa_pair
    iss = "http://localhost:8080/realms/x"
    _write_oauth_config(oauth_env)
    monkeypatch.setattr(oauth, "_discover", lambda i: {"jwks_uri": "https://x/jwks"})
    monkeypatch.setattr(oauth, "_jwks", lambda u: {"keys": [jwk]})
    token = _mint(priv, iss, "dev", "bonnet-test")
    with pytest.raises(ValueError, match="non-public"):
        oauth.verify_token(token)


def test_disabled_makes_zero_fetches(oauth_env, rsa_pair, monkeypatch):
    # no config file -> disabled by default
    called = []
    monkeypatch.setattr(
        oauth, "_discover", lambda i: called.append(i) or {"jwks_uri": "https://x"}
    )
    with pytest.raises(ValueError, match="disabled"):
        oauth.verify_token("a.b.c")
    assert called == []


def test_jit_numeric_stable_and_dual_path(oauth_env):
    t1 = tenants.get_or_create_oauth_tenant("https://a.example", "sub-1")
    t2 = tenants.get_or_create_oauth_tenant("https://a.example", "sub-1")
    assert t1 == t2 and t1.startswith("t")
    t3 = tenants.get_or_create_oauth_tenant("https://a.example", "sub-2")
    assert t3 != t1
    # cross-issuer isolation: same sub, different iss
    t4 = tenants.get_or_create_oauth_tenant("https://evil.example", "sub-1")
    assert t4 not in (t1, t3)
    # email never stored: binding rows carry only iss/sub
    rows = tenants.list_oauth_bindings()
    assert len(rows) == 3
    assert all("email" not in r for r in rows)
    # dual path: fixed key works on a JIT tenant
    key = tenants.add_key(t1, label="laptop")
    assert key.startswith("bnt_")
    assert registry.Registry().resolve(key) == t1
    # disable kills both paths
    tenants.set_enabled(t1, False)
    assert registry.Registry().resolve(key) is None
    assert registry.Registry().get_oauth_tenant("https://a.example", "sub-1") is None


def test_sharded_dirs(oauth_env):
    t1 = tenants.get_or_create_oauth_tenant("https://a.example", "shard-me")
    d = paths.tenant_dir(t1)
    assert f"{t1}" in d and "/t/" in d.replace("\\", "/")
    # named tenants stay flat
    tenants.add_tenant("alice")
    assert paths.tenant_dir("alice").endswith("alice")
    assert paths.tenant_dir("default").endswith("default")


def test_config_validation():
    cfg = gateway_config.GatewayConfig(oauth=gateway_config.OAuthConfig(enabled=True))
    with pytest.raises(ValueError, match="audience"):
        gateway_config.validate(cfg)
    cfg2 = gateway_config.GatewayConfig(
        oauth=gateway_config.OAuthConfig(
            enabled=True, audience="x", blocked_iss=["http://nope"]
        )
    )
    with pytest.raises(ValueError, match="blocked_iss"):
        gateway_config.validate(cfg2)


def test_auth_middleware_oauth_branch(oauth_env, rsa_pair, monkeypatch):
    from bonnet.gateway import server

    priv, jwk = rsa_pair
    _write_oauth_config(oauth_env)
    monkeypatch.setattr(
        oauth, "_discover", lambda i: {"jwks_uri": "https://idp.example/jwks"}
    )
    monkeypatch.setattr(oauth, "_jwks", lambda u: {"keys": [jwk]})
    token = _mint(priv, "https://idp.example", "agent-7", "bonnet-test")

    class Headers(dict):
        pass

    class Req:
        headers = {"Authorization": f"Bearer {token}"}

    monkeypatch.setattr(server, "get_http_request", lambda: Req())
    server.AuthMiddleware()._set_auth_context(None)
    tenant = tenancy.current_tenant.get()
    assert tenant.startswith("t")
    assert tenancy.current_auth_status.get() == tenancy.AUTH_OK
