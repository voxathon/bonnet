"""The tenant registry and the admin CLI that drives it."""

import pytest

pytest.importorskip("bcrypt")
pytest.importorskip("cryptography")
pytest.importorskip("fastmcp")

from pathlib import Path

from bonnet.gateway import paths, tenancy, tenants
from bonnet.gateway.registry import Registry, TenantError, hash_key, validate_tenant_id
from bonnet.gateway.server import run as gateway_run


@pytest.fixture
def gw(tmp_path, monkeypatch):
    monkeypatch.setenv("BONNET_GATEWAY_HOME", str(tmp_path / "gw"))
    tenancy.reset_store_cache()
    tenancy.reset_registry_cache()
    yield tmp_path / "gw"
    tenancy.reset_store_cache()
    tenancy.reset_registry_cache()


# --- tenant ids ------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "../escape",
        "a/b",
        "a\\b",
        "..",
        ".hidden",
        "-leading",
        "with space",
        "x" * 64,
    ],
)
def test_unusable_tenant_ids_are_rejected(bad):
    """A tenant id becomes a directory name. Without validation, an id of
    '../..' would place a tenant's stores outside the gateway entirely."""
    with pytest.raises(TenantError):
        validate_tenant_id(bad)


@pytest.mark.parametrize("name", ["default", "anonymous"])
def test_reserved_ids_are_rejected(name):
    """Registering either would silently take over a built-in: `default` is
    what stdio runs as, `anonymous` is the degraded fallback."""
    with pytest.raises(TenantError):
        validate_tenant_id(name)


@pytest.mark.parametrize("good", ["alice", "a", "team-1", "team_1", "A9"])
def test_ordinary_tenant_ids_are_accepted(good):
    assert validate_tenant_id(good) == good


# --- keys ------------------------------------------------------------------


def test_a_key_resolves_to_its_tenant(gw):
    key = tenants.add_tenant("alice")
    assert tenancy.resolve_key(key) == "alice"


def test_the_key_itself_is_never_stored(gw):
    """Only a hash is kept, so the registry file cannot be replayed even if
    it is read."""
    key = tenants.add_tenant("alice")
    blob = Path(paths.registry_db_path()).read_bytes()

    assert key.encode() not in blob
    assert hash_key(key).encode() in blob


def test_a_tenant_can_hold_several_live_keys(gw):
    """One key per consumer is what scopes a leak to the consumer that
    leaked it."""
    first = tenants.add_tenant("alice")
    second = tenants.add_key("alice", label="ci")
    tenancy.reset_registry_cache()

    assert tenancy.resolve_key(first) == "alice"
    assert tenancy.resolve_key(second) == "alice"
    assert len(tenants.list_keys("alice")) == 2


def test_revoking_is_per_key_not_per_tenant(gw):
    first = tenants.add_tenant("alice")
    second = tenants.add_key("alice")
    tenancy.reset_registry_cache()
    first_id = [k for k in tenants.list_keys("alice") if k["label"] == "initial"][0]["key_id"]

    tenants.revoke_key(first_id)
    tenancy.reset_registry_cache()

    assert tenancy.resolve_key(first) is None
    assert tenancy.resolve_key(second) == "alice"


def test_revoking_twice_is_an_error_not_a_silent_success(gw):
    tenants.add_tenant("alice")
    key_id = tenants.list_keys("alice")[0]["key_id"]
    tenants.revoke_key(key_id)

    with pytest.raises(TenantError):
        tenants.revoke_key(key_id)


def test_keys_cannot_be_minted_for_a_tenant_that_does_not_exist(gw):
    with pytest.raises(TenantError):
        tenants.add_key("nobody")


def test_listing_keys_for_a_tenant_that_does_not_exist_is_an_error(gw):
    """list_keys("nobody") used to return an empty list, indistinguishable
    from a real tenant that simply holds zero keys - add_key/revoke_key
    both already raise TenantError for an unknown tenant, so list_keys now
    matches them instead of being the one silent exception."""
    with pytest.raises(TenantError):
        tenants.list_keys("nobody")


# --- tenant lifecycle ------------------------------------------------------


def test_a_duplicate_tenant_is_refused(gw):
    tenants.add_tenant("alice")
    with pytest.raises(TenantError):
        tenants.add_tenant("alice")


def test_disabling_stops_resolution_without_destroying_anything(gw):
    key = tenants.add_tenant("alice")

    tenants.set_enabled("alice", False)
    tenancy.reset_registry_cache()
    assert tenancy.resolve_key(key) is None

    tenants.set_enabled("alice", True)
    tenancy.reset_registry_cache()
    assert tenancy.resolve_key(key) == "alice"


def test_removing_a_tenant_takes_its_directory_with_it(gw):
    key = tenants.add_tenant("alice")
    token = tenancy.current_tenant.set("alice")
    try:
        tenancy.identity_store().register("bbs.test", "scout")
        tenant_path = Path(paths.tenant_dir("alice"))
        assert tenant_path.exists()
    finally:
        tenancy.current_tenant.reset(token)

    tenants.remove_tenant("alice")

    assert not tenant_path.exists()
    assert tenancy.resolve_key(key) is None


def test_removing_a_tenant_that_does_not_exist_is_an_error(gw):
    with pytest.raises(TenantError):
        tenants.remove_tenant("nobody")


def test_resolution_survives_another_connection_writing(gw):
    """The server holds its registry connection open for the process's life
    while the CLI opens and closes its own. SQLite shows committed writes
    across connections, so a key minted by the CLI resolves without a
    restart — this pins that, since caching the connection would otherwise
    be a plausible source of staleness."""
    resolver = Registry(paths.registry_db_path())
    try:
        key = tenants.add_tenant("alice")
        assert resolver.resolve(key) == "alice"

        second = tenants.add_key("alice")
        assert resolver.resolve(second) == "alice"

        tenants.set_enabled("alice", False)
        assert resolver.resolve(second) is None
    finally:
        resolver.close()


# --- the admin CLI ---------------------------------------------------------


def _cli(capsys, *argv) -> tuple[int, str, str]:
    try:
        gateway_run(list(argv))
        code = 0
    except SystemExit as e:
        code = e.code or 0
    out = capsys.readouterr()
    return code, out.out, out.err


def test_cli_add_prints_a_working_key_once(gw, capsys):
    code, out, _ = _cli(capsys, "tenant", "add", "alice")

    assert code == 0
    key = [ln.split("api key: ")[1] for ln in out.splitlines() if ln.startswith("api key: ")][0]
    tenancy.reset_registry_cache()
    assert tenancy.resolve_key(key.strip()) == "alice"
    assert "not recoverable" in out


def test_cli_list_shows_enabled_state(gw, capsys):
    _cli(capsys, "tenant", "add", "alice", "--note", "a note")
    _cli(capsys, "tenant", "disable", "alice")

    _, out, _ = _cli(capsys, "tenant", "list")

    assert "alice" in out
    assert "disabled" in out
    assert "a note" in out


def test_cli_remove_requires_yes(gw, capsys):
    """Removal destroys signing keys that nothing else holds a copy of."""
    _cli(capsys, "tenant", "add", "alice")

    code, _, err = _cli(capsys, "tenant", "remove", "alice")

    assert code == 1
    assert "--yes" in err
    assert tenants.list_tenants()

    code, _, _ = _cli(capsys, "tenant", "remove", "alice", "--yes")
    assert code == 0
    assert tenants.list_tenants() == []


def test_cli_reports_errors_without_a_traceback(gw, capsys):
    code, _, err = _cli(capsys, "tenant", "add", "anonymous")

    assert code == 1
    assert "reserved" in err
    assert "Traceback" not in err


def test_cli_key_revoke_round_trip(gw, capsys):
    _cli(capsys, "tenant", "add", "alice")
    _cli(capsys, "key", "add", "alice", "--label", "laptop")

    _, out, _ = _cli(capsys, "key", "list", "alice")
    assert out.count("live") == 2

    key_id = out.splitlines()[0].split("\t")[0]
    code, _, _ = _cli(capsys, "key", "revoke", key_id)
    assert code == 0

    _, out, _ = _cli(capsys, "key", "list", "alice")
    assert "revoked" in out
    assert out.count("live") == 1


# --- --dir --------------------------------------------------------------


def test_dir_flag_relocates_state_and_persists(tmp_path, capsys, monkeypatch):
    """--dir sets this run's directory *and* remembers it — a later call with
    neither --dir nor $BONNET_GATEWAY_HOME must resolve to the same place."""
    monkeypatch.delenv("BONNET_GATEWAY_HOME", raising=False)
    monkeypatch.setattr("platformdirs.user_config_dir", lambda *a, **k: str(tmp_path / "cfg"))
    monkeypatch.setattr("platformdirs.user_data_dir", lambda *a, **k: str(tmp_path / "data"))
    chosen = tmp_path / "chosen-gw"
    tenancy.reset_registry_cache()
    tenancy.reset_store_cache()

    code, out, _ = _cli(capsys, "--dir", str(chosen), "tenant", "add", "alice")
    assert code == 0
    assert (chosen / "registry.db").exists()

    tenancy.reset_registry_cache()
    tenancy.reset_store_cache()

    # No --dir this time: resolves via the pointer file the first call wrote.
    code, out, _ = _cli(capsys, "tenant", "list")
    assert code == 0
    assert "alice" in out

    tenancy.reset_registry_cache()
    tenancy.reset_store_cache()
