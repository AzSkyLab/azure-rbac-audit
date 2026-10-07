import base64
import json
import os
import stat

import pytest
import yaml

from rbac_audit import auth
from rbac_audit.cli import summarize
from rbac_audit.collect import RunResult, _base_info
from rbac_audit.config import AuthConfig, ConfigError, parse_config
from conftest import ROOT, TENANT

CLIENT = "12345678-1234-1234-1234-1234567890ab"


def jwt(claims):
    enc = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")  # noqa: E731
    return f"{enc({'alg': 'none'})}.{enc(claims)}.sig"


class FakeCred:
    def __init__(self, arm, graph):
        self.tokens = {auth.ARM_SCOPE: arm, auth.GRAPH_SCOPE: graph}

    def get_token(self, scope):
        return type("T", (), {"token": jwt(self.tokens[scope]), "expires_on": 9e12})()


def cfg_raw(**auth_block):
    raw = yaml.safe_load((ROOT / "config.example.yaml").read_text())
    raw["tenant_id"] = TENANT
    if auth_block:
        raw["auth"] = auth_block
    return raw


# ---- config -------------------------------------------------------------------------------------------------
def test_auth_defaults_to_cli():
    assert parse_config(cfg_raw()).auth == AuthConfig("cli", "", "")


def test_certificate_mode_parses_and_lowercases_client_id():
    c = parse_config(cfg_raw(mode="certificate", client_id=CLIENT.upper(), certificate_path="~/x.pem"))
    assert c.auth == AuthConfig("certificate", CLIENT, "~/x.pem") and c.public_dict()["auth"]["mode"] == "certificate"


@pytest.mark.parametrize("block", [
    {"mode": "password"},
    {"mode": "certificate", "client_id": "not-a-guid", "certificate_path": "x.pem"},
    {"mode": "certificate", "client_id": "00000000-0000-0000-0000-000000000000", "certificate_path": "x.pem"},
    {"mode": "certificate", "certificate_path": "x.pem"},
    {"mode": "certificate", "client_id": CLIENT},
])
def test_bad_auth_config_rejected(block):
    with pytest.raises(ConfigError):
        parse_config(cfg_raw(**block))


def test_cli_mode_ignores_missing_client_id():
    assert parse_config(cfg_raw(mode="cli")).auth.mode == "cli"


# ---- credential ---------------------------------------------------------------------------------------------
@pytest.fixture
def fake_cert_cred(monkeypatch):
    seen = {}

    class Fake:
        def __init__(self, **kw):
            seen.update(kw)
    monkeypatch.setattr(auth, "CertificateCredential", Fake)
    return seen


def pem(tmp_path, mode):
    p = tmp_path / "k.pem"
    p.write_text("-----BEGIN PRIVATE KEY-----\n")
    os.chmod(p, mode)
    return p


def test_certificate_credential_built_with_tenant_client_and_path(tmp_path, fake_cert_cred):
    p = pem(tmp_path, 0o600)
    cred, warnings = auth.build_credential(AuthConfig("certificate", CLIENT, str(p)), TENANT)
    assert fake_cert_cred == {"tenant_id": TENANT, "client_id": CLIENT, "certificate_path": str(p)} and warnings == []


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o660, 0o700])
def test_wide_key_file_mode_warns(tmp_path, fake_cert_cred, mode):
    _, warnings = auth.build_credential(AuthConfig("certificate", CLIENT, str(pem(tmp_path, mode))), TENANT)
    assert len(warnings) == 1 and "chmod 600" in warnings[0] and f"{mode:o}" in warnings[0]


def test_owner_read_only_mode_is_fine(tmp_path, fake_cert_cred):
    assert auth.build_credential(AuthConfig("certificate", CLIENT, str(pem(tmp_path, 0o400))), TENANT)[1] == []


def test_missing_certificate_file_is_a_config_error(tmp_path, fake_cert_cred):
    with pytest.raises(ConfigError, match="does not exist"):
        auth.build_credential(AuthConfig("certificate", CLIENT, str(tmp_path / "nope.pem")), TENANT)


def test_tilde_in_certificate_path_is_expanded(tmp_path, monkeypatch, fake_cert_cred):
    monkeypatch.setenv("HOME", str(tmp_path))
    pem(tmp_path, 0o600)
    auth.build_credential(AuthConfig("certificate", CLIENT, "~/k.pem"), TENANT)
    assert fake_cert_cred["certificate_path"] == str(tmp_path / "k.pem")


def test_cli_mode_uses_existing_az_login(monkeypatch):
    monkeypatch.setattr(auth, "get_credential", lambda: "cli-cred")
    assert auth.build_credential(AuthConfig(), TENANT) == ("cli-cred", [])


# ---- identity / read-only flag -------------------------------------------------------------------------------
APP_ARM = {"tid": TENANT, "oid": "o1", "appid": CLIENT, "idtyp": "app"}


def test_app_identity_with_read_only_roles():
    graph = {"roles": ["Directory.Read.All", "RoleManagement.Read.Directory", "PrivilegedAccess.Read.AzureADGroup", "AccessReview.Read.All"]}
    ident = auth.describe_identity(FakeCred(APP_ARM, graph))
    assert ident["identity_type"] == "app" and ident["app_id"] == CLIENT and ident["read_only"] is True
    assert ident["graph_token"]["roles"] == sorted(graph["roles"]) and ident["graph_token"]["scp"] == []


@pytest.mark.parametrize("graph", [
    {"roles": ["Directory.Read.All", "Directory.ReadWrite.All"]},
    {"scp": "User.Read.All Application.ReadWrite.All"},
    {"roles": ["Group.Write.All"]},
])
def test_any_write_role_or_scope_makes_identity_not_read_only(graph):
    assert auth.describe_identity(FakeCred(APP_ARM, graph))["read_only"] is False


def test_delegated_cli_identity_reports_scopes():
    ident = auth.describe_identity(FakeCred({"tid": TENANT, "upn": "u@x", "appid": "04b07795"}, {"scp": "User.Read.All Directory.AccessAsUser.All"}))
    assert ident["upn"] == "u@x" and ident["graph_token"]["scp"] == ["Directory.AccessAsUser.All", "User.Read.All"] and ident["read_only"] is True


# ---- manifest + CLI warning -----------------------------------------------------------------------------------
def info_for(cfg, **identity):
    from datetime import datetime, timezone
    from rbac_audit.api import RawStore
    raw = RawStore(cfg.output_dir / "raw")
    info = _base_info(cfg, identity, datetime(2026, 1, 1, tzinfo=timezone.utc), raw, "complete")
    info.update(summary={"coverage_complete": True, "coverage_gaps_by_area": {}, "missing_graph_permissions": []}, warnings=[])
    return info


def test_manifest_records_identity_and_read_only_flag(cfg):
    info = info_for(cfg, identity_type="app", app_id=CLIENT, graph_token={"roles": ["Directory.Read.All"], "scp": []}, read_only=True)
    assert info["collector_identity_read_only"] is True and "read_only" not in info["signed_in_identity"]
    assert info["signed_in_identity"]["app_id"] == CLIENT and info["signed_in_identity"]["graph_token"]["roles"] == ["Directory.Read.All"]
    assert "collector_identity_read_only" not in info_for(cfg, upn="x")      # unknown -> not asserted


def test_cli_warns_when_collector_identity_is_not_read_only(cfg, tmp_path):
    info = info_for(cfg, graph_token={"roles": ["Directory.ReadWrite.All"], "scp": ["Application.ReadWrite.All", "User.Read.All"]}, read_only=False,
                    auth_warnings=["certificate file /k.pem has mode 644; it holds a private key, chmod 600 it"])
    out, err = summarize(RunResult(tmp_path, info, "0" * 64))
    ro = [e for e in err if "NOT read-only" in e]
    assert len(ro) == 1 and "Directory.ReadWrite.All" in ro[0] and "Application.ReadWrite.All" in ro[0] and "User.Read.All" not in ro[0]
    assert any("chmod 600" in e for e in err)


def test_cli_no_read_only_warning_when_read_only(cfg, tmp_path):
    info = info_for(cfg, graph_token={"roles": ["Directory.Read.All"], "scp": []}, read_only=True)
    assert not any("read-only" in e for e in summarize(RunResult(tmp_path, info, "0" * 64))[1])


def test_managed_identity_mode(monkeypatch):
    cfg = parse_config(cfg_raw(mode="managed_identity", client_id=CLIENT.upper()))
    assert cfg.auth.mode == "managed_identity" and cfg.auth.client_id == CLIENT
    seen = {}
    monkeypatch.setattr(auth, "ManagedIdentityCredential", lambda **kw: seen.update(kw) or "mi")
    assert auth.build_credential(cfg.auth, TENANT) == ("mi", [])
    assert seen == {"client_id": CLIENT}
    system = parse_config(cfg_raw(mode="managed_identity"))       # no client_id: system-assigned identity
    auth.build_credential(system.auth, TENANT)
    assert seen == {"client_id": None}


def test_managed_identity_rejects_bad_client_id():
    with pytest.raises(ConfigError, match="managed identity"):
        parse_config(cfg_raw(mode="managed_identity", client_id="not-a-guid"))
