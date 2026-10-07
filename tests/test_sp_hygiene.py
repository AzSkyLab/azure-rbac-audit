import csv
import dataclasses
from datetime import datetime, timezone

import pytest
import yaml

from rbac_audit import sp_hygiene
from rbac_audit.api import RawStore
from rbac_audit.collect import new_run_dir, run_collection
from rbac_audit.config import AllowEntry, ConfigError, ServicePrincipalConfig, parse_config
from conftest import ROOT, TENANT
from fakes import FakeApi

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
SP1, MI1 = "0000000c-0000-0000-0000-000000000001", "0000000c-0000-0000-0000-000000000002"
APP1 = "99999999-9999-9999-9999-999999999991"


def cred(start, end, name="c"):
    return {"displayName": name, "startDateTime": start, "endDateTime": end}


@pytest.mark.parametrize("creds,expected", [
    ([("application", "secret", cred("2025-12-01T00:00:00Z", "2026-05-01T00:00:00Z"))], []),             # 151 days: fine
    ([("service principal", "secret", cred("2023-01-26T18:17:33Z", "2123-01-26T18:17:33Z"))], ["secret_lifetime_too_long"]),
    ([("application", "certificate", cred("2025-01-01T00:00:00Z", "2030-01-01T00:00:00Z"))], []),        # long certs allowed
    ([("application", "certificate", cred("2025-09-08T00:00:00Z", "2025-09-15T00:00:00Z"))], ["credential_expired"]),
    ([("application", "secret", cred("2025-12-01T00:00:00Z", "2026-01-20T00:00:00Z"))], ["credential_expiring"]),
])
def test_credential_findings(creds, expected):
    assert [r for r, _ in sp_hygiene.credential_findings(creds, NOW, 180, 30)] == expected


def run(cfg, **kw):
    d = new_run_dir(cfg, NOW)
    raw = RawStore(d / "raw")
    api = FakeApi(raw, **{k: v for k, v in kw.items() if k != "mutate"})
    if kw.get("mutate"):
        kw["mutate"](api.entra)
    info = run_collection(cfg, api, raw, d, {"upn": "a@b"}, NOW).info

    def read(name):
        with open(d / name, newline="") as fh:
            return list(csv.DictReader(fh))
    return info, read("privileged_service_principals.csv"), read("exceptions_service_principal.csv")


def test_inventory_covers_direct_roles_and_group_membership(cfg):
    info, inv, exc = run(cfg)
    by = {r["principal_id"]: r for r in inv}
    assert set(by) == {SP1, MI1} and exc == [] and info["summary"]["coverage_complete"] is True
    assert "permanent_member of grp-platform-admins" in by[MI1]["privileged_access"]
    assert by[SP1]["external"] == "False" and by[SP1]["last_sign_in"].startswith("2026-01-01")


def test_findings_for_a_risky_service_principal(cfg):
    info, inv, exc = run(cfg,
                         sps={SP1: {"appOwnerOrganizationId": "bbbbbbbb-0000-0000-0000-000000000000",
                                    "passwordCredentials": [cred("2023-01-26T00:00:00Z", "2123-01-26T00:00:00Z", "forever")]}},
                         owners={(SP1, "sp"): [{"id": "u", "userPrincipalName": "dev@contoso.example"}]},
                         mutate=lambda e: e.update(sp_sign_ins=[]))
    got = {(r["principal_id"], r["reason"]) for r in exc}
    assert got == {(SP1, "external_app"), (SP1, "secret_lifetime_too_long"), (SP1, "has_owners"),
                   (SP1, "never_signed_in"), (MI1, "never_signed_in")}          # managed identity: inactivity only
    detail = next(r["detail"] for r in exc if r["reason"] == "has_owners")
    assert "dev@contoso.example" in detail
    assert info["summary"]["exceptions_service_principal_by_reason"]["external_app"] == 1


def test_application_credentials_and_owners_are_checked_for_own_apps(cfg):
    _, inv, exc = run(cfg, apps={SP1: {"keyCredentials": [cred("2025-09-08T00:00:00Z", "2025-09-15T00:00:00Z", "old cert")]}},
                      owners={(SP1, "app"): [{"id": "u2", "displayName": "App Owner"}]})
    reasons = {r["reason"]: r["detail"] for r in exc if r["principal_id"] == SP1}
    assert "on the application" in reasons["credential_expired"] and "App Owner" in reasons["has_owners"]
    assert next(r for r in inv if r["principal_id"] == SP1)["certificates"] == "1"


def test_inactive_service_principal(cfg):
    _, _, exc = run(cfg, mutate=lambda e: e.update(sp_sign_ins=[
        {"appId": APP1, "lastSignInActivity": {"lastSignInDateTime": "2025-06-01T00:00:00Z"}}]))
    assert {(r["principal_id"], r["reason"]) for r in exc} == {(SP1, "inactive"), (MI1, "never_signed_in")}


def test_unreadable_sign_in_report_is_a_gap(cfg):
    info, _, exc = run(cfg, graph_errors={"graph_sp_sign_in_activity": "HTTP 403 Forbidden"})
    assert exc == [] and info["summary"]["coverage_complete"] is False
    assert any("sign-in activity unreadable" in m for m in info["summary"]["coverage_gaps_by_area"]["service_principals"])


def test_allowlist_applies_to_service_principal_findings(cfg):
    cfg = dataclasses.replace(cfg, exception_allowlist=(AllowEntry(SP1, "vendor app, reviewed quarterly"),))
    info, _, exc = run(cfg, sps={SP1: {"appOwnerOrganizationId": "bbbbbbbb-0000-0000-0000-000000000000"}})
    assert exc == [] and info["summary"]["exceptions_allowlisted"] >= 1


def test_disabled_and_config_validation(cfg):
    info, inv, exc = run(dataclasses.replace(cfg, service_principals=ServicePrincipalConfig(enabled=False)))
    assert inv == exc == [] and info["summary"]["privileged_service_principals"] == 0
    raw = yaml.safe_load((ROOT / "config.example.yaml").read_text())
    raw["tenant_id"] = TENANT
    raw["service_principals"] = {"max_secret_days": 90, "flag_owners": False}
    c = parse_config(raw).service_principals
    assert (c.max_secret_days, c.flag_owners, c.expiry_warning_days) == (90, False, 30)
    for bad in ({"max_secret_days": 0}, {"flag_owners": "no"}, {"oops": 1}):
        raw["service_principals"] = bad
        with pytest.raises(ConfigError, match="service_principals"):
            parse_config(raw)


def test_microsoft_first_party_is_not_flagged_external_or_inactive(cfg):
    _, inv, exc = run(cfg, sps={SP1: {"appOwnerOrganizationId": "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
                                      "passwordCredentials": [cred("2023-01-01T00:00:00Z", "2123-01-01T00:00:00Z")]}},
                      mutate=lambda e: e.update(sp_sign_ins=[]))
    assert {(r["principal_id"], r["reason"]) for r in exc} == {(SP1, "secret_lifetime_too_long"), (MI1, "never_signed_in")}
    assert next(r for r in inv if r["principal_id"] == SP1)["microsoft_first_party"] == "True"
