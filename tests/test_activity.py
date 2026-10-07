import csv
import dataclasses
from datetime import datetime, timezone

import pytest
import yaml

from rbac_audit import activity
from rbac_audit.api import RawStore
from rbac_audit.collect import new_run_dir, run_collection
from rbac_audit.config import ConfigError, parse_config
from conftest import ROOT, TENANT, U1, U2
from fakes import FakeApi

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
U7 = "0000000a-0000-0000-0000-000000000007"
RECENT = {"signInActivity": {"lastSignInDateTime": "2025-12-30T00:00:00Z"}}


def run(cfg, **kw):
    d = new_run_dir(cfg, NOW)
    raw = RawStore(d / "raw")
    info = run_collection(cfg, FakeApi(raw, **kw), raw, d, {"upn": "a@b"}, NOW).info
    with open(d / "inactive_privileged_accounts.csv", newline="") as fh:
        return info, list(csv.DictReader(fh))


def reasons(rows):
    return {(r["principal_id"], r["reason"]) for r in rows}


def test_privileged_users_collects_every_access_path():
    rows = [{"principal_type": "User", "principal_id": U1, "privilege_tier": "privileged_admin", "role_name": "Owner",
             "pim_label": "permanent_active", "scope": "/subscriptions/s"},
            {"principal_type": "User", "principal_id": U2, "privilege_tier": "standard", "role_name": "Reader",
             "pim_label": "permanent_active", "scope": "/"},
            {"principal_type": "ServicePrincipal", "principal_id": "sp", "privilege_tier": "privileged_admin",
             "role_name": "Owner", "pim_label": "permanent_active", "scope": "/"}]
    entra = [{"principal_type": "Guest user", "principal_id": U2, "role_name": "Global Administrator", "pim_label": "eligible"}]
    members = [{"member_type": "User", "member_id": U1.upper(), "label": "eligible_member", "privileged_group_name": "g"}]
    got = activity.privileged_users(rows, entra, members)
    assert got == {U1: ["Azure Owner (permanent_active) at /subscriptions/s", "eligible_member of g"],
                   U2: ["Entra Global Administrator (eligible)"]}       # Reader and service principals excluded


@pytest.mark.parametrize("user,known,expected", [
    ({"accountEnabled": False, **RECENT}, True, {"disabled"}),
    ({"userType": "Guest", "externalUserState": "PendingAcceptance", **RECENT}, True, {"guest_invitation_pending"}),
    ({}, True, {"never_signed_in"}),                           # no creation date and no sign-in: treated as old
    ({"createdDateTime": "2025-01-01T00:00:00Z"}, True, {"never_signed_in"}),
    ({"createdDateTime": "2025-12-20T00:00:00Z"}, True, set()),                       # new account: grace period
    ({"signInActivity": {"lastSignInDateTime": "2025-06-01T00:00:00Z"}}, True, {"inactive"}),
    ({"signInActivity": {"lastSignInDateTime": "2025-06-01T00:00:00Z",                 # recent non-interactive sign-in
                         "lastNonInteractiveSignInDateTime": "2025-12-30T00:00:00Z"}}, True, set()),
    ({"createdDateTime": "2025-01-01T00:00:00Z"}, False, set()),                      # activity unknown: not judged
    ({"accountEnabled": False, "signInActivity": {"lastSignInDateTime": "2024-01-01T00:00:00Z"}}, True,
     {"disabled", "inactive"}),
])
def test_evaluate_reasons(user, known, expected):
    rows = activity.evaluate({U1: {"accountEnabled": True, **user}}, {U1: ["Azure Owner"]}, NOW, 90, known)
    assert {r["reason"] for r in rows} == expected
    assert all(r["privileged_access"] == "Azure Owner" for r in rows)


def test_end_to_end_flags_privileged_users(cfg):
    info, rows = run(cfg, users={
        U1: {"accountEnabled": False, "signInActivity": {"lastSignInDateTime": "2025-12-30T00:00:00Z"}},
        U7: {"signInActivity": {"lastSignInDateTime": "2025-03-01T00:00:00Z"}},        # nested group member
    })
    got = reasons(rows)
    assert (U1, "disabled") in got and (U7, "inactive") in got
    assert (U1, "inactive") not in got
    u7 = next(r for r in rows if r["principal_id"] == U7)
    assert "of grp-platform-admins" in u7["privileged_access"] and u7["days_since_sign_in"] == "307"
    s = info["summary"]
    assert s["inactive_privileged_by_reason"]["disabled"] >= 1 and "inactive_privileged_accounts.csv" in s["control_mapping"]["AC-2(3)"]


def test_without_audit_log_permission_is_a_gap_but_disabled_still_flagged(cfg):
    info, rows = run(cfg, sign_in_forbidden=True, users={U1: {"accountEnabled": False}})
    assert reasons(rows) == {(U1, "disabled")}                                      # no inactivity judgement
    s = info["summary"]
    assert s["coverage_complete"] is False and "AuditLog.Read.All" in s["missing_graph_permissions"]
    assert any("sign-in activity unreadable" in m for m in s["coverage_gaps_by_area"]["sign_in_activity"])


def test_disabled_by_config(cfg):
    info, rows = run(dataclasses.replace(cfg, inactive_account_days=0), sign_in_forbidden=True)
    assert rows == [] and info["summary"]["coverage_complete"] is True


def test_config_validation():
    raw = yaml.safe_load((ROOT / "config.example.yaml").read_text())
    raw["tenant_id"] = TENANT
    assert parse_config(raw).inactive_account_days == 90
    for bad in (-1, "30", True):
        raw["inactive_account_days"] = bad
        with pytest.raises(ConfigError, match="inactive_account_days"):
            parse_config(raw)
