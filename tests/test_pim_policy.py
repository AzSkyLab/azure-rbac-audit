import csv
import dataclasses
from datetime import datetime, timezone

import pytest
import yaml

from rbac_audit import pim_policy
from rbac_audit.api import RawStore
from rbac_audit.collect import new_run_dir, run_collection
from rbac_audit.config import ConfigError, PimPolicyConfig, parse_config
from conftest import G1, ROOT, SUB, TENANT
from fakes import GOOD_RULES, FakeApi

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
CFG = PimPolicyConfig()

# Effective rules of Owner at a subscription with Azure's default PIM settings (sanitized from a live tenant).
AZURE_DEFAULT = [
    {"id": "Expiration_Admin_Eligibility", "ruleType": "RoleManagementPolicyExpirationRule", "isExpirationRequired": True, "maximumDuration": "P365D"},
    {"id": "Enablement_Admin_Eligibility", "ruleType": "RoleManagementPolicyEnablementRule", "enabledRules": []},
    {"id": "Expiration_Admin_Assignment", "ruleType": "RoleManagementPolicyExpirationRule", "isExpirationRequired": True, "maximumDuration": "P180D"},
    {"id": "Enablement_Admin_Assignment", "ruleType": "RoleManagementPolicyEnablementRule", "enabledRules": ["Justification"]},
    {"id": "Expiration_EndUser_Assignment", "ruleType": "RoleManagementPolicyExpirationRule", "isExpirationRequired": True, "maximumDuration": "PT8H"},
    {"id": "Approval_EndUser_Assignment", "ruleType": "RoleManagementPolicyApprovalRule",
     "setting": {"approvalMode": "SingleStage", "isApprovalRequired": False, "isRequestorJustificationRequired": True}},
    {"id": "Enablement_EndUser_Assignment", "ruleType": "RoleManagementPolicyEnablementRule", "enabledRules": ["Justification"]},
    {"id": "AuthenticationContext_EndUser_Assignment", "ruleType": "RoleManagementPolicyAuthenticationContextRule", "isEnabled": False},
]


@pytest.mark.parametrize("value,hours", [("PT8H", 8), ("P1D", 24), ("PT30M", 0.5), ("P1DT2H", 26), ("", None), ("bogus", None), ("P", None)])
def test_duration_hours(value, hours):
    assert pim_policy.duration_hours(value) == hours


def test_azure_default_policy_lacks_mfa():
    s = pim_policy.settings(AZURE_DEFAULT)
    assert (s["activation_mfa"], s["activation_justification"], s["activation_approval"], s["activation_max_hours"]) == (False, True, False, 8)
    assert [r for r, _ in pim_policy.findings(s, CFG)] == ["activation_mfa_not_required"]


def test_findings_follow_config():
    weak = [{"id": "Enablement_EndUser_Assignment", "enabledRules": []},
            {"id": "Expiration_EndUser_Assignment", "maximumDuration": "PT24H"},
            {"id": "Expiration_Admin_Eligibility", "isExpirationRequired": False},
            {"id": "Expiration_Admin_Assignment", "isExpirationRequired": False}]
    s = pim_policy.settings(weak)
    strict = dataclasses.replace(CFG, require_approval=True)
    assert [r for r, _ in pim_policy.findings(s, strict)] == pim_policy.REASONS
    lax = PimPolicyConfig(require_mfa=False, require_justification=False, max_activation_hours=24,
                          allow_permanent_eligible=True, allow_permanent_active=True)
    assert pim_policy.findings(s, lax) == []


def test_authentication_context_counts_as_mfa():
    rules = [{"id": "Enablement_EndUser_Assignment", "enabledRules": ["Justification"]},
             {"id": "AuthenticationContext_EndUser_Assignment", "isEnabled": True, "claimValue": "c1"}]
    assert pim_policy.settings(rules)["activation_mfa"] is True


def run(cfg, mutate=None, **kw):
    d = new_run_dir(cfg, NOW)
    raw = RawStore(d / "raw")
    api = FakeApi(raw, **kw)
    if mutate:
        mutate(api.entra)
    info = run_collection(cfg, api, raw, d, {"upn": "a@b"}, NOW).info

    def read(name):
        with open(d / name, newline="") as fh:
            return list(csv.DictReader(fh))
    return info, read("pim_policies.csv"), read("exceptions_pim_policy.csv")


def test_well_configured_policies_produce_no_exceptions(cfg):
    info, policies, exc = run(cfg)
    types = {p["target_type"] for p in policies}
    assert types == {"azure_role", "entra_role", "pim_group"} and exc == []
    assert all(p["scope"] != "/" for p in policies if p["target_type"] == "azure_role")   # tenant root is not a PIM scope
    assert {(p["target"], p["role_name"]) for p in policies if p["target_type"] == "pim_group"} >= {("grp-platform-admins", "member"),
                                                                                                      ("grp-platform-admins", "owner")}
    assert info["summary"]["coverage_complete"] is True and info["summary"]["pim_policies_checked"] == len(policies)


def test_weak_azure_and_group_policies_are_reported(cfg):
    def weak(e):
        e["arm_pim_policies"] = {f"/subscriptions/{SUB}/resourcegroups/rg-app": [
            {"properties": {"roleDefinitionId": "/x/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
                            "policyId": "p-contrib", "effectiveRules": AZURE_DEFAULT}}]}
        e["group_pim_policies"] = {G1: [{"roleDefinitionId": "member", "policyId": "gp", "policy": {"rules": [
            *GOOD_RULES[1:], {"id": "Enablement_EndUser_Assignment", "enabledRules": ["MultiFactorAuthentication"]}]}}]}
    info, _, exc = run(cfg, mutate=weak)
    got = {(r["target_type"], r["target"], r["reason"]) for r in exc}
    assert ("azure_role", "Contributor", "activation_mfa_not_required") in got
    assert ("pim_group", "grp-platform-admins", "activation_justification_not_required") in got
    assert info["summary"]["exceptions_pim_policy_by_reason"]["activation_mfa_not_required"] == 1
    assert "exceptions_pim_policy.csv" in info["summary"]["control_mapping"]["AC-6(1)"]


def test_unreadable_group_policies_are_a_gap_with_permission(cfg):
    info, _, _ = run(cfg, graph_errors={"graph_pim_policies_group": 'HTTP 403 x {"errorCode":"PermissionScopeNotGranted",'
                                        '"message":"Authorization failed due to missing permission scope '
                                        'RoleManagementPolicy.Read.AzureADGroup,RoleManagementPolicy.ReadWrite.AzureADGroup."}'})
    s = info["summary"]
    assert s["coverage_complete"] is False and "RoleManagementPolicy.Read.AzureADGroup" in s["missing_graph_permissions"]
    assert any("PIM for Groups policies" in m for m in s["coverage_gaps_by_area"]["pim_policies"])


def test_role_missing_from_policy_list_is_a_gap(cfg):
    info, _, _ = run(cfg, mutate=lambda e: e.update(arm_pim_policies={f"/subscriptions/{SUB}/resourcegroups/rg-app": []}))
    assert any("no PIM policy returned" in m for m in info["summary"]["coverage_gaps_by_area"]["pim_policies"])


def test_disabled_by_config(cfg):
    info, policies, exc = run(dataclasses.replace(cfg, pim_policy=PimPolicyConfig(enabled=False)))
    assert policies == exc == [] and info["summary"]["pim_policies_checked"] == 0


def test_config_parsing():
    raw = yaml.safe_load((ROOT / "config.example.yaml").read_text())
    raw["tenant_id"] = TENANT
    raw["pim_policy"] = {"require_approval": True, "max_activation_hours": 4}
    c = parse_config(raw).pim_policy
    assert c.require_approval and c.max_activation_hours == 4 and c.require_mfa
    for bad, msg in [({"require_mfa": "yes"}, "true or false"), ({"max_activation_hours": 0}, "positive"),
                     ({"typo": True}, "unknown setting")]:
        raw["pim_policy"] = bad
        with pytest.raises(ConfigError, match=msg):
            parse_config(raw)
