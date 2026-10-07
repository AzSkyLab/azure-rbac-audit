"""PIM policy settings (AC-6 / AC-6(1)): is activation of privileged access actually gated?

For every privileged Azure role at a scope where it is assigned, every privileged Entra directory role that has a
holder, and the member / owner roles of every PIM-managed privileged group, read the effective PIM policy and check
activation (MFA or an authentication context, justification, approval, maximum duration) and whether permanent
eligible / active assignments are allowed. Azure policies come from ARM (roleManagementPolicyAssignments, which return
effectiveRules); Entra and group policies from Graph. ARM and Graph use the same rule ids.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .roles import STANDARD
from .scope import guid_of

ARM_API = "2020-10-01"
GRAPH_POLICIES = "/v1.0/policies/roleManagementPolicyAssignments"
PERM_DIRECTORY = "RoleManagementPolicy.Read.Directory (or RoleManagement.Read.Directory)"
PERM_GROUP = "RoleManagementPolicy.Read.AzureADGroup"
POLICY_COLUMNS = ["target_type", "target", "role_name", "scope", "activation_mfa", "activation_justification",
                  "activation_approval", "activation_max_hours", "eligible_expiration_required", "eligible_max_duration",
                  "active_expiration_required", "active_max_duration", "policy_id"]
EXCEPTION_COLUMNS = ["target_type", "target", "role_name", "scope", "reason", "detail", "policy_id"]
REASONS = ["activation_mfa_not_required", "activation_justification_not_required", "activation_approval_not_required",
           "activation_too_long", "permanent_eligibility_allowed", "permanent_active_assignment_allowed"]

_DURATION = re.compile(r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?)?$")


def duration_hours(value: str | None) -> float | None:
    m = _DURATION.match(value or "")
    if not m or not any(m.groups()):
        return None
    d, h, mins = (int(x or 0) for x in m.groups())
    return d * 24 + h + mins / 60


def settings(rules: list[dict]) -> dict:
    """The relevant settings of a policy, from its rules (ARM effectiveRules or Graph rules)."""
    by = {r.get("id"): r for r in rules}
    enable = set((by.get("Enablement_EndUser_Assignment") or {}).get("enabledRules") or [])
    auth_ctx = bool((by.get("AuthenticationContext_EndUser_Assignment") or {}).get("isEnabled"))
    approval = ((by.get("Approval_EndUser_Assignment") or {}).get("setting") or {}).get("isApprovalRequired")
    act, elig, active = (by.get(k) or {} for k in ("Expiration_EndUser_Assignment", "Expiration_Admin_Eligibility",
                                                   "Expiration_Admin_Assignment"))
    return {
        "activation_mfa": "MultiFactorAuthentication" in enable or auth_ctx,
        "activation_justification": "Justification" in enable,
        "activation_approval": bool(approval),
        "activation_max_hours": duration_hours(act.get("maximumDuration")),
        "eligible_expiration_required": elig.get("isExpirationRequired"),
        "eligible_max_duration": elig.get("maximumDuration", ""),
        "active_expiration_required": active.get("isExpirationRequired"),
        "active_max_duration": active.get("maximumDuration", ""),
    }


def findings(s: dict, cfg) -> list[tuple[str, str]]:
    out = []
    if cfg.require_mfa and not s["activation_mfa"]:
        out.append(("activation_mfa_not_required", "activation requires neither MFA nor an authentication context"))
    if cfg.require_justification and not s["activation_justification"]:
        out.append(("activation_justification_not_required", "activation does not require a justification"))
    if cfg.require_approval and not s["activation_approval"]:
        out.append(("activation_approval_not_required", "activation does not require approval"))
    if s["activation_max_hours"] is not None and s["activation_max_hours"] > cfg.max_activation_hours:
        out.append(("activation_too_long", f"activation lasts up to {s['activation_max_hours']:g} h "
                                           f"(limit {cfg.max_activation_hours} h)"))
    if not cfg.allow_permanent_eligible and s["eligible_expiration_required"] is False:
        out.append(("permanent_eligibility_allowed", "eligible assignments may be permanent"))
    if not cfg.allow_permanent_active and s["active_expiration_required"] is False:
        out.append(("permanent_active_assignment_allowed", "active assignments may be permanent"))
    return out


@dataclass
class PolicyResult:
    policies: list[dict] = field(default_factory=list)
    exceptions: list[dict] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    missing_permissions: set[str] = field(default_factory=set)

    def add(self, cfg, target_type: str, target: str, role: str, scope: str, policy_id: str, rules: list[dict]) -> None:
        s = settings(rules)
        base = {"target_type": target_type, "target": target, "role_name": role, "scope": scope, "policy_id": policy_id}
        self.policies.append({**base, **{k: ("" if v is None else v) for k, v in s.items()}})
        self.exceptions += [{**base, "reason": r, "detail": d} for r, d in findings(s, cfg)]


def _missing(err: str) -> bool:
    return "403" in err[:12] or "PermissionScopeNotGranted" in err or "Authorization_RequestDenied" in err


def check_policies(api, cfg, rows: list[dict], entra_rows: list[dict], groups: list[dict]) -> PolicyResult:
    """`rows`: the Azure inventory; `entra_rows`: privileged Entra role rows; `groups`: privileged_groups.csv rows."""
    res = PolicyResult()
    # Azure: the policy that governs an assignment is the one for its role at its own scope. The tenant root "/" is
    # not a PIM scope.
    wanted: dict[str, dict[str, str]] = {}
    for r in rows:
        if r["privilege_tier"] != STANDARD and r["scope"] not in ("", "/"):
            wanted.setdefault(r["scope"], {})[guid_of(r["role_definition_id"])] = r["role_name"]
    scopes = sorted(wanted)
    listed = api.parallel(lambda s: api.arm_list(
        "arm_pim_policy_assignments", f"{s.rstrip('/')}/providers/Microsoft.Authorization/roleManagementPolicyAssignments?api-version={ARM_API}"),
        scopes)
    for scope, (items, err) in zip(scopes, listed):
        if err:
            res.gaps.append(f"PIM policies unreadable at {scope} ({err[:200]}); needs Reader at the scope")
            continue
        found = {}
        for a in items or []:
            p = a.get("properties") or {}
            found[guid_of(p.get("roleDefinitionId") or "")] = p
        for guid, role in sorted(wanted[scope].items(), key=lambda kv: kv[1]):
            p = found.get(guid)
            if p is None:
                res.gaps.append(f"no PIM policy returned for {role} at {scope}")
                continue
            res.add(cfg, "azure_role", role, role, scope, p.get("policyId", ""), p.get("effectiveRules") or [])

    # Entra directory roles that have a privileged holder (definition found, so isPrivileged).
    entra = {r["role_definition_id"].lower(): r["role_name"] for r in entra_rows if r.get("role_privileged") == "True"}
    if entra:
        items, err = api.graph_list("graph_pim_policies_directory", f"{GRAPH_POLICIES}?$filter=scopeId eq '/' and "
                                    "scopeType eq 'DirectoryRole'&$expand=policy($expand=rules)")
        if err:
            res.gaps.append(f"Entra role PIM policies unreadable ({err[:200]}); needs {PERM_DIRECTORY}")
            if _missing(err):
                res.missing_permissions.add(PERM_DIRECTORY)
        else:
            by_role = {(a.get("roleDefinitionId") or "").lower(): a for a in items}
            for rid, role in sorted(entra.items(), key=lambda kv: kv[1]):
                a = by_role.get(rid)
                if a is None:
                    res.gaps.append(f"no PIM policy returned for Entra role {role}")
                    continue
                res.add(cfg, "entra_role", role, role, "/", a.get("policyId", ""), (a.get("policy") or {}).get("rules") or [])

    # PIM-managed privileged groups: the member and owner policies.
    pim_groups = [g for g in groups if str(g.get("pim_managed")) == "True"]
    results = api.parallel(lambda g: api.graph_list(
        "graph_pim_policies_group", f"{GRAPH_POLICIES}?$filter=scopeId eq '{g['group_id']}' and scopeType eq 'Group'"
                                    "&$expand=policy($expand=rules)"), pim_groups)
    for g, (items, err) in zip(pim_groups, results):
        if err:
            res.gaps.append(f"PIM for Groups policies of {g['group_name'] or g['group_id']} unreadable ({err[:200]}); "
                            f"needs {PERM_GROUP}")
            if _missing(err):
                res.missing_permissions.add(PERM_GROUP)
            continue
        for a in sorted(items, key=lambda a: a.get("roleDefinitionId") or ""):
            access = a.get("roleDefinitionId") or ""
            res.add(cfg, "pim_group", g["group_name"] or g["group_id"], access, g["group_id"], a.get("policyId", ""),
                    (a.get("policy") or {}).get("rules") or [])
    return res
