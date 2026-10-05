"""Phase 2a: which groups are privileged, and why (Azure roles, Entra directory roles, PIM for Groups)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .roles import STANDARD

# Graph permissions each feature needs, named in coverage gaps so a missing grant is actionable. With
# auth.mode=certificate these are *application* permissions on the app registration (admin consent):
# Directory.Read.All, RoleManagement.Read.Directory, PrivilegedAccess.Read.AzureADGroup, AccessReview.Read.All,
# plus Azure Reader at the tenant root management group. With auth.mode=cli they are delegated scopes.
PERM_DIRECTORY_ROLES = "RoleManagement.Read.Directory"
PERM_DIRECTORY_ELIGIBLE = "RoleEligibilitySchedule.Read.Directory (or RoleManagement.Read.Directory)"
PERM_GROUP_ELIGIBLE = "PrivilegedEligibilitySchedule.Read.AzureADGroup"
PERM_GROUP_ASSIGNMENT = "PrivilegedAssignmentSchedule.Read.AzureADGroup"
PERM_ACCESS_REVIEWS = "AccessReview.Read.All"
PERM_GROUP_MEMBERS = "Directory.Read.All (or GroupMember.Read.All)"

AZURE, ENTRA, PIM_GROUP = "azure_privileged_role", "entra_privileged_role", "pim_for_groups"
_MISSING = re.compile(r"missing permission scope ([A-Za-z0-9_.,]+)")


def missing_permissions(error: str) -> list[str]:
    """Read-only permission names Graph says would satisfy the call (any one suffices). ReadWrite variants are
    dropped on purpose: this tool never writes, so it must never be recommended write access."""
    m = _MISSING.search(error or "")
    names = [p.strip(".") for p in m.group(1).split(",") if p.strip(".")] if m else []
    return [n for n in names if "ReadWrite" not in n]


@dataclass
class PrivilegedGroup:
    id: str
    name: str = ""
    reasons: list[tuple[str, str]] = field(default_factory=list)  # (code, human text)

    def add(self, code: str, text: str) -> None:
        if (code, text) not in self.reasons:
            self.reasons.append((code, text))


def azure_role_reasons(rows: list[dict]) -> dict[str, list[tuple[str, str]]]:
    """Groups holding (active or eligible) a non-standard-tier Azure role, from the phase 1 inventory."""
    out: dict[str, list[tuple[str, str]]] = {}
    for r in rows:
        if r["principal_type"] == "Group" and r["privilege_tier"] != STANDARD:
            text = f"Azure role '{r['role_name']}' ({r['privilege_tier']}, {r['pim_label']}) at {r['scope_level']} {r['scope']}"
            out.setdefault(r["principal_id"].lower(), []).append((AZURE, text))
    return out


def privileged_role_ids(role_defs: list[dict]) -> dict[str, str]:
    """roleDefinition id -> displayName for Entra roles flagged isPrivileged (beta property)."""
    return {d["id"].lower(): d.get("displayName", d["id"]) for d in role_defs if d.get("isPrivileged")}


def directory_role_principals(active: list[dict], eligible: list[dict], privileged: dict[str, str]):
    """Yield (principalId, state, role name, directoryScopeId) for privileged Entra role holders."""
    for state, items in (("active", active), ("eligible", eligible)):
        for a in items:
            role = privileged.get((a.get("roleDefinitionId") or "").lower())
            if role:
                yield a["principalId"].lower(), state, role, a.get("directoryScopeId") or "/"


def build_privileged_groups(azure: dict[str, list[tuple[str, str]]], entra: dict[str, list[tuple[str, str]]],
                            names: dict[str, str]) -> dict[str, PrivilegedGroup]:
    groups: dict[str, PrivilegedGroup] = {}
    for source in (azure, entra):
        for gid, reasons in source.items():
            g = groups.setdefault(gid, PrivilegedGroup(gid, names.get(gid, "")))
            for code, text in reasons:
                g.add(code, text)
    return groups
