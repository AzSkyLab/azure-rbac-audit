"""Pure assembly of the assignment inventory from collected data."""
from __future__ import annotations

from .config import Config
from .controls import direct_user_result
from .pim import ELIGIBLE, UNVERIFIED, ActiveIndex, label_active
from .principals import Principal
from .roles import RoleDef, classify_tier, severity
from .scope import guid_of, resource_group, scope_level, subscription_id

COLUMNS = [
    "assignment_id", "source", "scope", "scope_level", "subscription_id", "resource_group",
    "role_name", "role_type", "role_definition_id", "privilege_tier", "tier_reason", "severity",
    "principal_id", "principal_type", "principal_name", "principal_upn_or_appid", "principal_resolution",
    "pim_label", "start", "end", "created_on", "has_condition", "direct_user_result",
]


def principal_hints(assignments: list[dict], eligible: list[dict]) -> dict[str, str | None]:
    hints: dict[str, str | None] = {}
    for a in assignments:
        p = a["properties"]
        hints.setdefault(p["principalId"].lower(), p.get("principalType"))
    for e in eligible:
        p = e["properties"]
        hints.setdefault(p["principalId"].lower(), p.get("principalType"))
    return hints


def _row(*, assignment_id, source, scope, role_def_id, principal_id, roles, principals, cfg,
         pim_label, start, end, created_on, has_condition) -> dict:
    role = roles.get(guid_of(role_def_id))
    level = scope_level(scope)
    tier, reason = classify_tier(role, cfg)
    pr = principals.get(principal_id.lower()) or Principal(principal_id, "Unknown", resolution="unresolved")
    return {
        "assignment_id": assignment_id, "source": source, "scope": scope, "scope_level": level,
        "subscription_id": subscription_id(scope), "resource_group": resource_group(scope),
        "role_name": role.name if role and role.name else guid_of(role_def_id),
        "role_type": role.role_type if role else "", "role_definition_id": role_def_id,
        "privilege_tier": tier, "tier_reason": reason, "severity": severity(tier, level),
        "principal_id": principal_id, "principal_type": pr.type, "principal_name": pr.name,
        "principal_upn_or_appid": pr.upn_or_appid, "principal_resolution": pr.resolution,
        "pim_label": pim_label, "start": start or "", "end": end or "", "created_on": created_on or "",
        "has_condition": has_condition, "direct_user_result": direct_user_result(pr.type, pr.resolution),
    }


def build_inventory(cfg: Config, assignments: list[dict], roles: dict[str, RoleDef], active: list[dict],
                    eligible: list[dict], principals: dict[str, Principal],
                    pim_failed_scopes: set[str]) -> tuple[list[dict], list[str]]:
    """Returns (rows, warnings). `active`/`eligible` are PIM schedule instances, already de-duplicated."""
    index = ActiveIndex(active)
    failed = {s.lower().rstrip("/") for s in pim_failed_scopes}
    rows: list[dict] = []
    matched: set[int] = set()
    for a in assignments:
        p = a["properties"]
        matches = index.match(a["id"], p["principalId"], p["roleDefinitionId"], p["scope"])
        matched.update(id(m) for m in matches)
        if matches:
            label, start, end = label_active(matches)
        elif p["scope"].lower().rstrip("/") in failed:
            label, start, end = UNVERIFIED, None, None
        else:
            label, start, end = label_active([])
        rows.append(_row(assignment_id=a["id"], source="resource_graph", scope=p["scope"],
                         role_def_id=p["roleDefinitionId"], principal_id=p["principalId"], roles=roles,
                         principals=principals, cfg=cfg, pim_label=label, start=start or p.get("createdOn"),
                         end=end, created_on=p.get("createdOn"), has_condition=bool(p.get("condition"))))
    for e in eligible:
        p = e["properties"]
        rows.append(_row(assignment_id=p.get("roleEligibilityScheduleId") or e["id"], source="eligibility_schedule",
                         scope=p["scope"], role_def_id=p["roleDefinitionId"], principal_id=p["principalId"],
                         roles=roles, principals=principals, cfg=cfg, pim_label=ELIGIBLE,
                         start=p.get("startDateTime"), end=p.get("endDateTime"), created_on=p.get("createdOn"),
                         has_condition=bool(p.get("condition"))))
    warnings = []
    unmatched = [i for i in active if id(i["properties"]) not in matched]
    # Active instances with no ARG row (e.g. assignment outside the collected scope) are not inventoried.
    if unmatched:
        warnings.append(f"{len(unmatched)} active PIM schedule instance(s) had no matching Resource Graph assignment (outside the collected scope)")
    return rows, warnings
