"""PIM classification of role assignments.

ARG reports JIT-activated assignments as ordinary assignments, so the ARM
schedule instances are needed to tell them apart.
"""
from __future__ import annotations

from .scope import guid_of

PERMANENT_ACTIVE = "permanent_active"
TIME_BOUND_ACTIVE = "time_bound_active"
ACTIVATED = "activated"
ELIGIBLE = "eligible"
UNVERIFIED = "unverified"  # PIM data for this scope could not be read


def _key(principal_id, role_def_id, scope) -> tuple:
    return ((principal_id or "").lower(), guid_of(role_def_id), (scope or "").lower().rstrip("/"))


class ActiveIndex:
    """Active schedule instances, indexed by origin role assignment and by (principal, role, scope)."""

    def __init__(self, instances: list[dict]):
        self.by_origin: dict[str, list[dict]] = {}
        self.by_key: dict[tuple, list[dict]] = {}
        for inst in instances:
            p = inst.get("properties", {})
            if p.get("originRoleAssignmentId"):
                self.by_origin.setdefault(p["originRoleAssignmentId"].lower(), []).append(p)
            self.by_key.setdefault(_key(p.get("principalId"), p.get("roleDefinitionId"), p.get("scope")), []).append(p)

    def match(self, assignment_id: str, principal_id: str, role_def_id: str, scope: str) -> list[dict]:
        return self.by_origin.get(assignment_id.lower()) or self.by_key.get(_key(principal_id, role_def_id, scope), [])


def label_active(matches: list[dict]) -> tuple[str, str | None, str | None]:
    """(pim_label, start, end) for an ARG assignment given its matching schedule instances."""
    for m in matches:
        if m.get("assignmentType") == "Activated":
            return ACTIVATED, m.get("startDateTime"), m.get("endDateTime")
    for m in matches:
        if m.get("assignmentType") == "Assigned" and m.get("endDateTime"):
            return TIME_BOUND_ACTIVE, m.get("startDateTime"), m["endDateTime"]
    start = matches[0].get("startDateTime") if matches else None
    return PERMANENT_ACTIVE, start, None
