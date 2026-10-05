"""Phase 2b: PIM for Groups state and nested membership of privileged groups."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .principals import DIRECT_USER_TYPES, GROUP, GUEST, MI, SP, USER

Fetch = Callable[[str, str], "tuple[list[dict] | None, str | None]"]

MEMBER_COLUMNS = [
    "privileged_group_id", "privileged_group_name", "member_id", "member_type", "member_name",
    "member_upn_or_appid", "access", "label", "state", "end", "depth", "direct", "via_group", "path",
    "group_path_ids",
]
PERMANENT, TIME_BOUND, ACTIVATED, ELIGIBLE, UNVERIFIED = "permanent", "time_bound", "activated", "eligible", "unverified"
# Strongest standing first: what a principal that holds several states is reported as.
_OWN_RANK = [PERMANENT, TIME_BOUND, ACTIVATED, ELIGIBLE]
# Weakest standing first: effective state across a chain of nested memberships.
_CHAIN_RANK = [UNVERIFIED, ELIGIBLE, ACTIVATED, TIME_BOUND, PERMANENT]

_SELECT = "$select=id,displayName,userPrincipalName,userType,servicePrincipalType,appId"
_BASE = "/v1.0/identityGovernance/privilegedAccess/group"


def instance_state(inst: dict, eligibility: bool) -> str:
    if eligibility:
        return ELIGIBLE
    if inst.get("assignmentType") == "Activated":
        return ACTIVATED
    return TIME_BOUND if inst.get("endDateTime") else PERMANENT


def strength(state: str) -> int:
    """Higher = more standing access (permanent strongest, unverified weakest)."""
    return _CHAIN_RANK.index(state)


def combine_states(chain: list[str]) -> str:
    """Effective standing through nested memberships: the weakest link wins."""
    for s in _CHAIN_RANK:
        if s in chain:
            return s
    return PERMANENT


def own_state(states: set[str]) -> str:
    for s in _OWN_RANK:
        if s in states:
            return s
    return UNVERIFIED


def object_type(obj: dict) -> str:
    t = (obj.get("@odata.type") or "").lower()
    if t.endswith("user"):
        upn = obj.get("userPrincipalName") or ""
        return GUEST if obj.get("userType") == "Guest" or "#ext#" in upn.lower() else USER
    if t.endswith("group"):
        return GROUP
    if t.endswith("serviceprincipal"):
        return MI if obj.get("servicePrincipalType") == "ManagedIdentity" else SP
    return "Unknown"


@dataclass
class WalkResult:
    rows: list[dict] = field(default_factory=list)
    errors: list[tuple[str, str, str]] = field(default_factory=list)  # (feature, group_id, error)
    pim_groups: dict[str, str] = field(default_factory=dict)          # group id -> name, groups with PIM schedules


def walk_group(root_id: str, root_name: str, fetch: Fetch, max_depth: int = 10) -> WalkResult:
    res = WalkResult()
    # Strongest effective state each nested group has been expanded with: a group reachable by several paths is
    # re-expanded when a later path gives it stronger standing (e.g. permanent via B after eligible via A), so a
    # standing exception cannot be hidden behind a weaker path. Strictly-stronger-only keeps this finite.
    best: dict[str, int] = {}
    # node: (group id, group name, [(id, name) from root to node], [edge states from root to node])
    queue = [(root_id.lower(), root_name, [(root_id.lower(), root_name)], [])]
    while queue:
        gid, gname, path, chain = queue.pop(0)
        members, e_m = fetch("graph_group_members", f"/v1.0/groups/{gid}/members?{_SELECT}")
        owners, e_o = fetch("graph_group_owners", f"/v1.0/groups/{gid}/owners?{_SELECT}")
        assigned, e_a = fetch("graph_group_pim_assignments", f"{_BASE}/assignmentScheduleInstances?$filter=groupId eq '{gid}'&$expand=principal")
        eligible, e_e = fetch("graph_group_pim_eligibility", f"{_BASE}/eligibilityScheduleInstances?$filter=groupId eq '{gid}'&$expand=principal")
        for feature, err in (("members", e_m), ("owners", e_o), ("pim_assignments", e_a), ("pim_eligibility", e_e)):
            if err:
                res.errors.append((feature, gid, err))
        pim_ok = e_a is None and e_e is None
        if assigned or eligible:
            res.pim_groups[gid] = gname

        entries: dict[tuple[str, str], dict] = {}

        def entry(obj: dict, access: str, state: str | None, end: str | None = None) -> None:
            e = entries.setdefault((obj["id"].lower(), access), {"obj": obj, "states": set(), "end": ""})
            if state:
                e["states"].add(state)
                e["end"] = e["end"] or end or ""
            if len(e["obj"]) < len(obj):
                e["obj"] = obj

        for inst, is_elig in [(i, False) for i in assigned or []] + [(i, True) for i in eligible or []]:
            obj = inst.get("principal") or {}
            obj = {**obj, "id": inst.get("principalId") or obj.get("id", "")}
            entry(obj, inst.get("accessId") or "member", instance_state(inst, is_elig), inst.get("endDateTime"))
        for access, items in (("member", members), ("owner", owners)):
            for obj in items or []:
                entry(obj, access, None)

        for (pid, access), e in entries.items():
            state = own_state(e["states"]) if e["states"] else (PERMANENT if pim_ok else UNVERIFIED)
            effective = combine_states(chain + [state])
            obj = e["obj"]
            mtype = object_type(obj)
            res.rows.append({
                "privileged_group_id": root_id.lower(), "privileged_group_name": root_name, "member_id": pid,
                "member_type": mtype, "member_name": obj.get("displayName") or "",
                "member_upn_or_appid": obj.get("userPrincipalName") or obj.get("appId") or "",
                "access": access, "label": "owner" if access == "owner" else f"{effective}_member",
                "state": effective, "end": e["end"], "depth": len(path) - 1, "direct": len(path) == 1,
                "via_group": gname, "path": " > ".join(n or i for i, n in path) + f" > {obj.get('displayName') or pid}",
                "group_path_ids": ";".join(i for i, _ in path),
            })
            if mtype == GROUP and access == "member" and pid not in [i for i, _ in path] and best.get(pid, -1) < strength(effective):
                if len(path) >= max_depth:
                    res.errors.append(("max_depth", pid, f"nested group below depth {max_depth} not expanded"))
                else:
                    best[pid] = strength(effective)
                    queue.append((pid, obj.get("displayName") or pid, path + [(pid, obj.get("displayName") or pid)], chain + [state]))
    return res


def standing_exceptions(rows: list[dict]) -> list[dict]:
    """Users (incl. guests) who are permanent, non-PIM members or owners of a privileged group."""
    return [r for r in rows if r["member_type"] in DIRECT_USER_TYPES and r["state"] == PERMANENT]
