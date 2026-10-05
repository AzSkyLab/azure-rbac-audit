"""Phase 2 orchestration: privileged groups -> PIM for Groups membership -> access reviews.

Every Graph failure becomes a coverage gap (area -> messages), never a pass.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from . import entra, reviews
from .config import Config
from .groups import MEMBER_COLUMNS, standing_exceptions, walk_group
from .principals import GROUP, classify_principal, graph_path

GROUP_COLUMNS = ["group_id", "group_name", "reason_codes", "reasons", "pim_managed", "members_total", "standing_users"]
AREA_DIRECTORY, AREA_GROUP_PIM, AREA_MEMBERS, AREA_REVIEWS = "entra_directory_roles", "pim_for_groups", "group_membership", "access_reviews"


@dataclass
class Phase2:
    groups: list[dict] = field(default_factory=list)
    members: list[dict] = field(default_factory=list)
    standing: list[dict] = field(default_factory=list)
    reviews: list[dict] = field(default_factory=list)
    decisions: list[dict] = field(default_factory=list)
    review_exceptions: list[dict] = field(default_factory=list)
    gaps: dict[str, list[str]] = field(default_factory=dict)
    missing_permissions: set[str] = field(default_factory=set)

    def gap(self, area: str, text: str, error: str, documented: str) -> None:
        """Record a gap and the permission(s) it implies (parsed from Graph's error, else the documented one)."""
        self.missing_permissions.update(entra.missing_permissions(error) or [documented])
        self.gaps.setdefault(area, []).append(f"{text} ({error[:200]}); needs {documented}")


def _directory_reasons(api, p2: Phase2, principals: dict, resolve) -> dict[str, list[tuple[str, str]]]:
    defs, err = api.graph_list("graph_dir_roledefinitions", "/beta/roleManagement/directory/roleDefinitions")
    if err:
        p2.gap(AREA_DIRECTORY, "Entra role definitions (isPrivileged) unreadable", err, entra.PERM_DIRECTORY_ROLES)
        return {}
    privileged = entra.privileged_role_ids(defs)
    active, err = api.graph_list("graph_dir_roleassignments", "/v1.0/roleManagement/directory/roleAssignments")
    if err:
        p2.gap(AREA_DIRECTORY, "Entra directory role assignments unreadable", err, entra.PERM_DIRECTORY_ROLES)
    eligible, err = api.graph_list("graph_dir_roleeligibility", "/v1.0/roleManagement/directory/roleEligibilityScheduleInstances")
    if err:
        p2.gap(AREA_DIRECTORY, "Entra eligible directory role assignments unreadable", err, entra.PERM_DIRECTORY_ELIGIBLE)
    holders = list(entra.directory_role_principals(active or [], eligible or [], privileged))
    resolve({pid for pid, *_ in holders})
    reasons: dict[str, list[tuple[str, str]]] = {}
    for pid, state, role, scope in holders:
        if principals.get(pid) and principals[pid].type == GROUP:
            reasons.setdefault(pid, []).append((entra.ENTRA, f"Entra directory role '{role}' (isPrivileged, {state}) at {scope}"))
    return reasons


def run_phase2(cfg: Config, api, rows: list[dict], known_principals: dict, now: datetime) -> Phase2:
    p2 = Phase2()
    principals = dict(known_principals)

    def resolve(ids: set[str]) -> None:
        todo = {i: graph_path(i, None) for i in ids if i not in principals}
        for pid, (status, body) in (api.graph_batch(todo) if todo else {}).items():
            principals[pid] = classify_principal(pid, None, status, body)

    entra_reasons = _directory_reasons(api, p2, principals, resolve)
    azure_reasons = entra.azure_role_reasons(rows)
    names = {pid: p.name for pid, p in principals.items()}
    groups = entra.build_privileged_groups(azure_reasons, entra_reasons, names)

    # B: PIM for Groups state + nested membership
    walks = dict(zip(groups, api.parallel(
        lambda gid: walk_group(gid, groups[gid].name, api.graph_list, cfg.group_max_depth), list(groups))))
    errors: dict[str, list[tuple[str, str]]] = {}
    for root, w in walks.items():
        p2.members += w.rows
        for gid, name in w.pim_groups.items():
            g = groups.setdefault(gid, entra.PrivilegedGroup(gid, name))
            g.add(entra.PIM_GROUP, "managed by PIM for Groups" if gid == root else f"managed by PIM for Groups (nested under {groups[root].name or root})")
        for feature, gid, err in w.errors:
            errors.setdefault(feature, []).append((gid, err))
    for feature, (area, text, perm) in {
        "members": (AREA_MEMBERS, "group members unreadable", entra.PERM_GROUP_MEMBERS),
        "owners": (AREA_MEMBERS, "group owners unreadable", entra.PERM_GROUP_MEMBERS),
        "pim_assignments": (AREA_GROUP_PIM, "PIM for Groups assignment schedules unreadable", entra.PERM_GROUP_ASSIGNMENT),
        "pim_eligibility": (AREA_GROUP_PIM, "PIM for Groups eligibility schedules unreadable", entra.PERM_GROUP_ELIGIBLE),
    }.items():
        if feature in errors:
            p2.gap(area, f"{text} for {len({g for g, _ in errors[feature]})} group(s); membership labels there are 'unverified'",
                   errors[feature][0][1], perm)
    for gid, err in errors.get("max_depth", []):
        p2.gaps.setdefault(AREA_MEMBERS, []).append(err)
    p2.standing = standing_exceptions(p2.members)
    for g in groups.values():
        n = sum(1 for r in p2.members if g.id in r["group_path_ids"].split(";"))
        standing = sum(1 for r in p2.standing if g.id in r["group_path_ids"].split(";"))
        p2.groups.append({"group_id": g.id, "group_name": g.name, "reason_codes": ";".join(sorted({c for c, _ in g.reasons})),
                          "reasons": " | ".join(t for _, t in g.reasons), "pim_managed": any(c == entra.PIM_GROUP for c, _ in g.reasons),
                          "members_total": n, "standing_users": standing})

    # C: access reviews
    defs, err = api.graph_list("graph_access_review_definitions", reviews.DEFS)
    if err:
        p2.gap(AREA_REVIEWS, "access review definitions unreadable", err, entra.PERM_ACCESS_REVIEWS)
        p2.review_exceptions = [{"group_id": g.id, "group_name": g.name, "reason": "coverage_gap", "review_ids": "",
                                 "detail": f"access review data unavailable; needs {entra.PERM_ACCESS_REVIEWS}"} for g in groups.values()]
        return p2
    results = api.parallel(lambda d: api.graph_list("graph_access_review_instances", f"{reviews.DEFS}/{d['id']}/instances"), defs)
    instances: dict[str, list[dict]] = {}
    for d, (items, err) in zip(defs, results):
        if err:
            p2.gap(AREA_REVIEWS, f"instances of review '{d.get('displayName')}' unreadable", err, entra.PERM_ACCESS_REVIEWS)
        instances[d["id"]] = items or []
    role_scopes = {gid: [r["scope"] for r in rows if r["principal_id"].lower() == gid and r["privilege_tier"] != "standard"]
                   for gid in groups}
    coverages = {gid: reviews.covering_reviews(gid, role_scopes[gid], defs, instances) for gid in groups}
    needed = sorted({k for covs in coverages.values() for k in reviews.decisions_needed(covs)})
    fetched = api.parallel(lambda k: api.graph_list("graph_access_review_decisions", f"{reviews.DEFS}/{k[0]}/instances/{k[1]}/decisions"), needed)
    decisions = {}
    for k, (items, err) in zip(needed, fetched):
        decisions[k] = items
        if err:
            p2.gap(AREA_REVIEWS, f"decisions of review {k[0]} instance {k[1]} unreadable", err, entra.PERM_ACCESS_REVIEWS)
    ev = reviews.evaluate(groups, coverages, decisions, p2.members, rows, now, cfg.review_frequency_days)
    p2.reviews, p2.decisions, p2.review_exceptions = ev.reviews, ev.decisions, ev.exceptions
    return p2
