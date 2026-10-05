"""Orchestrates a collection run: gather -> analyse -> write evidence."""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .api import AzureApi, RawStore
from .config import Config
from .controls import direct_user_exceptions, privileged_permanent_exceptions
from .inventory import COLUMNS, build_inventory, principal_hints
from .groups import MEMBER_COLUMNS
from .manifest import write_manifest
from .phase2 import GROUP_COLUMNS, Phase2, run_phase2
from .reviews import DECISION_COLUMNS, EXCEPTION_COLUMNS, REVIEW_COLUMNS
from .principals import DIRECT_USER_TYPES, Principal, classify_principal, graph_path
from .roles import RoleDef, parse_roledef
from .scope import guid_of

ASSIGNMENTS_Q = "authorizationresources | where type =~ 'microsoft.authorization/roleassignments'"
ROLEDEFS_Q = "authorizationresources | where type =~ 'microsoft.authorization/roledefinitions'"
MG_PREFIX = "/providers/Microsoft.Management/managementGroups/"


@dataclass
class Gathered:
    assignments: list[dict] = field(default_factory=list)
    roles: dict[str, RoleDef] = field(default_factory=dict)
    active: list[dict] = field(default_factory=list)
    eligible: list[dict] = field(default_factory=list)
    principals: dict[str, Principal] = field(default_factory=dict)
    pim_failed: dict[str, set[str]] = field(default_factory=lambda: {"active": set(), "eligible": set()})
    scopes: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)  # anything that makes the run's conclusions incomplete
    gap_areas: dict[str, list[str]] = field(default_factory=dict)

    def gap(self, msg: str, area: str = "azure_rbac") -> None:
        self.warnings.append(msg)
        self.gaps.append(msg)
        self.gap_areas.setdefault(area, []).append(msg)


def _dedupe(items: list[dict], key=lambda i: i["id"].lower()) -> list[dict]:
    return list({key(i): i for i in items}.values())


def _roles_scope(cfg: Config, subs: list[str]) -> dict:
    return {"management_groups": cfg.management_groups} if cfg.management_groups else {"subscriptions": subs}


def gather(cfg: Config, api: AzureApi) -> Gathered:
    g = Gathered()
    subs = list(cfg.subscriptions)
    if not subs and not cfg.management_groups:
        subs = [s["subscriptionId"].lower() for s in api.list_subscriptions() if s.get("state") == "Enabled"]
    kw = _roles_scope(cfg, subs)

    g.assignments = _dedupe(api.arg_query("arg_roleassignments", ASSIGNMENTS_Q, inherited=cfg.include_inherited, **kw))
    for row in api.arg_query("arg_roledefinitions", ROLEDEFS_Q, **kw):
        r = parse_roledef(row)
        g.roles[r.guid] = r
    for obj in api.list_builtin_roledefs():
        r = parse_roledef(obj)
        g.roles.setdefault(r.guid, r)

    # PIM instance queries return assignments at-and-above the queried scope, so ask at every scope.
    types = "'microsoft.resources/subscriptions'" + (
        ",'microsoft.resources/subscriptions/resourcegroups'" if cfg.scan_resource_groups else "")
    containers = api.arg_query("arg_resourcecontainers", f"resourcecontainers | where type in~ ({types}) | project id", **kw)
    pim_scopes = {c["id"] for c in containers} | {a["properties"]["scope"] for a in g.assignments}
    mgs = [MG_PREFIX + m for m in cfg.management_groups]
    if cfg.management_groups:
        # Configured MGs plus every descendant MG: PIM queries only see at-and-above.
        for m in cfg.management_groups:
            try:
                mgs += [d["id"] for d in api.list_mg_descendants(m) if d.get("type", "").lower().endswith("managementgroups")]
            except Exception as e:  # noqa: BLE001 - coverage gap, not fatal
                g.gap(f"descendants of management group {m} not listed: {e}")
    elif cfg.include_inherited:
        try:
            mgs = [m["id"] for m in api.list_management_groups()]
        except Exception as e:  # noqa: BLE001 - coverage gap, not fatal
            g.gap(f"management groups not listed: {e}")
    pim_scopes |= set(mgs)
    pim_scopes.discard("/")  # root is not directly queryable; its assignments appear in every lower query
    g.scopes = {"subscriptions": subs, "management_groups": cfg.management_groups,
                "pim_scopes_queried": len(pim_scopes)}

    jobs = [(k, s) for s in sorted(pim_scopes) for k in ("active", "eligible")]
    for (kind, scope), (items, err) in zip(jobs, api.parallel(lambda j: api.pim_instances(*j), jobs)):
        if err:
            g.gap(f"PIM {kind} instances unreadable at {scope or '/'}: {err}")
            g.pim_failed[kind].add(scope)
        else:
            (g.active if kind == "active" else g.eligible).extend(items)
    g.active, g.eligible = _dedupe(g.active), _dedupe(g.eligible)

    _fill_missing_roles(api, g)
    _resolve_principals(api, g)
    return g


def _fill_missing_roles(api: AzureApi, g: Gathered) -> None:
    wanted = [(a["properties"]["scope"], a["properties"]["roleDefinitionId"]) for a in g.assignments]
    wanted += [(e["properties"]["scope"], e["properties"]["roleDefinitionId"]) for e in g.eligible]
    missing = {guid_of(rid): scope for scope, rid in wanted if guid_of(rid) not in g.roles}
    for guid, scope in missing.items():
        obj = api.get_roledef(scope, guid)
        if obj:
            g.roles[guid] = parse_roledef(obj)
        else:
            g.gap(f"role definition {guid} could not be read; tier left as standard")


def _resolve_principals(api: AzureApi, g: Gathered) -> None:
    hints = principal_hints(g.assignments, g.eligible)
    responses = api.graph_batch({pid: graph_path(pid, hint) for pid, hint in hints.items()})
    for pid, hint in hints.items():
        status, body = responses.get(pid, (None, None))
        g.principals[pid] = classify_principal(pid, hint, status, body)
    unresolved = [p for p in g.principals.values() if p.resolution == "unresolved"]
    if unresolved:
        g.warnings.append(f"{len(unresolved)} principal(s) could not be resolved via Graph (check Graph read permission)")
    inconclusive = [p for p in unresolved if p.type not in DIRECT_USER_TYPES]
    if inconclusive:
        g.gap(f"{len(inconclusive)} principal(s) of unconfirmed type reported as REVIEW in the direct-user control")


_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value):
    """Neutralise spreadsheet formula injection (principal names are attacker-influenced)."""
    return "'" + value if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES) else value


def write_csv(path: Path, columns: list[str], rows: list[dict]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        w.writeheader()
        w.writerows({k: csv_safe(v) for k, v in r.items()} for r in rows)


def new_run_dir(cfg: Config, now: datetime) -> Path:
    return cfg.output_dir / now.strftime("%Y%m%dT%H%M%SZ")


CONTROL_MAPPING = {
    "AC-2": ["assignments.csv", "exceptions_direct_user.csv"],
    "AC-6": ["exceptions_privileged_permanent.csv"],
    "AC-2(j)": ["access_reviews.csv", "access_review_decisions.csv", "exceptions_access_review.csv"],
    "AC-6(7)": ["privileged_groups.csv", "access_reviews.csv", "exceptions_access_review.csv"],
    "AC-2(7)": ["privileged_groups.csv", "group_members.csv", "exceptions_privileged_group_standing.csv"],
}

KNOWN_LIMITATIONS = [
    "Eligible-only PIM assignments at resource scope (below resource group) are not enumerated: the "
    "roleAssignmentScheduleInstances/roleEligibilityScheduleInstances APIs return instances at-and-above the "
    "queried scope only, so resources are not individually queried. Eligible assignments on a resource whose "
    "principal has no active assignment there are therefore not reported.",
    "Privileged groups are computed from groups that hold a non-standard Azure role or a privileged Entra "
    "directory role; groups managed by PIM for Groups are added only when found while expanding those (Graph "
    "offers no v1.0 listing of onboarded groups). Access-review coverage of filtered all-groups reviews is "
    "matched through each instance's scope query; Azure role reviews match on path prefix only.",
]


@dataclass
class RunResult:
    run_dir: Path
    info: dict
    manifest_sha256: str


class CollectionFailed(RuntimeError):
    def __init__(self, failed_dir: Path, cause: BaseException):
        super().__init__(f"{type(cause).__name__}: {cause}")
        self.failed_dir = failed_dir
        self.cause = cause


def _base_info(cfg: Config, identity: dict, started: datetime, raw: RawStore, status: str) -> dict:
    identity = dict(identity)
    read_only = identity.pop("read_only", None)
    info = {
        "status": status, "tool": "rbac-audit", "tool_version": __version__,
        "run_started_utc": started.astimezone(timezone.utc).isoformat(timespec="seconds"),
        "run_finished_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "signed_in_identity": identity, "config": cfg.public_dict(), "api_calls": raw.calls,
    }
    if read_only is not None:
        info["collector_identity_read_only"] = read_only
    return info


def collect(cfg: Config, api: AzureApi, raw: RawStore, run_dir: Path, identity: dict, started: datetime) -> RunResult:
    """Run everything, write evidence into run_dir (raw/ must already be its RawStore dir)."""
    g = gather(cfg, api)
    rows, warnings = build_inventory(cfg, g.assignments, g.roles, g.active, g.eligible, g.principals,
                                     g.pim_failed["active"])
    p2 = Phase2()
    if cfg.entra_enabled:
        try:
            p2 = run_phase2(cfg, api, rows, g.principals, started)
        except Exception as e:  # noqa: BLE001 - phase 2 must not take phase 1 evidence down with it
            p2.gaps["phase2"] = [f"phase 2 aborted: {type(e).__name__}: {e}"]
    else:
        p2.gaps["phase2"] = ["phase 2 (privileged groups, PIM for Groups, access reviews) disabled by config"]
    for area, msgs in p2.gaps.items():
        for m in msgs:
            g.gap(m, area)
    warnings = g.warnings + warnings
    direct, priv_perm = direct_user_exceptions(rows), privileged_permanent_exceptions(rows)
    write_csv(run_dir / "assignments.csv", COLUMNS, rows)
    write_csv(run_dir / "exceptions_direct_user.csv", COLUMNS, direct)
    write_csv(run_dir / "exceptions_privileged_permanent.csv", COLUMNS, priv_perm)
    write_csv(run_dir / "privileged_groups.csv", GROUP_COLUMNS, p2.groups)
    write_csv(run_dir / "group_members.csv", MEMBER_COLUMNS, p2.members)
    write_csv(run_dir / "exceptions_privileged_group_standing.csv", MEMBER_COLUMNS, p2.standing)
    write_csv(run_dir / "access_reviews.csv", REVIEW_COLUMNS, p2.reviews)
    write_csv(run_dir / "access_review_decisions.csv", DECISION_COLUMNS, p2.decisions)
    write_csv(run_dir / "exceptions_access_review.csv", EXCEPTION_COLUMNS, p2.review_exceptions)

    summary = {
        "assignments_total": len(rows),
        "assignments_resource_graph": sum(r["source"] == "resource_graph" for r in rows),
        "eligible": sum(r["pim_label"] == "eligible" for r in rows),
        "by_pim_label": _count(rows, "pim_label"),
        "by_scope_level": _count(rows, "scope_level"),
        "by_principal_type": _count(rows, "principal_type"),
        "by_privilege_tier": _count(rows, "privilege_tier"),
        "exceptions_direct_user": len(direct),
        "orphaned_for_review": sum(r["direct_user_result"] == "REVIEW" for r in rows),
        "exceptions_privileged_permanent": len(priv_perm),
        "privileged_groups": len(p2.groups),
        "privileged_group_member_rows": len(p2.members),
        "group_members_by_label": _count(p2.members, "label"),
        "exceptions_privileged_group_standing": len(p2.standing),
        "access_reviews_covering": len(p2.reviews),
        "access_review_decisions": len(p2.decisions),
        "exceptions_access_review": len(p2.review_exceptions),
        "exceptions_access_review_by_reason": _count(p2.review_exceptions, "reason"),
        "coverage_complete": not g.gaps,
        "coverage_gaps": g.gaps,
        "coverage_gaps_by_area": g.gap_areas,
        "missing_graph_permissions": sorted(p2.missing_permissions),
        "control_mapping": CONTROL_MAPPING,
        "pim_failed_scopes": {k: sorted(v) for k, v in g.pim_failed.items()},
    }
    info = {**_base_info(cfg, identity, started, raw, "complete"), "scopes": g.scopes, "summary": summary,
            "warnings": warnings, "known_limitations": KNOWN_LIMITATIONS}
    return RunResult(run_dir, info, write_manifest(run_dir, info))


def run_collection(cfg: Config, api: AzureApi, raw: RawStore, run_dir: Path, identity: dict,
                   started: datetime) -> RunResult:
    """collect(), but a failed run is sealed as '<dir>-FAILED' with a status=failed manifest so that
    partial raw/ output can never be mistaken for evidence."""
    try:
        return collect(cfg, api, raw, run_dir, identity, started)
    except BaseException as e:
        run_dir.mkdir(parents=True, exist_ok=True)
        info = {**_base_info(cfg, identity, started, raw, "failed"),
                "error": {"type": type(e).__name__, "message": str(e)}}
        write_manifest(run_dir, info)
        failed = run_dir.with_name(run_dir.name + "-FAILED")
        run_dir.rename(failed)
        if isinstance(e, Exception):
            raise CollectionFailed(failed, e) from e
        raise


def _count(rows: list[dict], key: str) -> dict:
    out: dict = {}
    for r in rows:
        out[r[key]] = out.get(r[key], 0) + 1
    return dict(sorted(out.items()))
