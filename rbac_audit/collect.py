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
from .manifest import write_manifest
from .principals import Principal, classify_principal, graph_path
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
    pim_failed_scopes: set[str] = field(default_factory=set)
    scopes: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


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
    if not mgs and cfg.include_inherited:
        try:
            mgs = [m["id"] for m in api.list_management_groups()]
        except Exception as e:  # noqa: BLE001 - any failure here is a coverage warning, not fatal
            g.warnings.append(f"management groups not listed: {e}")
    pim_scopes |= set(mgs)
    pim_scopes.discard("/")  # root is not directly queryable; its assignments appear in every lower query
    g.scopes = {"subscriptions": subs, "management_groups": cfg.management_groups,
                "pim_scopes_queried": len(pim_scopes)}

    jobs = [(k, s) for s in sorted(pim_scopes) for k in ("active", "eligible")]
    for (kind, scope), (items, err) in zip(jobs, api.parallel(lambda j: api.pim_instances(*j), jobs)):
        if err:
            g.warnings.append(f"PIM {kind} instances unreadable at {scope or '/'}: {err}")
            if kind == "active":
                g.pim_failed_scopes.add(scope)
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
            g.warnings.append(f"role definition {guid} could not be read; tier left as standard")


def _resolve_principals(api: AzureApi, g: Gathered) -> None:
    hints = principal_hints(g.assignments, g.eligible)
    responses = api.graph_batch({pid: graph_path(pid, hint) for pid, hint in hints.items()})
    for pid, hint in hints.items():
        status, body = responses.get(pid, (None, None))
        g.principals[pid] = classify_principal(pid, hint, status, body)
    unresolved = sum(1 for p in g.principals.values() if p.resolution == "unresolved")
    if unresolved:
        g.warnings.append(f"{unresolved} principal(s) could not be resolved via Graph (check Graph read permission)")


def write_csv(path: Path, columns: list[str], rows: list[dict]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def new_run_dir(cfg: Config, now: datetime) -> Path:
    return cfg.output_dir / now.strftime("%Y%m%dT%H%M%SZ")


def collect(cfg: Config, api: AzureApi, raw: RawStore, run_dir: Path, identity: dict, started: datetime) -> dict:
    """Run everything, write evidence into run_dir (raw/ must already be its RawStore dir)."""
    g = gather(cfg, api)
    rows, warnings = build_inventory(cfg, g.assignments, g.roles, g.active, g.eligible, g.principals, g.pim_failed_scopes)
    warnings = g.warnings + warnings
    direct, priv_perm = direct_user_exceptions(rows), privileged_permanent_exceptions(rows)
    write_csv(run_dir / "assignments.csv", COLUMNS, rows)
    write_csv(run_dir / "exceptions_direct_user.csv", COLUMNS, direct)
    write_csv(run_dir / "exceptions_privileged_permanent.csv", COLUMNS, priv_perm)

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
    }
    info = {
        "tool": "rbac-audit", "tool_version": __version__,
        "run_started_utc": started.astimezone(timezone.utc).isoformat(timespec="seconds"),
        "run_finished_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "signed_in_identity": identity, "config": cfg.public_dict(), "scopes": g.scopes,
        "summary": summary, "warnings": warnings, "api_calls": raw.calls,
    }
    write_manifest(run_dir, info)
    return info


def _count(rows: list[dict], key: str) -> dict:
    out: dict = {}
    for r in rows:
        out[r[key]] = out.get(r[key], 0) + 1
    return dict(sorted(out.items()))
