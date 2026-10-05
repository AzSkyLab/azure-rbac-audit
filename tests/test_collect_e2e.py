"""Full collect() run against a fake API serving recorded fixtures: no network."""
import csv
import json
from datetime import datetime, timezone

from rbac_audit.api import RawStore
from rbac_audit.collect import collect, new_run_dir
from rbac_audit.inventory import COLUMNS
from rbac_audit.manifest import verify_manifest
from conftest import SUB, fixture


class FakeApi:
    def __init__(self, raw, graph=None):
        self.raw = raw
        self.graph = graph or fixture("graph_principals.json")

    def _rec(self, category, payload, url="fake://"):
        self.raw.save_json(category, payload, method="GET", url=url, status=200)

    def list_subscriptions(self):
        return [{"subscriptionId": SUB, "state": "Enabled"}]

    def list_management_groups(self):
        return [{"id": "/providers/Microsoft.Management/managementGroups/mg-test"}]

    def arg_query(self, category, query, **kw):
        data = {"arg_roleassignments": fixture("arg_roleassignments.json")["data"],
                "arg_roledefinitions": fixture("arg_roledefinitions.json")["data"],
                "arg_resourcecontainers": [{"id": f"/subscriptions/{SUB}"}, {"id": f"/subscriptions/{SUB}/resourceGroups/rg-app"}]}[category]
        self._rec(category, {"data": data})
        return data

    def list_builtin_roledefs(self):
        v = fixture("arm_roledefinitions_builtin.json")["value"]
        self._rec("arm_roledefinitions_builtin", {"value": v})
        return v

    def get_roledef(self, scope, guid):
        return None

    def pim_instances(self, kind, scope):
        v = fixture("pim_active.json" if kind == "active" else "pim_eligible.json")["value"]
        self._rec(f"pim_{kind}", {"value": v})
        return v, None  # every scope returns everything: exercises de-duplication

    def graph_batch(self, paths):
        out = {pid: tuple(self.graph[pid]) for pid in paths}
        self._rec("graph_batch", {"responses": list(paths)})
        return out

    def parallel(self, fn, args, workers=8):
        return [fn(a) for a in args]


def run(cfg, tmp_path, **kw):
    started = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    run_dir = new_run_dir(cfg, started)
    raw = RawStore(run_dir / "raw")
    info = collect(cfg, FakeApi(raw, **kw), raw, run_dir, {"upn": "auditor@contoso.example", "tenant_id": cfg.tenant_id}, started)
    return run_dir, info


def rows(path):
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def test_collect_writes_evidence_folder(cfg, tmp_path):
    run_dir, info = run(cfg, tmp_path)
    assert run_dir.name == "20260102T030405Z"
    assert len(rows(run_dir / "assignments.csv")) == 11
    assert len(rows(run_dir / "exceptions_direct_user.csv")) == 3
    assert len(rows(run_dir / "exceptions_privileged_permanent.csv")) == 5
    assert list((run_dir / "raw").glob("pim_active_*.json"))
    assert verify_manifest(run_dir) == []
    m = json.loads((run_dir / "manifest.json").read_text())
    assert m["signed_in_identity"]["upn"] == "auditor@contoso.example"
    assert m["config"]["tenant_id"] == cfg.tenant_id and m["tool_version"] and m["run_started_utc"].startswith("2026-01-02")
    assert "raw/arg_roleassignments_0001.json" in m["files"] and "assignments.csv" in m["files"]
    assert m["summary"]["exceptions_direct_user"] == 3 and m["summary"]["orphaned_for_review"] == 1


def test_compliant_estate_gives_header_only_direct_user_file(cfg, tmp_path, monkeypatch):
    # Same estate, but every "User" principal is actually a group: no direct users remain.
    import rbac_audit.collect as collect_mod
    original = collect_mod.principal_hints
    monkeypatch.setattr(collect_mod, "principal_hints",
                        lambda a, e: {k: ("Group" if v == "User" else v) for k, v in original(a, e).items()})
    graph = {pid: [status, {"id": pid, "displayName": "grp"} if status == 200 and "userPrincipalName" in body else body]
             for pid, (status, body) in fixture("graph_principals.json").items()}
    run_dir, _ = run(cfg, tmp_path, graph=graph)
    assert (run_dir / "exceptions_direct_user.csv").read_text().splitlines() == [",".join(COLUMNS)]
