"""Full collect() run against a fake API serving recorded fixtures: no network."""
import csv
import hashlib
import json
from datetime import datetime, timezone

from rbac_audit.api import RawStore
from rbac_audit.collect import CollectionFailed, csv_safe, new_run_dir, run_collection, write_csv
from rbac_audit.cli import summarize
from rbac_audit.inventory import COLUMNS
from rbac_audit.manifest import verify_manifest
import pytest
from conftest import SUB, fixture
from fakes import FakeApi


def run(cfg, tmp_path, api_cls=FakeApi, **kw):
    started = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    run_dir = new_run_dir(cfg, started)
    raw = RawStore(run_dir / "raw")
    result = run_collection(cfg, api_cls(raw, **kw), raw, run_dir,
                            {"upn": "auditor@contoso.example", "tenant_id": cfg.tenant_id}, started)
    return result.run_dir, result.info


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


SUBS = f"/subscriptions/{SUB}"


def test_manifest_status_digest_and_clean_run_is_complete(cfg, tmp_path):
    run_dir, info = run(cfg, tmp_path)
    m = json.loads((run_dir / "manifest.json").read_text())
    assert m["status"] == "complete" and m["summary"]["coverage_complete"] is True
    assert m["summary"]["pim_failed_scopes"] == {"active": [], "eligible": []}
    assert m["known_limitations"] and not any("resource scope" in k for k in m["known_limitations"])
    digest, name = (run_dir / "manifest.sha256").read_text().split()
    assert name == "manifest.json" and digest == hashlib.sha256((run_dir / "manifest.json").read_bytes()).hexdigest()
    assert "manifest.sha256" not in m["files"] and verify_manifest(run_dir) == []


def test_eligible_pim_failure_is_tracked_and_makes_coverage_incomplete(cfg, tmp_path):
    run_dir, info = run(cfg, tmp_path, pim_errors={("eligible", SUBS)})
    s = info["summary"]
    assert s["coverage_complete"] is False
    assert s["pim_failed_scopes"] == {"active": [], "eligible": [SUBS]}
    assert any("eligible" in g and SUBS in g for g in s["coverage_gaps"])
    assert json.loads((run_dir / "manifest.json").read_text())["summary"]["coverage_complete"] is False


def test_active_pim_failure_marks_unverified_and_incomplete(cfg, tmp_path):
    run_dir, info = run(cfg, tmp_path, pim_errors={("active", SUBS)})
    assert info["summary"]["pim_failed_scopes"]["active"] == [SUBS]
    assert info["summary"]["by_pim_label"].get("unverified", 0) > 0 and info["summary"]["coverage_complete"] is False


def test_cli_warns_when_coverage_incomplete(cfg, tmp_path):
    started = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    run_dir = new_run_dir(cfg, started)
    raw = RawStore(run_dir / "raw")
    bad = run_collection(cfg, FakeApi(raw, pim_errors={("eligible", SUBS)}), raw, run_dir, {}, started)
    out, err = summarize(bad)
    assert any("COVERAGE INCOMPLETE" in e and "NOT conclusive" in e for e in err)
    assert any(o.startswith("manifest sha256: ") and len(o.split()[-1]) == 64 for o in out)


def test_cli_no_coverage_warning_when_complete(cfg, tmp_path):
    started = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    run_dir = new_run_dir(cfg, started)
    raw = RawStore(run_dir / "raw")
    ok = run_collection(cfg, FakeApi(raw), raw, run_dir, {}, started)
    assert not any("COVERAGE" in e for e in summarize(ok)[1])


def test_unresolved_principals_without_type_are_review_not_pass(cfg, tmp_path):
    graph = fixture("graph_principals.json")
    graph["0000000c-0000-0000-0000-000000000001"] = [403, {"error": {"code": "Authorization_RequestDenied"}}]  # SP1
    graph["0000000a-0000-0000-0000-000000000001"] = [403, {"error": {"code": "Authorization_RequestDenied"}}]  # U1
    run_dir, info = run(cfg, tmp_path, graph=graph)
    by_pid = {}
    for r in rows(run_dir / "assignments.csv"):
        by_pid.setdefault(r["principal_id"], set()).add((r["principal_resolution"], r["direct_user_result"]))
    assert by_pid["0000000c-0000-0000-0000-000000000001"] == {("unresolved", "REVIEW")}   # SP, unconfirmed
    assert by_pid["0000000a-0000-0000-0000-000000000001"] == {("unresolved", "FAIL")}     # hint User stays FAIL
    assert info["summary"]["coverage_complete"] is False


def test_descendant_management_groups_are_queried(cfg, tmp_path):
    import dataclasses
    mg_cfg = dataclasses.replace(cfg, management_groups=("mg-test",))
    desc = [{"id": "/providers/Microsoft.Management/managementGroups/mg-child", "type": "Microsoft.Management/managementGroups"},
            {"id": "/providers/Microsoft.Management/managementGroups/mg-grandchild", "type": "Microsoft.Management/managementGroups"},
            {"id": SUBS, "type": "Microsoft.Management/managementGroups/subscriptions"}]
    holder = {}

    class Spy(FakeApi):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            holder["api"] = self

    run(mg_cfg, tmp_path, api_cls=Spy, descendants=desc)
    queried = {s for _, s in holder["api"].pim_queried}
    mgp = "/providers/Microsoft.Management/managementGroups/"
    assert {mgp + "mg-test", mgp + "mg-child", mgp + "mg-grandchild"} <= queried


def test_descendant_listing_failure_is_a_coverage_gap(cfg, tmp_path):
    import dataclasses
    mg_cfg = dataclasses.replace(cfg, management_groups=("mg-test",))
    _, info = run(mg_cfg, tmp_path, descendants_error="boom")
    assert info["summary"]["coverage_complete"] is False
    assert any("descendants of management group mg-test" in g for g in info["summary"]["coverage_gaps"])


class Exploding(FakeApi):
    def graph_batch(self, paths):
        raise RuntimeError("graph exploded")


def test_failed_run_is_sealed_as_failed(cfg, tmp_path):
    started = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    run_dir = new_run_dir(cfg, started)
    raw = RawStore(run_dir / "raw")
    with pytest.raises(CollectionFailed) as ei:
        run_collection(cfg, Exploding(raw), raw, run_dir, {"upn": "x"}, started)
    failed = ei.value.failed_dir
    assert failed.name == "20260102T030405Z-FAILED" and failed.exists() and not run_dir.exists()
    m = json.loads((failed / "manifest.json").read_text())
    assert m["status"] == "failed" and m["error"] == {"type": "RuntimeError", "message": "graph exploded"}
    assert any(k.startswith("raw/arg_roleassignments") for k in m["files"])  # partial raw is hashed
    assert not (failed / "assignments.csv").exists() and verify_manifest(failed) == []


def test_csv_formula_injection_neutralised(tmp_path):
    for bad in ("=HYPERLINK(\"http://x\")", "+1+1", "-2", "@SUM(A1)", "\tcmd", "\rcmd"):
        assert csv_safe(bad) == "'" + bad
    assert csv_safe("/subscriptions/x") == "/subscriptions/x" and csv_safe("safe=ok") == "safe=ok"
    assert csv_safe(True) is True and csv_safe("") == ""
    path = tmp_path / "x.csv"
    write_csv(path, ["name", "flag"], [{"name": "=cmd|' /C calc'!A0", "flag": False}])
    assert path.read_text().splitlines()[1].startswith("'=cmd") and rows(path)[0]["flag"] == "False"


class SubscriptionReturnsChildren(FakeApi):
    """Live behaviour: a subscription-scope PIM query also returns eligibilities on resources below it."""
    VM = f"/subscriptions/{SUB}/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm1"

    def pim_instances(self, kind, scope):
        items, err = super().pim_instances(kind, scope)
        if kind == "eligible" and scope == f"/subscriptions/{SUB}" and items is not None:
            import copy
            inst = copy.deepcopy(items[0])
            inst["id"] = f"{self.VM}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances/vm-elig"
            inst["properties"].update(scope=self.VM, roleEligibilityScheduleId=f"{self.VM}/rES/vm-elig")
            items = items + [inst]
        return items, err


def test_resource_level_eligibility_from_subscription_query_is_inventoried(cfg, tmp_path):
    started = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    run_dir = new_run_dir(cfg, started)
    raw = RawStore(run_dir / "raw")
    result = run_collection(cfg, SubscriptionReturnsChildren(raw), raw, run_dir, {"upn": "x"}, started)
    vm = [r for r in rows(run_dir / "assignments.csv") if r["scope"] == SubscriptionReturnsChildren.VM]
    assert [(r["pim_label"], r["scope_level"]) for r in vm] == [("eligible", "resource")]
    assert not any("resource scope" in k for k in result.info["known_limitations"])
