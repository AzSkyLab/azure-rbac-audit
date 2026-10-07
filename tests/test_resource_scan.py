import copy
import csv
import dataclasses
from datetime import datetime, timezone

import pytest

from rbac_audit.api import RawStore
from rbac_audit.collect import new_run_dir, run_collection
from rbac_audit.config import ConfigError, parse_config
from conftest import SUB, fixture
from fakes import FakeApi

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
VM = f"/subscriptions/{SUB}/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm1"
SA = f"/subscriptions/{SUB}/resourceGroups/rg-app/providers/Microsoft.Storage/storageAccounts/sa1"


def vm_only_eligibility():
    inst = copy.deepcopy(fixture("pim_eligible.json")["value"][0])
    inst["id"] = f"{VM}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances/vm-elig"
    p = inst["properties"]
    p["scope"], p["roleEligibilityScheduleId"] = VM, f"{VM}/providers/Microsoft.Authorization/roleEligibilitySchedules/vm-elig"
    return inst


def run(cfg, **kw):
    d = new_run_dir(cfg, NOW)
    raw = RawStore(d / "raw")
    api = FakeApi(raw, resources=[VM, SA], eligible_at={VM: [vm_only_eligibility()]}, **kw)
    info = run_collection(cfg, api, raw, d, {"upn": "a@b"}, NOW).info
    with open(d / "assignments.csv", newline="") as fh:
        return info, list(csv.DictReader(fh)), api


def test_resource_only_eligibility_found_when_scanning(cfg):
    info, rows, api = run(dataclasses.replace(cfg, scan_resources=True))
    vm = [r for r in rows if r["scope"] == VM]
    assert len(vm) == 1 and vm[0]["pim_label"] == "eligible" and vm[0]["scope_level"] == "resource"
    assert {("eligible", VM), ("eligible", SA)} <= set(api.pim_queried)
    assert not any(("active", r) in api.pim_queried for r in (VM, SA))          # active ones come from Resource Graph
    assert info["scopes"]["resources_queried"] == 2
    assert not any("resource scope" in k for k in info["known_limitations"])


def test_not_found_without_scanning_and_limitation_recorded(cfg):
    info, rows, api = run(cfg)
    assert not [r for r in rows if r["scope"] == VM] and ("eligible", VM) not in api.pim_queried
    assert any("resource scope" in k for k in info["known_limitations"])


def test_cap_is_a_coverage_gap(cfg):
    info, _, api = run(dataclasses.replace(cfg, scan_resources=True, max_resource_scopes=1))
    assert info["scopes"]["resources_queried"] == 1 and info["summary"]["coverage_complete"] is False
    assert any("1 of 2 resources not queried" in g for g in info["summary"]["coverage_gaps"])


def test_resource_query_failure_is_a_gap(cfg):
    info, _, _ = run(dataclasses.replace(cfg, scan_resources=True), pim_errors={("eligible", SA)})
    assert info["summary"]["coverage_complete"] is False and SA in info["summary"]["pim_failed_scopes"]["eligible"]


def test_config(cfg):
    import yaml
    from conftest import ROOT, TENANT
    raw = yaml.safe_load((ROOT / "config.example.yaml").read_text())
    raw["tenant_id"] = TENANT
    c = parse_config(raw)
    assert c.scan_resources is False and c.max_resource_scopes == 5000
    raw["scope"]["max_resource_scopes"] = 0
    with pytest.raises(ConfigError, match="max_resource_scopes"):
        parse_config(raw)
