import csv
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from rbac_audit import changes, cli
from rbac_audit.api import RawStore
from rbac_audit.collect import new_run_dir, run_collection
from conftest import G1, ROOT, SUB, U1
from fakes import FakeApi

T1 = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
T2 = T1 + timedelta(days=7)
U7 = "0000000a-0000-0000-0000-000000000007"


def run(cfg, when, mutate=None, **kw):
    d = new_run_dir(cfg, when)
    raw = RawStore(d / "raw")
    api = FakeApi(raw, **kw)
    if mutate:
        mutate(api.entra)
    return run_collection(cfg, api, raw, d, {"upn": "a@b"}, when).info, d


def read(d, name="changes.csv"):
    with open(d / name, newline="") as fh:
        return list(csv.DictReader(fh))


def drop_owner_and_activate(e):
    g1 = e["groups"][G1]
    g1["owners"] = []                                                  # owner U1 removed (plain and PIM)
    g1["assigned"] = [i for i in g1["assigned"] if i.get("accessId") != "owner"]
    for i in g1["assigned"]:
        if i["principalId"] == "0000000a-0000-0000-0000-000000000005":  # time-bound member now activated
            i["assignmentType"] = "activated"


def test_diff_added_removed_changed():
    old = {"group_members.csv": [{"privileged_group_id": "g", "member_id": "a", "access": "member", "label": "eligible_member",
                                  "privileged_group_name": "G", "path": "G > A", "member_name": "A"},
                                 {"privileged_group_id": "g", "member_id": "b", "access": "owner", "label": "owner",
                                  "privileged_group_name": "G", "path": "G > B", "member_name": "B"}]}
    new = {"group_members.csv": [{**old["group_members.csv"][0], "label": "permanent_member"},
                                 {**old["group_members.csv"][1], "member_id": "c", "member_name": "C", "path": "G > C"}]}
    got = {(r["change"], r["principal"], r["field"], r["before"], r["after"]) for r in changes.diff(old, new)}
    assert got == {("changed", "A", "label", "eligible_member", "permanent_member"),
                   ("added", "C", "", "", ""), ("removed", "B", "", "", "")}


def test_first_run_has_no_baseline(cfg):
    info, d = run(cfg, T1)
    assert info["summary"]["changes_since"] is None and read(d) == []


def test_second_run_reports_changes_against_the_first(cfg):
    run(cfg, T1)
    info, d = run(cfg, T2, mutate=drop_owner_and_activate)
    s = info["summary"]
    assert s["changes_since"] == "20260102T030405Z"
    rows = read(d)
    removed_owner = [r for r in rows if r["change"] == "removed" and r["source"] == "group_members" and r["key"].endswith(f"{U1}|owner")]
    relabelled = [r for r in rows if r["change"] == "changed" and r["field"] == "label"]
    assert removed_owner and ("time_bound_member", "activated_member") in {(r["before"], r["after"]) for r in relabelled}
    assert s["changes"]["group_members:removed"] >= 1
    assert "Changes since the previous run" in (d / "report.html").read_text()


def test_unchanged_second_run_reports_nothing(cfg):
    run(cfg, T1)
    info, d = run(cfg, T2)
    assert info["summary"]["changes_since"] == "20260102T030405Z" and read(d) == [] and info["summary"]["changes"] == {}


def test_baseline_skips_incomplete_coverage_and_tampered_runs(cfg):
    run(cfg, T1)
    _, d2 = run(cfg, T1 + timedelta(days=1), pim_errors={("active", f"/subscriptions/{SUB}")})   # coverage incomplete
    info, _ = run(cfg, T2)
    assert info["summary"]["changes_since"] == "20260102T030405Z"                                # d2 skipped
    first = cfg.output_dir / "20260102T030405Z"
    (first / "group_members.csv").write_text("tampered\n")
    info, _ = run(cfg, T2 + timedelta(days=1))
    assert info["summary"]["changes_since"] == "20260109T030405Z"                                # tampered T1 skipped too


class Blob:
    def __init__(self, name):
        self.name = name


class Container:
    """Read-only view of local runs laid out as <prefix><run>/<file> blobs."""

    def __init__(self, root: Path, prefix: str, tamper: str = ""):
        self.root, self.prefix, self.tamper = root, prefix, tamper

    def list_blobs(self, name_starts_with):
        assert name_starts_with == self.prefix
        return [Blob(f"{self.prefix}{p.relative_to(self.root).as_posix()}") for p in self.root.rglob("*") if p.is_file()]

    def download_blob(self, name):
        data = (self.root / name[len(self.prefix):]).read_bytes()
        if self.tamper and name.endswith(self.tamper):
            data += b"x"
        return type("D", (), {"readall": lambda _self: data})()


def test_blob_baseline_used_when_no_local_runs(cfg, tmp_path):
    _, d1 = run(cfg, T1)
    published = tmp_path / "published"
    published.mkdir()
    d1.rename(published / d1.name)
    found = changes.blob_baseline(Container(published, "prod/"), "prod/", "20260109T030405Z")
    assert found and found[0] == d1.name and found[1]["group_members.csv"]
    with pytest.raises(ValueError, match="does not match its manifest"):
        changes.blob_baseline(Container(published, "prod/", tamper="group_members.csv"), "prod/", "20260109T030405Z")


def test_collect_falls_back_to_the_publish_container(cfg, tmp_path):
    import dataclasses
    from rbac_audit.config import PublishConfig
    _, d1 = run(cfg, T1)
    published = tmp_path / "published"
    published.mkdir()
    d1.rename(published / d1.name)
    pcfg = dataclasses.replace(cfg, publish=PublishConfig("https://a.blob.core.windows.net", "ev", "prod/"))
    FakeApi.evidence_container = lambda self, url, name: Container(published, "prod/")
    try:
        info, d2 = run(pcfg, T2, mutate=drop_owner_and_activate)
    finally:
        del FakeApi.evidence_container
    assert info["summary"]["changes_since"] == d1.name and read(d2)


def test_diff_command(cfg, capsys):
    _, d1 = run(cfg, T1)
    _, d2 = run(cfg, T2, mutate=drop_owner_and_activate)
    assert cli.main(["diff", str(d1), str(d2)]) == cli.EXIT_OK
    out = list(csv.DictReader(capsys.readouterr().out.splitlines()))
    assert out == read(d2)
    (d1 / "assignments.csv").write_text("x")
    assert cli.main(["diff", str(d1), str(d2)]) == cli.EXIT_CONFIG


def test_sql_view_uses_the_same_keys_as_python():
    sql = (ROOT / "sql" / "schema.sql").read_text()
    for source in changes.SOURCES:
        assert re.search(rf"WHEN '{source}'\s+THEN", sql), source


def test_source_missing_from_one_run_is_skipped():
    rows = [{"principal_id": "u", "reason": "disabled"}]
    assert changes.diff({}, {"inactive_privileged_accounts.csv": rows}) == []
    assert changes.diff({"inactive_privileged_accounts.csv": []}, {"inactive_privileged_accounts.csv": rows})[0]["change"] == "added"
