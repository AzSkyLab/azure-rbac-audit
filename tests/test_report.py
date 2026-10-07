import json
from datetime import datetime, timezone

from rbac_audit import report
from rbac_audit.api import RawStore
from rbac_audit.collect import new_run_dir, run_collection
from rbac_audit.manifest import verify_manifest
from conftest import SUB
from fakes import FakeApi

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def test_report_written_hashed_and_lists_findings(cfg):
    d = new_run_dir(cfg, NOW)
    raw = RawStore(d / "raw")
    run_collection(cfg, FakeApi(raw), raw, d, {"upn": "a@b", "tenant_id": "t"}, NOW)
    html = (d / "report.html").read_text()
    assert "report.html" in json.loads((d / "manifest.json").read_text())["files"] and verify_manifest(d) == []
    assert "Coverage complete" in html and "Standing privileged Azure access" in html and "User One" in html
    assert "<script" not in html and "http" not in html.split("</style>")[0]       # self-contained


def test_report_escapes_names_and_flags_incomplete_coverage():
    info = {"summary": {"coverage_complete": False, "coverage_gaps_by_area": {"pim": ["PIM <unreadable>"]},
                        "missing_graph_permissions": ["AuditLog.Read.All"]},
            "signed_in_identity": {"tenant_id": "t", "upn": "x@y"}, "warnings": ["w&1"]}
    evil = '<img src=x onerror=alert(1)>"'
    html = report.render(info, {"exceptions_privileged_group_standing.csv": [{"privileged_group_name": evil, "member_name": "m"}]})
    assert evil not in html and "&lt;img src=x onerror=alert(1)&gt;&quot;" in html
    assert "Coverage INCOMPLETE" in html and "PIM &lt;unreadable&gt;" in html and "AuditLog.Read.All" in html and "w&amp;1" in html


def test_report_caps_long_tables():
    rows = [{"group_name": f"g{i}", "reason": "no_review", "detail": ""} for i in range(report.MAX_ROWS + 5)]
    html = report.render({"summary": {"coverage_complete": True}}, {"exceptions_access_review.csv": rows})
    assert f"Showing {report.MAX_ROWS} of {report.MAX_ROWS + 5} rows" in html and f"g{report.MAX_ROWS + 1}" not in html


def test_report_shows_object_id_for_deleted_principals_and_readable_headers():
    rows = [{"role_name": "Owner", "principal_type": "Orphaned", "principal_name": "", "principal_id": "dead-beef"}]
    html = report.render({"summary": {"coverage_complete": True}}, {"exceptions_privileged_permanent.csv": rows})
    assert "dead-beef" in html and "<th>UPN / app id</th>" in html and "<th>role name</th>" in html
