import csv
import dataclasses
import json
from datetime import datetime, timezone

import pytest

from rbac_audit.api import RawStore
from rbac_audit.cli import summarize
from rbac_audit.collect import new_run_dir, run_collection
from conftest import G1, SUB, fixture
from fakes import FakeApi

G = lambda n: f"0000000b-0000-0000-0000-00000000000{n}"  # noqa: E731
U = lambda n: f"0000000a-0000-0000-0000-00000000000{n}"  # noqa: E731
G2, G3, G4 = G(2), G(3), G(4)
NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
PERM_ERR = ('HTTP 403 /v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances UnknownError: '
            '{"errorCode":"PermissionScopeNotGranted","message":"Authorization failed due to missing permission scope '
            'PrivilegedAssignmentSchedule.Read.AzureADGroup,PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup."}')


def run(cfg, **kw):
    run_dir = new_run_dir(cfg, NOW)
    raw = RawStore(run_dir / "raw")
    result = run_collection(cfg, FakeApi(raw, **kw), raw, run_dir, {"upn": "a@b"}, NOW)
    return result, run_dir


def read(run_dir, name):
    with open(run_dir / name, newline="") as fh:
        return list(csv.DictReader(fh))


@pytest.fixture
def ok(cfg):
    result, run_dir = run(cfg)
    return result.info, run_dir


def test_privileged_group_set_is_computed_with_reasons(ok):
    _, d = ok
    groups = {r["group_id"]: r for r in read(d, "privileged_groups.csv")}
    assert set(groups) == {G1, G2, G3, G4}
    assert set(groups[G1]["reason_codes"].split(";")) == {"azure_privileged_role", "pim_for_groups"}
    assert "Azure role 'Contributor'" in groups[G1]["reasons"] and "Azure role 'Owner'" in groups[G1]["reasons"]
    assert groups[G2]["reason_codes"] == "entra_privileged_role" and "Global Administrator" in groups[G2]["reasons"]
    assert "eligible" in groups[G3]["reasons"]                       # eligible for a privileged Entra role
    assert groups[G4]["reason_codes"] == "pim_for_groups" and "nested under grp-platform-admins" in groups[G4]["reasons"]
    assert groups[G1]["pim_managed"] == "True" and groups[G2]["pim_managed"] == "False"


def test_non_privileged_directory_role_and_users_do_not_create_groups(ok):
    # Directory Readers (isPrivileged=false) held by G1 adds no Entra reason; user holding GA is not a group.
    _, d = ok
    g1 = next(r for r in read(d, "privileged_groups.csv") if r["group_id"] == G1)
    assert "Directory Readers" not in g1["reasons"] and "entra_privileged_role" not in g1["reason_codes"]


def test_group_member_labels(ok):
    _, d = ok
    rows = [r for r in read(d, "group_members.csv") if r["privileged_group_id"] == G1]
    by = {(r["member_id"], r["access"], r["depth"]): r for r in rows}
    assert by[(U(1), "member", "0")]["label"] == "permanent_member"
    assert by[(U(2), "member", "0")]["label"] == "activated_member"        # activated + eligible -> activated
    assert by[(U(5), "member", "0")]["label"] == "time_bound_member" and by[(U(5), "member", "0")]["end"] == "2026-06-01T00:00:00Z"
    assert by[(U(6), "member", "0")]["label"] == "eligible_member"          # eligible-only: not in /members
    assert by[(U(1), "owner", "0")]["label"] == "owner" and by[(U(1), "owner", "0")]["state"] == "permanent"
    assert by[("0000000c-0000-0000-0000-000000000002", "member", "0")]["label"] == "permanent_member"  # SP, no PIM schedule
    assert by[("0000000c-0000-0000-0000-000000000002", "member", "0")]["member_type"] == "ManagedIdentity"
    assert by[(U(2), "member", "0")]["member_type"] == "Guest user"


def test_nested_groups_expanded_with_path_and_weakest_link(ok):
    _, d = ok
    rows = [r for r in read(d, "group_members.csv") if r["privileged_group_id"] == G1]
    u7 = next(r for r in rows if r["member_id"] == U(7))
    assert u7["depth"] == "1" and u7["direct"] == "False" and u7["via_group"] == "grp-nested"
    assert u7["path"] == "grp-platform-admins > grp-nested > User 7"
    assert u7["group_path_ids"] == f"{G1};{G4}"
    # U7 is a permanent member of the nested group, but the nested group is only *eligible* in G1.
    assert u7["label"] == "eligible_member"
    # G4 contains G1 (cycle): recorded, not re-expanded.
    assert sum(1 for r in rows if r["member_id"] == G1) == 1 and len(rows) == 9


def test_standing_exceptions_are_permanent_users_only(ok):
    info, d = ok
    ex = read(d, "exceptions_privileged_group_standing.csv")
    assert sorted((r["privileged_group_id"], r["member_id"], r["access"]) for r in ex) == sorted([
        (G1, U(1), "member"), (G1, U(1), "owner"), (G2, U(8), "member"), (G3, U(9), "member")])
    assert info["summary"]["exceptions_privileged_group_standing"] == 4
    assert all(r["member_type"] in ("User", "Guest user") for r in ex)       # no SP, no unverified, no eligible/activated


def test_pim_for_groups_unreadable_marks_unverified_and_reports_exact_permission(cfg):
    result, d = run(cfg, graph_errors={"/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances": PERM_ERR})
    s = result.info["summary"]
    assert s["coverage_complete"] is False and "pim_for_groups" in s["coverage_gaps_by_area"]
    assert "PrivilegedAssignmentSchedule.Read.AzureADGroup" in s["missing_graph_permissions"]
    labels = {r["label"] for r in read(d, "group_members.csv")}
    assert "unverified_member" in labels and "permanent_member" not in labels  # never silently permanent/pass
    assert read(d, "exceptions_privileged_group_standing.csv") == []            # unknown != exception
    out, err = summarize(result)
    assert any("PHASE 2 COVERAGE INCOMPLETE" in e and "pim_for_groups" in e for e in err)
    assert any("missing Graph permissions" in e and "PrivilegedAssignmentSchedule.Read.AzureADGroup" in e for e in err)


def test_unverified_when_pim_unreadable_only_for_that_group(cfg):
    class OnlyG3(FakeApi):
        def graph_list(self, category, path):
            if category.startswith("graph_group_pim") and G3 in path:
                return None, PERM_ERR
            return super().graph_list(category, path)

    run_dir = new_run_dir(cfg, NOW)
    raw = RawStore(run_dir / "raw")
    result = run_collection(cfg, OnlyG3(raw), raw, run_dir, {}, NOW)
    rows = read(run_dir, "group_members.csv")
    assert {r["label"] for r in rows if r["privileged_group_id"] == G3} == {"unverified_member"}
    assert {r["label"] for r in rows if r["privileged_group_id"] == G2} == {"permanent_member"}


def test_access_review_coverage_and_exceptions(ok):
    info, d = ok
    reviews = read(d, "access_reviews.csv")
    keyed = {(r["group_id"], r["definition_id"][-1]) for r in reviews}
    assert keyed == {(G1, "1"), (G1, "4"), (G2, "2"), (G3, "5")}        # D3 (principalType=User only) must NOT cover G1
    d4 = next(r for r in reviews if r["definition_id"].endswith("4"))
    assert d4["review_kind"] == "azure_resource_role" and d4["covers_via"] == "azure_role_scope"
    d1 = next(r for r in reviews if r["definition_id"].endswith("1"))
    assert (d1["interval_days"], d1["frequency_ok"], d1["completed_within_frequency"], d1["latest_completed_instance_id"][-1]) == ("90", "True", "True", "1")
    assert d1["decisions_total"] == "2" and d1["denied_still_member"] == "1" and d1["denied_unapplied"] == "0"
    d2 = next(r for r in reviews if r["definition_id"].endswith("2"))
    assert (d2["covers_via"], d2["overdue"], d2["default_approve"], d2["self_review"]) == ("instance_scope", "True", "True", "True")

    ex = {(r["group_id"], r["reason"]) for r in read(d, "exceptions_access_review.csv")}
    assert ex == {
        (G1, "denied_still_member"),
        (G2, "frequency_too_low"), (G2, "overdue"), (G2, "not_completed"), (G2, "self_review"), (G2, "default_approve"),
        (G3, "denied_still_member"), (G3, "decisions_not_applied"), (G3, "self_review"),
        (G4, "no_review"),
    }
    assert info["summary"]["exceptions_access_review"] == 10
    assert info["summary"]["exceptions_access_review_by_reason"]["no_review"] == 1


def test_access_review_decisions_csv(ok):
    _, d = ok
    dec = read(d, "access_review_decisions.csv")
    assert len(dec) == 3
    deny = next(r for r in dec if r["reviewee_id"] == U(2))
    assert (deny["group_id"], deny["decision"], deny["reviewer"], deny["justification"], deny["apply_result"]) == \
        (G1, "Deny", "Reviewer One", "checked", "AppliedSuccessfully")
    assert deny["applied_datetime"] == "2025-12-21T00:00:00Z" and deny["reviewed_datetime"] == "2025-12-18T10:00:00Z"
    unapplied = next(r for r in dec if r["reviewee_id"] == U(9))
    assert unapplied["applied_datetime"] == "" and unapplied["group_id"] == G3


def test_access_reviews_unreadable_is_a_coverage_gap_never_no_review(cfg):
    err = "HTTP 403 /v1.0/identityGovernance/accessReviews/definitions : Attempted to perform an unauthorized operation."
    result, d = run(cfg, graph_errors={"/v1.0/identityGovernance/accessReviews": err})
    ex = read(d, "exceptions_access_review.csv")
    assert {r["reason"] for r in ex} == {"coverage_gap"} and {r["group_id"] for r in ex} == {G1, G2, G3, G4}
    assert read(d, "access_reviews.csv") == []
    s = result.info["summary"]
    assert "access_reviews" in s["coverage_gaps_by_area"] and s["missing_graph_permissions"] == ["AccessReview.Read.All"]
    assert s["coverage_complete"] is False


def test_directory_role_failures_are_gaps_with_permission_names(cfg):
    miss = ('HTTP 403 UnknownError: {"errorCode":"PermissionScopeNotGranted","message":"Authorization failed due to missing '
            'permission scope RoleEligibilitySchedule.Read.Directory,RoleManagement.Read.Directory."}')
    result, d = run(cfg, graph_errors={"/v1.0/roleManagement/directory/roleEligibilityScheduleInstances": miss})
    s = result.info["summary"]
    assert "entra_directory_roles" in s["coverage_gaps_by_area"]
    assert {"RoleEligibilitySchedule.Read.Directory", "RoleManagement.Read.Directory"} <= set(s["missing_graph_permissions"])
    ids = {r["group_id"] for r in read(d, "privileged_groups.csv")}
    assert G3 not in ids and G2 in ids                      # eligible-only Entra group missed -> reported as gap, not silently


def test_isprivileged_definitions_unreadable_skips_entra_reasons_with_gap(cfg):
    result, d = run(cfg, graph_errors={"/beta/roleManagement/directory/roleDefinitions": "HTTP 400 BadRequest"})
    assert G2 not in {r["group_id"] for r in read(d, "privileged_groups.csv")}
    assert "entra_directory_roles" in result.info["summary"]["coverage_gaps_by_area"]


def test_manifest_summary_counts_and_control_mapping(ok):
    info, d = ok
    s = info["summary"]
    assert s["coverage_complete"] is True and s["coverage_gaps_by_area"] == {} and s["missing_graph_permissions"] == []
    assert (s["privileged_groups"], s["privileged_group_member_rows"], s["access_reviews_covering"], s["access_review_decisions"]) == (4, 11, 4, 3)
    assert s["group_members_by_label"]["owner"] == 1
    assert {"AC-2(j)", "AC-6(7)", "AC-2(7)", "AC-2", "AC-6"} <= set(s["control_mapping"])
    assert "access_reviews.csv" in s["control_mapping"]["AC-2(j)"]
    m = json.loads((d / "manifest.json").read_text())
    for f in ("privileged_groups.csv", "group_members.csv", "exceptions_privileged_group_standing.csv", "access_reviews.csv",
              "access_review_decisions.csv", "exceptions_access_review.csv"):
        assert f in m["files"]
    assert any(k.startswith("raw/graph_access_review_definitions") for k in m["files"])


def test_phase2_disabled_by_config_is_a_gap_not_a_clean_result(cfg):
    result, _ = run(dataclasses.replace(cfg, entra_enabled=False))
    assert "phase2" in result.info["summary"]["coverage_gaps_by_area"] and result.info["summary"]["coverage_complete"] is False


def test_phase2_crash_does_not_lose_phase1_evidence(cfg):
    class Boom(FakeApi):
        def graph_list(self, category, path):
            raise RuntimeError("kaboom")

    run_dir = new_run_dir(cfg, NOW)
    raw = RawStore(run_dir / "raw")
    result = run_collection(cfg, Boom(raw), raw, run_dir, {}, NOW)
    assert result.info["status"] == "complete" and len(read(run_dir, "assignments.csv")) == 11
    assert "phase2" in result.info["summary"]["coverage_gaps_by_area"]
