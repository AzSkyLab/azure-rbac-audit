"""Entra directory-role inventory, unknown role definitions, allowlist, stale reviews, recycle-bin orphans."""
import csv
import dataclasses
from datetime import datetime, timezone

import pytest

from rbac_audit.api import RawStore
from rbac_audit.collect import new_run_dir, run_collection
from rbac_audit.config import AllowEntry, ConfigError, parse_config
from rbac_audit.entra import directory_role_principals
from rbac_audit.roles import SENSITIVE_DATA_PLANE, RoleDef, classify_tier
from conftest import ORPH, TENANT, U1, U2
from fakes import FakeApi

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
GA = "62e90394-69f5-4237-9190-012177145e10"
G2, G3 = "0000000b-0000-0000-0000-000000000002", "0000000b-0000-0000-0000-000000000003"
HIDDEN = "eb1d8c34-acf5-460d-8424-c1f1a6fbdb85"


def run(cfg, mutate=None, **kw):
    run_dir = new_run_dir(cfg, NOW)
    raw = RawStore(run_dir / "raw")
    api = FakeApi(raw, **kw)
    if mutate:
        mutate(api.entra)
    return run_collection(cfg, api, raw, run_dir, {"upn": "a@b"}, NOW).info, run_dir


def read(d, name):
    with open(d / name, newline="") as fh:
        return list(csv.DictReader(fh))


def test_entra_role_inventory_labels_from_schedule_instances(cfg):
    info, d = run(cfg)
    rows = {(r["principal_id"], r["state"]): r for r in read(d, "entra_role_assignments.csv")}
    assert rows[(G2, "active")]["pim_label"] == "time_bound_active" and rows[(G2, "active")]["end"] == "2026-03-01T00:00:00Z"
    assert rows[(U1, "active")]["pim_label"] == "permanent_active" and rows[(U1, "active")]["principal_type"] == "User"
    assert rows[(G3, "eligible")]["pim_label"] == "eligible"
    assert all(r["role_name"] == "Global Administrator" for r in rows.values())   # Directory Readers is not privileged
    exc = read(d, "exceptions_entra_privileged_permanent.csv")
    assert [(r["principal_id"], r["role_name"]) for r in exc] == [(U1, "Global Administrator")]
    s = info["summary"]
    assert s["entra_role_assignments"] == 3 and s["exceptions_entra_privileged_permanent"] == 1
    assert s["entra_roles_by_pim_label"] == {"eligible": 1, "permanent_active": 1, "time_bound_active": 1}
    assert "exceptions_entra_privileged_permanent.csv" in s["control_mapping"]["AC-6"]


def test_group_inherited_instances_do_not_label_direct_assignments(cfg):
    # i3 is U2's Activated instance via a group (memberType Group); it must not turn a direct assignment "activated".
    def add_direct_u2(e):
        e["dir_roleassignments"].append({"id": "a9", "principalId": U2, "roleDefinitionId": GA, "directoryScopeId": "/"})
    _, d = run(cfg, mutate=add_direct_u2)
    u2 = next(r for r in read(d, "entra_role_assignments.csv") if r["principal_id"] == U2)
    assert u2["pim_label"] == "permanent_active" and u2["principal_type"] == "Guest user"


def test_unreadable_schedule_instances_mark_unverified_and_gap(cfg):
    info, d = run(cfg, graph_errors={"graph_dir_roleassignment_instances": "HTTP 403 Forbidden"})
    active = [r for r in read(d, "entra_role_assignments.csv") if r["state"] == "active"]
    assert active and all(r["pim_label"] == "unverified" for r in active)
    assert read(d, "exceptions_entra_privileged_permanent.csv") == []
    assert info["summary"]["coverage_complete"] is False
    assert any("schedules unreadable" in m for m in info["summary"]["coverage_gaps_by_area"]["entra_directory_roles"])


def test_unknown_role_definition_is_treated_as_privileged():
    holders = list(directory_role_principals(
        [{"principalId": "P", "roleDefinitionId": HIDDEN.upper()}, {"principalId": "Q", "roleDefinitionId": "known-np"}],
        [], {GA: "Global Administrator"}, known={GA, "known-np"}))
    assert [(h[0], h[2], h[5]) for h in holders] == [("p", HIDDEN, False)]
    # Without the set of known ids (legacy call) only isPrivileged roles are yielded.
    assert list(directory_role_principals([{"principalId": "P", "roleDefinitionId": HIDDEN}], [], {})) == []


def test_group_holding_unknown_role_becomes_privileged_with_reason(cfg):
    def hidden(e):
        e["dir_roleassignments"].append({"id": "a8", "principalId": G3, "roleDefinitionId": HIDDEN, "directoryScopeId": "/"})
    _, d = run(cfg, mutate=hidden)
    g3 = next(r for r in read(d, "privileged_groups.csv") if r["group_id"] == G3)
    assert "definition not found, treated as privileged" in g3["reasons"]
    row = next(r for r in read(d, "entra_role_assignments.csv") if r["role_definition_id"] == HIDDEN)
    assert row["role_privileged"] == "unknown" and row["pim_label"] == "permanent_active"


def test_allowlist_moves_rows_with_reason_and_warns_on_unused(cfg):
    cfg = dataclasses.replace(cfg, exception_allowlist=(
        AllowEntry(U1, "break-glass account, monitored", role="Global Administrator"),
        AllowEntry("0000000f-0000-0000-0000-000000000001", "left over"),
    ))
    info, d = run(cfg)
    assert read(d, "exceptions_entra_privileged_permanent.csv") == []
    ok = read(d, "exceptions_allowlisted.csv")
    assert [(r["exception_file"], r["principal_id"], r["allowlist_reason"]) for r in ok] == [
        ("exceptions_entra_privileged_permanent.csv", U1, "break-glass account, monitored")]
    assert info["summary"]["exceptions_allowlisted"] == 1
    assert any("0000000f-0000-0000-0000-000000000001" in w and "matched nothing" in w for w in info["warnings"])
    assert info["config"]["exception_allowlist"][0]["reason"] == "break-glass account, monitored"


def test_allowlist_role_and_scope_narrow_the_match():
    e = AllowEntry(U1, "r", role="Owner", scope="/subscriptions/x/")
    assert e.matches({"principal_id": U1.upper(), "role_name": "owner", "scope": "/subscriptions/X"})
    assert not e.matches({"principal_id": U1, "role_name": "Contributor", "scope": "/subscriptions/x"})
    assert not e.matches({"principal_id": U1, "role_name": "Owner", "scope": "/subscriptions/y"})
    assert AllowEntry(U1, "r").matches({"principal_id": U1, "role_name": "Anything", "scope": "/"})


@pytest.mark.parametrize("entry,msg", [
    ({"principal_id": "not-a-guid", "reason": "x"}, "principal_id"),
    ({"principal_id": U1}, "reason is required"),
    ({"principal_id": U1, "reason": "   "}, "reason is required"),
    ("oops", "must be a mapping"),
])
def test_allowlist_config_validation(cfg, entry, msg):
    raw = {"tenant_id": TENANT, "privileged_roles": {"privileged_admin": ["Owner"]},
           "custom_role_privileged_actions": ["*"], "exception_allowlist": [entry]}
    with pytest.raises(ConfigError, match=msg):
        parse_config(raw)


def test_review_of_deleted_group_is_reported_stale(cfg):
    info, d = run(cfg)
    stale = read(d, "access_reviews_stale.csv")
    assert [(r["definition_id"], r["target_group_id"]) for r in stale] == [
        ("dddddddd-0000-0000-0000-000000000006", "0000000b-0000-0000-0000-000000000009")]
    assert "not found" in stale[0]["detail"] and info["summary"]["access_reviews_stale"] == 1


def test_soft_deleted_orphan_is_named_but_stays_review(cfg):
    _, d = run(cfg, deleted={ORPH: {"id": ORPH, "displayName": "id-old-identity", "appId": "app-1"}})
    rows = [r for r in read(d, "assignments.csv") if r["principal_id"] == ORPH]
    assert rows and all(r["principal_type"] == "Orphaned" and r["principal_name"] == "id-old-identity"
                        and r["principal_resolution"] == "soft_deleted" and r["direct_user_result"] == "REVIEW" for r in rows)


def test_hard_deleted_orphan_unchanged(cfg):
    _, d = run(cfg)
    rows = [r for r in read(d, "assignments.csv") if r["principal_id"] == ORPH]
    assert rows and all(r["principal_resolution"] == "orphaned" and r["principal_name"] == "" for r in rows)


def test_messaging_data_owner_roles_are_sensitive_in_example_config(cfg):
    for name in ("Azure Event Hubs Data Owner", "Azure Service Bus Data Owner"):
        tier, _ = classify_tier(RoleDef(guid="x", name=name, role_type="BuiltInRole"), cfg)
        assert tier == SENSITIVE_DATA_PLANE


def test_stale_review_detected_with_graph_single_group_shape(cfg):
    # Real Graph single-group reviews carry instanceEnumerationScope = that group (v1.0-prefixed queries).
    gone = "0000000b-0000-0000-0000-000000000008"

    def real_shape(e):
        e["review_defs"].append({"id": "dddddddd-0000-0000-0000-000000000007", "displayName": "Access Review: sg-gone",
                                 "status": "InProgress",
                                 "scope": {"query": f"/v1.0/groups/{gone}/members/microsoft.graph.user", "queryType": "MicrosoftGraph"},
                                 "instanceEnumerationScope": {"query": f"/v1.0/groups/{gone}", "queryType": "MicrosoftGraph"},
                                 "settings": {"recurrence": {"pattern": {"type": "absoluteMonthly", "interval": 3}}}})
    _, d = run(cfg, mutate=real_shape)
    assert ("dddddddd-0000-0000-0000-000000000007", gone) in {
        (r["definition_id"], r["target_group_id"]) for r in read(d, "access_reviews_stale.csv")}


# ---- review shapes from Microsoft's documentation: self-review, Entra role reviews, ARM Azure role reviews -------
SUBSCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
G1 = "0000000b-0000-0000-0000-000000000001"
CONTRIBUTOR = "b24988ac-6180-42a0-ab88-20f7382dd24c"
ARM_DEF = f"{SUBSCOPE}/providers/Microsoft.Authorization/accessReviewScheduleDefinitions/arm-def-1"


def arm_definition(principal_type="user,group", role=CONTRIBUTOR, below=None, reviewers_type="Assigned"):
    scope = {"resourceId": SUBSCOPE, "principalType": principal_type, "assignmentState": "active",
             "roleDefinitionId": f"{SUBSCOPE}/providers/Microsoft.Authorization/roleDefinitions/{role}" if role else None}
    if below is not None:
        scope["includeAccessBelowResource"] = below
    return {"id": ARM_DEF, "name": "arm-def-1", "type": "Microsoft.Authorization/accessReviewScheduleDefinitions",
            "properties": {"displayName": "Azure role review", "status": "InProgress", "reviewersType": reviewers_type,
                           "reviewers": [{"principalId": U1 + " ", "principalType": "user"}], "scope": scope,
                           "settings": {"autoApplyDecisionsEnabled": False, "defaultDecisionEnabled": False,
                                        "instanceDurationInDays": 7,
                                        "recurrence": {"pattern": {"type": "absoluteMonthly", "interval": 3},
                                                       "range": {"type": "noEnd", "startDate": "2025-10-01T00:00:00Z"}}}}}


@pytest.mark.parametrize("defn,expected", [
    ({"reviewers": []}, True),                                                           # documented self-review
    ({}, True),                                                                          # reviewers omitted
    ({"stageSettings": [{"reviewers": [{"query": "/users/0000000f-0000-0000-0000-000000000001"}]}, {"reviewers": []}]}, True),
    ({"reviewers": [], "stageSettings": [{"reviewers": [{"query": "./manager"}]}]}, False),  # stages replace reviewers
])
def test_self_review_shapes(defn, expected):
    from rbac_audit.reviews import self_review
    assert bool(self_review(defn, set(), set())) is expected


def test_entra_role_review_covers_groups_holding_the_role():
    from rbac_audit.reviews import covering_reviews
    by_def = lambda q, extra=None: [{"id": "d", "scope": {"query": q, **(extra or {})}}]  # noqa: E731
    all_holders = f"/roleManagement/directory/roleDefinitions/{GA}"
    covs = covering_reviews(G2, [], by_def(all_holders), {}, {GA})
    assert covs and covs[0].kind == "entra_role" and covs[0].via == "entra_role"
    assert not covering_reviews(G2, [], by_def(all_holders), {}, {"0000000f-0000-0000-0000-000000000009"})  # other role
    users_only = ("/roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal&$filter=(isof(principal,"
                  f"'microsoft.graph.user') and roleDefinitionId eq '{GA}')")
    assert not covering_reviews(G2, [], by_def(users_only), {}, {GA})
    guests = {"@odata.type": "#microsoft.graph.principalResourceMembershipsScope",
              "principalScopes": [{"query": "/users?$filter=(userType eq 'Guest')"}],
              "resourceScopes": [{"query": all_holders}]}
    assert not covering_reviews(G2, [], [{"id": "d", "scope": guests}], {}, {GA})


@pytest.mark.parametrize("kw,scopes,covered", [
    ({}, [(f"{SUBSCOPE}/resourceGroups/rg-app", CONTRIBUTOR)], True),           # below the reviewed resource
    ({}, [(f"{SUBSCOPE}/resourceGroups/rg-app", "8e3af657-a8ff-443c-a75c-2fe8c4bcb635")], False),  # other role
    ({"role": None}, [(f"{SUBSCOPE}/resourceGroups/rg-app", "anything")], True),  # all roles
    ({"principal_type": "user"}, [(SUBSCOPE, CONTRIBUTOR)], False),             # users only: groups not reviewed
    ({"below": False}, [(f"{SUBSCOPE}/resourceGroups/rg-app", CONTRIBUTOR)], False),
    ({"below": False}, [(SUBSCOPE, CONTRIBUTOR)], True),
    ({}, [("/subscriptions/22222222-2222-2222-2222-222222222222", CONTRIBUTOR)], False),
])
def test_arm_azure_role_review_coverage(kw, scopes, covered):
    from rbac_audit.reviews import covering_reviews, from_arm_definition
    d = from_arm_definition(arm_definition(**kw))
    assert bool(covering_reviews(G1, scopes, [d], {})) is covered


def test_arm_definition_mapping():
    from rbac_audit.reviews import from_arm_definition, interval_days, self_review
    d = from_arm_definition(arm_definition())
    assert d["id"] == ARM_DEF and interval_days(d) == 90
    assert d["reviewers"] == [{"query": f"/users/{U1}"}]
    assert d["scope"]["query"].startswith(f"{SUBSCOPE}/providers/Microsoft.Authorization/roleAssignmentScheduleInstances")
    assert self_review(from_arm_definition(arm_definition(reviewers_type="Self")), set(), set())


def test_arm_review_end_to_end_with_unapplied_deny(cfg):
    def arm(e):
        e["arm_review_defs"] = {SUBSCOPE: [arm_definition()]}
        e["arm_review_instances"] = {ARM_DEF: [{"name": "arm-inst-1", "properties": {
            "status": "Completed", "startDateTime": "2025-12-01T00:00:00Z", "endDateTime": "2025-12-08T00:00:00Z"}}]}
        e["arm_review_decisions"] = {f"{ARM_DEF}/arm-inst-1": [{"name": "dec-1", "properties": {
            "decision": "Deny", "principal": {"id": G1, "displayName": "grp-platform-admins", "type": "group"},
            "reviewedBy": {"principalId": U1, "principalName": "User One", "principalType": "user"},
            "applyResult": "New", "appliedDateTime": None}}]}
    info, d = run(cfg, mutate=arm)
    rows = [r for r in read(d, "access_reviews.csv") if r["definition_id"] == ARM_DEF]
    assert [(r["group_id"], r["review_kind"], r["covers_via"], r["decisions_denied"], r["denied_unapplied"])
            for r in rows] == [(G1, "azure_resource_role", "azure_role_scope", "1", "1")]
    ex = {(r["group_id"], r["reason"]) for r in read(d, "exceptions_access_review.csv") if ARM_DEF in r["detail"]}
    # the reviewer (User One) is a member of G1, so the ARM review is also a self-review
    assert ex == {(G1, "decisions_not_applied"), (G1, "denied_still_member"), (G1, "self_review")}
    dec = next(r for r in read(d, "access_review_decisions.csv") if r["definition_id"] == ARM_DEF)
    assert dec["reviewer"] == "User One" and dec["decision"] == "Deny"


def test_entra_role_review_end_to_end(cfg):
    def entra_review(e):
        e["review_defs"].append({"id": "dddddddd-0000-0000-0000-000000000008", "displayName": "GA holders", "status": "InProgress",
                                 "scope": {"query": f"/roleManagement/directory/roleDefinitions/{GA}", "queryType": "MicrosoftGraph"},
                                 "reviewers": [{"query": f"/users/{U1}"}],
                                 "settings": {"recurrence": {"pattern": {"type": "absoluteMonthly", "interval": 3}}}})
    _, d = run(cfg, mutate=entra_review)
    covered = {r["group_id"] for r in read(d, "access_reviews.csv") if r["definition_id"].endswith("8")}
    assert covered == {G2, G3}             # active and eligible Global Administrator groups; not G1 / G4


def test_unreadable_arm_reviews_are_a_gap(cfg):
    info, _ = run(cfg, graph_errors={"arm_access_review_definitions": "HTTP 403 AuthorizationFailed"})
    s = info["summary"]
    assert s["coverage_complete"] is False
    assert any("Azure role access reviews unreadable" in m for m in s["coverage_gaps_by_area"]["access_reviews"])
    assert not any("Reader" in p for p in s["missing_graph_permissions"])


def portal_arm_review(below):
    """Shape of a review created in the portal (PIM > Azure resources > subscription > Access reviews), sanitized."""
    return {"id": f"{SUBSCOPE}/providers/Microsoft.Authorization/accessReviewScheduleDefinitions/portal-1", "name": "portal-1",
            "properties": {"displayName": "az review test", "status": "NotStarted", "reviewersType": "Assigned",
                           "reviewers": [{"principalId": U1, "principalType": "user"}],
                           "scope": {"assignmentState": None, "excludeResourceId": "", "excludeRoleDefinitionId": "",
                                     "expandNestedMemberships": True, "inactiveDuration": None,
                                     "includeAccessBelowResource": below, "includeInheritedAccess": False,
                                     "principalType": "user", "resourceId": SUBSCOPE,
                                     "roleDefinitionId": f"{SUBSCOPE}/providers/Microsoft.Authorization/roleDefinitions/{CONTRIBUTOR}"},
                           "settings": {"recurrence": {"pattern": {"interval": 3, "type": "absoluteMonthly"},
                                                       "range": {"endDate": "2027-01-08T01:22:35.458+00:00", "numberOfOccurrences": 0,
                                                                 "startDate": "2026-10-07T00:26:26.975+00:00", "type": "endDate"}},
                                        "defaultDecisionEnabled": False, "autoApplyDecisionsEnabled": False,
                                        "instanceDurationInDays": 25}}}


@pytest.mark.parametrize("below,scope,covered", [
    (False, SUBSCOPE, True),                                  # role held at the reviewed subscription itself
    (False, f"{SUBSCOPE}/resourceGroups/rg-app", False),      # portal default: access below the resource not reviewed
    (True, f"{SUBSCOPE}/resourceGroups/rg-app", True),
])
def test_portal_arm_review_users_with_nested_expansion_cover_groups(below, scope, covered):
    from rbac_audit.reviews import covering_reviews, from_arm_definition, interval_days
    d = from_arm_definition(portal_arm_review(below))
    assert interval_days(d) == 90
    assert bool(covering_reviews(G1, [(scope, CONTRIBUTOR)], [d], {})) is covered


def test_users_only_review_without_nested_expansion_does_not_cover_groups():
    from rbac_audit.reviews import covering_reviews, from_arm_definition
    item = portal_arm_review(True)
    item["properties"]["scope"]["expandNestedMemberships"] = False
    assert not covering_reviews(G1, [(SUBSCOPE, CONTRIBUTOR)], [from_arm_definition(item)], {})
