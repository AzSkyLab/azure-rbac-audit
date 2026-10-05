from datetime import datetime, timezone

import pytest

from rbac_audit.entra import missing_permissions
from rbac_audit.groups import (ACTIVATED, ELIGIBLE, PERMANENT, TIME_BOUND, UNVERIFIED, combine_states, instance_state,
                               object_type, own_state, standing_exceptions, walk_group)
from rbac_audit import reviews as rv

NOW = datetime(2026, 1, 2, tzinfo=timezone.utc)
UUID_A = "0000000a-0000-0000-0000-000000000001"
UUID_G = "0000000b-0000-0000-0000-000000000001"


def test_instance_states():
    assert instance_state({"assignmentType": "Assigned"}, False) == PERMANENT
    assert instance_state({"assignmentType": "Assigned", "endDateTime": "x"}, False) == TIME_BOUND
    assert instance_state({"assignmentType": "Activated", "endDateTime": "x"}, False) == ACTIVATED
    assert instance_state({}, True) == ELIGIBLE


@pytest.mark.parametrize("chain,expected", [
    ([PERMANENT, PERMANENT], PERMANENT), ([PERMANENT, TIME_BOUND], TIME_BOUND), ([TIME_BOUND, ACTIVATED], ACTIVATED),
    ([ACTIVATED, ELIGIBLE, PERMANENT], ELIGIBLE), ([PERMANENT, UNVERIFIED], UNVERIFIED), ([], PERMANENT)])
def test_chain_weakest_link_wins(chain, expected):
    assert combine_states(chain) == expected


def test_own_state_prefers_standing_access_and_unverified_when_empty():
    assert own_state({ELIGIBLE, ACTIVATED}) == ACTIVATED and own_state({ELIGIBLE, PERMANENT}) == PERMANENT
    assert own_state(set()) == UNVERIFIED


def test_object_types():
    assert object_type({"@odata.type": "#microsoft.graph.user", "userType": "Guest"}) == "Guest user"
    assert object_type({"@odata.type": "#microsoft.graph.user", "userPrincipalName": "a#EXT#@t"}) == "Guest user"
    assert object_type({"@odata.type": "#microsoft.graph.servicePrincipal", "servicePrincipalType": "ManagedIdentity"}) == "ManagedIdentity"
    assert object_type({"@odata.type": "#microsoft.graph.group"}) == "Group" and object_type({}) == "Unknown"


def test_walk_stops_at_max_depth_and_reports_it():
    def fetch(cat, path):
        if cat == "graph_group_members":
            gid = path.split("/")[3]
            nxt = f"{int(gid, 16) + 1:032x}"
            return [{"@odata.type": "#microsoft.graph.group", "id": nxt, "displayName": "n"}], None
        return [], None
    res = walk_group("0" * 31 + "1", "root", fetch, max_depth=3)
    assert max(r["depth"] for r in res.rows) == 2 and any(f == "max_depth" for f, _, _ in res.errors)


def test_standing_exceptions_exclude_non_users():
    rows = [{"member_type": t, "state": s} for t, s in [("User", "permanent"), ("Guest user", "permanent"), ("Group", "permanent"),
                                                        ("ServicePrincipal", "permanent"), ("User", "eligible"), ("User", "unverified")]]
    assert [r["member_type"] for r in standing_exceptions(rows)] == ["User", "Guest user"]


@pytest.mark.parametrize("pattern,days", [
    ({"type": "weekly", "interval": 2}, 14), ({"type": "absoluteMonthly", "interval": 3}, 90), ({"type": "relativeMonthly", "interval": 1}, 30),
    ({"type": "absoluteYearly", "interval": 1}, 365), ({"type": "daily", "interval": 30}, 30), (None, None)])
def test_interval_days(pattern, days):
    assert rv.interval_days({"settings": {"recurrence": {"pattern": pattern}}}) == days
    assert rv.interval_days({}) is None  # one-time review


def test_review_kind():
    assert rv.review_kind("/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?$filter=x") == "pim_for_groups"
    assert rv.review_kind("/subscriptions/x/providers/Microsoft.Authorization/roleAssignments") == "azure_resource_role"
    assert rv.review_kind("/groups/x/transitiveMembers") == "group_membership"


def cover(defn, role_scopes=(), instances=()):
    return rv.covering_reviews(UUID_G, list(role_scopes), [defn], {defn["id"]: list(instances)})


def test_covering_matches_group_id_pim_group_review_and_azure_scope_rules():
    assert cover({"id": "d", "scope": {"query": f"/groups/{UUID_G}/members"}})[0].via == "definition_scope"
    pim = cover({"id": "d", "scope": {"query": f"/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?$filter=(groupId eq '{UUID_G}')"}})
    assert pim and pim[0].kind == "pim_for_groups"
    az = "/subscriptions/s1/providers/Microsoft.Authorization/roleAssignmentScheduleInstances"
    assert cover({"id": "d", "scope": {"query": az}}, ["/subscriptions/s1/resourceGroups/rg"])[0].via == "azure_role_scope"
    assert not cover({"id": "d", "scope": {"query": az}}, ["/subscriptions/s2"])                    # different subscription
    assert not cover({"id": "d", "scope": {"query": az + "?$filter=(principalType eq 'User')"}}, ["/subscriptions/s1"])
    assert cover({"id": "d", "scope": {"query": az + "?$filter=(principalType eq 'Group')"}}, ["/subscriptions/s1"])
    assert not cover({"id": "d", "scope": {"query": "/groups/00000000-0000-0000-0000-00000000dead/members"}})


def test_enumerated_review_covers_only_groups_with_an_instance():
    d = {"id": "d", "scope": {"query": "./members"}, "instanceEnumerationScope": {"query": "/groups"}}
    inst = {"id": "i", "scope": {"query": f"/groups/{UUID_G}/transitiveMembers"}}
    assert cover(d, instances=[inst])[0].via == "instance_scope"
    assert not cover(d, instances=[])


def test_latest_instance_helpers():
    insts = [{"id": "old", "status": "Completed", "startDateTime": "2025-01-01T00:00:00Z", "endDateTime": "2025-01-10T00:00:00Z"},
             {"id": "new", "status": "Applied", "startDateTime": "2025-10-01T00:00:00Z", "endDateTime": "2025-10-10T00:00:00Z"},
             {"id": "future", "status": "NotStarted", "startDateTime": "2026-06-01T00:00:00Z", "endDateTime": "2026-06-10T00:00:00Z"}]
    assert rv.latest_started(insts, NOW)["id"] == "new" and rv.latest_completed(insts)["id"] == "new"
    assert rv.latest_completed([insts[2]]) is None


@pytest.mark.parametrize("reviewers,expected", [
    ([{"query": "./members"}], True),
    ([{"query": f"/users/{UUID_A}"}], True),                     # reviewer is a member
    ([{"query": "/users/0000000a-0000-0000-0000-0000000000ff"}], False),
    ([{"query": f"/groups/{UUID_G}/transitiveMembers"}], True),
    ([{"query": "./owners"}, {"query": "./manager"}], False)])
def test_self_review_detection(reviewers, expected):
    assert bool(rv.self_review({"reviewers": reviewers}, {UUID_A}, {UUID_G})) is expected


def test_missing_permissions_parse():
    e = 'x "message":"Authorization failed due to missing permission scope A.Read.All,B.ReadWrite.All.","y"'
    assert missing_permissions(e) == ["A.Read.All"]            # ReadWrite alternatives never recommended
    assert missing_permissions("HTTP 403 nope") == []
