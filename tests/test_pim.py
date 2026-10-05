from rbac_audit.pim import ACTIVATED, PERMANENT_ACTIVE, TIME_BOUND_ACTIVE, ActiveIndex, label_active
from conftest import fixture


def inst(**p):
    return {"id": "x", "properties": p}


def test_activated_beats_assigned():
    assert label_active([{"assignmentType": "Assigned"}, {"assignmentType": "Activated", "endDateTime": "e"}])[0] == ACTIVATED


def test_time_bound_has_end_date():
    assert label_active([{"assignmentType": "Assigned", "endDateTime": "2030-01-01"}]) == (TIME_BOUND_ACTIVE, None, "2030-01-01")


def test_permanent_when_assigned_without_end():
    assert label_active([{"assignmentType": "Assigned", "startDateTime": "s"}]) == (PERMANENT_ACTIVE, "s", None)


def test_permanent_when_no_schedule():
    assert label_active([]) == (PERMANENT_ACTIVE, None, None)


def test_index_matches_origin_case_insensitively():
    ai = ActiveIndex(fixture("pim_active.json")["value"])
    a2 = fixture("arg_roleassignments.json")["data"][1]  # ARG says RoleAssignments, PIM says roleAssignments
    p = a2["properties"]
    m = ai.match(a2["id"], p["principalId"], p["roleDefinitionId"], p["scope"])
    assert label_active(m)[0] == ACTIVATED


def test_index_falls_back_to_principal_role_scope_key():
    ai = ActiveIndex([inst(principalId="P", roleDefinitionId="/x/roleDefinitions/R", scope="/subscriptions/s",
                           assignmentType="Assigned", endDateTime="e")])
    assert label_active(ai.match("/no/origin", "p", "/providers/Microsoft.Authorization/RoleDefinitions/r", "/subscriptions/S/"))[0] \
        == TIME_BOUND_ACTIVE
