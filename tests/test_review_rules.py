"""evaluate() rules: single-review qualification, inactive reviews, decision-based apply check, coverage gaps."""
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from rbac_audit import reviews as rv

NOW = datetime(2026, 1, 2, tzinfo=timezone.utc)
GID = "0000000b-0000-0000-0000-000000000001"
U1 = "0000000a-0000-0000-0000-000000000001"


def defn(n, name=None, status="InProgress", pattern=None, rng=None, auto=False, reviewers=None, default=None, enum=False, scope=None):
    d = {"id": f"d{n}", "displayName": name or f"review{n}", "status": status,
         "scope": {"query": scope or f"/groups/{GID}/members"},
         "reviewers": reviewers if reviewers is not None else [{"query": "./owners"}],
         "settings": {"autoApplyDecisionsEnabled": auto,
                      "defaultDecisionEnabled": bool(default), "defaultDecision": default or "None",
                      "recurrence": {"pattern": pattern, "range": rng or {"type": "noEnd"}}}}
    if enum:
        d["instanceEnumerationScope"] = {"query": "/groups"}
    return d


WEEKLY = {"type": "weekly", "interval": 1}
YEARLY = {"type": "absoluteYearly", "interval": 1}
RECENT = ("2025-12-10T00:00:00Z", "2025-12-20T00:00:00Z")   # ended 13 days before NOW
OLD = ("2025-01-01T00:00:00Z", "2025-01-10T00:00:00Z")


def inst(n, status, window, query=None):
    return {"id": f"i{n}", "status": status, "startDateTime": window[0], "endDateTime": window[1], "scope": {"query": query or f"/groups/{GID}/members"}}


def dec(decision, applied=None, result=None, pid=U1):
    return {"id": f"x-{decision}", "decision": decision, "principal": {"id": pid, "displayName": "u"}, "appliedDateTime": applied, "applyResult": result}


def run(defs, instances, decisions=None, members=(), unreadable=(), freq=90):
    groups = {GID: SimpleNamespace(name="grp")}
    covs = {GID: rv.covering_reviews(GID, [], defs, instances)}
    rows = [{"group_path_ids": GID, "member_id": m, "member_type": "User", "principal_id": "x", "privilege_tier": "standard"} for m in members]
    return rv.evaluate(groups, covs, decisions or {}, rows, [], NOW, freq, list(unreadable))


def reasons(res):
    return {e["reason"] for e in res.exceptions}


def test_one_review_that_both_recurs_and_completed_in_window_passes():
    res = run([defn(1, pattern=WEEKLY)], {"d1": [inst(1, "Completed", RECENT)]})
    assert reasons(res) == set() and res.reviews[0]["active"] is True


def test_frequency_and_completion_must_come_from_the_same_review():
    # X recurs weekly but never completed in the window; Y completed recently but only recurs yearly.
    defs = [defn(1, "X", pattern=WEEKLY), defn(2, "Y", pattern=YEARLY)]
    res = run(defs, {"d1": [inst(1, "Completed", OLD)], "d2": [inst(2, "Completed", RECENT)]})
    assert reasons(res) == {"not_completed"}
    assert "X" in next(e["detail"] for e in res.exceptions)


def test_only_infrequent_review_completed_recently_is_frequency_too_low_only():
    res = run([defn(1, pattern=YEARLY)], {"d1": [inst(1, "Completed", RECENT)]})
    assert reasons(res) == {"frequency_too_low"}


def test_infrequent_and_never_completed_raises_both():
    res = run([defn(1, pattern=YEARLY)], {"d1": [inst(1, "Completed", OLD)]})
    assert reasons(res) == {"frequency_too_low", "not_completed"}


def test_one_time_review_is_not_recurring():
    assert "frequency_too_low" in reasons(run([defn(1, pattern=None)], {"d1": [inst(1, "Completed", RECENT)]}))


@pytest.mark.parametrize("status", ["Completed", "Stopped", "stopping"])
def test_stopped_or_completed_definition_does_not_count(status):
    res = run([defn(1, status=status, pattern=WEEKLY)], {"d1": [inst(1, "Completed", RECENT)]})
    assert reasons(res) == {"frequency_too_low", "not_completed"}
    row = res.reviews[0]
    assert row["active"] is False and row["definition_status"] == status      # still listed in access_reviews.csv
    assert "inactive" in next(e["detail"] for e in res.exceptions if e["reason"] == "frequency_too_low")


def test_expired_recurrence_range_does_not_count_but_future_range_does():
    ended = {"type": "endDate", "startDate": "2024-01-01", "endDate": "2025-06-30"}
    future = {"type": "endDate", "startDate": "2024-01-01", "endDate": "2027-01-01"}
    assert "frequency_too_low" in reasons(run([defn(1, pattern=WEEKLY, rng=ended)], {"d1": [inst(1, "Completed", RECENT)]}))
    assert reasons(run([defn(1, pattern=WEEKLY, rng=future)], {"d1": [inst(1, "Completed", RECENT)]})) == set()


def test_definition_active_helper():
    assert rv.definition_active(defn(1), NOW) == (True, "")
    assert rv.definition_active(defn(1, status="Stopped"), NOW)[0] is False
    assert rv.definition_active(defn(1, rng={"type": "endDate", "endDate": "2026-01-02"}), NOW)[0] is True  # ends today: still active


def test_inactive_review_does_not_raise_self_review_or_default_approve():
    d = defn(1, status="Stopped", pattern=WEEKLY, reviewers=[{"query": "./members"}], default="Approve")
    assert not {"self_review", "default_approve"} & reasons(run([d], {"d1": [inst(1, "Completed", RECENT)]}))


@pytest.mark.parametrize("auto,decision,expected", [
    (True, dec("Deny"), True),                                                    # auto-apply on, nothing applied
    (True, dec("Deny", "2025-12-21T00:00:00Z", "AppliedWithUnknownFailure"), True),
    (True, dec("Deny", "2025-12-21T00:00:00Z", "ApplyNotSupported"), True),
    (False, dec("Deny", "2025-12-21T00:00:00Z", "New"), True),                    # timestamp but result still New
    (False, dec("Deny", "2025-12-21T00:00:00Z", "AppliedSuccessfully"), False),   # applied, auto-apply off: fine
    (True, dec("Deny", "2025-12-21T00:00:00Z", "AppliedSuccessfullyButObjectNotFound"), False),
    (True, dec("Approve"), False),                                                # approvals need no apply
])
def test_decisions_not_applied_is_judged_on_decisions_not_autoapply(auto, decision, expected):
    res = run([defn(1, pattern=WEEKLY, auto=auto)], {"d1": [inst(1, "Completed", RECENT)]}, {("d1", "i1"): [decision]})
    assert ("decisions_not_applied" in reasons(res)) is expected


def test_denied_still_member_is_independent_of_apply_status():
    applied = dec("Deny", "2025-12-21T00:00:00Z", "AppliedSuccessfully")
    res = run([defn(1, pattern=WEEKLY)], {"d1": [inst(1, "Completed", RECENT)]}, {("d1", "i1"): [applied]}, members=[U1])
    assert reasons(res) == {"denied_still_member"}


def test_unreadable_instances_give_coverage_gap_not_not_completed():
    d = defn(1, pattern=WEEKLY)
    res = run([d], {"d1": []}, unreadable=[d])
    assert reasons(res) == {"coverage_gap"}


def test_unreadable_instances_of_infrequent_review_do_not_invent_not_completed():
    d = defn(1, pattern=YEARLY)
    assert reasons(run([d], {"d1": []}, unreadable=[d])) == {"frequency_too_low", "coverage_gap"}


def test_unreadable_decisions_give_coverage_gap_not_silent_pass():
    res = run([defn(1, pattern=WEEKLY)], {"d1": [inst(1, "Completed", RECENT)]}, {("d1", "i1"): None})
    assert reasons(res) == {"coverage_gap"} and res.decisions == []


def test_unreadable_all_groups_review_blocks_no_review():
    enum = defn(9, enum=True, scope="./members")
    assert reasons(run([enum], {"d9": []}, unreadable=[enum])) == {"coverage_gap"}
    assert reasons(run([], {})) == {"no_review"}                       # nothing unreadable: genuinely uncovered


def test_review_result_has_no_dead_gaps_field():
    assert not hasattr(rv.ReviewResult(), "gaps")


def test_parse_dt_treats_naive_as_utc():
    assert rv.parse_dt("2026-01-01T00:00:00").tzinfo is not None and rv.parse_dt("2026-01-01T00:00:00Z") == rv.parse_dt("2026-01-01T00:00:00")
