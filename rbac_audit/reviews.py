"""Phase 2c: do privileged groups have effective access reviews?

Graph shapes used (accessReviewScheduleDefinition / accessReviewInstance / accessReviewInstanceDecisionItem):
definition.scope.query, definition.instanceEnumerationScope.query, definition.reviewers[].query,
definition.settings.{recurrence, defaultDecisionEnabled, defaultDecision, autoApplyDecisionsEnabled},
instance.{status, startDateTime, endDateTime, scope.query}, decision.{decision, justification, principal,
reviewedBy, reviewedDateTime, applyResult, appliedDateTime, appliedBy}.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone

DEFS = "/v1.0/identityGovernance/accessReviews/definitions"
COMPLETED = {"completed", "applied"}
INACTIVE_STATUSES = {"completed", "stopped", "stopping"}  # definition statuses that are no longer running a review
FAILED_APPLY = {"new", "appliedwithunknownfailure", "applynotsupported"}  # applyResult values meaning "not applied"
_INTERVAL_DAYS = {"daily": 1, "weekly": 7, "absolutemonthly": 30, "relativemonthly": 30,
                  "absoluteyearly": 365, "relativeyearly": 365}  # months approximated as 30 days (quarterly = 90)
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])"

REVIEW_COLUMNS = [
    "group_id", "group_name", "definition_id", "definition_name", "review_kind", "covers_via", "scope_query",
    "definition_status", "active", "recurrence", "interval_days", "frequency_ok", "reviewers", "self_review",
    "default_decision", "default_approve", "auto_apply", "latest_instance_id", "latest_instance_status",
    "latest_instance_start", "latest_instance_end", "overdue", "latest_completed_instance_id",
    "latest_completed_end", "completed_within_frequency", "decisions_total", "decisions_denied",
    "denied_unapplied", "denied_still_member",
]
DECISION_COLUMNS = [
    "group_id", "group_name", "definition_id", "definition_name", "instance_id", "reviewee_id", "reviewee_name",
    "reviewee_upn", "resource", "reviewer", "decision", "justification", "reviewed_datetime", "recommendation",
    "apply_result", "applied_datetime", "applied_by",
]
EXCEPTION_COLUMNS = ["group_id", "group_name", "reason", "detail", "review_ids"]
REASONS = ["no_review", "frequency_too_low", "overdue", "not_completed", "decisions_not_applied",
           "denied_still_member", "self_review", "default_approve", "coverage_gap"]


def parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def definition_active(defn: dict, now: datetime) -> tuple[bool, str]:
    """A stopped/completed definition, or one whose recurrence range has ended, is not running reviews any more."""
    status = (defn.get("status") or "").lower()
    if status in INACTIVE_STATUSES:
        return False, f"definition status {defn.get('status')}"
    rng = ((defn.get("settings") or {}).get("recurrence") or {}).get("range") or {}
    if (rng.get("type") or "").lower() == "enddate" and rng.get("endDate"):
        try:
            if date.fromisoformat(str(rng["endDate"])[:10]) < now.date():
                return False, f"recurrence range ended {rng['endDate']}"
        except ValueError:
            pass
    return True, ""


def decision_applied(item: dict) -> bool:
    """A decision counts as applied only if appliedDateTime is set and applyResult is not a failure."""
    return bool(item.get("appliedDateTime")) and (item.get("applyResult") or "").lower() not in FAILED_APPLY


def _q(obj: dict | None) -> str:
    return ((obj or {}).get("query") or "").lower()


def review_kind(query: str) -> str:
    q = query.lower()
    if "/privilegedaccess/group/" in q:
        return "pim_for_groups"
    if "/providers/microsoft.authorization/" in q:
        return "azure_resource_role"
    if "/groups" in q:
        return "group_membership"
    return "other"


def interval_days(defn: dict) -> int | None:
    """Days between review cycles, None for a one-time (non-recurring) review."""
    rec = (defn.get("settings") or {}).get("recurrence") or {}
    pattern = rec.get("pattern") or {}
    unit = _INTERVAL_DAYS.get((pattern.get("type") or "").lower())
    if not unit:
        return None
    return unit * int(pattern.get("interval") or 1)


def recurrence_text(defn: dict) -> str:
    rec = (defn.get("settings") or {}).get("recurrence") or {}
    p = rec.get("pattern") or {}
    return f"{p.get('type')} x{p.get('interval')}" if p.get("type") else "one-time"


def _excludes_groups(query: str) -> bool:
    m = re.search(r"principaltype\s+eq\s+'(\w+)'", query)
    return bool(m) and m.group(1) != "group"


@dataclass
class Coverage:
    group_id: str
    defn: dict
    instances: list[dict]
    kind: str
    via: str


def covering_reviews(group_id: str, role_scopes: list[str], defs: list[dict],
                     instances_by_def: dict[str, list[dict]]) -> list[Coverage]:
    gid = group_id.lower()
    out = []
    for d in defs:
        insts = instances_by_def.get(d["id"], [])
        dq = _q(d.get("scope"))
        if d.get("instanceEnumerationScope"):  # one instance per enumerated group: match on instance scope
            mine = [i for i in insts if gid in _q(i.get("scope"))]
            if mine:
                out.append(Coverage(gid, d, mine, review_kind(_q(mine[0].get("scope"))), "instance_scope"))
            continue
        if gid in dq and review_kind(dq) != "azure_resource_role":
            out.append(Coverage(gid, d, insts, review_kind(dq), "definition_scope"))
        elif review_kind(dq) == "azure_resource_role" and not _excludes_groups(dq):
            prefix = dq.split("/providers/microsoft.authorization")[0].rstrip("/")
            if gid in dq:
                out.append(Coverage(gid, d, insts, "azure_resource_role", "principal_filter"))
            elif any(s.lower().rstrip("/") == prefix or s.lower().startswith(prefix + "/") for s in role_scopes):
                out.append(Coverage(gid, d, insts, "azure_resource_role", "azure_role_scope"))
    return out


def latest_started(insts: list[dict], now: datetime) -> dict | None:
    started = [i for i in insts if (parse_dt(i.get("startDateTime")) or now) <= now]
    return max(started, key=lambda i: parse_dt(i.get("startDateTime")) or datetime.min.replace(tzinfo=timezone.utc), default=None)


def latest_completed(insts: list[dict]) -> dict | None:
    done = [i for i in insts if (i.get("status") or "").lower() in COMPLETED]
    return max(done, key=lambda i: parse_dt(i.get("endDateTime")) or datetime.min.replace(tzinfo=timezone.utc), default=None)


def decisions_needed(coverages: list[Coverage]) -> set[tuple[str, str]]:
    return {(c.defn["id"], i["id"]) for c in coverages if (i := latest_completed(c.instances))}


def self_review(defn: dict, member_ids: set[str], group_ids: set[str]) -> str:
    for r in defn.get("reviewers") or []:
        q = _q(r)
        if q in ("./members", "./", "."):
            return "reviewers are the reviewees themselves"
        m = re.match(rf"/users/({_UUID})", q)
        if m and m.group(1) in member_ids:
            return f"reviewer {m.group(1)} is a member of the group under review"
        m = re.search(rf"/groups/({_UUID})/(?:transitive)?members", q)
        if m and m.group(1) in group_ids:
            return f"reviewers are members of {m.group(1)}, a group in the reviewed membership"
    return ""


def reviewers_text(defn: dict) -> str:
    return "; ".join(_q(r) for r in defn.get("reviewers") or []) or "(none)"


@dataclass
class ReviewResult:
    reviews: list[dict] = field(default_factory=list)
    decisions: list[dict] = field(default_factory=list)
    exceptions: list[dict] = field(default_factory=list)


def evaluate(groups: dict, coverages: dict[str, list[Coverage]], decisions: dict[tuple[str, str], list[dict] | None],
             member_rows: list[dict], role_rows: list[dict], now: datetime, freq_days: int,
             unreadable_defs: list[dict] | None = None) -> ReviewResult:
    """`groups`: id -> PrivilegedGroup. `decisions`: (definition, instance) -> items, or None if unreadable.
    `unreadable_defs`: definitions whose instances could not be read; whatever depends on them is a coverage_gap."""
    res = ReviewResult()
    window = timedelta(days=freq_days)
    unreadable = {d["id"]: d for d in unreadable_defs or []}
    for gid, group in groups.items():
        gname = group.name
        mrows = [r for r in member_rows if gid in r["group_path_ids"].split(";")]
        member_ids = {r["member_id"] for r in mrows if r["member_type"] != "Group"}
        group_ids = {gid} | {i for r in mrows for i in r["group_path_ids"].split(";")}
        holds_role = any(r["principal_id"].lower() == gid and r["privilege_tier"] != "standard" for r in role_rows)
        covs = coverages.get(gid, [])
        flags = {r: [] for r in REASONS}
        unknown: list[str] = []
        # An enumerated (all-groups) review whose instances are unreadable might cover this group.
        for d in unreadable.values():
            if d.get("instanceEnumerationScope") and not any(c.defn["id"] == d["id"] for c in covs):
                unknown.append(f"instances of all-groups review '{d.get('displayName')}' unreadable; it may cover this group")
        qual_freq, qual_complete = set(), set()
        for c in covs:
            d, s = c.defn, c.defn.get("settings") or {}
            ids = d["id"]
            active, inactive_reason = definition_active(d, now)
            c_unknown = ids in unreadable
            if c_unknown:
                unknown.append(f"instances of review '{d.get('displayName')}' unreadable")
            days = interval_days(d)
            started, done = latest_started(c.instances, now), latest_completed(c.instances)
            overdue = active and bool(started and (started.get("status") or "").lower() == "inprogress"
                                      and (parse_dt(started.get("endDateTime")) or now) < now)
            done_end = parse_dt(done.get("endDateTime")) if done else None
            within = bool(done_end and now - done_end <= window)
            items = decisions.get((ids, done["id"]), []) if done else []
            if done and items is None:
                unknown.append(f"decisions of review '{d.get('displayName')}' instance {done['id']} unreadable")
            deny = [x for x in items or [] if (x.get("decision") or "").lower() == "deny"]
            unapplied = [x for x in deny if not decision_applied(x)]  # judged on the decisions, not on autoApply
            still = [x for x in deny if ((x.get("principal") or {}).get("id") or "").lower() in {r["member_id"] for r in mrows}
                     or (((x.get("principal") or {}).get("id") or "").lower() == gid and holds_role)]
            selfrev = self_review(d, member_ids, group_ids) if active else ""
            default_approve = active and bool(s.get("defaultDecisionEnabled")) and (s.get("defaultDecision") or "").lower() == "approve"
            frequency_ok = days is not None and days <= freq_days
            if active and frequency_ok:
                qual_freq.add(ids)
            if active and within and not c_unknown:
                qual_complete.add(ids)
            if overdue:
                flags["overdue"].append(f"{ids}: instance {started['id']} InProgress, ended {started.get('endDateTime')}")
            if unapplied:
                flags["decisions_not_applied"].append(
                    f"{ids}: {len(unapplied)} denied decision(s) without a successful apply (appliedDateTime/applyResult)")
            if still:
                flags["denied_still_member"].append(f"{ids}: " + ", ".join(
                    (x.get("principal") or {}).get("displayName") or (x.get("principal") or {}).get("id", "?") for x in still))
            if selfrev:
                flags["self_review"].append(f"{ids}: {selfrev}")
            if default_approve:
                flags["default_approve"].append(f"{ids}: no-response decision is Approve")
            res.reviews.append({
                "group_id": gid, "group_name": gname, "definition_id": ids, "definition_name": d.get("displayName", ""),
                "review_kind": c.kind, "covers_via": c.via, "scope_query": (d.get("scope") or {}).get("query", ""),
                "definition_status": d.get("status", ""), "active": active, "recurrence": recurrence_text(d),
                "interval_days": "" if days is None else days, "frequency_ok": frequency_ok,
                "reviewers": reviewers_text(d), "self_review": bool(selfrev),
                "default_decision": s.get("defaultDecision", "") if s.get("defaultDecisionEnabled") else "",
                "default_approve": default_approve, "auto_apply": bool(s.get("autoApplyDecisionsEnabled")),
                "latest_instance_id": started["id"] if started else "",
                "latest_instance_status": (started or {}).get("status", ""),
                "latest_instance_start": (started or {}).get("startDateTime", ""),
                "latest_instance_end": (started or {}).get("endDateTime", ""), "overdue": overdue,
                "latest_completed_instance_id": done["id"] if done else "",
                "latest_completed_end": (done or {}).get("endDateTime", ""), "completed_within_frequency": within,
                "decisions_total": len(items or []), "decisions_denied": len(deny), "denied_unapplied": len(unapplied),
                "denied_still_member": len(still),
            })
            for x in items or []:
                p, by = x.get("principal") or {}, x.get("reviewedBy") or {}
                res.decisions.append({
                    "group_id": gid, "group_name": gname, "definition_id": ids, "definition_name": d.get("displayName", ""),
                    "instance_id": done["id"], "reviewee_id": p.get("id", ""), "reviewee_name": p.get("displayName", ""),
                    "reviewee_upn": p.get("userPrincipalName", ""),
                    "resource": (x.get("resource") or {}).get("displayName") or (x.get("resource") or {}).get("id", ""),
                    "reviewer": by.get("displayName") or by.get("userPrincipalName") or by.get("id", ""),
                    "decision": x.get("decision", ""), "justification": x.get("justification", ""),
                    "reviewed_datetime": x.get("reviewedDateTime", ""), "recommendation": x.get("recommendation", ""),
                    "apply_result": x.get("applyResult", ""), "applied_datetime": x.get("appliedDateTime", ""),
                    "applied_by": (x.get("appliedBy") or {}).get("displayName", ""),
                })
        details = {r: " | ".join(v) for r, v in flags.items() if v}
        names = lambda ids: ", ".join(sorted(c.defn.get("displayName") or c.defn["id"] for c in covs if c.defn["id"] in ids))  # noqa: E731
        if not covs:
            if not unknown:
                details["no_review"] = "no access review covers this group (group membership, PIM for Groups or Azure role scope)"
        elif not qual_freq:
            why = "; ".join(f"{c.defn.get('displayName')} ({recurrence_text(c.defn)}"
                            + ("" if definition_active(c.defn, now)[0] else f", inactive: {definition_active(c.defn, now)[1]}") + ")"
                            for c in covs)
            details["frequency_too_low"] = f"no active covering review recurs within {freq_days} days: {why}"
            if not qual_complete and not unknown:
                details["not_completed"] = f"no active covering review has a completed instance ending within the last {freq_days} days"
        elif not (qual_freq & qual_complete) and not any(i in unreadable for i in qual_freq):
            # Some review recurs often enough, but no single review both recurs in time and completed in the window.
            details["not_completed"] = (f"review(s) recurring within {freq_days} days ({names(qual_freq)}) have no completed "
                                        f"instance ending within the last {freq_days} days")
        if unknown:
            details["coverage_gap"] = " | ".join(dict.fromkeys(unknown))
        for reason in REASONS:
            if reason in details:
                res.exceptions.append({"group_id": gid, "group_name": gname, "reason": reason, "detail": details[reason],
                                       "review_ids": ";".join(c.defn["id"] for c in covs)})
    return res
