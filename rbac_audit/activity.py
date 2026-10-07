"""Accounts with privileged access that are disabled, never accepted their invitation, or have not signed in
for `inactive_days` (NIST AC-2(3)). Users only: privileged Azure roles held directly, privileged Entra directory roles,
and any membership or ownership of a privileged group (eligible included: a stale eligible account can still activate).

Sign-in dates need AuditLog.Read.All (and Entra ID P1+). Without it the disabled / pending-guest checks still run and the
inactivity checks are a coverage gap, never a pass.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .principals import DIRECT_USER_TYPES
from .reviews import parse_dt
from .roles import STANDARD

PERM_SIGN_IN_ACTIVITY = "AuditLog.Read.All"
_BASIC = "id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,externalUserState"
SELECT_FULL = _BASIC + ",signInActivity"
COLUMNS = ["principal_id", "principal_type", "principal_name", "upn", "reason", "detail", "account_enabled", "created",
           "last_sign_in", "days_since_sign_in", "privileged_access"]
REASONS = ["disabled", "guest_invitation_pending", "never_signed_in", "inactive"]


def privileged_users(rows: list[dict], entra_rows: list[dict], member_rows: list[dict]) -> dict[str, list[str]]:
    """user id -> human descriptions of each privileged access path."""
    out: dict[str, list[str]] = {}

    def add(pid: str, text: str) -> None:
        items = out.setdefault(pid.lower(), [])
        if text not in items:
            items.append(text)
    for r in rows:
        if r["principal_type"] in DIRECT_USER_TYPES and r["privilege_tier"] != STANDARD:
            add(r["principal_id"], f"Azure {r['role_name']} ({r['pim_label']}) at {r['scope']}")
    for r in entra_rows:
        if r["principal_type"] in DIRECT_USER_TYPES:
            add(r["principal_id"], f"Entra {r['role_name']} ({r['pim_label']})")
    for r in member_rows:
        if r["member_type"] in DIRECT_USER_TYPES:
            add(r["member_id"], f"{r['label']} of {r['privileged_group_name']}")
    return out


def last_sign_in(user: dict) -> datetime | None:
    """Latest of interactive, non-interactive and successful sign-in."""
    act = user.get("signInActivity") or {}
    seen = [parse_dt(act.get(k)) for k in ("lastSignInDateTime", "lastNonInteractiveSignInDateTime", "lastSuccessfulSignInDateTime")]
    return max((d for d in seen if d), default=None)


def evaluate(users: dict[str, dict], access: dict[str, list[str]], now: datetime, inactive_days: int,
             activity_known: bool) -> list[dict]:
    """One row per user per reason. Accounts created within the window get no never_signed_in / inactive row."""
    window = timedelta(days=inactive_days)
    rows = []
    for pid, u in sorted(users.items()):
        created, last = parse_dt(u.get("createdDateTime")), last_sign_in(u)
        guest = (u.get("userType") or "").lower() == "guest"
        found = []
        if u.get("accountEnabled") is False:
            found.append(("disabled", "account is disabled but still holds privileged access"))
        if guest and (u.get("externalUserState") or "").lower() == "pendingacceptance":
            found.append(("guest_invitation_pending", "guest has not accepted the invitation"))
        old_enough = created is None or now - created > window
        if activity_known and old_enough:
            if last is None:
                found.append(("never_signed_in", f"no recorded sign-in; account created {u.get('createdDateTime') or 'unknown'}"))
            elif now - last > window:
                found.append(("inactive", f"last sign-in {(now - last).days} days ago (threshold {inactive_days})"))
        for reason, detail in found:
            rows.append({
                "principal_id": pid, "principal_type": "Guest user" if guest else "User",
                "principal_name": u.get("displayName") or "", "upn": u.get("userPrincipalName") or "",
                "reason": reason, "detail": detail, "account_enabled": u.get("accountEnabled"),
                "created": u.get("createdDateTime") or "", "last_sign_in": last.isoformat() if last else "",
                "days_since_sign_in": (now - last).days if last else "", "privileged_access": " | ".join(access.get(pid, [])),
            })
    return rows


@dataclass
class ActivityResult:
    rows: list[dict] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    missing_permissions: set[str] = field(default_factory=set)


def check_activity(api, rows: list[dict], entra_rows: list[dict], member_rows: list[dict], now: datetime,
                   inactive_days: int) -> ActivityResult:
    res = ActivityResult()
    access = privileged_users(rows, entra_rows, member_rows)
    if not access:
        return res
    got = api.graph_batch({pid: f"/users/{pid}?$select={SELECT_FULL}" for pid in access})
    activity_known = True
    if any(status == 403 for status, _ in got.values()):
        # signInActivity is what needs AuditLog.Read.All: read the rest without it, report the gap
        activity_known = False
        res.missing_permissions.add(PERM_SIGN_IN_ACTIVITY)
        res.gaps.append(f"sign-in activity unreadable (needs {PERM_SIGN_IN_ACTIVITY}, Entra ID P1+): never_signed_in / "
                        f"inactive not evaluated for {len(access)} privileged user(s)")
        got = api.graph_batch({pid: f"/users/{pid}?$select={_BASIC}" for pid in access})
    users = {pid: body for pid, (status, body) in got.items() if status == 200 and body}
    failed = sorted(set(access) - set(users))
    if failed:
        res.gaps.append(f"{len(failed)} privileged user(s) could not be read for account status: {', '.join(failed[:5])}")
    res.rows = evaluate(users, access, now, inactive_days, activity_known)
    return res
