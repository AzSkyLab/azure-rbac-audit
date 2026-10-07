"""Service principals and managed identities with privileged access (AC-2, IA-5, AC-6).

Who: every service principal or managed identity holding a non-standard Azure role directly, a privileged Entra role,
or membership of a privileged group. What: client secrets that live too long, expired or soon-expiring credentials (on
the service principal and, for this tenant's apps, on the application), apps owned by another tenant (or with no
owning tenant) holding privileged access, owners of the service principal / application (an owner can add a credential
and act as it), and no sign-in within `inactive_account_days` (beta servicePrincipalSignInActivities report).
Managed identities have platform-managed credentials and no owners, so only inactivity applies to them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .principals import MI, SP
from .reviews import parse_dt
from .roles import STANDARD

SP_TYPES = {SP, MI}
# Tenants that own Microsoft's first-party service principals (e.g. MS-PIM): platform services, not third-party apps,
# so the external-app and inactivity checks skip them (credential checks still apply).
MICROSOFT_TENANTS = {"f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"}
SIGN_IN_REPORT = "/beta/reports/servicePrincipalSignInActivities"
_SP_SELECT = "id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,passwordCredentials,keyCredentials,accountEnabled"
INVENTORY_COLUMNS = ["principal_id", "principal_type", "display_name", "app_id", "sp_type", "owner_tenant", "external",
                     "microsoft_first_party",
                     "secrets", "certificates", "next_credential_expiry", "last_sign_in", "owners", "privileged_access"]
EXCEPTION_COLUMNS = ["principal_id", "principal_type", "display_name", "app_id", "reason", "detail", "privileged_access"]
REASONS = ["external_app", "secret_lifetime_too_long", "credential_expired", "credential_expiring", "has_owners",
           "never_signed_in", "inactive"]


def privileged_service_principals(rows: list[dict], entra_rows: list[dict], member_rows: list[dict]) -> dict[str, dict]:
    """id -> {"type", "access": [descriptions]}."""
    out: dict[str, dict] = {}

    def add(pid: str, kind: str, text: str) -> None:
        e = out.setdefault(pid.lower(), {"type": kind, "access": []})
        if text not in e["access"]:
            e["access"].append(text)
    for r in rows:
        if r["principal_type"] in SP_TYPES and r["privilege_tier"] != STANDARD:
            add(r["principal_id"], r["principal_type"], f"Azure {r['role_name']} ({r['pim_label']}) at {r['scope']}")
    for r in entra_rows:
        if r["principal_type"] in SP_TYPES:
            add(r["principal_id"], r["principal_type"], f"Entra {r['role_name']} ({r['pim_label']})")
    for r in member_rows:
        if r["member_type"] in SP_TYPES:
            add(r["member_id"], r["member_type"], f"{r['label']} of {r['privileged_group_name']}")
    return out


def credential_findings(creds: list[tuple[str, str, dict]], now: datetime, max_secret_days: int, warn_days: int) -> list[tuple[str, str]]:
    """creds: (where, kind 'secret'/'certificate', credential). Returns (reason, detail)."""
    out = []
    for where, kind, c in creds:
        start, end = parse_dt(c.get("startDateTime")), parse_dt(c.get("endDateTime"))
        label = f"{kind} '{c.get('displayName') or c.get('keyId') or '?'}' on the {where}"
        if end and end < now:
            out.append(("credential_expired", f"{label} expired {end.date()}"))
            continue
        if kind == "secret" and start and end and (end - start).days > max_secret_days:
            out.append(("secret_lifetime_too_long", f"{label} is valid {(end - start).days} days (limit {max_secret_days}), "
                                                    f"until {end.date()}"))
        if end and end - now <= timedelta(days=warn_days):
            out.append(("credential_expiring", f"{label} expires {end.date()}"))
    return out


@dataclass
class SpResult:
    inventory: list[dict] = field(default_factory=list)
    exceptions: list[dict] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    missing_permissions: set[str] = field(default_factory=set)


def _names(owners: list[dict]) -> list[str]:
    return [o.get("userPrincipalName") or o.get("displayName") or o.get("id", "") for o in owners]


def check_service_principals(api, rows, entra_rows, member_rows, now: datetime, tenant_id: str, cfg,
                             inactive_days: int) -> SpResult:
    res = SpResult()
    sps = privileged_service_principals(rows, entra_rows, member_rows)
    if not sps:
        return res
    got = api.graph_batch({pid: f"/servicePrincipals/{pid}?$select={_SP_SELECT}" for pid in sps})
    sp_owners = api.graph_batch({pid: f"/servicePrincipals/{pid}/owners?$select=id,displayName,userPrincipalName" for pid in sps})
    bodies = {pid: b for pid, (s, b) in got.items() if s == 200 and b}
    unread = sorted(set(sps) - set(bodies))
    if unread:
        res.gaps.append(f"{len(unread)} privileged service principal(s) could not be read: {', '.join(unread[:5])}")
    # This tenant's applications carry the credentials most service principals authenticate with.
    own_apps = {pid: b["appId"] for pid, b in bodies.items()
                if (b.get("appOwnerOrganizationId") or "").lower() == tenant_id and b.get("servicePrincipalType") == "Application"}
    apps = api.graph_batch({pid: f"/applications(appId='{app}')?$select=id,displayName,passwordCredentials,keyCredentials"
                            for pid, app in own_apps.items()}) if own_apps else {}
    app_owners = api.graph_batch({pid: f"/applications(appId='{app}')/owners?$select=id,displayName,userPrincipalName"
                                  for pid, app in own_apps.items()}) if own_apps else {}

    activity: dict[str, datetime | None] | None = None
    if inactive_days:
        items, err = api.graph_list("graph_sp_sign_in_activity", SIGN_IN_REPORT)
        if err:
            res.gaps.append(f"service principal sign-in activity unreadable ({err[:200]}); needs AuditLog.Read.All: "
                            "never_signed_in / inactive not evaluated for service principals")
            if "403" in err[:12]:
                res.missing_permissions.add("AuditLog.Read.All")
        else:
            activity = {(i.get("appId") or "").lower(): parse_dt((i.get("lastSignInActivity") or {}).get("lastSignInDateTime"))
                        for i in items}

    for pid, info in sorted(sps.items()):
        b = bodies.get(pid)
        if not b:
            continue
        kind, access = info["type"], " | ".join(info["access"])
        app_id = (b.get("appId") or "").lower()
        owner_tenant = (b.get("appOwnerOrganizationId") or "").lower()
        microsoft = owner_tenant in MICROSOFT_TENANTS
        external = kind == SP and owner_tenant != tenant_id and not microsoft
        creds = [("service principal", "secret", c) for c in b.get("passwordCredentials") or []]
        creds += [("service principal", "certificate", c) for c in b.get("keyCredentials") or []]
        owners = _names(((sp_owners.get(pid) or (None, None))[1] or {}).get("value") or [])
        if pid in own_apps:
            status, app = apps.get(pid, (None, None))
            if status == 200 and app:
                creds += [("application", "secret", c) for c in app.get("passwordCredentials") or []]
                creds += [("application", "certificate", c) for c in app.get("keyCredentials") or []]
            else:
                res.gaps.append(f"application of {b.get('displayName') or pid} unreadable (HTTP {status}); its credentials not checked")
            owners += _names(((app_owners.get(pid) or (None, None))[1] or {}).get("value") or [])
        last = activity.get(app_id) if activity is not None else None
        live_ends = [parse_dt(c.get("endDateTime")) for _, _, c in creds]
        live_ends = sorted(e for e in live_ends if e and e >= now)
        res.inventory.append({
            "principal_id": pid, "principal_type": kind, "display_name": b.get("displayName") or "", "app_id": app_id,
            "sp_type": b.get("servicePrincipalType") or "", "owner_tenant": owner_tenant, "external": external,
            "microsoft_first_party": microsoft,
            "secrets": sum(k == "secret" for _, k, _ in creds), "certificates": sum(k == "certificate" for _, k, _ in creds),
            "next_credential_expiry": live_ends[0].isoformat() if live_ends else "",
            "last_sign_in": last.isoformat() if last else "", "owners": "; ".join(dict.fromkeys(owners)), "privileged_access": access,
        })
        found = []
        if external:
            found.append(("external_app", f"owned by tenant {owner_tenant}" if owner_tenant else
                          f"no owning tenant (servicePrincipalType {b.get('servicePrincipalType')})"))
        if kind == SP:
            found += credential_findings(creds, now, cfg.max_secret_days, cfg.expiry_warning_days)
            if owners and cfg.flag_owners:
                found.append(("has_owners", f"owners can add credentials and act as it: {', '.join(dict.fromkeys(owners))}"))
        if activity is not None and not microsoft:
            if app_id not in activity or activity[app_id] is None:
                found.append(("never_signed_in", "no sign-in recorded in the service principal sign-in report"))
            elif now - activity[app_id] > timedelta(days=inactive_days):
                found.append(("inactive", f"last sign-in {(now - activity[app_id]).days} days ago (threshold {inactive_days})"))
        res.exceptions += [{"principal_id": pid, "principal_type": kind, "display_name": b.get("displayName") or "",
                            "app_id": app_id, "reason": r, "detail": d, "privileged_access": access} for r, d in found]
    return res
