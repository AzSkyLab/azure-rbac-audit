"""Principal typing from Microsoft Graph lookups."""
from __future__ import annotations

from dataclasses import dataclass

USER, GUEST, GROUP, SP, MI, ORPHANED = "User", "Guest user", "Group", "ServicePrincipal", "ManagedIdentity", "Orphaned"
DIRECT_USER_TYPES = frozenset({USER, GUEST})

_HINT_TYPE = {"User": USER, "Group": GROUP, "ServicePrincipal": SP, "ForeignGroup": GROUP}


@dataclass(frozen=True)
class Principal:
    id: str
    type: str
    name: str = ""
    upn_or_appid: str = ""
    resolution: str = "resolved"  # resolved | orphaned | unresolved


def graph_path(principal_id: str, hint: str | None) -> str:
    base = {"User": "/users/{}?$select=id,displayName,userPrincipalName,userType",
            "Group": "/groups/{}?$select=id,displayName",
            "ServicePrincipal": "/servicePrincipals/{}?$select=id,displayName,appId,servicePrincipalType"}
    return base.get(hint or "", "/directoryObjects/{}").format(principal_id)


def _not_found(status: int, body: dict | None) -> bool:
    code = ((body or {}).get("error") or {}).get("code", "")
    return status == 404 or code == "Request_ResourceNotFound"


def classify_principal(principal_id: str, hint: str | None, status: int | None, body: dict | None) -> Principal:
    """Combine the ARG/PIM principalType hint with the Graph response."""
    fallback = _HINT_TYPE.get(hint or "", hint or "Unknown")
    if status is not None and _not_found(status, body):
        return Principal(principal_id, ORPHANED, "", "", "orphaned")
    if status != 200 or not body:
        return Principal(principal_id, fallback, "", "", "unresolved")
    odata = (body.get("@odata.type") or "").lower()
    name = body.get("displayName") or ""
    if hint == "User" or odata.endswith("user"):
        upn = body.get("userPrincipalName") or ""
        is_guest = body.get("userType") == "Guest" or "#ext#" in upn.lower()
        return Principal(principal_id, GUEST if is_guest else USER, name, upn)
    if hint == "Group" or odata.endswith("group"):
        return Principal(principal_id, GROUP, name)
    if hint == "ServicePrincipal" or odata.endswith("serviceprincipal"):
        kind = MI if body.get("servicePrincipalType") == "ManagedIdentity" else SP
        return Principal(principal_id, kind, name, body.get("appId") or "")
    return Principal(principal_id, fallback, name, "", "unresolved")
