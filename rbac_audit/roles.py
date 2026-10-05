"""Role definitions and privilege-tier assignment."""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase

from .config import Config
from .scope import BROAD_LEVELS, guid_of

PRIVILEGED_ADMIN = "privileged_admin"
SENSITIVE_DATA_PLANE = "sensitive_data_plane"
CUSTOM_PRIVILEGED = "custom_privileged"
STANDARD = "standard"


@dataclass(frozen=True)
class RoleDef:
    guid: str
    name: str
    role_type: str  # BuiltInRole | CustomRole
    actions: tuple[str, ...] = ()


def parse_roledef(obj: dict) -> RoleDef:
    """Works for both ARG rows and ARM roleDefinition objects (same `properties` shape)."""
    p = obj.get("properties", {})
    actions = tuple(a for perm in p.get("permissions", []) for a in perm.get("actions", []))
    return RoleDef(guid_of(obj.get("id") or obj.get("name")), p.get("roleName") or "", p.get("type") or "", actions)


def privileged_action(actions, patterns) -> str | None:
    """First role action that equals a configured pattern or is a wildcard covering one."""
    for a in actions:
        for pat in patterns:
            if a.lower() == pat.lower() or fnmatchcase(pat.lower(), a.lower()):
                return a
    return None


def classify_tier(role: RoleDef | None, cfg: Config) -> tuple[str, str]:
    """Returns (tier, reason)."""
    if role is None or not role.name:
        return STANDARD, "role definition not found"
    name = role.name.lower()
    if name in {r.lower() for r in cfg.privileged_admin_roles}:
        return PRIVILEGED_ADMIN, f"role '{role.name}' in privileged_admin list"
    if role.role_type == "CustomRole":
        hit = privileged_action(role.actions, cfg.custom_role_privileged_actions)
        if hit:
            return CUSTOM_PRIVILEGED, f"custom role action '{hit}'"
    if name in {r.lower() for r in cfg.sensitive_data_plane_roles}:
        return SENSITIVE_DATA_PLANE, f"role '{role.name}' in sensitive_data_plane list"
    return STANDARD, ""


def severity(tier: str, level: str) -> str:
    if tier == STANDARD:
        return "low"
    return "high" if level in BROAD_LEVELS else "medium"
