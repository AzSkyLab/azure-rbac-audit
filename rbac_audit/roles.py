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
    data_actions: tuple[str, ...] = ()
    # Permission blocks as (actions, notActions) and (dataActions, notDataActions): a notAction only applies to the
    # actions of its own block.
    blocks: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = ()
    data_blocks: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = ()


def parse_roledef(obj: dict) -> RoleDef:
    """Works for both ARG rows and ARM roleDefinition objects (same `properties` shape)."""
    p = obj.get("properties", {})
    perms = p.get("permissions", [])
    actions = tuple(a for perm in perms for a in perm.get("actions", []))
    data_actions = tuple(a for perm in perms for a in perm.get("dataActions", []))
    blocks = tuple((tuple(x.get("actions") or ()), tuple(x.get("notActions") or ())) for x in perms)
    data_blocks = tuple((tuple(x.get("dataActions") or ()), tuple(x.get("notDataActions") or ())) for x in perms)
    return RoleDef(guid_of(obj.get("id") or obj.get("name")), p.get("roleName") or "", p.get("type") or "",
                   actions, data_actions, blocks, data_blocks)


def _covers(granted: str, pattern: str) -> bool:
    return granted.lower() == pattern.lower() or fnmatchcase(pattern.lower(), granted.lower())


def privileged_action(actions, patterns, not_actions=()) -> str | None:
    """First role action that equals a configured pattern or is a wildcard covering one, unless a notAction of the same
    permission block covers that whole pattern (a partial exclusion leaves the pattern granted: conservative)."""
    for a in actions:
        for pat in patterns:
            if _covers(a, pat) and not any(_covers(n, pat) for n in not_actions):
                return a
    return None


def _granted(blocks, flat, patterns) -> str | None:
    if not blocks:  # RoleDef built without blocks (e.g. in tests): no exclusions known
        return privileged_action(flat, patterns)
    for actions, not_actions in blocks:
        hit = privileged_action(actions, patterns, not_actions)
        if hit:
            return hit
    return None


def classify_tier(role: RoleDef | None, cfg: Config) -> tuple[str, str]:
    """Returns (tier, reason)."""
    if role is None or not role.name:
        return STANDARD, "role definition not found"
    name = role.name.lower()
    if name in {r.lower() for r in cfg.privileged_admin_roles}:
        return PRIVILEGED_ADMIN, f"role '{role.name}' in privileged_admin list"
    if role.role_type == "CustomRole":
        hit = _granted(role.blocks, role.actions, cfg.custom_role_privileged_actions)
        if hit:
            return CUSTOM_PRIVILEGED, f"custom role action '{hit}'"
    if name in {r.lower() for r in cfg.sensitive_data_plane_roles}:
        return SENSITIVE_DATA_PLANE, f"role '{role.name}' in sensitive_data_plane list"
    if role.role_type == "CustomRole":
        hit = _granted(role.data_blocks, role.data_actions, cfg.custom_role_sensitive_data_actions)
        if hit:
            return SENSITIVE_DATA_PLANE, f"custom role dataAction '{hit}'"
    return STANDARD, ""


def severity(tier: str, level: str) -> str:
    if tier == STANDARD:
        return "low"
    return "high" if level in BROAD_LEVELS else "medium"
