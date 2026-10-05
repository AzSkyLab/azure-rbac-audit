"""Config loading. All environment-specific values come from here."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

_GUID = re.compile(r"^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$", re.I)
_NIL_GUID = "00000000-0000-0000-0000-000000000000"


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Config:
    tenant_id: str
    subscriptions: tuple[str, ...]
    management_groups: tuple[str, ...]
    include_inherited: bool
    scan_resource_groups: bool
    output_dir: Path
    review_frequency_days: int
    privileged_admin_roles: tuple[str, ...]
    sensitive_data_plane_roles: tuple[str, ...]
    custom_role_privileged_actions: tuple[str, ...]

    def public_dict(self) -> dict:
        """Config echo for the manifest. Holds no secrets by construction."""
        return {
            "tenant_id": self.tenant_id,
            "subscriptions": list(self.subscriptions),
            "management_groups": list(self.management_groups),
            "include_inherited": self.include_inherited,
            "scan_resource_groups": self.scan_resource_groups,
            "review_frequency_days": self.review_frequency_days,
            "privileged_admin_roles": list(self.privileged_admin_roles),
            "sensitive_data_plane_roles": list(self.sensitive_data_plane_roles),
            "custom_role_privileged_actions": list(self.custom_role_privileged_actions),
        }


def _strs(value, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{name} must be a list of strings")
    return tuple(value)


def parse_config(raw: dict) -> Config:
    if not isinstance(raw, dict):
        raise ConfigError("config must be a YAML mapping")
    tenant = str(raw.get("tenant_id", ""))
    if not _GUID.match(tenant) or tenant == _NIL_GUID:
        raise ConfigError("tenant_id must be set to a real tenant GUID")
    scope = raw.get("scope") or {}
    subs = _strs(scope.get("subscriptions"), "scope.subscriptions")
    for s in subs:
        if not _GUID.match(s):
            raise ConfigError(f"scope.subscriptions entry is not a GUID: {s}")
    roles = raw.get("privileged_roles") or {}
    freq = raw.get("review_frequency_days", 90)
    if not isinstance(freq, int) or freq <= 0:
        raise ConfigError("review_frequency_days must be a positive integer")
    admin = _strs(roles.get("privileged_admin"), "privileged_roles.privileged_admin")
    data_plane = _strs(roles.get("sensitive_data_plane"), "privileged_roles.sensitive_data_plane")
    custom = _strs(raw.get("custom_role_privileged_actions"), "custom_role_privileged_actions")
    if not (admin and custom):
        raise ConfigError("privileged_roles.privileged_admin and custom_role_privileged_actions must be set "
                          "(see config.example.yaml); empty lists would classify everything as standard")
    return Config(
        tenant_id=tenant.lower(),
        subscriptions=tuple(s.lower() for s in subs),
        management_groups=_strs(scope.get("management_groups"), "scope.management_groups"),
        include_inherited=bool(scope.get("include_inherited", True)),
        scan_resource_groups=bool(scope.get("scan_resource_groups", True)),
        output_dir=Path(raw.get("output_dir", "evidence")),
        review_frequency_days=freq,
        privileged_admin_roles=admin,
        sensitive_data_plane_roles=data_plane,
        custom_role_privileged_actions=custom,
    )


def load_config(path: str | Path) -> Config:
    with open(path, encoding="utf-8") as fh:
        return parse_config(yaml.safe_load(fh))
