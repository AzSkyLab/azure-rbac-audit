"""Config loading. All environment-specific values come from here."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

_GUID = re.compile(r"^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$", re.I)
_NIL_GUID = "00000000-0000-0000-0000-000000000000"
DEFAULT_SENSITIVE_DATA_ACTIONS = (
    "*",
    "Microsoft.KeyVault/vaults/secrets/*",
    "Microsoft.KeyVault/vaults/keys/*",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*",
)


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class AuthConfig:
    """How the collector signs in. `cli` reuses `az login` (also what CI uses after an OIDC `azure/login`);
    `certificate` uses an app registration + PEM key; `managed_identity` uses the Azure-hosted identity of the
    runner (client_id selects a user-assigned identity; empty = system-assigned)."""
    mode: str = "cli"
    client_id: str = ""
    certificate_path: str = ""

    def public_dict(self) -> dict:
        return {"mode": self.mode, "client_id": self.client_id, "certificate_path": self.certificate_path}


@dataclass(frozen=True)
class PublishConfig:
    """Where `publish` sends a finished run. Empty storage_account_url / postgres_host = that target is skipped."""
    storage_account_url: str = ""
    storage_container: str = ""
    storage_prefix: str = ""
    postgres_host: str = ""
    postgres_database: str = ""
    postgres_user: str = ""
    postgres_schema: str = "rbac_audit"

    def public_dict(self) -> dict:
        return dict(self.__dict__)


_IDENT = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def _publish(raw) -> PublishConfig:
    raw = raw or {}
    if not isinstance(raw, dict):
        raise ConfigError("publish must be a mapping")
    st, pg = raw.get("storage") or {}, raw.get("postgres") or {}
    url = str(st.get("account_url") or "")
    if url and not (url.startswith("https://") and st.get("container")):
        raise ConfigError("publish.storage needs an https account_url and a container")
    prefix = str(st.get("prefix") or "")
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    host, schema = str(pg.get("host") or ""), str(pg.get("schema") or "rbac_audit")
    if host and not (pg.get("database") and pg.get("user")):
        raise ConfigError("publish.postgres needs host, database and user (the Entra principal name)")
    if not _IDENT.match(schema):
        raise ConfigError("publish.postgres.schema must be a lowercase SQL identifier")
    return PublishConfig(url, str(st.get("container") or ""), prefix, host, str(pg.get("database") or ""),
                         str(pg.get("user") or ""), schema)


@dataclass(frozen=True)
class AllowEntry:
    """An accepted exception: matches rows by principal id, optionally narrowed to a role name and scope."""
    principal_id: str
    reason: str
    role: str = ""
    scope: str = ""

    def matches(self, row: dict) -> bool:
        return (row.get("principal_id", "").lower() == self.principal_id
                and (not self.role or row.get("role_name", "").lower() == self.role.lower())
                and (not self.scope or row.get("scope", "").lower().rstrip("/") == self.scope.lower().rstrip("/")))

    def public_dict(self) -> dict:
        return {"principal_id": self.principal_id, "role": self.role, "scope": self.scope, "reason": self.reason}


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
    custom_role_sensitive_data_actions: tuple[str, ...]
    entra_enabled: bool = True
    group_max_depth: int = 10
    auth: AuthConfig = AuthConfig()
    exception_allowlist: tuple[AllowEntry, ...] = ()
    publish: PublishConfig = PublishConfig()

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
            "custom_role_sensitive_data_actions": list(self.custom_role_sensitive_data_actions),
            "entra_enabled": self.entra_enabled,
            "group_max_depth": self.group_max_depth,
            "auth": self.auth.public_dict(),
            "exception_allowlist": [e.public_dict() for e in self.exception_allowlist],
            "publish": self.publish.public_dict(),
        }


def _strs(value, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{name} must be a list of strings")
    return tuple(value)


def _allowlist(value) -> tuple[AllowEntry, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ConfigError("exception_allowlist must be a list")
    out = []
    for i, e in enumerate(value):
        if not isinstance(e, dict):
            raise ConfigError(f"exception_allowlist[{i}] must be a mapping")
        pid, reason = str(e.get("principal_id") or ""), str(e.get("reason") or "").strip()
        if not _GUID.match(pid):
            raise ConfigError(f"exception_allowlist[{i}].principal_id must be a principal object id GUID")
        if not reason:
            raise ConfigError(f"exception_allowlist[{i}].reason is required (it is the recorded justification)")
        out.append(AllowEntry(pid.lower(), reason, str(e.get("role") or ""), str(e.get("scope") or "")))
    return tuple(out)


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
    data_actions = _strs(raw.get("custom_role_sensitive_data_actions"), "custom_role_sensitive_data_actions") \
        or DEFAULT_SENSITIVE_DATA_ACTIONS
    if not (admin and custom):
        raise ConfigError("privileged_roles.privileged_admin and custom_role_privileged_actions must be set "
                          "(see config.example.yaml); empty lists would classify everything as standard")
    entra = raw.get("entra") or {}
    depth = entra.get("max_group_depth", 10)
    if not isinstance(depth, int) or depth < 1:
        raise ConfigError("entra.max_group_depth must be a positive integer")
    auth_raw = raw.get("auth") or {}
    mode = str(auth_raw.get("mode", "cli")).lower()
    if mode not in ("cli", "certificate", "managed_identity"):
        raise ConfigError("auth.mode must be 'cli', 'certificate' or 'managed_identity'")
    client_id, cert = str(auth_raw.get("client_id") or ""), str(auth_raw.get("certificate_path") or "")
    if mode == "certificate":
        if not _GUID.match(client_id) or client_id == _NIL_GUID:
            raise ConfigError("auth.client_id must be the app registration's application (client) id GUID")
        if not cert:
            raise ConfigError("auth.certificate_path is required for auth.mode 'certificate'")
    if mode == "managed_identity" and client_id and (not _GUID.match(client_id) or client_id == _NIL_GUID):
        raise ConfigError("auth.client_id must be the user-assigned managed identity's client id GUID (or empty)")
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
        custom_role_sensitive_data_actions=data_actions,
        entra_enabled=bool(entra.get("enabled", True)),
        group_max_depth=depth,
        auth=AuthConfig(mode, client_id.lower(), cert),
        exception_allowlist=_allowlist(raw.get("exception_allowlist")),
        publish=_publish(raw.get("publish")),
    )


def load_config(path: str | Path) -> Config:
    with open(path, encoding="utf-8") as fh:
        return parse_config(yaml.safe_load(fh))
