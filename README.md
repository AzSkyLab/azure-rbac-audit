# azure-rbac-audit

Read-only evidence collector for Azure RBAC audits (NIST 800-53 AC-2/AC-5/AC-6, CIS Azure Foundations identity & access).
Uses your existing `az login` session (AzureCliCredential, falling back to DefaultAzureCredential). Stores no secrets and
never calls a create/update/delete API (enforced in `rbac_audit/api.py`).

```
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
cp config.example.yaml config.local.yaml    # set tenant_id, scopes; gitignored
.venv/bin/rbac-audit collect --config config.local.yaml
.venv/bin/pytest
```

Each run writes `evidence/<UTC timestamp>/`:

| file | content |
|---|---|
| `raw/` | untouched API responses (ARG, ARM PIM schedules, role definitions, Graph) |
| `assignments.csv` | full inventory: principal type, PIM label, privilege tier, scope level, severity, direct-user result |
| `exceptions_direct_user.csv` | active or eligible assignments held directly by a User / Guest user (header only when compliant) |
| `exceptions_privileged_permanent.csv` | privileged tier + `permanent_active` |
| `manifest.json` | run time, signed-in identity, tenant, scopes, tool version, call log, warnings, SHA-256 of every file |

Labels: `permanent_active`, `time_bound_active`, `activated`, `eligible`, plus `unverified` when PIM schedules could not be
read at that scope (see manifest `warnings`). Principal types: User, Guest user, Group, ServicePrincipal, ManagedIdentity,
Orphaned (Graph 404). Tiers: `privileged_admin`, `sensitive_data_plane`, `custom_privileged`, `standard`.

Required read access: Reader (or equivalent) on the scopes, Microsoft Graph directory read (e.g. Directory.Read.All) to resolve
principals, and permission to read PIM schedules (Role Based Access Control Administrator / Owner / User Access Administrator
at the scope). Principals Graph denies are reported as `unresolved`, never `Orphaned`.
