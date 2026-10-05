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
| `manifest.json` | status (`complete`/`failed`), run time, signed-in identity, tenant, scopes, tool version, call log, warnings, coverage, SHA-256 of every file |
| `manifest.sha256` | `sha256sum`-format digest of `manifest.json` (also printed at the end of the run; record it out-of-band) |

Labels: `permanent_active`, `time_bound_active`, `activated`, `eligible`, plus `unverified` when PIM schedules could not be
read at that scope (see manifest `warnings`). Principal types: User, Guest user, Group, ServicePrincipal, ManagedIdentity,
Orphaned (Graph 404). Tiers: `privileged_admin`, `sensitive_data_plane`, `custom_privileged`, `standard`.

Required read access: Reader (or equivalent) on the scopes, Microsoft Graph directory read (e.g. Directory.Read.All) to resolve
principals, and permission to read PIM schedules (Role Based Access Control Administrator / Owner / User Access Administrator
at the scope). Principals Graph denies are reported as `unresolved`, never `Orphaned`.

## Coverage and known limitations

- `summary.coverage_complete` is `false` (and the CLI prints a "NOT conclusive" warning) if any PIM query, management-group
  enumeration or role-definition lookup failed, or any principal's type could not be confirmed (those are `REVIEW`, never
  `PASS`, in the direct-user control). `summary.pim_failed_scopes` lists failed `active` / `eligible` scopes.
- A run that errors part-way is sealed as `<timestamp>-FAILED/` with `status: "failed"` in its manifest; it is not evidence.
- **Known gap: eligible-only assignments at resource scope.** The PIM schedule-instance APIs return instances at-and-above
  the queried scope only (checked against a subscription and the tenant root management group: unfiltered and
  `$filter=atScope()` return identical sets, nothing from child scopes). The tool therefore queries every management group
  (including descendants of configured ones), subscription and, with `scan_resource_groups`, resource group, but not each
  resource. An eligible assignment on a single resource whose principal has no active assignment there is not reported.
  This is recorded in the manifest as `known_limitations`.
- Custom roles are tiered on `actions` (-> `custom_privileged`) and `dataActions` (-> `sensitive_data_plane`, patterns in
  `custom_role_sensitive_data_actions`). `notActions` / `notDataActions` are not subtracted (conservative).
- CSV cells starting with `= + - @ TAB CR` are prefixed with `'` to prevent spreadsheet formula injection; `raw/` is untouched.
