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
| `entra_role_assignments.csv` | every holder (any principal type) of a privileged Entra directory role, active or eligible, labelled from the directory PIM schedule instances like Azure roles |
| `exceptions_entra_privileged_permanent.csv` | Entra rows labelled `permanent_active` (standing Global Administrator and the like) |
| `exceptions_allowlisted.csv` | exception rows accepted by `exception_allowlist`, with the source file and the configured reason |
| `privileged_groups.csv` | groups computed as privileged (Azure role / Entra directory role / PIM for Groups) with reasons |
| `group_members.csv` | members and owners of each privileged group, nested groups expanded, labelled `eligible_member` / `activated_member` / `time_bound_member` / `permanent_member` / `owner` (`unverified_member` if PIM for Groups could not be read) |
| `exceptions_privileged_group_standing.csv` | users who are permanent (non-PIM) members/owners of a privileged group |
| `access_reviews.csv`, `access_review_decisions.csv` | covering access reviews per privileged group and their decisions |
| `access_reviews_stale.csv` | active reviews whose target group no longer exists (or could not be checked) |
| `exceptions_access_review.csv` | one row per group per reason: `no_review`, `frequency_too_low`, `overdue`, `not_completed`, `decisions_not_applied`, `denied_still_member`, `self_review`, `default_approve`, or `coverage_gap` when review data could not be read |
| `manifest.json` | status (`complete`/`failed`), run time, signed-in identity, tenant, scopes, tool version, call log, warnings, coverage, SHA-256 of every file |
| `manifest.sha256` | `sha256sum`-format digest of `manifest.json` (also printed at the end of the run; record it out-of-band) |

Labels: `permanent_active`, `time_bound_active`, `activated`, `eligible`, plus `unverified` when PIM schedules could not be
read at that scope (see manifest `warnings`). Principal types: User, Guest user, Group, ServicePrincipal, ManagedIdentity,
Orphaned (Graph 404; `principal_resolution` is `soft_deleted`, with the name and UPN/appId from the recycle bin, when the
object can still be restored, else `orphaned`). Tiers: `privileged_admin`, `sensitive_data_plane`, `custom_privileged`, `standard`.

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
- An Entra role definition that Graph does not list (hidden first-party roles, for example) is treated as privileged and
  named by its id (`role_privileged = unknown`), so a holder cannot drop out silently. Microsoft first-party service
  principals holding such roles show up in `exceptions_entra_privileged_permanent.csv`; accept them with the allowlist.
- CSV cells starting with `= + - @ TAB CR` are prefixed with `'` to prevent spreadsheet formula injection; `raw/` is untouched.

## Phase 2: privileged groups, PIM for Groups, access reviews

Privileged groups are *computed*: any Group holding (active or eligible) a non-standard-tier Azure role, any group holding or
eligible for an Entra directory role with `isPrivileged = true` (beta `roleDefinitions`), plus groups found to be PIM-for-Groups
managed while expanding those. Membership is walked via `/groups/{id}/members` (nested groups expanded, cycle-safe, path
recorded) merged with PIM for Groups `assignmentScheduleInstances` / `eligibilityScheduleInstances`; nested chains take the
weakest link (a permanent member of a group that is only *eligible* in the privileged group is `eligible_member`).

Access reviews (`identityGovernance/accessReviews`) cover a group if the definition scope or an instance scope names the group
(membership or PIM for Groups review) or an Azure role review's scope path is a prefix of a scope where the group holds a role
(a `principalType eq 'User'` filter excludes groups). Frequency uses `review_frequency_days` (monthly = 30 days, so quarterly = 90).

**Permissions (all read-only).** Application permissions on the collector's app registration (admin consent):
`Directory.Read.All`, `RoleManagement.Read.Directory`, `PrivilegedAccess.Read.AzureADGroup` (covers both group PIM schedule
APIs), `AccessReview.Read.All`; plus Azure **Reader** at the tenant root management group (ARM/Resource Graph). With
`auth.mode: cli` the same names apply as delegated scopes, and the Azure CLI token does **not** carry
`RoleManagement.Read.Directory`, `PrivilegedAccess.Read.AzureADGroup` or `AccessReview.Read.All`. Any 403 is recorded as a
coverage gap (`coverage_gaps_by_area`, `missing_graph_permissions`); exceptions that depend on it are
`unverified`/`coverage_gap`, never a pass.

### Accepted exceptions (`exception_allowlist`)

Entries need `principal_id` and a `reason`; `role` (exact name) and `scope` (exact, `/` for tenant-wide Entra roles)
narrow the match. Matching rows move from `exceptions_direct_user.csv`, `exceptions_privileged_permanent.csv` and
`exceptions_entra_privileged_permanent.csv` to `exceptions_allowlisted.csv`; they are never dropped. The allowlist is echoed in
the manifest config, and an entry that matches nothing is a warning so stale acceptances get cleaned up.

### Authentication

`auth.mode: cli` (default) uses the `az login` session. `auth.mode: certificate` uses
`azure.identity.CertificateCredential(tenant_id, client_id, certificate_path)` for both ARM and Graph (config:
`auth.client_id`, `auth.certificate_path`; no secrets in config; a warning is printed if the PEM is readable by anyone but
its owner). The manifest records the identity (type, appId/UPN), the Graph token's `roles` / `scp`, and
`collector_identity_read_only` (false, with a CLI warning, if any granted role or scope contains "Write").

### Creating the collector app registration

`scripts/create-collector-app.sh` sets up the certificate identity in the tenant of the current `az login` session. Run it
signed in as an admin who can grant admin consent and assign roles at the tenant root management group; it prints the tenant
ID and asks for confirmation before changing anything.

```
az login --tenant <tenant id>
bash scripts/create-collector-app.sh
```

It creates the single-tenant app `rbac-audit-collector` and its service principal, generates a self-signed RSA-4096
certificate valid for 365 days (key and cert combined in `~/.config/rbac-audit/rbac-audit-collector.pem`, mode 600, outside
the repo; the public `.crt` is uploaded as the app's credential), adds the four Graph application permissions above with admin
consent, and assigns **Reader** at the tenant root management group. Copy the printed `auth:` block into
`config.local.yaml`. It is a one-time setup, not an updater: on a re-run `az ad app create` patches the existing app of
that name, and the script then stops at `az ad sp create` because the service principal already exists. Renew the
certificate before it expires (`az ad app credential reset --id <client id> --cert @<new .crt> --append`).

### Minimal lab setup to exercise each path live

1. *Group PIM labels:* make a security group `lab-priv` hold Contributor on a resource group (so it is privileged); in Entra PIM >
   Groups > Discover groups > Make managed. Add user A as **eligible** member, user B as **permanent active** member (should hit
   `exceptions_privileged_group_standing`), user C as **time-bound active** (7 days), have A **activate**, add a permanent **owner**,
   and nest group `lab-nested` (with user D permanent) as an eligible member of `lab-priv`.
2. *Entra role path (already in the lab):* a role-assignable group holding a privileged directory role (e.g. Application
   Administrator), and one holding a non-privileged role (e.g. Directory Readers) to show it is excluded; make a group *eligible*
   for a privileged role to exercise the eligibility API.
3. *Access reviews (needs the P2/Governance licence):* (a) quarterly membership review of `lab-priv`, reviewer = an owner who is not a
   member, auto-apply on; complete one instance denying a user, check the user is removed (otherwise `denied_still_member`);
   (b) a second review of a different group with *default decision = Approve* and reviewers = *members (self review)* with a yearly
   recurrence (`default_approve`, `self_review`, `frequency_too_low`); (c) a one-day review left unreviewed for >1 day (`overdue`);
   (d) a PIM for Groups review and (e) an Azure resource role review (PIM > Azure resources > Access reviews) at the subscription;
   leave one privileged group with no review (`no_review`).
4. *Token:* run with `auth.mode: certificate` (or credentials) carrying the permissions above.

### Review-evaluation rules

- A covering review counts only if it is *active* (definition status not Completed/Stopped, recurrence range not ended;
  `access_reviews.csv` keeps inactive ones with `active=False`). One active review must both recur within
  `review_frequency_days` and have a completed instance ending inside that window; otherwise `frequency_too_low` /
  `not_completed`.
- A Deny only counts as applied if `appliedDateTime` is set and `applyResult` is not a failure (`New`,
  `AppliedWithUnknownFailure`, `ApplyNotSupported`), regardless of `autoApplyDecisionsEnabled`.
- If a covering definition's instances, or the latest decisions, cannot be read the group gets a `coverage_gap` row instead of
  a guessed `not_completed` or a silent pass.
- Nested groups reachable by several paths are re-expanded when a later path gives stronger standing (permanent beats
  eligible), so a standing exception cannot hide behind a weaker path.
