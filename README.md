# azure-rbac-audit

Read-only evidence collector for Azure RBAC audits (NIST 800-53 AC-2/AC-5/AC-6, CIS Azure Foundations identity & access).
Signs in with your `az login` session, an app certificate or a managed identity. Stores no secrets, and collection never
calls a create/update/delete API against Azure or Microsoft Graph (enforced in `rbac_audit/api.py`). The optional
`publish` step is the only writer: it uploads a finished run to a blob container and loads it into PostgreSQL.

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
| `inactive_privileged_accounts.csv` | privileged users that are disabled, pending guests, never signed in or inactive (AC-2(3)) |
| `pim_policies.csv`, `exceptions_pim_policy.csv` | PIM activation settings for privileged access, and where they fall short of `pim_policy` (AC-6(1)) |
| `privileged_service_principals.csv`, `exceptions_service_principal.csv` | service principals / managed identities with privileged access: credentials, owners, owning tenant, last sign-in, and their hygiene findings (IA-5) |
| `changes.csv` | privileged access added, removed or changed since the previous fully covered run |
| `report.html` | one self-contained page summarising the run for reviewers |
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
- **PIM scopes.** The tool queries the PIM schedule instances at every management group (including descendants of
  configured ones), every subscription and, with `scan_resource_groups`, every resource group. Verified live (2026-10): an
  unfiltered query at a subscription or resource group returns instances at, above **and below** it (an eligible-only
  assignment on a single resource came back from both), while a management group query returns its own level and above
  only. Resource-level eligible assignments are therefore found through their subscription; no per-resource query is
  needed.
- Custom roles are tiered on `actions` (-> `custom_privileged`) and `dataActions` (-> `sensitive_data_plane`, patterns in
  `custom_role_sensitive_data_actions`). A `notActions` / `notDataActions` entry removes a pattern only if it
  covers the whole pattern within the same permission block (`*` minus `Microsoft.Authorization/*/write` stays privileged).
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

Access reviews cover a group if:
- a Graph review (`identityGovernance/accessReviews`) names the group in its definition or instance scope (membership or PIM
  for Groups review);
- a Graph Entra role review (`/roleManagement/directory/roleDefinitions/{id}` or a `roleDefinitionId eq` filter) targets a
  privileged directory role the group holds or is eligible for, unless it is limited to users or service principals; or
- an Azure resource role review, read from ARM (`Microsoft.Authorization/accessReviewScheduleDefinitions`, per subscription:
  the API rejects management group and resource group scope), covers a scope where the group holds that role (`resourceId`
  and below, `roleDefinitionId`, a `principalType` that includes groups).

A review with no reviewers (or ARM `reviewersType: Self`), in any stage, is a self-review. Frequency uses `review_frequency_days` (monthly = 30 days, so quarterly = 90).

**Permissions (all read-only).** Application permissions on the collector's app registration (admin consent):
`Directory.Read.All`, `RoleManagement.Read.Directory`, `PrivilegedAccess.Read.AzureADGroup` (covers both group PIM schedule
APIs), `AccessReview.Read.All`, `AuditLog.Read.All` (sign-in dates for the inactive-account check; needs Entra ID P1+),
`RoleManagementPolicy.Read.AzureADGroup` (PIM for Groups policies); plus
Azure **Reader** at the tenant root management group (ARM/Resource Graph). With
`auth.mode: cli` the same names apply as delegated scopes, and the Azure CLI token does **not** carry
`RoleManagement.Read.Directory`, `PrivilegedAccess.Read.AzureADGroup` or `AccessReview.Read.All`. Any 403 is recorded as a
coverage gap (`coverage_gaps_by_area`, `missing_graph_permissions`); exceptions that depend on it are
`unverified`/`coverage_gap`, never a pass.

### Inactive and disabled privileged accounts (`inactive_privileged_accounts.csv`, AC-2(3))

Every user with privileged access (a non-standard Azure role held directly, a privileged Entra role, or membership or
ownership of a privileged group, eligible included) is checked: `disabled` (account disabled), `guest_invitation_pending`,
`never_signed_in` and `inactive` (latest interactive, non-interactive or successful sign-in older than
`inactive_account_days`, default 90; accounts newer than that are not judged). One row per user per reason, with every
privileged access path listed. Without `AuditLog.Read.All` the first two still run and the sign-in checks are a coverage
gap; `inactive_account_days: 0` turns the check off. Service principals are not covered. Microsoft refreshes
`signInActivity` with a delay, so a very recent sign-in may not show yet.

### PIM policy settings (`pim_policies.csv`, `exceptions_pim_policy.csv`, AC-6(1))

Eligibility only protects anything if activation is gated. For every privileged Azure role at each scope where it is
assigned (ARM `roleManagementPolicyAssignments`, effective rules; the tenant root `/` is not a PIM scope), every privileged
Entra role with a holder, and the member and owner policies of every PIM-managed privileged group (Graph), the tool records
whether activation needs MFA (or an authentication context), a justification and approval, its maximum duration, and
whether permanent eligible / active assignments are allowed, and reports what falls short of `pim_policy` in the config
(`activation_mfa_not_required`, `activation_justification_not_required`, `activation_approval_not_required`,
`activation_too_long`, `permanent_eligibility_allowed`, `permanent_active_assignment_allowed`). Azure's default role
settings do not require MFA on activation.

### Service principal hygiene (`privileged_service_principals.csv`, `exceptions_service_principal.csv`, IA-5)

Every service principal or managed identity holding a non-standard Azure role directly, a privileged Entra role, or
membership of a privileged group is inventoried with its credentials (on the service principal and, for this tenant's
apps, the application), owners, owning tenant and last sign-in (beta `reports/servicePrincipalSignInActivities`), and
checked for: `external_app` (owned by another tenant, or by none, e.g. legacy service principals), `secret_lifetime_too_long`
(client secret valid longer than `service_principals.max_secret_days`, default 180; certificates are not limited),
`credential_expired`, `credential_expiring` (within `expiry_warning_days`, default 30), `has_owners` (an owner can add a
credential and act as the service principal; `flag_owners: false` turns this off), `never_signed_in` and `inactive`
(`inactive_account_days`). Managed identities only get the sign-in checks. Microsoft first-party service principals
(e.g. MS-PIM) are marked `microsoft_first_party` and skip the external-app and inactivity checks. Findings honour
`exception_allowlist`.

### Changes since the previous run (`changes.csv`)

Each run is compared with the newest earlier run that is complete, had complete coverage and still matches its manifest
(so a coverage gap is never reported as access appearing or disappearing): privileged assignments, Entra role holders,
privileged groups, group members and owners, access review exceptions and inactive accounts are reported as `added`,
`removed` or `changed` (PIM label, tier, membership label, group reasons). The baseline is looked up in `output_dir`, then,
for ephemeral runners, in the `publish.storage` container (read only; each CSV is checked against that run's manifest
hash). `summary.changes_since` names the baseline. `rbac-audit diff <old> <new>` compares any two local runs, and
`sql/schema.sql` provides `rbac_audit.row_keys` and `rbac_audit.latest_changes` for the Postgres copy.

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
`auth.mode: managed_identity` uses the runner's Azure managed identity (`auth.client_id` = a user-assigned identity's client
id; empty = system-assigned): the recommended mode for a scheduled deployment, with nothing to rotate. In CI, sign in with
OIDC (`azure/login`) and use `auth.mode: cli`.

### Publishing a run (blob storage + PostgreSQL)

`rbac-audit collect --publish` (or later, `rbac-audit publish --run evidence/<timestamp>`) publishes a run only if its status
is `complete` and every file still matches the manifest hashes. Install with `pip install -e '.[publish]'`.

- **Blob storage** (`publish.storage`): every file goes to `<container>/<prefix><run>/...`, the manifest and its digest last,
  never overwriting (use a container with a time-based immutability policy: this is the evidence of record).
- **PostgreSQL** (`publish.postgres`, e.g. Azure Database for PostgreSQL Flexible Server with Entra authentication; the
  identity's Entra token is the password): one `runs` row (summary, manifest hash, evidence URL) and every CSV row as `jsonb`
  in `run_rows`, in one transaction, insert-only (a run already loaded is skipped). An admin applies `sql/schema.sql` once
  and grants the identity `SELECT, INSERT` only.

Exit codes for schedulers: `0` complete and conclusive, `1` collection failed (sealed `-FAILED` folder), `2` config or tenant
mismatch, `3` complete but coverage incomplete, `4` publish failed (evidence kept locally). Exceptions found are findings,
not failures. `--json` prints one JSON line (status, summary counts, manifest hash, publish result) for log pipelines.

The `Dockerfile` builds a non-root image whose default command is `collect --config /config/config.yaml --publish --json`;
mount the config there and set `output_dir: /evidence` (or any writable path) in it.

`infra/terraform/` deploys it as a scheduled Azure Container Apps job under a user-assigned managed identity, with the
Reader and Graph permissions, an immutable evidence container, optional PostgreSQL loading and alerting; see its README.

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
the repo; the public `.crt` is uploaded as the app's credential), adds the six Graph application permissions above with admin
consent, and assigns **Reader** at the tenant root management group. Copy the printed `auth:` block into
`config.local.yaml`. It is safe to re-run: each step checks what exists (app, service principal, certificate registered
on the app by thumbprint, permissions, admin consent, Reader) and only adds what is missing, printing which. Re-run it to
repair a removed permission or role. Before the certificate expires, run it with `--rotate-cert`: a new certificate is
generated and appended to the app (the old PEM is kept as `*.old` and keeps working until you remove its credential).

### Minimal lab setup to exercise each path live

Validated against a live tenant (2026-10); the notes are what the lab actually needed.

1. *Group PIM labels:* make security groups `lab-priv` and `lab-selfrev` hold Contributor on a resource group (so they are
   privileged). In PIM for Groups, on `lab-priv`: user A **eligible** member, user C **active** member for 7 days, nested group
   `lab-nested` (user D a plain member) **eligible** member; then A **activates**. Assignments onboard the group; there is no
   separate "make managed" call. Add user B as a **plain member** (outside PIM) and a plain **owner**: both are standing
   (`exceptions_privileged_group_standing`). The default PIM for Groups policy forbids *permanent* eligible or active
   assignments, so use an end date (e.g. 180 days): the label is the same.
2. *Entra role path:* a role-assignable group holding a privileged directory role (e.g. Application Administrator), one
   holding a non-privileged role (e.g. Guest Inviter) to show it is excluded, and a principal *eligible* for a privileged role.
3. *Access reviews (P2 / ID Governance licence):* every reviewed group needs at least one member, otherwise Graph completes the
   instance at once. (a) quarterly review of `lab-priv`, reviewer a non-member, auto-apply **off**: deny user B and stop the
   instance (`decisions_not_applied`, `denied_still_member`); (b) annual self-review of `lab-selfrev` (no reviewers) with
   no-response default Approve (`frequency_too_low`, `self_review`, `default_approve`, `not_completed`); (c) a one-time 1-day
   review of a third privileged group left unreviewed (`overdue` once it has ended) and (d) a quarterly review of it left open
   (`not_completed`); (e) an Azure resource role review in the portal (PIM > Azure resources > subscription > Access reviews) for a
   role the group holds **at the subscription itself** (the portal default excludes access below it); leave one privileged
   group with no review (`no_review`). Graph rejected Entra directory-role reviews scoped to `roleDefinitions/{id}` and
   accepted forms limited to users or service principals, which do not cover a group; and creating the ARM review through the
   API failed in this tenant, so (e) was made in the portal.
4. *Token:* run with `auth.mode: certificate` carrying the permissions above.

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
