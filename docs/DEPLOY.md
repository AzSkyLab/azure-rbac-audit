# Deploying rbac-audit as a scheduled Azure Container Apps job

Runbook for a work tenant: image built with `az acr build`, run as a **Container Apps job** under a **user-assigned
managed identity**, evidence to an **immutable blob container**, a queryable copy in **Azure Database for PostgreSQL
Flexible Server**. Use your own IaC / CI patterns for the resources; the commands below show exactly what each needs.
(`infra/terraform/` is a reference implementation of the same.)

Placeholders: `<tenant>` tenant id, `<rg>` resource group, `<acr>` registry name, `<sa>` storage account,
`<pg>` Postgres server name, `<db>` database, `<mi>` managed identity name.

## 1. Identity

```bash
az identity create -g <rg> -n <mi>
MI_PRINCIPAL=$(az identity show -g <rg> -n <mi> --query principalId -o tsv)
MI_CLIENT=$(az identity show -g <rg> -n <mi> --query clientId -o tsv)
```

## 2. Read access (one-time, by admins)

**Azure Reader at the tenant root management group** (needs User Access Administrator or Owner there):

```bash
az role assignment create --assignee-object-id $MI_PRINCIPAL --assignee-principal-type ServicePrincipal \
  --role Reader --scope /providers/Microsoft.Management/managementGroups/<tenant>
```

**Six Microsoft Graph application permissions**, all read-only (needs Privileged Role Administrator or Global
Administrator; a managed identity has no consent button, so they are assigned directly):

```bash
GRAPH=00000003-0000-0000-c000-000000000000
GRAPH_SP=$(az ad sp show --id $GRAPH --query id -o tsv)
for p in Directory.Read.All RoleManagement.Read.Directory PrivilegedAccess.Read.AzureADGroup \
         AccessReview.Read.All AuditLog.Read.All RoleManagementPolicy.Read.AzureADGroup; do
  ROLE=$(az ad sp show --id $GRAPH --query "appRoles[?value=='$p'].id | [0]" -o tsv)
  az rest --method post --url "https://graph.microsoft.com/v1.0/servicePrincipals/$MI_PRINCIPAL/appRoleAssignments" \
    --body "{\"principalId\":\"$MI_PRINCIPAL\",\"resourceId\":\"$GRAPH_SP\",\"appRoleId\":\"$ROLE\"}"
done
```

| Permission | Used for | Without it |
|---|---|---|
| Directory.Read.All | principals, groups, members, owners, apps, credentials | most of phase 2 is a gap |
| RoleManagement.Read.Directory | Entra roles, their PIM schedules and policies | Entra role checks are gaps |
| PrivilegedAccess.Read.AzureADGroup | PIM for Groups memberships | group labels `unverified` |
| AccessReview.Read.All | access reviews | review checks are `coverage_gap` |
| AuditLog.Read.All | sign-in dates (users and service principals; needs Entra ID P1+) | inactivity checks are gaps |
| RoleManagementPolicy.Read.AzureADGroup | PIM for Groups policies | group policy checks are gaps |

Access reviews need Entra ID P2 or ID Governance. Anything missing is reported as a coverage gap (exit code 3) and
named in `missing_graph_permissions`, never as a pass.

## 3. Evidence storage (blob, immutable)

```bash
SA_ID=$(az storage account show -g <rg> -n <sa> --query id -o tsv)
az storage container create --account-name <sa> -n rbac-audit-evidence --auth-mode login
# time-based retention: blobs cannot be changed or deleted for 365 days. Leave it unlocked until runs look right;
# locking is irreversible.
az storage container immutability-policy create --account-name <sa> -c rbac-audit-evidence --period 365
az role assignment create --assignee-object-id $MI_PRINCIPAL --assignee-principal-type ServicePrincipal \
  --role "Storage Blob Data Contributor" --scope "$SA_ID/blobServices/default/containers/rbac-audit-evidence"
```

## 4. PostgreSQL (optional queryable copy)

As an Entra admin of the Flexible Server, connected to `<db>`:

```sql
\i sql/schema.sql
SELECT * FROM pgaadauth_create_principal_with_oid('<mi>', '<MI_PRINCIPAL>', 'service', false, false);
GRANT USAGE ON SCHEMA rbac_audit TO "<mi>";
GRANT SELECT, INSERT ON rbac_audit.runs, rbac_audit.run_rows TO "<mi>";
```

The collector signs in with the identity's Entra token (no password), inserts only, and never updates or deletes.
`rbac_audit.latest_changes` shows what changed between the two newest fully covered runs.

## 5. Image

```bash
az acr build --registry <acr> --image rbac-audit:<version> .        # from the repo root
ACR_ID=$(az acr show -n <acr> --query id -o tsv)
az role assignment create --assignee-object-id $MI_PRINCIPAL --assignee-principal-type ServicePrincipal \
  --role AcrPull --scope $ACR_ID
```

## 6. Config

`config.yaml` (no secrets in it):

```yaml
tenant_id: "<tenant>"
scope:
  subscriptions: []
  management_groups: ["<tenant>"]        # tenant root: every subscription and management group
  include_inherited: true
  scan_resource_groups: true
output_dir: /evidence
auth:
  mode: managed_identity
  client_id: "<MI_CLIENT>"
publish:
  storage:
    account_url: "https://<sa>.blob.core.windows.net"
    container: "rbac-audit-evidence"
  postgres:
    host: "<pg>.postgres.database.azure.com"
    database: "<db>"
    user: "<mi>"
# everything else (privileged role lists, review cadence, pim_policy, service_principals, inactive_account_days,
# exception_allowlist): copy from config.example.yaml and adjust
```

Check it locally before deploying: `rbac-audit collect --config config.yaml` fails fast on a config error (exit 2).

## 7. Container Apps job

- Image `<acr>.azurecr.io/rbac-audit:<version>`, registry pulled with the managed identity.
- Identity: the user-assigned `<mi>`.
- Get the config file into the container. With a **secret volume** (simplest; the config holds no secrets, it is just
  how Container Apps mounts a file), each secret becomes a file named after the secret, and secret names cannot contain
  a dot: store it as secret `collector-config`, mount the volume at `/config`, and set the container args to
  `collect --config /config/collector-config --publish --json`. With an Azure Files mount of `config.yaml` at `/config`,
  the image's default command (`collect --config /config/config.yaml --publish --json`) works as is.
- Trigger: schedule (e.g. `0 6 * * 1`, Mondays 06:00 UTC). Replica timeout 3600 s, **retry limit 0** (a retry would be a
  second evidence run). 0.5 vCPU / 1 GiB is plenty.

## 8. First run and checks

```bash
az containerapp job start -n <job> -g <rg>
```

The last stdout line is one JSON object: `"status": "complete"`, `"coverage_complete": true`, `"published": {...}`.

| Exit code | Meaning | Action |
|---|---|---|
| 0 | complete, fully covered, published | none |
| 1 | collection failed | read the error; nothing is evidence |
| 2 | config error or tenant mismatch | fix the config / identity |
| 3 | complete but coverage incomplete | `coverage_gaps_by_area` / `missing_graph_permissions` say what to grant |
| 4 | publish failed | evidence was collected; fix storage / Postgres access and re-run |

Then open `report.html` from the blob container
(`rbac-audit-evidence/<timestamp>/report.html`). Expect real findings on the first run (Azure's default PIM settings do
not require MFA on activation); accept deliberate ones with `exception_allowlist` (each needs a reason, and stays
visible in `exceptions_allowlisted.csv`). Alert on exit code != 0 or on the JSON line with your usual log pattern.
