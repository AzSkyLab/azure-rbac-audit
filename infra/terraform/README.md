# rbac-audit deployment (Terraform)

Runs the collector as a scheduled **Azure Container Apps job** under a **user-assigned managed identity** (nothing to
rotate), keeps every run in an **immutable blob container** (evidence of record) and optionally loads it into
**Azure Database for PostgreSQL Flexible Server** (for queries). Alerts go to your action groups when a run fails, is
inconclusive (`coverage_complete = false`) or does not publish.

## What it creates

| Resource | Notes |
|---|---|
| User-assigned managed identity `<prefix>-collector` | the collector's only identity |
| Reader at the tenant root management group | ARM / Resource Graph reads for every subscription |
| Graph app roles `Directory.Read.All`, `RoleManagement.Read.Directory`, `PrivilegedAccess.Read.AzureADGroup`, `AccessReview.Read.All` | read-only; the managed-identity equivalent of admin consent |
| Blob container + time-based immutability policy; Storage Blob Data Contributor on that container only | in your existing storage account |
| AcrPull on your registry (if `acr_id` set) | image pull with the same identity |
| Log Analytics workspace (unless one is given), Container Apps environment, Container Apps job | weekly by default (`schedule_cron`) |
| Scheduled query alert (if `action_group_ids` set) | on the job's one-line JSON result and on error output |

## Who can apply it

- Contributor on the resource group, and on the storage account for the container and its policy.
- **User Access Administrator** (or Owner) at the **tenant root management group** for the Reader assignment, plus on the
  storage container and registry for the data-plane roles. Root management group access often needs elevated access.
- In Entra: rights to assign Microsoft Graph application permissions (e.g. **Privileged Role Administrator**; for an
  automation principal: `AppRoleAssignment.ReadWrite.All` and `Application.Read.All`).
- Entra ID P2 or ID Governance for access reviews (otherwise reviews show as coverage gaps, never as passes).

## Steps

1. Build and push the image from the repo root: `docker build -t <acr>.azurecr.io/rbac-audit:<version> . && docker push ...`
2. `cp example.tfvars <env>.tfvars`, fill it in, then `terraform init` (with your backend) and
   `terraform apply -var-file=<env>.tfvars`.
3. PostgreSQL (if used): as an Entra admin of the server, in the target database, run `../../sql/schema.sql`, then the
   `postgres_setup_sql` output (creates the identity's role with `SELECT, INSERT` only).
4. Run once by hand and check the result:
   `az containerapp job start -n <job_name> -g <rg>`, then the job's execution logs: the last line is
   `{"event": "rbac_audit_run", "status": "complete", "coverage_complete": true, "published": {...}}`.
5. Once a few runs look right, consider `lock_immutability = true` (irreversible).

`terraform output collector_config` shows the exact config the job runs with. Collector settings (review cadence,
allowlist, privileged role lists) go in `collector_config`; they are merged over the repo's `config.example.yaml`.
