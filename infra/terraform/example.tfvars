# Copy to <env>.tfvars (gitignored) and fill in.
tenant_id           = "00000000-0000-0000-0000-000000000000"
resource_group_name = "rg-security-tooling"
location            = "eastus"
image               = "myacr.azurecr.io/rbac-audit:0.1.0"
registry_server     = "myacr.azurecr.io"
acr_id              = "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.ContainerRegistry/registries/myacr"
storage_account_id  = "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<account>"
postgres = {
  host     = "<server>.postgres.database.azure.com"
  database = "<database>"
}
action_group_ids = ["/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Insights/actionGroups/<group>"]
collector_config = {
  review_frequency_days = 90
  exception_allowlist = [
    { principal_id = "<MS-PIM object id>", role = "User Access Administrator", reason = "Microsoft PIM service principal" },
  ]
}
