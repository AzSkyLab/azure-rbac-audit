variable "tenant_id" {
  description = "Entra tenant to audit; also the tenant root management group id (Reader is assigned there)."
  type        = string
}

variable "resource_group_name" {
  description = "Existing resource group for the collector's resources."
  type        = string
}

variable "location" {
  type = string
}

variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  default     = "rbac-audit"
}

variable "image" {
  description = "Collector image built from the repo Dockerfile, e.g. myacr.azurecr.io/rbac-audit:1.0.0."
  type        = string
}

variable "registry_server" {
  description = "Registry login server to pull the image with the managed identity (e.g. myacr.azurecr.io); empty for a public image."
  type        = string
  default     = ""
}

variable "acr_id" {
  description = "Resource id of that Azure Container Registry, to grant the identity AcrPull; empty to manage that outside."
  type        = string
  default     = ""
}

variable "schedule_cron" {
  description = "When the job runs (UTC cron)."
  type        = string
  default     = "0 6 * * 1" # Mondays 06:00 UTC
}

variable "timeout_seconds" {
  type    = number
  default = 3600
}

variable "storage_account_id" {
  description = "Existing storage account for the evidence of record."
  type        = string
}

variable "storage_container_name" {
  type    = string
  default = "rbac-audit-evidence"
}

variable "storage_prefix" {
  description = "Optional blob prefix inside the container, e.g. \"prod/\"."
  type        = string
  default     = ""
}

variable "immutability_days" {
  description = "Time-based retention on the evidence container: blobs cannot be modified or deleted for this many days."
  type        = number
  default     = 365
}

variable "lock_immutability" {
  description = "Lock the immutability policy. IRREVERSIBLE: the retention can then only be extended, and the container cannot be deleted while blobs are retained. Leave false until the setup is proven."
  type        = bool
  default     = false
}

variable "postgres" {
  description = "Azure Database for PostgreSQL Flexible Server to load runs into (Entra auth), or null to skip. The identity is created in the database by the SQL in the postgres_setup_sql output."
  type = object({
    host     = string
    database = string
    schema   = optional(string, "rbac_audit")
  })
  default = null
}

variable "log_analytics_workspace_id" {
  description = "Existing Log Analytics workspace for the Container Apps environment; empty to create one."
  type        = string
  default     = ""
}

variable "action_group_ids" {
  description = "Action groups notified when a run fails, is inconclusive or does not publish; empty = no alert rule."
  type        = list(string)
  default     = []
}

variable "collector_config" {
  description = "Overrides merged over config.example.yaml (e.g. review_frequency_days, exception_allowlist, privileged_roles). Scope, output_dir, auth and publish are set by this module."
  type        = any
  default     = {}
}

variable "tags" {
  type    = map(string)
  default = {}
}
