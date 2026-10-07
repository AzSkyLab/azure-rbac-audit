locals {
  # Microsoft Graph application permissions the collector needs; all read-only.
  graph_roles = ["Directory.Read.All", "RoleManagement.Read.Directory", "PrivilegedAccess.Read.AzureADGroup", "AccessReview.Read.All"]
  identity    = "${var.name_prefix}-collector"

  # The collector config: the repo's config.example.yaml, the caller's overrides, then what this deployment fixes.
  base_config = yamldecode(file("${path.module}/../../config.example.yaml"))
  collector_config = merge(local.base_config, var.collector_config, {
    tenant_id  = var.tenant_id
    scope      = merge(local.base_config.scope, { subscriptions = [], management_groups = [var.tenant_id] })
    output_dir = "/evidence"
    auth       = { mode = "managed_identity", client_id = azurerm_user_assigned_identity.collector.client_id }
    publish = {
      storage = {
        account_url = data.azurerm_storage_account.evidence.primary_blob_endpoint
        container   = azurerm_storage_container.evidence.name
        prefix      = var.storage_prefix
      }
      postgres = var.postgres == null ? null : {
        host     = var.postgres.host
        database = var.postgres.database
        user     = local.identity
        schema   = var.postgres.schema
      }
    }
  })
}

data "azurerm_resource_group" "this" {
  name = var.resource_group_name
}

# ---- identity and its read-only access ------------------------------------------------------------------------
resource "azurerm_user_assigned_identity" "collector" {
  name                = local.identity
  resource_group_name = data.azurerm_resource_group.this.name
  location            = var.location
  tags                = var.tags
}

# Azure: Reader at the tenant root management group (covers every subscription and management group).
resource "azurerm_role_assignment" "reader_root" {
  scope                = "/providers/Microsoft.Management/managementGroups/${var.tenant_id}"
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.collector.principal_id
  principal_type       = "ServicePrincipal"
}

# Microsoft Graph application permissions (the equivalent of admin consent for a managed identity).
data "azuread_service_principal" "msgraph" {
  client_id = "00000003-0000-0000-c000-000000000000"
}

resource "azuread_app_role_assignment" "graph" {
  for_each            = toset(local.graph_roles)
  app_role_id         = data.azuread_service_principal.msgraph.app_role_ids[each.value]
  principal_object_id = azurerm_user_assigned_identity.collector.principal_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

resource "azurerm_role_assignment" "acr_pull" {
  count                = var.acr_id == "" ? 0 : 1
  scope                = var.acr_id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.collector.principal_id
  principal_type       = "ServicePrincipal"
}

# ---- evidence of record: immutable blob container -------------------------------------------------------------
data "azurerm_storage_account" "evidence" {
  name                = element(split("/", var.storage_account_id), 8)
  resource_group_name = element(split("/", var.storage_account_id), 4)
}

resource "azurerm_storage_container" "evidence" {
  name                  = var.storage_container_name
  storage_account_id    = var.storage_account_id
  container_access_type = "private"
}

resource "azurerm_storage_container_immutability_policy" "evidence" {
  storage_container_resource_manager_id = azurerm_storage_container.evidence.id
  immutability_period_in_days           = var.immutability_days
  protected_append_writes_all_enabled   = false
  locked                                = var.lock_immutability
}

# Write access to this container only; the immutability policy stops overwrites and deletes.
resource "azurerm_role_assignment" "evidence_writer" {
  scope                = azurerm_storage_container.evidence.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.collector.principal_id
  principal_type       = "ServicePrincipal"
}

# ---- scheduled job -------------------------------------------------------------------------------------------
resource "azurerm_log_analytics_workspace" "this" {
  count               = var.log_analytics_workspace_id == "" ? 1 : 0
  name                = "${var.name_prefix}-logs"
  resource_group_name = data.azurerm_resource_group.this.name
  location            = var.location
  sku                 = "PerGB2018"
  retention_in_days   = 90
  tags                = var.tags
}

locals {
  workspace_id = var.log_analytics_workspace_id != "" ? var.log_analytics_workspace_id : azurerm_log_analytics_workspace.this[0].id
}

resource "azurerm_container_app_environment" "this" {
  name                       = "${var.name_prefix}-env"
  resource_group_name        = data.azurerm_resource_group.this.name
  location                   = var.location
  log_analytics_workspace_id = local.workspace_id
  tags                       = var.tags
}

resource "azurerm_container_app_job" "collector" {
  name                         = "${var.name_prefix}-collector"
  resource_group_name          = data.azurerm_resource_group.this.name
  location                     = var.location
  container_app_environment_id = azurerm_container_app_environment.this.id
  replica_timeout_in_seconds   = var.timeout_seconds
  replica_retry_limit          = 0 # a retry would be a second run with its own evidence; investigate instead
  tags                         = var.tags

  schedule_trigger_config {
    cron_expression          = var.schedule_cron
    parallelism              = 1
    replica_completion_count = 1
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.collector.id]
  }

  dynamic "registry" {
    for_each = var.registry_server == "" ? [] : [var.registry_server]
    content {
      server   = registry.value
      identity = azurerm_user_assigned_identity.collector.id
    }
  }

  # Not a secret (the config holds none); a secret volume is how Container Apps mounts a file.
  secret {
    name  = "collector-config"
    value = yamlencode(local.collector_config)
  }

  template {
    container {
      name   = "rbac-audit"
      image  = var.image
      cpu    = 0.5
      memory = "1Gi"
      args   = ["collect", "--config", "/config/collector-config", "--publish", "--json"]

      volume_mounts {
        name = "config"
        path = "/config"
      }
    }

    volume {
      name         = "config"
      storage_type = "Secret"
    }
  }

  depends_on = [azurerm_role_assignment.acr_pull, azurerm_role_assignment.reader_root, azuread_app_role_assignment.graph]
}

# ---- alerting -------------------------------------------------------------------------------------------------
# Fires on a failed or inconclusive run, a publish failure, or a crash before the summary line.
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "run_problem" {
  count                = length(var.action_group_ids) == 0 ? 0 : 1
  name                 = "${var.name_prefix}-run-problem"
  resource_group_name  = data.azurerm_resource_group.this.name
  location             = var.location
  scopes               = [local.workspace_id]
  severity             = 2
  evaluation_frequency = "PT1H"
  window_duration      = "PT1H"
  description          = "rbac-audit run failed, had incomplete coverage, or did not publish its evidence."
  tags                 = var.tags

  criteria {
    query                   = <<-KQL
      ContainerAppConsoleLogs_CL
      | where ContainerJobName_s == "${azurerm_container_app_job.collector.name}"
      | extend d = iff(Log_s startswith "{", parse_json(Log_s), dynamic(null))
      | where (tostring(d.event) == "rbac_audit_run" and (tostring(d.status) != "complete" or tobool(d.coverage_complete) != true or isnotempty(tostring(d.publish_error))))
           or Log_s has_any ("config error", "collection failed", "publish failed", "Traceback")
      KQL
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0
  }

  action {
    action_groups = var.action_group_ids
  }
}
