output "identity_client_id" {
  value = azurerm_user_assigned_identity.collector.client_id
}

output "identity_principal_id" {
  value = azurerm_user_assigned_identity.collector.principal_id
}

output "job_name" {
  value = azurerm_container_app_job.collector.name
}

output "evidence_container_url" {
  value = "${data.azurerm_storage_account.evidence.primary_blob_endpoint}${azurerm_storage_container.evidence.name}/${var.storage_prefix}"
}

output "collector_config" {
  description = "The config the job runs with (no secrets)."
  value       = yamlencode(local.collector_config)
}

output "postgres_setup_sql" {
  description = "Run once as an Entra admin of the Flexible Server, in the target database, after sql/schema.sql."
  value       = var.postgres == null ? null : <<-SQL
    SELECT * FROM pgaadauth_create_principal_with_oid('${local.identity}', '${azurerm_user_assigned_identity.collector.principal_id}', 'service', false, false);
    GRANT USAGE ON SCHEMA ${var.postgres.schema} TO "${local.identity}";
    GRANT SELECT, INSERT ON ${var.postgres.schema}.runs, ${var.postgres.schema}.run_rows TO "${local.identity}";
  SQL
}
