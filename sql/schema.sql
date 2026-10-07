-- rbac-audit evidence tables for Azure Database for PostgreSQL (Flexible Server). Applied once by a DB admin.
-- The collector's managed identity only needs USAGE + SELECT + INSERT: runs are never updated or deleted by it.
CREATE SCHEMA IF NOT EXISTS rbac_audit;

CREATE TABLE IF NOT EXISTS rbac_audit.runs (
    run_id            text PRIMARY KEY,            -- evidence folder name (UTC timestamp)
    tenant_id         text NOT NULL,
    run_started_utc   timestamptz NOT NULL,
    run_finished_utc  timestamptz NOT NULL,
    tool_version      text NOT NULL,
    coverage_complete boolean NOT NULL,
    manifest_sha256   text NOT NULL,               -- ties every row back to the immutable files in blob storage
    evidence_url      text NOT NULL DEFAULT '',
    summary           jsonb NOT NULL,
    loaded_at         timestamptz NOT NULL DEFAULT now()
);

-- One row per CSV row of a run; `source` is the CSV name without .csv (e.g. 'exceptions_privileged_permanent').
CREATE TABLE IF NOT EXISTS rbac_audit.run_rows (
    run_id  text NOT NULL REFERENCES rbac_audit.runs (run_id),
    source  text NOT NULL,
    row_no  integer NOT NULL,
    data    jsonb NOT NULL,
    PRIMARY KEY (run_id, source, row_no)
);
CREATE INDEX IF NOT EXISTS run_rows_source ON rbac_audit.run_rows (source, run_id);

-- Grant the collector (Entra principal name of the managed identity, created with pgaadauth_create_principal):
--   SELECT * FROM pgaadauth_create_principal('<identity name>', false, false);
--   GRANT USAGE ON SCHEMA rbac_audit TO "<identity name>";
--   GRANT SELECT, INSERT ON rbac_audit.runs, rbac_audit.run_rows TO "<identity name>";
