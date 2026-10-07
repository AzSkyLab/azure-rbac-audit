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

-- Row identity per source, the same keys as rbac_audit/changes.py, so runs can be compared.
CREATE OR REPLACE VIEW rbac_audit.row_keys AS
SELECT r.run_id, r.source, r.data,
       CASE r.source
           WHEN 'assignments'                  THEN lower(r.data->>'assignment_id')
           WHEN 'entra_role_assignments'       THEN concat_ws('|', r.data->>'assignment_id', r.data->>'state')
           WHEN 'privileged_groups'            THEN r.data->>'group_id'
           WHEN 'group_members'                THEN concat_ws('|', r.data->>'privileged_group_id', r.data->>'member_id', r.data->>'access')
           WHEN 'exceptions_access_review'     THEN concat_ws('|', r.data->>'group_id', r.data->>'reason')
           WHEN 'inactive_privileged_accounts' THEN concat_ws('|', r.data->>'principal_id', r.data->>'reason')
       END AS key
FROM rbac_audit.run_rows r
WHERE r.source IN ('assignments', 'entra_role_assignments', 'privileged_groups', 'group_members',
                   'exceptions_access_review', 'inactive_privileged_accounts');

-- Added / removed rows between the two newest fully covered runs (each run also carries its own changes.csv rows,
-- source = 'changes', computed by the collector with field-level detail).
CREATE OR REPLACE VIEW rbac_audit.latest_changes AS
WITH ranked AS (
    SELECT run_id, row_number() OVER (ORDER BY run_id DESC) AS n FROM rbac_audit.runs WHERE coverage_complete
), cur AS (
    SELECT k.* FROM rbac_audit.row_keys k JOIN ranked r ON r.run_id = k.run_id AND r.n = 1
), prev AS (
    SELECT k.* FROM rbac_audit.row_keys k JOIN ranked r ON r.run_id = k.run_id AND r.n = 2
)
SELECT coalesce(cur.source, prev.source) AS source,
       CASE WHEN prev.key IS NULL THEN 'added' ELSE 'removed' END AS change,
       coalesce(cur.key, prev.key) AS key,
       coalesce(cur.data, prev.data) AS data
FROM cur FULL OUTER JOIN prev ON cur.source = prev.source AND cur.key = prev.key
WHERE cur.key IS NULL OR prev.key IS NULL;

-- Grant the collector (Entra principal name of the managed identity, created with pgaadauth_create_principal):
--   SELECT * FROM pgaadauth_create_principal('<identity name>', false, false);
--   GRANT USAGE ON SCHEMA rbac_audit TO "<identity name>";
--   GRANT SELECT, INSERT ON rbac_audit.runs, rbac_audit.run_rows TO "<identity name>";
