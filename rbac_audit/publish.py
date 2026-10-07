"""Publish a finished evidence run: files to blob storage (evidence of record), rows to PostgreSQL (for queries).

This is the only part of the tool that writes, and it writes only to the configured storage container and Postgres
schema; collection itself stays read-only against Azure and Microsoft Graph (enforced in api.py).
A run is published only if its status is complete and every file still matches the manifest hashes.
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path

from .config import PublishConfig
from .manifest import DIGEST_NAME, MANIFEST_NAME, sha256_file, verify_manifest

POSTGRES_SCOPE = "https://ossrdbms-aad.database.windows.net/.default"


class PublishError(RuntimeError):
    pass


@dataclass
class PublishResult:
    blobs_uploaded: int = 0
    blobs_existing: int = 0
    rows_loaded: int = 0
    run_already_loaded: bool = False


def check_run(run_dir: Path) -> dict:
    """The run's manifest, after checking it is a complete run whose files are unchanged."""
    path = run_dir / MANIFEST_NAME
    if not path.is_file():
        raise PublishError(f"{run_dir} has no {MANIFEST_NAME}")
    info = json.loads(path.read_text(encoding="utf-8"))
    if info.get("status") != "complete":
        raise PublishError(f"{run_dir} has status {info.get('status')!r}; only complete runs are published")
    changed = verify_manifest(run_dir)
    if changed:
        raise PublishError(f"{run_dir} does not match its manifest (changed/missing/extra: {', '.join(changed[:10])})")
    recorded = (run_dir / DIGEST_NAME).read_text(encoding="utf-8").split()[0]
    if recorded != sha256_file(path):
        raise PublishError(f"{DIGEST_NAME} does not match {MANIFEST_NAME}")
    return info


def upload_blobs(run_dir: Path, container, prefix: str = "") -> tuple[int, int]:
    """Upload every file as <prefix><run>/<path>; the manifest and its digest go last, so a partial upload never looks
    complete. Existing blobs are left alone (the container is meant to be immutable). Returns (uploaded, existing)."""
    from azure.core.exceptions import ResourceExistsError

    files = sorted(p for p in run_dir.rglob("*") if p.is_file())
    last = {MANIFEST_NAME, DIGEST_NAME}
    files = [p for p in files if p.name not in last or p.parent != run_dir] + [run_dir / MANIFEST_NAME, run_dir / DIGEST_NAME]
    uploaded = existing = 0
    for p in files:
        name = f"{prefix}{run_dir.name}/{p.relative_to(run_dir).as_posix()}"
        try:
            with open(p, "rb") as fh:
                container.upload_blob(name, fh, overwrite=False)
            uploaded += 1
        except ResourceExistsError:
            existing += 1
    return uploaded, existing


# Rows loaded per CSV; everything is kept as jsonb so a column added later needs no migration.
TABLE_FILES = [
    "assignments.csv", "exceptions_direct_user.csv", "exceptions_privileged_permanent.csv", "entra_role_assignments.csv",
    "exceptions_entra_privileged_permanent.csv", "exceptions_allowlisted.csv", "privileged_groups.csv",
    "group_members.csv", "exceptions_privileged_group_standing.csv", "access_reviews.csv",
    "access_review_decisions.csv", "exceptions_access_review.csv", "access_reviews_stale.csv",
    "inactive_privileged_accounts.csv",
]


def load_postgres(run_dir: Path, info: dict, manifest_sha256: str, conn, schema: str, blob_url: str = "") -> tuple[int, bool]:
    """Insert the run and its CSV rows in one transaction. Insert-only: a run already present is skipped, never
    updated. Returns (rows inserted, already loaded). The tables come from sql/schema.sql (applied by an admin)."""
    s = info.get("summary") or {}
    with conn.transaction():
        cur = conn.cursor()
        cur.execute(
            f"INSERT INTO {schema}.runs (run_id, tenant_id, run_started_utc, run_finished_utc, tool_version, "
            "coverage_complete, manifest_sha256, evidence_url, summary) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (run_id) DO NOTHING",
            (run_dir.name, (info.get("signed_in_identity") or {}).get("tenant_id"), info.get("run_started_utc"),
             info.get("run_finished_utc"), info.get("tool_version"), s.get("coverage_complete"), manifest_sha256,
             blob_url, json.dumps(s)))
        if cur.rowcount == 0:
            return 0, True
        rows = []
        for name in TABLE_FILES:
            path = run_dir / name
            if not path.is_file():
                continue
            with open(path, newline="", encoding="utf-8") as fh:
                rows += [(run_dir.name, name.removesuffix(".csv"), i, json.dumps(r)) for i, r in enumerate(csv.DictReader(fh))]
        if rows:
            cur.executemany(f"INSERT INTO {schema}.run_rows (run_id, source, row_no, data) VALUES (%s, %s, %s, %s)", rows)
        return len(rows), False


def publish(run_dir: Path, pcfg: PublishConfig, credential, *, container=None, connect=None) -> PublishResult:
    """Verify, upload to storage, then load Postgres (each only if configured). `container` / `connect` are injectable
    for tests; by default they are built from the config with the collector's credential (no secrets)."""
    info = check_run(run_dir)
    digest = sha256_file(run_dir / MANIFEST_NAME)
    res = PublishResult()
    blob_url = ""
    if pcfg.storage_account_url:
        if container is None:
            from azure.storage.blob import ContainerClient
            container = ContainerClient(pcfg.storage_account_url, pcfg.storage_container, credential=credential)
        res.blobs_uploaded, res.blobs_existing = upload_blobs(run_dir, container, pcfg.storage_prefix)
        blob_url = f"{pcfg.storage_account_url.rstrip('/')}/{pcfg.storage_container}/{pcfg.storage_prefix}{run_dir.name}/"
    if pcfg.postgres_host:
        if connect is None:
            import psycopg

            def connect():
                token = credential.get_token(POSTGRES_SCOPE).token  # Entra token as the password
                return psycopg.connect(host=pcfg.postgres_host, dbname=pcfg.postgres_database, user=pcfg.postgres_user,
                                       password=token, sslmode="require")
        with connect() as conn:
            res.rows_loaded, res.run_already_loaded = load_postgres(run_dir, info, digest, conn, pcfg.postgres_schema, blob_url)
    return res
