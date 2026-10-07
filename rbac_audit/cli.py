"""rbac-audit command line."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .api import AzureApi, RawStore
from .auth import build_credential, describe_identity
from .collect import CollectionFailed, RunResult, new_run_dir, run_collection
from .config import ConfigError, load_config

# Exit codes, so a scheduler can alert without parsing output. Exceptions found are findings, not failures.
EXIT_OK, EXIT_FAILED, EXIT_CONFIG, EXIT_INCOMPLETE, EXIT_PUBLISH = 0, 1, 2, 3, 4


def _load(args):
    """(cfg, credential, auth warnings), or None after printing a config error."""
    try:
        cfg = load_config(args.config)
        cred, warnings = build_credential(cfg.auth, cfg.tenant_id)
    except (OSError, ConfigError) as e:
        print(f"config error: {e}", file=sys.stderr)
        return None
    return cfg, cred, warnings


def _publish(cfg, cred, run_dir) -> tuple[dict | None, str | None]:
    """(result dict, None) or (None, error text)."""
    if not (cfg.publish.storage_account_url or cfg.publish.postgres_host):
        return None, "publish requested but neither publish.storage nor publish.postgres is configured"
    from .publish import PublishError, publish
    try:
        return dict(publish(run_dir, cfg.publish, cred).__dict__), None
    except PublishError as e:
        return None, str(e)
    except Exception as e:  # noqa: BLE001 - storage / database errors are reported, the evidence stays on disk
        return None, f"{type(e).__name__}: {e}"


def _publish_cmd(args) -> int:
    loaded = _load(args)
    if not loaded:
        return EXIT_CONFIG
    cfg, cred, _ = loaded
    res, err = _publish(cfg, cred, Path(args.run))
    if err:
        print(f"publish failed: {err}", file=sys.stderr)
        return EXIT_PUBLISH
    print(json.dumps({"event": "rbac_audit_publish", "run": Path(args.run).name, **res}))
    return EXIT_OK


def _diff_cmd(args) -> int:
    """Changes between two local evidence folders, as CSV on stdout. Both must still match their manifests."""
    import csv as _csv
    from .changes import COLUMNS, diff, read_tables
    from .manifest import verify_manifest
    for d in (args.old, args.new):
        if verify_manifest(Path(d)):
            print(f"{d} does not match its manifest; refusing to compare", file=sys.stderr)
            return EXIT_CONFIG
    w = _csv.DictWriter(sys.stdout, fieldnames=COLUMNS)
    w.writeheader()
    w.writerows(diff(read_tables(Path(args.old)), read_tables(Path(args.new))))
    return EXIT_OK


def _collect_cmd(args) -> int:
    loaded = _load(args)
    if not loaded:
        return EXIT_CONFIG
    cfg, cred, auth_warnings = loaded
    identity = describe_identity(cred)
    identity["auth_mode"] = cfg.auth.mode
    identity["auth_warnings"] = auth_warnings
    if (identity["tenant_id"] or "").lower() != cfg.tenant_id:
        print(f"signed in to tenant {identity['tenant_id']}, config expects {cfg.tenant_id}; refusing to run",
              file=sys.stderr)
        return EXIT_CONFIG
    started = datetime.now(timezone.utc)
    run_dir = new_run_dir(cfg, started)
    raw = RawStore(run_dir / "raw")
    try:
        result = run_collection(cfg, AzureApi(cred, raw), raw, run_dir, identity, started)
    except CollectionFailed as e:
        print(f"collection failed: {e}\npartial output sealed as {e.failed_dir} (status=failed; NOT evidence)",
              file=sys.stderr)
        if args.json:
            print(json.dumps({"event": "rbac_audit_run", "status": "failed", "error": str(e), "run_dir": str(e.failed_dir)}))
        return EXIT_FAILED
    out, err = summarize(result)
    published, publish_err = (_publish(cfg, cred, result.run_dir) if args.publish else (None, None))
    if publish_err:
        err.append(f"PUBLISH FAILED: {publish_err} (evidence kept in {result.run_dir}; retry with `rbac-audit publish`)")
    s = result.info["summary"]
    if args.json:  # one line for log pipelines (e.g. Log Analytics); warnings still go to stderr
        print(json.dumps({"event": "rbac_audit_run", "status": "complete", "run_dir": str(result.run_dir),
                          "manifest_sha256": result.manifest_sha256, "published": published,
                          "publish_error": publish_err, **{k: v for k, v in s.items() if k != "control_mapping"}}))
    else:
        print("\n".join(out))
        if published:
            print(f"published: {json.dumps(published)}")
    if err:
        print("\n".join(err), file=sys.stderr)
    if publish_err:
        return EXIT_PUBLISH
    return EXIT_OK if s["coverage_complete"] else EXIT_INCOMPLETE


def summarize(result: RunResult) -> tuple[list[str], list[str]]:
    """(stdout lines, stderr lines) for a finished run."""
    info = result.info
    out = [f"evidence written to {result.run_dir}", json.dumps(info["summary"], indent=2),
           f"manifest sha256: {result.manifest_sha256}"]
    err = [f"WARNING: {w}" for w in info["warnings"]]
    err += [f"WARNING: {w}" for w in info["signed_in_identity"].get("auth_warnings", [])]
    if info.get("collector_identity_read_only") is False:
        gt = info["signed_in_identity"].get("graph_token", {})
        bad = [p for p in gt.get("roles", []) + gt.get("scp", []) if "write" in p.lower()]
        err.append("WARNING: collector identity is NOT read-only; its Graph token carries write permissions: " + ", ".join(bad))
    s = info["summary"]
    areas = s.get("coverage_gaps_by_area", {})
    if areas.get("azure_rbac") or not s["coverage_complete"] and not areas:
        err.append("WARNING: COVERAGE INCOMPLETE - the direct-user control result (and exception lists) are "
                   "NOT conclusive. See coverage_gaps in manifest.json.")
    p2_areas = sorted(a for a in areas if a != "azure_rbac")
    if p2_areas:
        err.append("WARNING: PHASE 2 COVERAGE INCOMPLETE (" + ", ".join(p2_areas) + ") - results in these areas are NOT "
                   "conclusive; gaps are never reported as passes. See coverage_gaps_by_area in manifest.json.")
    if s.get("missing_graph_permissions"):
        err.append("WARNING: missing Graph permissions on the signed-in token: " + ", ".join(s["missing_graph_permissions"]))
    return out, [line for line in err if line]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="rbac-audit", description="Read-only Azure RBAC audit evidence collector")
    p.add_argument("--version", action="version", version=f"rbac-audit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect", help="collect role assignments and write an evidence folder")
    c.add_argument("--config", required=True, help="path to config yaml (e.g. config.local.yaml)")
    c.add_argument("--publish", action="store_true", help="after a complete run, upload / load it as configured under publish:")
    c.add_argument("--json", action="store_true", help="print one JSON line instead of the human summary")
    c.set_defaults(fn=_collect_cmd)
    pb = sub.add_parser("publish", help="upload / load an existing complete evidence folder as configured under publish:")
    pb.add_argument("--config", required=True)
    pb.add_argument("--run", required=True, help="evidence folder, e.g. evidence/20261007T002813Z")
    pb.set_defaults(fn=_publish_cmd)
    df = sub.add_parser("diff", help="privileged access changes between two evidence folders (CSV on stdout)")
    df.add_argument("old")
    df.add_argument("new")
    df.set_defaults(fn=_diff_cmd)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
