"""rbac-audit command line."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from . import __version__
from .api import AzureApi, RawStore
from .auth import build_credential, describe_identity
from .collect import CollectionFailed, RunResult, new_run_dir, run_collection
from .config import ConfigError, load_config


def _collect_cmd(args) -> int:
    try:
        cfg = load_config(args.config)
    except (OSError, ConfigError) as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    try:
        cred, auth_warnings = build_credential(cfg.auth, cfg.tenant_id)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    identity = describe_identity(cred)
    identity["auth_mode"] = cfg.auth.mode
    identity["auth_warnings"] = auth_warnings
    if (identity["tenant_id"] or "").lower() != cfg.tenant_id:
        print(f"signed in to tenant {identity['tenant_id']}, config expects {cfg.tenant_id}; refusing to run",
              file=sys.stderr)
        return 2
    started = datetime.now(timezone.utc)
    run_dir = new_run_dir(cfg, started)
    raw = RawStore(run_dir / "raw")
    try:
        result = run_collection(cfg, AzureApi(cred, raw), raw, run_dir, identity, started)
    except CollectionFailed as e:
        print(f"collection failed: {e}\npartial output sealed as {e.failed_dir} (status=failed; NOT evidence)",
              file=sys.stderr)
        return 1
    out, err = summarize(result)
    print("\n".join(out))
    if err:
        print("\n".join(err), file=sys.stderr)
    return 0


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
        err.append("WARNING: PHASE 2 COVERAGE INCOMPLETE (" + ", ".join(p2_areas) + ") - privileged-group, group-membership and "
                   "access-review results are NOT conclusive; gaps are never reported as passes.")
    if s.get("missing_graph_permissions"):
        err.append("WARNING: missing Graph permissions on the signed-in token: " + ", ".join(s["missing_graph_permissions"]))
    return out, [line for line in err if line]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="rbac-audit", description="Read-only Azure RBAC audit evidence collector")
    p.add_argument("--version", action="version", version=f"rbac-audit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect", help="collect role assignments and write an evidence folder")
    c.add_argument("--config", required=True, help="path to config yaml (e.g. config.local.yaml)")
    c.set_defaults(fn=_collect_cmd)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
