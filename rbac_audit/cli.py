"""rbac-audit command line."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from . import __version__
from .api import AzureApi, RawStore
from .auth import ARM_SCOPE, get_credential, identity_from_claims, token_claims
from .collect import CollectionFailed, RunResult, new_run_dir, run_collection
from .config import ConfigError, load_config


def _collect_cmd(args) -> int:
    try:
        cfg = load_config(args.config)
    except (OSError, ConfigError) as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    cred = get_credential()
    identity = identity_from_claims(token_claims(cred.get_token(ARM_SCOPE).token))
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
    if not info["summary"]["coverage_complete"]:
        err.append("WARNING: COVERAGE INCOMPLETE - the direct-user control result (and exception lists) are "
                   "NOT conclusive. See coverage_gaps in manifest.json.")
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
