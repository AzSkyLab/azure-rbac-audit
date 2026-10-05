"""rbac-audit command line."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from . import __version__
from .api import ApiError, AzureApi, RawStore
from .auth import ARM_SCOPE, get_credential, identity_from_claims, token_claims
from .collect import collect, new_run_dir
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
        info = collect(cfg, AzureApi(cred, raw), raw, run_dir, identity, started)
    except ApiError as e:
        print(f"collection failed: {e}", file=sys.stderr)
        return 1
    print(f"evidence written to {run_dir}")
    print(json.dumps(info["summary"], indent=2))
    for w in info["warnings"]:
        print(f"WARNING: {w}", file=sys.stderr)
    return 0


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
