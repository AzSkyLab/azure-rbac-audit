"""What changed in privileged access since the previous run (changes.csv).

The baseline is the newest earlier run that is complete *and* had complete coverage, so a gap in either run is not
reported as access appearing or disappearing. It is found in the local evidence folder, or, when that has none (e.g. an
ephemeral container), in the publish blob container, whose files are checked against that run's manifest first.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path

from .manifest import MANIFEST_NAME, verify_manifest

COLUMNS = ["source", "change", "key", "principal", "access", "field", "before", "after"]


def _who(r: dict) -> str:
    name = r.get("principal_name") or r.get("member_name") or r.get("group_name") or ""
    ident = r.get("principal_upn_or_appid") or r.get("member_upn_or_appid") or r.get("upn") or ""
    pid = r.get("principal_id") or r.get("member_id") or r.get("group_id") or ""
    return " / ".join(x for x in (name, ident) if x) or pid


# source -> (key, access description, fields whose change is reported)
SOURCES = {
    "assignments": (lambda r: r["assignment_id"].lower(),
                    lambda r: f"{r['role_name']} at {r['scope']}", ["pim_label", "privilege_tier"]),
    "entra_role_assignments": (lambda r: f"{r['assignment_id']}|{r['state']}",
                               lambda r: f"Entra {r['role_name']} at {r['scope']}", ["pim_label"]),
    "privileged_groups": (lambda r: r["group_id"], lambda r: r["reasons"], ["reason_codes"]),
    "group_members": (lambda r: f"{r['privileged_group_id']}|{r['member_id']}|{r['access']}",
                      lambda r: f"{r['access']} of {r['privileged_group_name']} via {r['path']}", ["label"]),
    "exceptions_access_review": (lambda r: f"{r['group_id']}|{r['reason']}", lambda r: r["reason"], []),
    "inactive_privileged_accounts": (lambda r: f"{r['principal_id']}|{r['reason']}", lambda r: r["reason"], []),
}
FILES = [f"{s}.csv" for s in SOURCES]


def diff(old: dict[str, list[dict]], new: dict[str, list[dict]]) -> list[dict]:
    """old/new: csv name -> rows. Returns added / removed / changed rows. A source missing from either run (e.g. a
    baseline from an older tool version) is skipped rather than reported as everything added or removed."""
    out = []
    for source, (key, access, fields) in SOURCES.items():
        if f"{source}.csv" not in old or f"{source}.csv" not in new:
            continue
        before = {key(r): r for r in old.get(f"{source}.csv", [])}
        after = {key(r): r for r in new.get(f"{source}.csv", [])}
        for k in sorted(after.keys() - before.keys()):
            out.append({"source": source, "change": "added", "key": k, "principal": _who(after[k]), "access": access(after[k]),
                        "field": "", "before": "", "after": ""})
        for k in sorted(before.keys() - after.keys()):
            out.append({"source": source, "change": "removed", "key": k, "principal": _who(before[k]),
                        "access": access(before[k]), "field": "", "before": "", "after": ""})
        for k in sorted(before.keys() & after.keys()):
            for f in fields:
                if before[k].get(f) != after[k].get(f):
                    out.append({"source": source, "change": "changed", "key": k, "principal": _who(after[k]),
                                "access": access(after[k]), "field": f, "before": before[k].get(f, ""), "after": after[k].get(f, "")})
    return out


def read_tables(run_dir: Path) -> dict[str, list[dict]]:
    tables = {}
    for name in FILES:
        if (run_dir / name).is_file():
            with open(run_dir / name, newline="", encoding="utf-8") as fh:
                tables[name] = list(csv.DictReader(fh))
    return tables


def _usable(info: dict) -> bool:
    return info.get("status") == "complete" and bool((info.get("summary") or {}).get("coverage_complete"))


def local_baseline(output_dir: Path, current: str) -> tuple[str, dict[str, list[dict]]] | None:
    """Newest earlier local run that is complete, had complete coverage and still matches its manifest."""
    if not output_dir.is_dir():
        return None
    for d in sorted((p for p in output_dir.iterdir() if p.is_dir() and p.name < current and not p.name.endswith("-FAILED")),
                    reverse=True):
        try:
            info = json.loads((d / MANIFEST_NAME).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if _usable(info) and not verify_manifest(d):
            return d.name, read_tables(d)
    return None


def blob_baseline(container, prefix: str, current: str) -> tuple[str, dict[str, list[dict]]] | None:
    """Same, from the publish container: the run's manifest is read first, and each CSV must match its recorded hash."""
    runs = sorted({b.name[len(prefix):].split("/", 1)[0] for b in container.list_blobs(name_starts_with=prefix)
                   if b.name.endswith(f"/{MANIFEST_NAME}")}, reverse=True)
    for run in (r for r in runs if r < current):
        info = json.loads(container.download_blob(f"{prefix}{run}/{MANIFEST_NAME}").readall())
        if not _usable(info):
            continue
        tables = {}
        for name in FILES:
            if name not in info.get("files", {}):
                continue
            data = container.download_blob(f"{prefix}{run}/{name}").readall()
            if hashlib.sha256(data).hexdigest() != info["files"][name]:
                raise ValueError(f"{prefix}{run}/{name} does not match its manifest")
            tables[name] = list(csv.DictReader(io.StringIO(data.decode("utf-8"))))
        return run, tables
    return None
