"""Run manifest with a SHA-256 for every evidence file."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

MANIFEST_NAME = "manifest.json"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_tree(root: Path) -> dict[str, str]:
    """Relative posix path -> sha256, for every file under root except the manifest."""
    return {
        p.relative_to(root).as_posix(): sha256_file(p)
        for p in sorted(root.rglob("*"))
        if p.is_file() and p.relative_to(root).as_posix() != MANIFEST_NAME
    }


def write_manifest(root: Path, info: dict) -> Path:
    manifest = {**info, "files": hash_tree(root)}
    path = root / MANIFEST_NAME
    path.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return path


def verify_manifest(root: Path) -> list[str]:
    """Return relative paths whose hash no longer matches (or that are missing/extra)."""
    recorded = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))["files"]
    current = hash_tree(root)
    return sorted(k for k in set(recorded) | set(current) if recorded.get(k) != current.get(k))
