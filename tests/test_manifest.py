import hashlib
import json

from rbac_audit.manifest import hash_tree, sha256_file, verify_manifest, write_manifest


def make(tmp_path):
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw" / "a.json").write_text('{"a": 1}')
    (tmp_path / "assignments.csv").write_text("x,y\n")
    return tmp_path


def test_sha256_matches_hashlib(tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"hello")
    assert sha256_file(f) == hashlib.sha256(b"hello").hexdigest()


def test_manifest_lists_every_file_except_itself(tmp_path):
    root = make(tmp_path)
    write_manifest(root, {"tool": "t"})
    m = json.loads((root / "manifest.json").read_text())
    assert set(m["files"]) == {"raw/a.json", "assignments.csv"}
    assert m["files"]["raw/a.json"] == hashlib.sha256(b'{"a": 1}').hexdigest()
    assert m["tool"] == "t" and verify_manifest(root) == []


def test_verify_detects_tamper_missing_and_extra(tmp_path):
    root = make(tmp_path)
    write_manifest(root, {})
    (root / "assignments.csv").write_text("x,y\n1,2\n")
    (root / "raw" / "b.json").write_text("{}")
    (root / "raw" / "a.json").unlink()
    assert verify_manifest(root) == ["assignments.csv", "raw/a.json", "raw/b.json"]
    assert "manifest.json" not in hash_tree(root)
