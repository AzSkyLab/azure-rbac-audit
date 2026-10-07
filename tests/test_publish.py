import json
from datetime import datetime, timezone

import pytest
import yaml
from azure.core.exceptions import ResourceExistsError

from rbac_audit import cli
from rbac_audit.api import RawStore
from rbac_audit.collect import new_run_dir, run_collection
from rbac_audit.config import ConfigError, PublishConfig, parse_config
from rbac_audit.publish import PublishError, check_run, load_postgres, publish, upload_blobs
from conftest import ROOT, SUB, TENANT
from fakes import FakeApi

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
PCFG = PublishConfig("https://acct.blob.core.windows.net", "evidence", "prod/", "srv.postgres.database.azure.com",
                     "audit", "id-rbac-audit", "rbac_audit")


@pytest.fixture
def run_dir(cfg):
    d = new_run_dir(cfg, NOW)
    raw = RawStore(d / "raw")
    run_collection(cfg, FakeApi(raw), raw, d, {"upn": "a@b", "tenant_id": TENANT}, NOW)
    return d


class Container:
    def __init__(self, existing=()):
        self.names, self.existing = [], set(existing)

    def upload_blob(self, name, data, overwrite):
        assert overwrite is False                           # never overwrite evidence
        if name in self.existing:
            raise ResourceExistsError("exists")
        data.read()
        self.names.append(name)


class Cursor:
    def __init__(self, conn):
        self.conn, self.rowcount = conn, 0

    def execute(self, sql, params):
        self.conn.sql.append(sql)
        self.conn.params.append(params)
        self.rowcount = 0 if self.conn.loaded else 1

    def executemany(self, sql, rows):
        self.conn.sql.append(sql)
        self.conn.rows += list(rows)


class Conn:
    def __init__(self, loaded=False):
        self.sql, self.params, self.rows, self.loaded, self.committed = [], [], [], loaded, False

    def transaction(self):
        conn = self

        class Tx:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                conn.committed = exc[0] is None
        return Tx()

    def cursor(self):
        return Cursor(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_check_run_accepts_complete_unchanged_run(run_dir):
    assert check_run(run_dir)["status"] == "complete"


def test_check_run_rejects_tampered_failed_or_missing(run_dir, tmp_path):
    (run_dir / "assignments.csv").write_text("tampered")
    with pytest.raises(PublishError, match="does not match its manifest"):
        check_run(run_dir)
    m = run_dir / "manifest.json"
    m.write_text(json.dumps({**json.loads(m.read_text()), "status": "failed"}))
    with pytest.raises(PublishError, match="only complete runs"):
        check_run(run_dir)
    with pytest.raises(PublishError, match="no manifest.json"):
        check_run(tmp_path)


def test_upload_puts_manifest_last_and_never_overwrites(run_dir):
    c = Container()
    uploaded, existing = upload_blobs(run_dir, c, "prod/")
    assert existing == 0 and uploaded == len(c.names)
    assert c.names[-2:] == [f"prod/{run_dir.name}/manifest.json", f"prod/{run_dir.name}/manifest.sha256"]
    assert f"prod/{run_dir.name}/raw/arg_roleassignments_0001.json" in c.names
    again = Container(existing=c.names)                     # re-publish: everything already there
    assert upload_blobs(run_dir, again, "prod/") == (0, len(c.names))


def test_postgres_load_is_insert_only_and_idempotent(run_dir):
    info = check_run(run_dir)
    conn = Conn()
    n, already = load_postgres(run_dir, info, "abc", conn, "rbac_audit", "https://x/")
    assert not already and n == len(conn.rows) > 0 and conn.committed
    assert all("INSERT" in q and "UPDATE" not in q and "DELETE" not in q for q in conn.sql)
    assert "ON CONFLICT (run_id) DO NOTHING" in conn.sql[0]
    sources = {r[1] for r in conn.rows}
    assert {"assignments", "exceptions_privileged_permanent", "entra_role_assignments"} <= sources
    assert all(r[0] == run_dir.name and json.loads(r[3]) for r in conn.rows)
    loaded = Conn(loaded=True)                              # run already present: nothing else inserted
    assert load_postgres(run_dir, info, "abc", loaded, "rbac_audit") == (0, True) and loaded.rows == []


def test_publish_runs_both_targets(run_dir):
    c, conn = Container(), Conn()
    res = publish(run_dir, PCFG, credential=None, container=c, connect=lambda: conn)
    assert res.blobs_uploaded == len(c.names) and res.rows_loaded == len(conn.rows) and not res.run_already_loaded
    run_id, tenant, *_, coverage, digest, evidence_url, _summary = conn.params[0]   # the runs row
    assert run_id == run_dir.name and tenant == TENANT and coverage is True and len(digest) == 64
    assert evidence_url == f"https://acct.blob.core.windows.net/evidence/prod/{run_dir.name}/"


def test_publish_skips_unconfigured_targets(run_dir):
    res = publish(run_dir, PublishConfig(), credential=None,
                  container=pytest.fail, connect=pytest.fail)   # neither may be touched
    assert res.blobs_uploaded == res.rows_loaded == 0


def raw_cfg(**publish_block):
    raw = yaml.safe_load((ROOT / "config.example.yaml").read_text())
    raw["tenant_id"] = TENANT
    raw["publish"] = publish_block
    return raw


def test_publish_config_parsing_and_validation():
    c = parse_config(raw_cfg(storage={"account_url": "https://a.blob.core.windows.net", "container": "ev", "prefix": "p"},
                             postgres={"host": "h", "database": "d", "user": "u"})).publish
    assert (c.storage_prefix, c.postgres_schema) == ("p/", "rbac_audit")
    for bad, msg in [({"storage": {"account_url": "http://a", "container": "c"}}, "https account_url"),
                     ({"storage": {"account_url": "https://a"}}, "container"),
                     ({"postgres": {"host": "h"}}, "database and user"),
                     ({"postgres": {"host": "h", "database": "d", "user": "u", "schema": "x; drop"}}, "SQL identifier")]:
        with pytest.raises(ConfigError, match=msg):
            parse_config(raw_cfg(**bad))
    assert parse_config(raw_cfg()).publish == PublishConfig()


# ---- CLI exit codes ---------------------------------------------------------------------------------------------
@pytest.fixture
def cli_env(cfg, tmp_path, monkeypatch):
    path = tmp_path / "cfg.yaml"
    raw = yaml.safe_load((ROOT / "config.example.yaml").read_text())
    raw.update(tenant_id=TENANT, output_dir=str(cfg.output_dir))
    raw["scope"]["subscriptions"] = [SUB]
    path.write_text(yaml.safe_dump(raw))
    monkeypatch.setattr(cli, "build_credential", lambda auth, tenant: ("cred", []))
    monkeypatch.setattr(cli, "describe_identity", lambda cred: {"tenant_id": TENANT, "upn": "a@b"})
    monkeypatch.setattr(cli, "AzureApi", lambda cred, raw: FakeApi(raw))
    return path


def test_collect_exit_ok_and_json_line(cli_env, capsys):
    assert cli.main(["collect", "--config", str(cli_env), "--json"]) == cli.EXIT_OK
    line = json.loads(capsys.readouterr().out.strip())
    assert line["event"] == "rbac_audit_run" and line["status"] == "complete" and line["coverage_complete"] is True
    assert line["published"] is None and "control_mapping" not in line


def test_collect_exit_incomplete_on_coverage_gap(cli_env, monkeypatch):
    monkeypatch.setattr(cli, "AzureApi", lambda cred, raw: FakeApi(raw, pim_errors={("active", f"/subscriptions/{SUB}")}))
    assert cli.main(["collect", "--config", str(cli_env)]) == cli.EXIT_INCOMPLETE


def test_publish_requested_but_not_configured_is_a_publish_failure(cli_env, capsys):
    assert cli.main(["collect", "--config", str(cli_env), "--publish"]) == cli.EXIT_PUBLISH
    assert "neither publish.storage nor publish.postgres" in capsys.readouterr().err


def test_tenant_mismatch_is_config_error(cli_env, monkeypatch):
    monkeypatch.setattr(cli, "describe_identity", lambda cred: {"tenant_id": "other"})
    assert cli.main(["collect", "--config", str(cli_env)]) == cli.EXIT_CONFIG
