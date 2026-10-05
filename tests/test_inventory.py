from rbac_audit.controls import direct_user_exceptions, privileged_permanent_exceptions
from rbac_audit.inventory import build_inventory, principal_hints
from rbac_audit.principals import classify_principal
from rbac_audit.roles import parse_roledef
from conftest import SUB, fixture


def build(cfg, failed=()):
    assignments = fixture("arg_roleassignments.json")["data"]
    eligible = fixture("pim_eligible.json")["value"]
    roles = {r.guid: r for r in map(parse_roledef, fixture("arg_roledefinitions.json")["data"] + fixture("arm_roledefinitions_builtin.json")["value"])}
    graph = fixture("graph_principals.json")
    principals = {pid: classify_principal(pid, h, *graph[pid]) for pid, h in principal_hints(assignments, eligible).items()}
    return build_inventory(cfg, assignments, roles, fixture("pim_active.json")["value"], eligible, principals, set(failed))


def by_name(rows):
    return {(r["source"], r["role_name"], r["principal_name"]): r for r in rows}


def test_inventory_counts_and_labels(cfg):
    rows, warnings = build(cfg)
    assert len(rows) == 11 and warnings == []
    labels = [r["pim_label"] for r in rows]
    assert labels.count("eligible") == 2 and labels.count("activated") == 1 and labels.count("time_bound_active") == 1
    assert labels.count("permanent_active") == 7


def test_row_details(cfg):
    rows, _ = build(cfg)
    r = by_name(rows)
    kv = r[("resource_graph", "Key Vault Administrator", "mi-app")]
    assert (kv["scope_level"], kv["principal_type"], kv["privilege_tier"], kv["pim_label"]) == \
        ("resource", "ManagedIdentity", "sensitive_data_plane", "permanent_active")
    assert kv["subscription_id"] == SUB and kv["resource_group"] == "rg-app" and kv["severity"] == "medium"
    act = r[("resource_graph", "Contributor", "grp-platform-admins")]
    assert (act["pim_label"], act["scope_level"], act["end"]) == ("activated", "resource_group", "2025-06-01T08:00:00Z")
    mg = r[("resource_graph", "Custom Role Writer", "Guest Two")]
    assert (mg["scope_level"], mg["principal_type"], mg["privilege_tier"], mg["severity"]) == \
        ("management_group", "Guest user", "custom_privileged", "high")
    assert r[("resource_graph", "Reader", "sp-pipeline")]["pim_label"] == "time_bound_active"


def test_direct_user_control(cfg):
    rows, _ = build(cfg)
    fails = direct_user_exceptions(rows)
    assert sorted((r["principal_type"], r["pim_label"]) for r in fails) == \
        [("Guest user", "permanent_active"), ("User", "eligible"), ("User", "permanent_active")]
    assert [r["direct_user_result"] for r in rows if r["principal_type"] == "Orphaned"] == ["REVIEW"]
    assert all(r["direct_user_result"] == "PASS" for r in rows if r["principal_type"] in ("Group", "ServicePrincipal", "ManagedIdentity"))


def test_privileged_permanent_exceptions(cfg):
    rows, _ = build(cfg)
    got = sorted(r["role_name"] for r in privileged_permanent_exceptions(rows))
    # Owner@sub(user), KV Admin(MI), custom writer(guest), Owner@MG(group), custom everything(SP).
    # Not: activated Contributor, eligible rows, time-bound/standard roles.
    assert got == ["Custom Everything", "Custom Role Writer", "Key Vault Administrator", "Owner", "Owner"]


def test_unverified_when_pim_unreadable_at_scope(cfg):
    rows, _ = build(cfg, failed=[f"/subscriptions/{SUB}/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/kv-test"])
    kv = by_name(rows)[("resource_graph", "Key Vault Administrator", "mi-app")]
    assert kv["pim_label"] == "unverified"
    assert kv not in privileged_permanent_exceptions(rows)


def test_unmatched_active_instance_warns(cfg):
    extra = {"id": "z", "properties": {"assignmentType": "Assigned", "principalId": "p", "roleDefinitionId": "/r/1", "scope": "/subscriptions/zzz"}}
    assignments = fixture("arg_roleassignments.json")["data"]
    _, warnings = build_inventory(cfg, assignments, {}, [extra], [], {}, set())
    assert len(warnings) == 1
