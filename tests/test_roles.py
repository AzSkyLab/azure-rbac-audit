import pytest

from rbac_audit.roles import (CUSTOM_PRIVILEGED, PRIVILEGED_ADMIN, SENSITIVE_DATA_PLANE, STANDARD, RoleDef,
                              classify_tier, parse_roledef, privileged_action, severity)
from conftest import fixture


@pytest.mark.parametrize("name", ["Owner", "contributor", "User Access Administrator",
                                  "Role Based Access Control Administrator", "Reservations Administrator"])
def test_privileged_admin_builtin(cfg, name):
    assert classify_tier(RoleDef("g", name, "BuiltInRole"), cfg)[0] == PRIVILEGED_ADMIN


@pytest.mark.parametrize("name", ["Key Vault Administrator", "Key Vault Secrets Officer", "Storage Blob Data Owner",
                                  "Virtual Machine Administrator Login"])
def test_sensitive_data_plane(cfg, name):
    assert classify_tier(RoleDef("g", name, "BuiltInRole"), cfg)[0] == SENSITIVE_DATA_PLANE


def test_standard_and_unknown(cfg):
    assert classify_tier(RoleDef("g", "Reader", "BuiltInRole"), cfg)[0] == STANDARD
    assert classify_tier(None, cfg)[0] == STANDARD


@pytest.mark.parametrize("actions,expected", [
    (["*"], True),
    (["Microsoft.Authorization/*"], True),
    (["Microsoft.Authorization/roleAssignments/write"], True),
    (["Microsoft.Authorization/roleDefinitions/write"], True),
    (["microsoft.authorization/roleassignments/write"], True),          # case-insensitive
    (["Microsoft.Authorization/roleAssignments/*"], True),              # narrower wildcard still covers write
    (["Microsoft.Authorization/*/write"], True),
    (["Microsoft.Authorization/*/read"], False),
    (["Microsoft.Compute/*"], False),
    (["Microsoft.Compute/virtualMachines/read", "Microsoft.Authorization/roleAssignments/read"], False),
    ([], False),
])
def test_custom_role_detection(cfg, actions, expected):
    tier, _ = classify_tier(RoleDef("g", "Some Custom", "CustomRole", tuple(actions)), cfg)
    assert (tier == CUSTOM_PRIVILEGED) is expected


def test_wildcard_actions_do_not_make_builtin_roles_custom_privileged(cfg):
    assert classify_tier(RoleDef("g", "Reader", "BuiltInRole", ("*",)), cfg)[0] == STANDARD


def test_custom_role_with_admin_name_still_privileged_admin(cfg):
    assert classify_tier(RoleDef("g", "Owner", "CustomRole", ()), cfg)[0] == PRIVILEGED_ADMIN


def test_fixture_custom_roles_parse(cfg):
    roles = {r.name: r for r in map(parse_roledef, fixture("arg_roledefinitions.json")["data"])}
    assert classify_tier(roles["Custom Role Writer"], cfg)[0] == CUSTOM_PRIVILEGED
    assert classify_tier(roles["Custom Auth Wildcard"], cfg)[0] == CUSTOM_PRIVILEGED
    assert classify_tier(roles["Custom Everything"], cfg)[0] == CUSTOM_PRIVILEGED
    assert classify_tier(roles["Custom Reader"], cfg)[0] == STANDARD


def test_privileged_action_returns_match():
    assert privileged_action(["a/b", "Microsoft.Authorization/*"], ["Microsoft.Authorization/roleAssignments/write"]) \
        == "Microsoft.Authorization/*"


@pytest.mark.parametrize("tier,level,sev", [
    (PRIVILEGED_ADMIN, "management_group", "high"), (PRIVILEGED_ADMIN, "subscription", "high"),
    (PRIVILEGED_ADMIN, "root", "high"), (PRIVILEGED_ADMIN, "resource_group", "medium"),
    (SENSITIVE_DATA_PLANE, "resource", "medium"), (STANDARD, "subscription", "low"),
])
def test_severity(tier, level, sev):
    assert severity(tier, level) == sev
