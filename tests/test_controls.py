import pytest

from rbac_audit.controls import direct_user_result


@pytest.mark.parametrize("ptype,resolution,expected", [
    ("User", "resolved", "FAIL"),
    ("Guest user", "resolved", "FAIL"),
    ("User", "unresolved", "FAIL"),              # hint says User: stays FAIL even if Graph lookup failed
    ("Group", "resolved", "PASS"),
    ("ServicePrincipal", "resolved", "PASS"),
    ("ManagedIdentity", "resolved", "PASS"),
    ("Orphaned", "orphaned", "REVIEW"),
    ("Unknown", "unresolved", "REVIEW"),         # no hint, Graph failed: never PASS
    ("ServicePrincipal", "unresolved", "REVIEW"),
    ("Group", "unresolved", "REVIEW"),
])
def test_direct_user_result(ptype, resolution, expected):
    assert direct_user_result(ptype, resolution) == expected
