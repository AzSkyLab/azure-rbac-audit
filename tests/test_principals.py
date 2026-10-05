import pytest

from rbac_audit.principals import GROUP, GUEST, MI, ORPHANED, SP, USER, classify_principal, graph_path
from conftest import G1, MI1, ORPH, SP1, U1, U2, fixture

G = fixture("graph_principals.json")


def typed(pid, hint):
    status, body = G[pid]
    return classify_principal(pid, hint, status, body)


@pytest.mark.parametrize("pid,hint,ptype", [
    (U1, "User", USER), (U2, "User", GUEST), (G1, "Group", GROUP), (SP1, "ServicePrincipal", SP),
    (MI1, "ServicePrincipal", MI), (ORPH, "User", ORPHANED),
])
def test_principal_types(pid, hint, ptype):
    assert typed(pid, hint).type == ptype


def test_names_and_identifiers():
    assert typed(U1, "User").upn_or_appid == "user.one@contoso.example"
    assert typed(SP1, "ServicePrincipal").upn_or_appid.startswith("9999")
    assert typed(ORPH, "User").resolution == "orphaned"


def test_guest_detected_by_ext_upn_even_without_usertype():
    body = {"id": "x", "displayName": "g", "userPrincipalName": "a_b.com#EXT#@t.onmicrosoft.com"}
    assert classify_principal("x", "User", 200, body).type == GUEST


def test_forbidden_is_unresolved_not_orphaned():
    p = classify_principal("x", "User", 403, {"error": {"code": "Authorization_RequestDenied"}})
    assert (p.type, p.resolution) == (USER, "unresolved")


def test_graph_path_per_hint_has_no_version_prefix():
    assert graph_path("1", "User").startswith("/users/1")
    assert graph_path("1", "Group").startswith("/groups/1")
    assert graph_path("1", "ServicePrincipal").startswith("/servicePrincipals/1")
    assert graph_path("1", "Device") == "/directoryObjects/1"
