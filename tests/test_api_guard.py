import pytest

from rbac_audit.api import ARG_PATH, ARM, GRAPH, AzureApi, ReadOnlyViolation

check = AzureApi._check


def test_allowed_calls():
    check("GET", f"{ARM}/subscriptions?api-version=1", None)
    check("GET", f"{GRAPH}/v1.0/users/1", None)
    check("POST", f"{ARM}{ARG_PATH}?api-version=2022-10-01", {})
    check("POST", f"{GRAPH}/v1.0/$batch", {"requests": [{"id": "1", "method": "GET", "url": "/users/1"}]})


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
def test_mutating_methods_refused(method):
    with pytest.raises(ReadOnlyViolation):
        check(method, f"{ARM}/subscriptions/x/providers/Microsoft.Authorization/roleAssignments/y", {})


def test_other_posts_refused():
    with pytest.raises(ReadOnlyViolation):
        check("POST", f"{ARM}/subscriptions/x/providers/Microsoft.Authorization/roleAssignments/y/write", {})
    with pytest.raises(ReadOnlyViolation):
        check("POST", f"{GRAPH}/v1.0/users", {})


def test_batch_with_non_get_subrequest_refused():
    with pytest.raises(ReadOnlyViolation):
        check("POST", f"{GRAPH}/v1.0/$batch", {"requests": [{"id": "1", "method": "DELETE", "url": "/users/1"}]})


@pytest.mark.parametrize("url", ["http://management.azure.com/x", "https://evil.example/x", "https://management.azure.com.evil.example/x"])
def test_foreign_hosts_refused(url):
    with pytest.raises(ReadOnlyViolation):
        check("GET", url, None)
