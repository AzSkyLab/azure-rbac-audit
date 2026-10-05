"""Fake AzureApi serving sanitized fixtures; no network."""
import re

from conftest import SUB, fixture


class FakeApi:
    def __init__(self, raw, graph=None, pim_errors=(), descendants=None, descendants_error=None, graph_errors=None):
        self.raw = raw
        self.graph = graph or fixture("graph_principals.json")
        self.pim_errors = set(pim_errors)  # {(kind, scope)}
        self.descendants = descendants or []
        self.descendants_error = descendants_error
        self.pim_queried: list[tuple[str, str]] = []
        self.graph_errors = dict(graph_errors or {})  # path prefix or category -> error text
        self.graph_paths: list[str] = []
        self.entra = fixture("entra.json")

    def _rec(self, category, payload, url="fake://"):
        self.raw.save_json(category, payload, method="GET", url=url, status=200)

    def list_subscriptions(self):
        return [{"subscriptionId": SUB, "state": "Enabled"}]

    def list_management_groups(self):
        return [{"id": "/providers/Microsoft.Management/managementGroups/mg-test"}]

    def arg_query(self, category, query, **kw):
        data = {"arg_roleassignments": fixture("arg_roleassignments.json")["data"],
                "arg_roledefinitions": fixture("arg_roledefinitions.json")["data"],
                "arg_resourcecontainers": [{"id": f"/subscriptions/{SUB}"}, {"id": f"/subscriptions/{SUB}/resourceGroups/rg-app"}]}[category]
        self._rec(category, {"data": data})
        return data

    def list_builtin_roledefs(self):
        v = fixture("arm_roledefinitions_builtin.json")["value"]
        self._rec("arm_roledefinitions_builtin", {"value": v})
        return v

    def get_roledef(self, scope, guid):
        return None

    def list_mg_descendants(self, mg):
        if self.descendants_error:
            raise RuntimeError(self.descendants_error)
        return self.descendants

    def pim_instances(self, kind, scope):
        self.pim_queried.append((kind, scope))
        if (kind, scope) in self.pim_errors:
            return None, "HTTP 403 AuthorizationFailed"
        v = fixture("pim_active.json" if kind == "active" else "pim_eligible.json")["value"]
        self._rec(f"pim_{kind}", {"value": v})
        return v, None  # every scope returns everything: exercises de-duplication

    def graph_batch(self, paths):
        out = {pid: tuple(self.graph[pid]) for pid in paths}
        self._rec("graph_batch", {"responses": list(paths)})
        return out

    def parallel(self, fn, args, workers=8):
        return [fn(a) for a in args]


    def graph_list(self, category, path):
        """Route Graph collection reads to the sanitized entra.json fixture; graph_errors injects failures."""
        self.graph_paths.append(path)
        self._rec(category, {"path": path})
        for key, err in self.graph_errors.items():
            if category == key or path.startswith(key):
                return None, err
        e, base = self.entra, path.split("?")[0]
        if base == "/beta/roleManagement/directory/roleDefinitions":
            return e["dir_roledefinitions"], None
        if base == "/v1.0/roleManagement/directory/roleAssignments":
            return e["dir_roleassignments"], None
        if base == "/v1.0/roleManagement/directory/roleEligibilityScheduleInstances":
            return e["dir_roleeligibility"], None
        if m := re.fullmatch(r"/v1.0/groups/([^/]+)/(members|owners)", base):
            return e["groups"].get(m.group(1), {}).get(m.group(2), []), None
        if m := re.fullmatch(r"/v1.0/identityGovernance/privilegedAccess/group/(assignment|eligibility)ScheduleInstances", base):
            gid = re.search(r"groupId eq '([^']+)'", path).group(1)
            return e["groups"].get(gid, {}).get("assigned" if m.group(1) == "assignment" else "eligible", []), None
        if base == "/v1.0/identityGovernance/accessReviews/definitions":
            return e["review_defs"], None
        if m := re.fullmatch(r"/v1.0/identityGovernance/accessReviews/definitions/([^/]+)/instances", base):
            return e["review_instances"].get(m.group(1), []), None
        if m := re.fullmatch(r"/v1.0/identityGovernance/accessReviews/definitions/([^/]+)/instances/([^/]+)/decisions", base):
            return e["review_decisions"].get(f"{m.group(1)}/{m.group(2)}", []), None
        raise AssertionError(f"unrouted graph path {path}")
