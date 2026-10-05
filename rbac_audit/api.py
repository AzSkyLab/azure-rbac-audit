"""Thin read-only HTTP layer over ARM, Resource Graph and Microsoft Graph.

Every response is recorded untouched via RawStore. Mutating calls are refused:
the only POSTs allowed are Resource Graph queries and Graph $batch (whose
sub-requests must all be GETs).
"""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .auth import ARM_SCOPE, GRAPH_SCOPE, TokenCache

ARM = "https://management.azure.com"
GRAPH = "https://graph.microsoft.com"
_HOSTS = {"management.azure.com": ARM_SCOPE, "graph.microsoft.com": GRAPH_SCOPE}
ARG_PATH = "/providers/Microsoft.ResourceGraph/resources"
GRAPH_BATCH_PATH = "/v1.0/$batch"
PIM_API = "2020-10-01"
ROLEDEF_API = "2022-04-01"
PIM_KINDS = {"active": "roleAssignmentScheduleInstances", "eligible": "roleEligibilityScheduleInstances"}


class ReadOnlyViolation(RuntimeError):
    pass


class RawStore:
    """Writes raw/<category>_NNNN.json and keeps an index of every call made."""

    def __init__(self, raw_dir):
        self.dir = raw_dir
        self.calls: list[dict] = []
        self._counts: dict[str, int] = {}
        self._lock = threading.Lock()

    def save(self, category: str, content: bytes, *, method: str, url: str, status: int, request=None) -> str:
        with self._lock:
            n = self._counts[category] = self._counts.get(category, 0) + 1
            name = f"{category}_{n:04d}.json"
            self.dir.mkdir(parents=True, exist_ok=True)
            (self.dir / name).write_bytes(content)
            self.calls.append({"file": f"raw/{name}", "method": method, "url": url, "status": status, "request": request})
        return name

    def save_json(self, category: str, payload, **kw) -> str:
        return self.save(category, json.dumps(payload, indent=2).encode(), **kw)


class AzureApi:
    def __init__(self, credential, raw: RawStore):
        self.tokens = TokenCache(credential)
        self.raw = raw
        self._sleep = time.sleep
        self.session = requests.Session()
        retry = Retry(total=5, backoff_factor=1.0, status_forcelist=(429, 500, 502, 503, 504),
                      allowed_methods=None, respect_retry_after_header=True)
        self.session.mount("https://", HTTPAdapter(max_retries=retry, pool_maxsize=16))

    # -- plumbing -------------------------------------------------------
    def token(self, scope: str = ARM_SCOPE) -> str:
        return self.tokens.get(scope)

    @staticmethod
    def _check(method: str, url: str, body) -> None:
        u = urlparse(url)
        if u.scheme != "https" or u.hostname not in _HOSTS:
            raise ReadOnlyViolation(f"refusing request to {url}")
        if method == "GET":
            return
        if method == "POST" and u.hostname == "management.azure.com" and u.path == ARG_PATH:
            return
        if method == "POST" and u.hostname == "graph.microsoft.com" and u.path == GRAPH_BATCH_PATH:
            if all(r.get("method") == "GET" for r in body.get("requests", [])):
                return
        raise ReadOnlyViolation(f"{method} {u.path} is not an allowed read-only call")

    def _send(self, category: str, method: str, url: str, body=None, request_note=None):
        """Returns (status, parsed_json_or_None). Raw bytes are saved either way."""
        self._check(method, url, body)
        scope = _HOSTS[urlparse(url).hostname]
        r = self.session.request(method, url, json=body, timeout=120,
                                 headers={"Authorization": f"Bearer {self.token(scope)}"})
        self.raw.save(category, r.content, method=method, url=url, status=r.status_code, request=request_note)
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, None

    def _paged(self, category: str, url: str):
        """GET following nextLink (same host only). Raises on HTTP error."""
        items = []
        while url:
            status, data = self._send(category, "GET", url)
            if status != 200 or data is None:
                raise ApiError(status, url, data)
            items.extend(data.get("value", []))
            url = data.get("nextLink") or data.get("@odata.nextLink")
        return items

    # -- ARM / Resource Graph ------------------------------------------
    def arg_query(self, category: str, query: str, *, subscriptions=(), management_groups=(), inherited=False) -> list[dict]:
        body: dict = {"query": query, "options": {"$top": 1000, "resultFormat": "objectArray"}}
        if management_groups:
            body["managementGroups"] = list(management_groups)
        elif subscriptions:
            body["subscriptions"] = list(subscriptions)
        if inherited and category.startswith("arg_role"):
            body["options"]["authorizationScopeFilter"] = "AtScopeAboveAndBelow"
        url = f"{ARM}{ARG_PATH}?api-version=2022-10-01"
        rows: list[dict] = []
        while True:
            status, data = self._send(category, "POST", url, body, request_note={"query": query, "scope": {
                k: body[k] for k in ("subscriptions", "managementGroups") if k in body}})
            if status != 200 or data is None:
                raise ApiError(status, url, data)
            rows.extend(data.get("data", []))
            token = data.get("$skipToken")
            if not token:
                return rows
            body["options"]["$skipToken"] = token

    def list_subscriptions(self) -> list[dict]:
        return self._paged("arm_subscriptions", f"{ARM}/subscriptions?api-version=2022-12-01")

    def list_management_groups(self) -> list[dict]:
        return self._paged("arm_managementgroups", f"{ARM}/providers/Microsoft.Management/managementGroups?api-version=2021-04-01")

    def list_mg_descendants(self, management_group: str) -> list[dict]:
        url = (f"{ARM}/providers/Microsoft.Management/managementGroups/{quote(management_group)}"
               "/descendants?api-version=2021-04-01")
        return self._paged("arm_mg_descendants", url)

    def list_builtin_roledefs(self) -> list[dict]:
        flt = quote("type eq 'BuiltInRole'")
        return self._paged("arm_roledefinitions_builtin",
                           f"{ARM}/providers/Microsoft.Authorization/roleDefinitions?api-version={ROLEDEF_API}&$filter={flt}")

    def get_roledef(self, scope: str, guid: str) -> dict | None:
        url = f"{ARM}{scope.rstrip('/')}/providers/Microsoft.Authorization/roleDefinitions/{guid}?api-version={ROLEDEF_API}"
        status, data = self._send("arm_roledefinition", "GET", url)
        return data if status == 200 else None

    def graph_list(self, category: str, path: str) -> tuple[list[dict] | None, str | None]:
        """GET a Microsoft Graph collection (all pages). Returns (items, None) or (None, error text)."""
        try:
            return self._paged(category, f"{GRAPH}{path}"), None
        except ApiError as e:
            return None, str(e)

    def pim_instances(self, kind: str, scope: str) -> tuple[list[dict] | None, str | None]:
        """Schedule instances at-and-above `scope`. Returns (items, None) or (None, error)."""
        url = f"{ARM}{scope.rstrip('/')}/providers/Microsoft.Authorization/{PIM_KINDS[kind]}?api-version={PIM_API}"
        try:
            return self._paged(f"pim_{kind}", url), None
        except ApiError as e:
            return None, str(e)

    # -- Microsoft Graph -----------------------------------------------
    def _batch_chunk(self, chunk: list[tuple[str, str]]) -> dict[str, tuple[int, dict | None, dict]]:
        """One $batch call. Returns id -> (status, body, headers)."""
        body = {"requests": [{"id": i, "method": "GET", "url": p} for i, p in chunk]}
        status, data = self._send("graph_batch", "POST", f"{GRAPH}{GRAPH_BATCH_PATH}", body,
                                  request_note={"requests": len(chunk)})
        if status != 200 or data is None:
            return {i: (status, None, {}) for i, _ in chunk}
        return {r["id"]: (r["status"], r.get("body"), r.get("headers") or {}) for r in data.get("responses", [])}

    def graph_batch(self, paths: dict[str, str], attempts: int = 3) -> dict[str, tuple[int, dict | None]]:
        """GET many Graph paths via $batch (20 per call). Sub-requests answered 429/5xx are retried
        (honouring Retry-After) up to `attempts` times. Returns id -> (status, body)."""
        out: dict[str, tuple[int, dict | None]] = {}
        pending = list(paths.items())
        for attempt in range(1, attempts + 1):
            chunks = [pending[i:i + 20] for i in range(0, len(pending), 20)]
            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(self._batch_chunk, chunks))
            retry, wait = [], 0.0
            for part in results:
                for pid, (status, body, headers) in part.items():
                    out[pid] = (status, body)
                    if status == 429 or status >= 500:
                        retry.append((pid, paths[pid]))
                        wait = max(wait, _retry_after(headers, attempt))
            if not retry or attempt == attempts:
                break
            self._sleep(wait)
            pending = retry
        return out

    def parallel(self, fn, args, workers: int = 8):
        with ThreadPoolExecutor(max_workers=workers) as pool:
            return list(pool.map(fn, args))


def _retry_after(headers: dict, attempt: int) -> float:
    """Seconds to wait before retrying: Retry-After if given (capped), else exponential backoff."""
    for k, v in headers.items():
        if k.lower() == "retry-after":
            try:
                return min(float(v), 60.0)
            except ValueError:
                break
    return float(2 ** attempt)


class ApiError(RuntimeError):
    def __init__(self, status: int, url: str, body):
        msg = ""
        if isinstance(body, dict):
            err = body.get("error") or {}
            msg = f"{err.get('code', '')}: {err.get('message', '')}"[:600]
        super().__init__(f"HTTP {status} {urlparse(url).path} {msg}".strip())
        self.status = status
