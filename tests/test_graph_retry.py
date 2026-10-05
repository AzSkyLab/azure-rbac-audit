from rbac_audit.api import AzureApi, RawStore, _retry_after


def make(tmp_path, script):
    """AzureApi whose $batch chunks are served from `script(chunk, call_no)`."""
    api = AzureApi(object(), RawStore(tmp_path / "raw"))
    api.sleeps = []
    api._sleep = api.sleeps.append
    calls = []

    def chunk(c):
        calls.append([i for i, _ in c])
        return script(c, len(calls))

    api._batch_chunk = chunk
    api.calls = calls
    return api


def ok(i):
    return (200, {"id": i}, {})


def test_throttled_subrequests_retried_honouring_retry_after(tmp_path):
    def script(c, n):
        if n == 1:
            return {"a": ok("a"), "b": (429, None, {"Retry-After": "7"}), "c": (503, None, {})}
        return {i: ok(i) for i, _ in c}
    api = make(tmp_path, script)
    out = api.graph_batch({"a": "/a", "b": "/b", "c": "/c"})
    assert api.calls == [["a", "b", "c"], ["b", "c"]]           # only the failed ids are re-sent
    assert api.sleeps == [7.0] and all(v[0] == 200 for v in out.values())


def test_gives_up_after_three_attempts_and_keeps_last_status(tmp_path):
    api = make(tmp_path, lambda c, n: {i: (429, None, {"retry-after": "1"}) for i, _ in c})
    out = api.graph_batch({"a": "/a"})
    assert len(api.calls) == 3 and len(api.sleeps) == 2 and out["a"][0] == 429


def test_404_is_not_retried(tmp_path):
    api = make(tmp_path, lambda c, n: {i: (404, {"error": {"code": "Request_ResourceNotFound"}}, {}) for i, _ in c})
    out = api.graph_batch({"a": "/a"})
    assert len(api.calls) == 1 and api.sleeps == [] and out["a"][0] == 404


def test_batches_of_twenty(tmp_path):
    api = make(tmp_path, lambda c, n: {i: ok(i) for i, _ in c})
    api.graph_batch({str(i): f"/{i}" for i in range(45)})
    assert sorted(len(c) for c in api.calls) == [5, 20, 20]


def test_retry_after_parsing():
    assert _retry_after({"Retry-After": "12"}, 1) == 12.0
    assert _retry_after({"Retry-After": "9999"}, 1) == 60.0     # capped
    assert _retry_after({}, 2) == 4.0                            # backoff fallback
    assert _retry_after({"Retry-After": "Wed, 21 Oct"}, 1) == 2.0
