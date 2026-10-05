import threading
from types import SimpleNamespace

from rbac_audit.auth import TokenCache


class Cred:
    def __init__(self, lifetime=3600, clock=None):
        self.calls = []
        self.lifetime, self.clock = lifetime, clock

    def get_token(self, scope):
        self.calls.append(scope)
        return SimpleNamespace(token=f"tok{len(self.calls)}", expires_on=self.clock() + self.lifetime)


def test_cached_per_scope_until_five_minutes_before_expiry():
    now = [1000.0]
    cred = Cred(3600, lambda: now[0])
    cache = TokenCache(cred, clock=lambda: now[0])
    assert cache.get("arm") == "tok1" and cache.get("arm") == "tok1"
    assert cache.get("graph") == "tok2"                      # separate scope, separate token
    now[0] += 3600 - 301                                      # still > 300s left
    assert cache.get("arm") == "tok1"
    now[0] += 2                                               # now < 300s left: refresh
    assert cache.get("arm") == "tok3" and cred.calls == ["arm", "graph", "arm"]


def test_thread_safe_single_fetch():
    now = [0.0]
    cred = Cred(3600, lambda: now[0])
    cache = TokenCache(cred, clock=lambda: now[0])
    threads = [threading.Thread(target=cache.get, args=("arm",)) for _ in range(16)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert cred.calls == ["arm"]
