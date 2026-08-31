"""Client-side rate limiting (--rps) — hold requests to a max rate."""
from __future__ import annotations

import time

from proofmark.authorization import Authorization
from proofmark.http_client import HttpClient, Request, RequestLog


class FastSandbox:
    runner_path = "/runner.py"

    def exec(self, cmd, timeout=None):
        return 0, '{"status":200,"body":"ok"}'


def _client(rps):
    return HttpClient(FastSandbox(), Authorization.grant("https://app.test", "me"),
                      RequestLog(), rps=rps)


def test_unlimited_is_fast():
    c = _client(0)
    start = time.monotonic()
    for i in range(6):
        c.send(Request("GET", f"https://app.test/{i}"))
    assert time.monotonic() - start < 0.5


def test_rps_throttles_requests():
    c = _client(10)  # 10 req/s -> ~0.1s min interval
    start = time.monotonic()
    for i in range(5):
        c.send(Request("GET", f"https://app.test/{i}"))
    elapsed = time.monotonic() - start
    # 5 distinct requests: 1 immediate + 4 gaps of ~0.1s ≈ 0.4s
    assert elapsed >= 0.35, elapsed


def test_cache_hits_are_not_throttled():
    c = _client(2)  # slow: 0.5s interval
    c.send(Request("GET", "https://app.test/same"))     # first real send
    start = time.monotonic()
    for _ in range(5):
        c.send(Request("GET", "https://app.test/same"))  # cached -> no throttle
    assert time.monotonic() - start < 0.3
