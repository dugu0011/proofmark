"""Prototype-pollution + race-condition tools."""
from __future__ import annotations

import json
import threading

from proofmark.authorization import Authorization
from proofmark.http_client import HttpClient, RequestLog
from proofmark.tools.protopollution_tool import PrototypePollutionTool
from proofmark.tools.race_tool import RaceConditionTool


def _client(sandbox):
    return HttpClient(sandbox, Authorization.grant("https://app.test", "me"), RequestLog(),
                      safe_mode=True)


# ---------------------------------------------------------------- prototype pollution


class VulnProtoSandbox:
    """Merges __proto__ into a global; every later object then shows the property."""
    runner_path = "/runner.py"

    def __init__(self):
        self.polluted = None

    def exec(self, cmd, timeout=None):
        spec = json.loads(cmd[-1])
        body = spec.get("body") or ""
        if "PM_PP_INJECTED" in body:
            self.polluted = "PM_PP_INJECTED"
        # a GET afterwards reflects the polluted global property
        payload = {"ok": True}
        if self.polluted:
            payload["pmProtoPolluted"] = self.polluted
        return 0, json.dumps({"status": 200, "body": json.dumps(payload)})


class SafeProtoSandbox:
    runner_path = "/runner.py"

    def exec(self, cmd, timeout=None):
        return 0, json.dumps({"status": 200, "body": json.dumps({"ok": True})})


def test_prototype_pollution_detected():
    out = PrototypePollutionTool(_client(VulnProtoSandbox())).run(url="https://app.test/merge")
    assert "PROTOTYPE POLLUTION LIKELY" in out.output


def test_prototype_pollution_safe():
    out = PrototypePollutionTool(_client(SafeProtoSandbox())).run(url="https://app.test/merge")
    assert "No prototype pollution detected" in out.output


# ---------------------------------------------------------------- race condition


class VulnRaceSandbox:
    """No lock: every concurrent request succeeds."""
    runner_path = "/runner.py"

    def exec(self, cmd, timeout=None):
        return 0, json.dumps({"status": 200, "body": "ok"})


class GuardedRaceSandbox:
    """A lock: the first request wins (200), the rest are rejected (409)."""
    runner_path = "/runner.py"

    def __init__(self):
        self._lock = threading.Lock()
        self._used = False

    def exec(self, cmd, timeout=None):
        with self._lock:
            first = not self._used
            self._used = True
        return (0, json.dumps({"status": 200 if first else 409, "body": "ok"}))


def test_race_condition_flagged_when_unguarded():
    out = RaceConditionTool(_client(VulnRaceSandbox())).run(url="https://app.test/redeem", count=10)
    assert "POSSIBLE RACE CONDITION" in out.output


def test_race_condition_clean_when_guarded():
    out = RaceConditionTool(_client(GuardedRaceSandbox())).run(url="https://app.test/redeem", count=10)
    assert "No race detected" in out.output
