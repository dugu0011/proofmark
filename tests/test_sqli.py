"""Deterministic SQL-injection tool — error, boolean, and time based.

Fake sandboxes simulate a vulnerable backend so no real DB or network is needed.
"""
from __future__ import annotations

import json
import re
import time
from urllib.parse import unquote_plus

from proofmark.authorization import Authorization
from proofmark.http_client import HttpClient, RequestLog
from proofmark.tools.sqli_tool import SqlInjectionTool

_SLEEP = re.compile(r"SLEEP\((\d+)\)|pg_sleep\((\d+)\)|WAITFOR DELAY '0:0:(\d+)'")


def _spec_text(cmd):
    # A real target decodes the query/body; the tool sends them percent-encoded,
    # so decode before matching payloads.
    spec = json.loads(cmd[-1])
    return unquote_plus(f"{spec.get('url','')} {spec.get('body','') or ''}")


class _Base:
    runner_path = "/runner.py"

    def _resp(self, status, body):
        return 0, json.dumps({"status": status, "body": body})


class ErrorVulnSandbox(_Base):
    def exec(self, cmd, timeout=None):
        text = _spec_text(cmd)
        pure_error = any(c in text for c in ("'", '"', "\\")) and "OR '1'='" not in text \
            and not _SLEEP.search(text)
        if pure_error:
            return self._resp(500, "Fatal error: you have an error in your SQL syntax near ''")
        return self._resp(200, "normal page " * 20)


class TimeVulnSandbox(_Base):
    def exec(self, cmd, timeout=None):
        m = _SLEEP.search(_spec_text(cmd))
        if m:
            secs = int(next(g for g in m.groups() if g))
            time.sleep(secs)
        return self._resp(200, "normal page " * 20)


class BooleanVulnSandbox(_Base):
    def exec(self, cmd, timeout=None):
        text = _spec_text(cmd)
        if "OR '1'='1" in text:
            return self._resp(200, "row " * 400)     # TRUE -> many rows (long)
        if "OR '1'='2" in text:
            return self._resp(200, "none")            # FALSE -> empty (short)
        return self._resp(200, "row " * 100)          # baseline (medium)


class SafeSandbox(_Base):
    def exec(self, cmd, timeout=None):
        return self._resp(200, "static page " * 20)   # identical regardless of input


def _client(sandbox):
    return HttpClient(sandbox, Authorization.grant("https://app.test", "me"), RequestLog(),
                      safe_mode=True)


URL = "https://app.test/items?id=1&sort=name"


def test_error_based_detection():
    out = SqlInjectionTool(_client(ErrorVulnSandbox())).run(url=URL, param="id")
    assert "SQL INJECTION LIKELY" in out.output
    assert "ERROR-BASED" in out.output
    assert "confidence: high" in out.output


def test_time_based_detection():
    out = SqlInjectionTool(_client(TimeVulnSandbox()), delay_seconds=1).run(url=URL, param="id")
    assert "TIME-BASED" in out.output
    assert "confidence: high" in out.output


def test_boolean_based_detection():
    out = SqlInjectionTool(_client(BooleanVulnSandbox())).run(url=URL, param="id")
    assert "BOOLEAN-BASED" in out.output
    assert "confidence: medium" in out.output


def test_safe_parameter_is_clean():
    out = SqlInjectionTool(_client(SafeSandbox()), delay_seconds=1).run(url=URL, param="id")
    assert "No SQL injection detected" in out.output


def test_missing_parameter_errors():
    out = SqlInjectionTool(_client(SafeSandbox())).run(url=URL, param="nope")
    assert out.is_error
    assert "was not found" in out.output


def test_body_parameter_injection():
    out = SqlInjectionTool(_client(ErrorVulnSandbox())).run(
        url="https://app.test/login", param="user", method="POST", where="body",
        body="user=admin&pass=x")
    assert "ERROR-BASED" in out.output


def test_output_is_fenced_as_untrusted():
    assert SqlInjectionTool(_client(SafeSandbox())).returns_untrusted_data is True
