"""NoSQL injection + subdomain takeover tools."""
from __future__ import annotations

import json
from urllib.parse import unquote_plus

from proofmark.authorization import Authorization
from proofmark.http_client import HttpClient, RequestLog
from proofmark.tools.nosql_tool import NoSqlInjectionTool
from proofmark.tools.takeover_tool import SubdomainTakeoverTool

_OPS = ("[$ne]", "[$gt]", "[$regex]", '"$ne"', '"$gt"', '"$regex"')


def _client(sandbox):
    return HttpClient(sandbox, Authorization.grant("https://app.test", "me"), RequestLog(),
                      safe_mode=True)


def _client_for(host, sandbox):
    return HttpClient(sandbox, Authorization.grant(host, "me"), RequestLog(), safe_mode=True)


# ---------------------------------------------------------------------- NoSQL


class MongoSandbox:
    """Interprets Mongo operators: an operator matches every record (big response);
    a plain no-match value returns nothing."""
    runner_path = "/runner.py"

    def exec(self, cmd, timeout=None):
        spec = json.loads(cmd[-1])
        text = unquote_plus(spec.get("url", "") + " " + (spec.get("body") or ""))
        if any(op in text for op in _OPS):
            return 0, json.dumps({"status": 200, "body": "record " * 80})   # matched everything
        return 0, json.dumps({"status": 200, "body": "[]"})                  # matched nothing


class SafeMongoSandbox:
    runner_path = "/runner.py"

    def exec(self, cmd, timeout=None):
        return 0, json.dumps({"status": 200, "body": "[]"})                  # operator treated literally


def test_nosql_query_operator_injection():
    out = NoSqlInjectionTool(_client(MongoSandbox())).run(
        url="https://app.test/users?username=admin", param="username")
    assert "NOSQL INJECTION LIKELY" in out.output


def test_nosql_json_auth_bypass():
    out = NoSqlInjectionTool(_client(MongoSandbox())).run(
        url="https://app.test/login", method="POST", where="json", param="password",
        body='{"username":"admin","password":"x"}')
    assert "NOSQL INJECTION LIKELY" in out.output


def test_nosql_safe_backend():
    out = NoSqlInjectionTool(_client(SafeMongoSandbox())).run(
        url="https://app.test/users?username=admin", param="username")
    assert "No NoSQL injection" in out.output


def test_nosql_missing_param():
    out = NoSqlInjectionTool(_client(SafeMongoSandbox())).run(
        url="https://app.test/users?username=admin", param="nope")
    assert out.is_error


# ------------------------------------------------------------------- Takeover


class TakeoverSandbox:
    def __init__(self, body):
        self.body = body
        self.runner_path = "/runner.py"

    def exec(self, cmd, timeout=None):
        return 0, json.dumps({"status": 404, "body": self.body})


def test_github_pages_takeover_detected():
    sb = TakeoverSandbox("There isn't a GitHub Pages site here.")
    out = SubdomainTakeoverTool(_client_for("https://blog.app.test", sb)).run(url="https://blog.app.test")
    assert "POTENTIAL SUBDOMAIN TAKEOVER" in out.output and "GitHub Pages" in out.output


def test_s3_takeover_detected():
    sb = TakeoverSandbox("<Error><Code>NoSuchBucket</Code></Error>")
    out = SubdomainTakeoverTool(_client_for("https://assets.app.test", sb)).run(url="assets.app.test")
    assert "POTENTIAL SUBDOMAIN TAKEOVER" in out.output and "AWS S3" in out.output


def test_normal_page_no_takeover():
    sb = TakeoverSandbox("<html><body>Welcome to our site</body></html>")
    out = SubdomainTakeoverTool(_client_for("https://www.app.test", sb)).run(url="https://www.app.test")
    assert "No takeover fingerprint" in out.output
