"""CORS and CSRF tools (both use HttpClient.send_full)."""
from __future__ import annotations

from proofmark.tools.cors_tool import CorsTool
from proofmark.tools.csrf_tool import CsrfTool


class FakeClient:
    def __init__(self, response):
        self.response = response
        self.sent = None

    def send_full(self, request, identity=None):
        self.sent = request
        return self.response


# ------------------------------------------------------------------------ CORS


def test_cors_reflects_arbitrary_origin_with_credentials():
    c = FakeClient({"status": 200, "headers": {
        "Access-Control-Allow-Origin": "https://evil.example",
        "Access-Control-Allow-Credentials": "true"}, "body": ""})
    out = CorsTool(c).run(url="https://app.test/api/me")
    assert "CORS MISCONFIGURATION (high)" in out.output
    assert "reflects an arbitrary Origin" in out.output


def test_cors_null_origin():
    c = FakeClient({"status": 200, "headers": {"Access-Control-Allow-Origin": "null"}, "body": ""})
    out = CorsTool(c).run(url="https://app.test/api")
    assert "CORS MISCONFIGURATION" in out.output and "null" in out.output


def test_cors_safe_when_not_reflected():
    c = FakeClient({"status": 200, "headers": {
        "Access-Control-Allow-Origin": "https://app.test"}, "body": ""})
    out = CorsTool(c).run(url="https://app.test/api")
    assert "CORS looks safe" in out.output


def test_cors_no_headers():
    c = FakeClient({"status": 200, "headers": {}, "body": ""})
    assert "No CORS headers" in CorsTool(c).run(url="https://app.test/api").output


def test_cors_sends_evil_origin():
    c = FakeClient({"status": 200, "headers": {}, "body": ""})
    CorsTool(c).run(url="https://app.test/api")
    assert c.sent.headers["Origin"] == "https://evil.example"


# ------------------------------------------------------------------------ CSRF


def test_csrf_accepted_cross_origin_is_flagged():
    c = FakeClient({"status": 200, "headers": {}, "body": "ok"})
    out = CsrfTool(c).run(url="https://app.test/account/email", method="POST", body="email=x@x")
    assert "POSSIBLE CSRF" in out.output
    assert c.sent.headers["Origin"] == "https://evil.example"


def test_csrf_rejected_is_safe():
    c = FakeClient({"status": 403, "headers": {}, "body": "forbidden"})
    out = CsrfTool(c).run(url="https://app.test/account/email", method="POST")
    assert "CSRF unlikely" in out.output
