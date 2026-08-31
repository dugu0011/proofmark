"""SSTI, path-traversal, and open-redirect tools."""
from __future__ import annotations

import json
import urllib.request
from urllib.parse import parse_qsl, unquote_plus, urlsplit

import pytest

from proofmark.authorization import Authorization
from proofmark.http_client import HttpClient, RequestLog
from proofmark.oob import InteractionServer
from proofmark.tools.ssti_tool import SstiTool
from proofmark.tools.lfi_tool import PathTraversalTool
from proofmark.tools.redirect_tool import OpenRedirectTool


def _decoded(cmd):
    spec = json.loads(cmd[-1])
    return unquote_plus(f"{spec.get('url','')} {spec.get('body','') or ''}")


def _client(sandbox):
    return HttpClient(sandbox, Authorization.grant("https://app.test", "me"), RequestLog(),
                      safe_mode=True)


# ---------------------------------------------------------------------- SSTI


class SstiSandbox:
    runner_path = "/runner.py"

    def exec(self, cmd, timeout=None):
        text = _decoded(cmd)
        # a naive template renderer: evaluate 73*79 when the template braces appear
        body = text
        for delim_open, delim_close in (("{{", "}}"), ("${", "}"), ("#{", "}"),
                                        ("<%=", "%>"), ("*{", "}")):
            if f"{delim_open}73*79{delim_close}" in text:
                body = body.replace(f"{delim_open}73*79{delim_close}", "5767")
        return 0, json.dumps({"status": 200, "body": f"Hello {body}"})


class NoSstiSandbox:
    runner_path = "/runner.py"

    def exec(self, cmd, timeout=None):
        # reflects input verbatim (no template evaluation)
        return 0, json.dumps({"status": 200, "body": "Hello " + _decoded(cmd)})


def test_ssti_confirmed_and_engine_named():
    out = SstiTool(_client(SstiSandbox())).run(url="https://app.test/greet?name=bob", param="name")
    assert "SSTI CONFIRMED" in out.output
    assert "Jinja2" in out.output


def test_ssti_negative_when_not_evaluated():
    out = SstiTool(_client(NoSstiSandbox())).run(url="https://app.test/greet?name=bob", param="name")
    assert "No template injection" in out.output


# -------------------------------------------------------------- path traversal


class LfiSandbox:
    runner_path = "/runner.py"

    def exec(self, cmd, timeout=None):
        text = _decoded(cmd)
        if "etc/passwd" in text:
            return 0, json.dumps({"status": 200, "body": "root:x:0:0:root:/root:/bin/bash\n"})
        return 0, json.dumps({"status": 200, "body": "page contents"})


class SafeFileSandbox:
    runner_path = "/runner.py"

    def exec(self, cmd, timeout=None):
        return 0, json.dumps({"status": 200, "body": "page not found"})


def test_path_traversal_confirmed():
    out = PathTraversalTool(_client(LfiSandbox())).run(
        url="https://app.test/view?file=home.txt", param="file")
    assert "PATH TRAVERSAL CONFIRMED" in out.output
    assert "root:x:0:0" in out.output


def test_path_traversal_negative():
    out = PathTraversalTool(_client(SafeFileSandbox())).run(
        url="https://app.test/view?file=home.txt", param="file")
    assert "No path traversal" in out.output


def test_missing_param_errors():
    out = PathTraversalTool(_client(SafeFileSandbox())).run(
        url="https://app.test/view?file=home.txt", param="nope")
    assert out.is_error


# --------------------------------------------------------------- open redirect


def _find_url(cmd):
    spec = json.loads(cmd[-1])
    for _, v in parse_qsl(urlsplit(spec.get("url", "")).query, keep_blank_values=True):
        v = unquote_plus(v)
        if v.startswith("http://") or v.startswith("https://"):
            return v
    return None


class RedirectSandbox:
    """Follows the redirect to whatever absolute URL the parameter holds."""
    runner_path = "/runner.py"

    def exec(self, cmd, timeout=None):
        target = _find_url(cmd)
        if target:
            try:
                urllib.request.urlopen(target, timeout=3).read()
            except Exception:
                pass
        return 0, json.dumps({"status": 200, "body": "redirected"})


class NoRedirectSandbox:
    runner_path = "/runner.py"

    def exec(self, cmd, timeout=None):
        return 0, json.dumps({"status": 200, "body": "staying here"})


@pytest.fixture
def oob():
    s = InteractionServer(bind_host="127.0.0.1", bind_port=0, public_host="127.0.0.1")
    try:
        yield s
    finally:
        s.close()


def test_open_redirect_confirmed(oob):
    out = OpenRedirectTool(_client(RedirectSandbox()), oob=oob).run(
        url="https://app.test/login?next=/home", param="next")
    assert "OPEN REDIRECT CONFIRMED" in out.output


def test_open_redirect_negative(oob):
    out = OpenRedirectTool(_client(NoRedirectSandbox()), oob=oob).run(
        url="https://app.test/login?next=/home", param="next")
    assert "No open redirect" in out.output


def test_open_redirect_needs_oob():
    out = OpenRedirectTool(_client(NoRedirectSandbox())).run(
        url="https://app.test/login?next=/home", param="next")
    assert out.is_error and "out-of-band listener" in out.output
