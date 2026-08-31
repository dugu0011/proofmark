"""SSRF tool — out-of-band blind proof + metadata/file reads.

A fake sandbox stands in for a vulnerable app: it extracts the URL the app was
told to fetch and either actually fetches it (so the real OOB listener records a
hit) or returns canned sensitive content for metadata/file URLs.
"""
from __future__ import annotations

import json
import urllib.request
from urllib.parse import parse_qsl, unquote_plus, urlsplit

import pytest

from proofmark.authorization import Authorization
from proofmark.http_client import HttpClient, RequestLog
from proofmark.oob import InteractionServer
from proofmark.tools.ssrf_tool import SsrfTool


def _find_url(spec):
    vals = [v for _, v in parse_qsl(urlsplit(spec.get("url", "")).query, keep_blank_values=True)]
    vals += [v for _, v in parse_qsl(spec.get("body") or "", keep_blank_values=True)]
    for v in vals:
        v = unquote_plus(v)
        if v.startswith(("http://", "https://", "file://")):
            return v
    return None


class VulnSsrfSandbox:
    runner_path = "/runner.py"

    def exec(self, cmd, timeout=None):
        target = _find_url(json.loads(cmd[-1]))
        if target and target.startswith("file://"):
            return 0, json.dumps({"status": 200, "body": "root:x:0:0:root:/root:/bin/bash\n"})
        if target and "169.254.169.254" in target:
            return 0, json.dumps({"status": 200,
                                  "body": "ami-id\ninstance-id\niam/security-credentials/role\n"})
        if target and target.startswith("http"):
            try:
                urllib.request.urlopen(target, timeout=3).read()  # the SSRF: app fetches it
            except Exception:
                pass
            return 0, json.dumps({"status": 200, "body": "fetched"})
        return 0, json.dumps({"status": 200, "body": "ok"})


class SafeSsrfSandbox:
    runner_path = "/runner.py"

    def exec(self, cmd, timeout=None):
        return 0, json.dumps({"status": 200, "body": "static content, never fetches"})


def _client(sandbox):
    return HttpClient(sandbox, Authorization.grant("https://app.test", "me"), RequestLog(),
                      safe_mode=True)


URL = "https://app.test/fetch?url=http://example.com&x=1"


@pytest.fixture
def oob():
    s = InteractionServer(bind_host="127.0.0.1", bind_port=0, public_host="127.0.0.1")
    try:
        yield s
    finally:
        s.close()


def test_blind_ssrf_confirmed_out_of_band(oob):
    out = SsrfTool(_client(VulnSsrfSandbox()), oob=oob).run(url=URL, param="url")
    assert "SSRF CONFIRMED" in out.output
    assert "BLIND SSRF (out-of-band)" in out.output


def test_metadata_read_detected():
    out = SsrfTool(_client(VulnSsrfSandbox())).run(url=URL, param="url")
    assert "SSRF CONFIRMED" in out.output
    assert "aws-imds" in out.output


def test_file_read_detected():
    out = SsrfTool(_client(VulnSsrfSandbox())).run(url=URL, param="url")
    assert "file-passwd" in out.output


def test_safe_parameter_is_clean(oob):
    out = SsrfTool(_client(SafeSsrfSandbox()), oob=oob).run(url=URL, param="url")
    assert "No SSRF confirmed" in out.output


def test_missing_parameter_errors():
    out = SsrfTool(_client(SafeSsrfSandbox())).run(url=URL, param="nope")
    assert out.is_error and "was not found" in out.output


def test_body_parameter(oob):
    out = SsrfTool(_client(VulnSsrfSandbox()), oob=oob).run(
        url="https://app.test/import", param="src", method="POST", where="body",
        body="src=http://x&name=a")
    assert "BLIND SSRF (out-of-band)" in out.output


def test_output_is_fenced_as_untrusted():
    assert SsrfTool(_client(SafeSsrfSandbox())).returns_untrusted_data is True
