"""Deserialization (OOB) + session-fixation tools."""
from __future__ import annotations

import json
import re
import urllib.request
from urllib.parse import unquote_plus

import pytest

from proofmark.authorization import Authorization
from proofmark.http_client import HttpClient, RequestLog
from proofmark.oob import InteractionServer
from proofmark.tools.deserialization_tool import DeserializationTool
from proofmark.tools.session_tool import SessionFixationTool


def _client(sandbox):
    return HttpClient(sandbox, Authorization.grant("https://app.test", "me"), RequestLog(),
                      safe_mode=True)


# ------------------------------------------------------------ deserialization


class VulnDeserSandbox:
    """Deserializes the blob and runs its embedded `curl <canary>` (OOB)."""
    runner_path = "/runner.py"

    def exec(self, cmd, timeout=None):
        spec = json.loads(cmd[-1])
        text = unquote_plus((spec.get("body") or "") + " " + json.dumps(spec.get("headers") or {}))
        m = re.search(r"curl\s+(https?://[^\s&|;)'\"\\]+)", text)
        if m:
            try:
                urllib.request.urlopen(m.group(1), timeout=3).read()
            except Exception:
                pass
        return 0, json.dumps({"status": 200, "body": "ok"})


class SafeDeserSandbox:
    runner_path = "/runner.py"

    def exec(self, cmd, timeout=None):
        return 0, json.dumps({"status": 200, "body": "ok"})


@pytest.fixture
def oob():
    s = InteractionServer(bind_host="127.0.0.1", bind_port=0, public_host="127.0.0.1")
    try:
        yield s
    finally:
        s.close()


def test_deserialization_confirmed_oob(oob):
    out = DeserializationTool(_client(VulnDeserSandbox()), oob=oob).run(url="https://app.test/load")
    assert "INSECURE DESERIALIZATION CONFIRMED" in out.output


def test_deserialization_safe(oob):
    out = DeserializationTool(_client(SafeDeserSandbox()), oob=oob).run(url="https://app.test/load")
    assert "No deserialization RCE confirmed" in out.output


def test_deserialization_needs_oob():
    out = DeserializationTool(_client(SafeDeserSandbox())).run(url="https://app.test/load")
    assert out.is_error and "out-of-band" in out.output.lower()


# ------------------------------------------------------------ session fixation


class FakeClient:
    def __init__(self, response):
        self.response = response
        self.sent = None

    def send_full(self, request, identity=None):
        self.sent = request
        return self.response


def test_session_fixation_flagged_when_accepted():
    c = FakeClient({"status": 200, "headers": {}, "body": ""})   # no Set-Cookie -> accepted
    out = SessionFixationTool(c).run(url="https://app.test/login", cookie_name="session")
    assert "POSSIBLE SESSION FIXATION" in out.output


def test_session_fixation_clean_when_rotated():
    c = FakeClient({"status": 200, "headers": {"Set-Cookie": "session=freshRotated999; Path=/"}, "body": ""})
    out = SessionFixationTool(c).run(url="https://app.test/login", cookie_name="session")
    assert "No session fixation" in out.output
