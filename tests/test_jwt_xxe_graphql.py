"""JWT, XXE, and GraphQL tools."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import urllib.request

import pytest

from proofmark.authorization import Authorization
from proofmark.http_client import HttpClient, RequestLog
from proofmark.oob import InteractionServer
from proofmark.tools.jwt_tool import JwtAttackTool
from proofmark.tools.xxe_tool import XxeTool
from proofmark.tools.graphql_tool import GraphQLTool


def _client(sandbox):
    return HttpClient(sandbox, Authorization.grant("https://app.test", "me"), RequestLog(),
                      safe_mode=True)


# ------------------------------------------------------------------------ JWT


def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _make_jwt(payload, secret, alg="HS256"):
    h = _b64(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    p = _b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def test_jwt_weak_secret_cracked_and_forged():
    token = _make_jwt({"sub": "1", "role": "user"}, "secret")
    out = JwtAttackTool().run(token=token, claims={"role": "admin"})
    assert "WEAK SECRET CRACKED: 'secret'" in out.output
    forged = out.data["forged"]["signed"]
    # the forged token must verify under the cracked secret and carry the new claim
    h, p, sig = forged.split(".")
    expect = _b64(hmac.new(b"secret", f"{h}.{p}".encode(), hashlib.sha256).digest())
    assert sig == expect
    payload = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    assert payload["role"] == "admin"


def test_jwt_alg_none_always_offered():
    token = _make_jwt({"sub": "1"}, "unguessable-random-key-9x8y7z-not-in-list")
    out = JwtAttackTool().run(token=token, claims={"admin": True})
    assert "alg=none" in out.output
    assert out.data["forged"]["alg_none"].endswith(".")   # empty signature


def test_jwt_rejects_non_token():
    assert JwtAttackTool().run(token="not-a-jwt").is_error


# ------------------------------------------------------------------------ XXE


class XxeSandbox:
    runner_path = "/runner.py"

    def exec(self, cmd, timeout=None):
        body = json.loads(cmd[-1]).get("body", "") or ""
        m = re.search(r'SYSTEM\s+"(https?://[^"]+)"', body)
        if m:
            try:
                urllib.request.urlopen(m.group(1), timeout=3).read()
            except Exception:
                pass
            return 0, json.dumps({"status": 200, "body": "<r></r>"})
        if 'file:///etc/passwd' in body:
            return 0, json.dumps({"status": 200, "body": "<r>root:x:0:0:root:/root:/bin/bash</r>"})
        return 0, json.dumps({"status": 200, "body": "<r>ok</r>"})


class SafeXmlSandbox:
    runner_path = "/runner.py"

    def exec(self, cmd, timeout=None):
        return 0, json.dumps({"status": 200, "body": "<r>entities disabled</r>"})


@pytest.fixture
def oob():
    s = InteractionServer(bind_host="127.0.0.1", bind_port=0, public_host="127.0.0.1")
    try:
        yield s
    finally:
        s.close()


def test_xxe_blind_out_of_band(oob):
    out = XxeTool(_client(XxeSandbox()), oob=oob).run(url="https://app.test/xml")
    assert "XXE CONFIRMED" in out.output
    assert "BLIND XXE" in out.output


def test_xxe_file_read():
    out = XxeTool(_client(XxeSandbox())).run(url="https://app.test/xml")
    assert "XXE FILE READ" in out.output


def test_xxe_safe():
    out = XxeTool(_client(SafeXmlSandbox())).run(url="https://app.test/xml")
    assert "No XXE confirmed" in out.output


# -------------------------------------------------------------------- GraphQL


class GraphQLSandbox:
    runner_path = "/runner.py"

    def exec(self, cmd, timeout=None):
        schema = {"data": {"__schema": {"queryType": {"name": "Query"},
                  "types": [{"name": "User"}, {"name": "createUser"}, {"name": "password"},
                            {"name": "Product"}]}}}
        return 0, json.dumps({"status": 200, "body": json.dumps(schema)})


class NoIntrospectionSandbox:
    runner_path = "/runner.py"

    def exec(self, cmd, timeout=None):
        return 0, json.dumps({"status": 200, "body": '{"errors":[{"message":"introspection disabled"}]}'})


def test_graphql_introspection_enabled_flags_sensitive():
    out = GraphQLTool(_client(GraphQLSandbox())).run(url="https://app.test/graphql")
    assert "INTROSPECTION ENABLED" in out.output
    assert "createUser" in out.output and "password" in out.output


def test_graphql_introspection_disabled():
    out = GraphQLTool(_client(NoIntrospectionSandbox())).run(url="https://app.test/graphql")
    assert "did not return a schema" in out.output
