"""The mass_assignment_probe tool: inject privileged fields and read the echo."""
from __future__ import annotations

import json

from proofmark.authorization import Authorization
from proofmark.http_client import HttpClient, Request, RequestLog
from proofmark.tools.mass_assignment_tool import MassAssignmentTool


class EchoSandbox:
    """A runner that echoes the request body back (a server that binds it), or a
    fixed response when echo=False."""

    def __init__(self, echo: bool = True, status: int = 200) -> None:
        self.runner_path = "/r"
        self.echo = echo
        self.status = status

    def exec(self, cmd, timeout=None):
        spec = json.loads(cmd[-1])
        body = spec.get("body") or '{"ok":true}'
        return 0, json.dumps({
            "status": self.status,
            "body": body if self.echo else '{"ok":true}',
            "headers": {}, "elapsed_ms": 1,
        })


def _client(sandbox):
    return HttpClient(sandbox, Authorization.grant("https://app.test", "me"),
                      RequestLog(), safe_mode=True)


def _seed_post(client, body='{"name":"alice"}'):
    client.send(Request("POST", "https://app.test/api/users", {"Content-Type": "application/json"}, body))


def test_injected_fields_that_are_echoed_are_flagged():
    c = _client(EchoSandbox(echo=True))
    _seed_post(c)
    out = MassAssignmentTool(c).run(index=0)
    assert not out.is_error
    assert "echoes the injected field" in out.output
    assert "is_admin" in out.output or "role" in out.output


def test_no_echo_is_reported_as_inconclusive():
    c = _client(EchoSandbox(echo=False))
    _seed_post(c)
    out = MassAssignmentTool(c).run(index=0)
    assert not out.is_error
    assert "None of the injected fields" in out.output


def test_custom_fields_are_injected():
    c = _client(EchoSandbox(echo=True))
    _seed_post(c)
    out = MassAssignmentTool(c).run(index=0, fields={"balance": 999999})
    assert "balance" in out.output


def test_a_request_without_a_json_body_is_refused():
    c = _client(EchoSandbox())
    c.send(Request("GET", "https://app.test/api/users"))
    out = MassAssignmentTool(c).run(index=0)
    assert out.is_error and "JSON" in out.output


def test_unknown_request_number_is_refused():
    c = _client(EchoSandbox())
    assert MassAssignmentTool(c).run(index=42).is_error


def test_original_body_fields_are_preserved_alongside_injected_ones():
    c = _client(EchoSandbox(echo=True))
    _seed_post(c, '{"name":"alice"}')
    out = MassAssignmentTool(c).run(index=0, fields={"is_admin": True})
    # the replayed request echoed a body carrying both the original and injected field
    replay = c.log.get(1)
    sent = json.loads(replay.response_preview)
    assert sent["name"] == "alice" and sent["is_admin"] is True
    assert not out.is_error
