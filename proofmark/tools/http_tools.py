"""The agent's HTTP tools: send, list what was sent, and replay with changes.

Together these are an intercept proxy in agent form. `http_request` sends a
fresh request; `list_requests` shows the history; `replay_request` takes a past
request and resends it with any field overridden — the capture-mutate-replay
loop that confirms an injection or an authorization bypass.
"""
from __future__ import annotations

from proofmark.http_client import HttpClient, Request
from proofmark.tools.base import Tool, ToolResult


class HttpRequestTool(Tool):
    name = "http_request"
    returns_untrusted_data = True
    description = (
        "Send an HTTP request to the target and get the response. Use it to probe "
        "endpoints and test a hypothesis. Only hosts within the authorized scope "
        "are allowed. Every request is logged and can be replayed."
    )
    parameters = {
        "type": "object",
        "properties": {
            "method": {"type": "string"},
            "url": {"type": "string"},
            "headers": {"type": "object"},
            "body": {"type": "string"},
        },
        "required": ["method", "url"],
    }

    def __init__(self, client: HttpClient) -> None:
        self._client = client

    def run(self, **kwargs) -> ToolResult:
        req = Request(kwargs.get("method", "GET"), kwargs.get("url", ""),
                      kwargs.get("headers") or {}, kwargs.get("body"))
        ok, text, ex = self._client.send(req)
        return ToolResult(f"[request #{ex.index}] {text}", is_error=not ok)


class ListRequestsTool(Tool):
    name = "list_requests"
    description = "List the HTTP requests you have sent so far, with their status, so you can replay one."
    parameters = {"type": "object", "properties": {}}

    def __init__(self, client: HttpClient) -> None:
        self._client = client

    def run(self, **kwargs) -> ToolResult:
        return ToolResult(self._client.log.summary())


class ReplayRequestTool(Tool):
    name = "replay_request"
    returns_untrusted_data = True
    description = (
        "Resend a previous request with fields changed — the core of confirming a "
        "bug. Give the request number from list_requests and override any of method, "
        "url, headers, body. Omitted fields are reused from the original."
    )
    parameters = {
        "type": "object",
        "properties": {
            "index": {"type": "integer", "description": "The request number to replay."},
            "method": {"type": "string"},
            "url": {"type": "string"},
            "headers": {"type": "object", "description": "Replaces the original headers if given."},
            "body": {"type": "string"},
        },
        "required": ["index"],
    }

    def __init__(self, client: HttpClient) -> None:
        self._client = client

    def run(self, **kwargs) -> ToolResult:
        original = self._client.log.get(int(kwargs.get("index", -1)))
        if original is None:
            return ToolResult("No request with that number. Use list_requests first.", is_error=True)
        base = original.request
        req = Request(
            method=kwargs.get("method", base.method),
            url=kwargs.get("url", base.url),
            headers=kwargs["headers"] if "headers" in kwargs else base.headers,
            body=kwargs["body"] if "body" in kwargs else base.body,
        )
        ok, text, ex = self._client.send(req)
        if ok:
            # A reproduced live response is the corroboration that lets a finding
            # earn "high" confidence rather than "I think" — see record_finding.
            self._client.log.replays_ok += 1
        return ToolResult(f"[replay of #{original.index} as #{ex.index}] {text}", is_error=not ok)
