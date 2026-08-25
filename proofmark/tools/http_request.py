"""Send one HTTP request, from inside the sandbox, within the authorized scope.

This is the agent's main probe against a live target. Two things are enforced
here in code rather than trusted to the prompt:

  * the request leaves from inside the sandbox (via the runner script), not the
    host
  * the destination host must be in the authorized scope — an out-of-scope URL
    is refused and the agent is told why, so it cannot wander onto a host the
    operator never authorized.
"""
from __future__ import annotations

import json

from proofmark.authorization import Authorization
from proofmark.sandbox import Sandbox
from proofmark.tools.base import Tool, ToolResult


class HttpRequestTool(Tool):
    name = "http_request"
    description = (
        "Send an HTTP request to the target and get the response back. Use this to "
        "probe endpoints, test parameters, and reproduce a suspected vulnerability. "
        "Only hosts within the authorized scope are allowed."
    )
    parameters = {
        "type": "object",
        "properties": {
            "method": {"type": "string", "description": "GET, POST, PUT, DELETE, ..."},
            "url": {"type": "string", "description": "Full URL, within the authorized scope."},
            "headers": {"type": "object", "description": "Optional request headers."},
            "body": {"type": "string", "description": "Optional request body."},
        },
        "required": ["method", "url"],
    }

    def __init__(self, sandbox: Sandbox, authorization: Authorization) -> None:
        self._sandbox = sandbox
        self._auth = authorization

    def run(self, **kwargs) -> ToolResult:
        url = kwargs.get("url", "")
        if not self._auth.permits_host(url):
            return ToolResult(
                f"Refused: {url} is outside the authorized scope "
                f"({', '.join(sorted(self._auth.allowed_hosts)) or 'no live host'}). "
                "Stay on the target you were pointed at.",
                is_error=True,
            )
        spec = json.dumps({
            "method": kwargs.get("method", "GET"),
            "url": url,
            "headers": kwargs.get("headers") or {},
            "body": kwargs.get("body"),
            "timeout": 20,
        })
        code, out = self._sandbox.exec(["python", self._sandbox.runner_path, spec], timeout=30)
        if code != 0 and not out.strip():
            return ToolResult(f"request failed (exit {code})", is_error=True)
        return ToolResult(out.strip() or "(empty response)")
