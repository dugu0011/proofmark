"""Open redirect — confirm that a redirect parameter will send a user to an
attacker-controlled URL, proven out of band: point the parameter at a canary and
check whether following the redirect reached it."""
from __future__ import annotations

from proofmark.tools._paraminject import base_value, set_param, send_timed
from proofmark.tools.base import Tool, ToolResult


class OpenRedirectTool(Tool):
    name = "open_redirect_test"
    description = (
        "Test a redirect parameter (?next=, ?return_to=, ?url=, ?redirect_uri=) for open redirect. "
        "Points it at an out-of-band canary and, because redirects are followed, confirms the vuln "
        "when the canary is reached — the app would send a real user to an attacker's site. "
        "Requires the OOB listener. Give the full url and the parameter."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Full URL including the redirect parameter."},
            "param": {"type": "string", "description": "The redirect parameter."},
            "method": {"type": "string", "description": "HTTP method (default GET)."},
            "where": {"type": "string", "enum": ["query", "body"], "description": "query (default) or body."},
            "body": {"type": "string", "description": "Form body, required when where=body."},
        },
        "required": ["url", "param"],
    }
    returns_untrusted_data = True

    def __init__(self, client, oob=None) -> None:
        self._client = client
        self._oob = oob

    def run(self, url="", param="", method="GET", where="query", body=None, **_) -> ToolResult:
        method, where = (method or "GET").upper(), ("body" if where == "body" else "query")
        if base_value(url, param, where, body) is None:
            return ToolResult(f"Parameter '{param}' was not found in the {where}.", is_error=True)
        if self._oob is None:
            return ToolResult("Open-redirect confirmation needs the out-of-band listener, which is "
                              "not available in this run.", is_error=True)

        token = self._oob.new_canary(f"open-redirect {param}")
        canary = self._oob.http_url(token)
        host = canary.split("://", 1)[-1]
        # absolute, scheme-relative, and backslash variants that bypass naive checks
        for target in (canary, f"//{host}", f"/\\{host}", f"https:{host}"):
            u, b = set_param(url, param, where, body, target)
            send_timed(self._client, method, u, b)
            if self._oob.interactions(token):
                return ToolResult(
                    f"OPEN REDIRECT CONFIRMED on '{param}' (medium). The redirect sent the request "
                    f"to the attacker-controlled canary via {target!r}: "
                    f"{self._oob.interactions(token)[0].summary()}")
        return ToolResult(f"No open redirect confirmed on '{param}'. The redirect target was not "
                          "reached out of band (the parameter may be validated).")
