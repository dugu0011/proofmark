"""CSRF check. Sends a state-changing request with a foreign Origin/Referer and no
anti-CSRF token; if the endpoint still accepts it, it isn't validating origin or a
token. Most meaningful when authenticated (so the request would really do something)."""
from __future__ import annotations

from proofmark.http_client import Request
from proofmark.tools.base import Tool, ToolResult

_EVIL = "https://evil.example"


class CsrfTool(Tool):
    name = "csrf_test"
    description = (
        "Check a state-changing endpoint for CSRF protection. Sends the request with a foreign "
        "Origin/Referer and no anti-CSRF token; if it's accepted (2xx), the endpoint doesn't appear "
        "to validate origin or a token — a cross-site page could trigger it. Use on POST endpoints "
        "while authenticated. Give the url, method, and body."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "The state-changing endpoint."},
            "method": {"type": "string", "description": "HTTP method (default POST)."},
            "body": {"type": "string", "description": "Request body to submit."},
        },
        "required": ["url"],
    }
    returns_untrusted_data = True

    def __init__(self, client) -> None:
        self._client = client

    def run(self, url="", method="POST", body=None, **_) -> ToolResult:
        method = (method or "POST").upper()
        headers = {"Origin": _EVIL, "Referer": _EVIL + "/",
                   "Content-Type": "application/x-www-form-urlencoded"}
        data = self._client.send_full(Request(method, url, headers, body))
        if data.get("error"):
            return ToolResult(f"request failed: {data['error']}", is_error=True)
        status = data.get("status")
        if isinstance(status, int) and 200 <= status < 300:
            return ToolResult(
                f"POSSIBLE CSRF (medium) on {method} {url}: the request was accepted (HTTP {status}) "
                f"with a foreign Origin ({_EVIL}) and no anti-CSRF token — the endpoint doesn't appear "
                "to check origin or a token. Confirm it performs a real state change and that the "
                "session cookie lacks SameSite=Lax/Strict, then record it.")
        return ToolResult(
            f"CSRF unlikely on {method} {url}: the cross-origin request was rejected (HTTP {status}). "
            "The endpoint appears to enforce an origin or token check.")
