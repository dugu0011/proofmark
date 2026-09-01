"""Session-fixation check.

If the server accepts a session identifier the client supplies and does not issue
a fresh one, an attacker can fix a victim's session id ahead of time and ride it
after the victim authenticates. This sends a request carrying an attacker-chosen
session cookie and checks whether the server replaces it (rotates) or accepts it.
"""
from __future__ import annotations

import re

from proofmark.http_client import Request
from proofmark.tools.base import Tool, ToolResult

_FIXED = "proofmarkFixedSid123456"


class SessionFixationTool(Tool):
    name = "session_fixation_test"
    description = (
        "Check for session fixation. Sends a request with an attacker-chosen value for the session "
        "cookie and inspects Set-Cookie: if the server keeps that value instead of issuing a fresh "
        "session, an attacker can pre-fix a victim's session. Give the url and the session cookie "
        "name (e.g. session, sessionid, connect.sid, JSESSIONID). Most telling on the login endpoint."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "URL to probe (ideally the login endpoint)."},
            "cookie_name": {"type": "string", "description": "Name of the session cookie."},
            "method": {"type": "string", "description": "HTTP method (default GET)."},
        },
        "required": ["url", "cookie_name"],
    }
    returns_untrusted_data = True

    def __init__(self, client) -> None:
        self._client = client

    def run(self, url="", cookie_name="", method="GET", **_) -> ToolResult:
        method = (method or "GET").upper()
        data = self._client.send_full(
            Request(method, url, {"Cookie": f"{cookie_name}={_FIXED}"}))
        if data.get("error"):
            return ToolResult(f"request failed: {data['error']}", is_error=True)
        headers = {k.lower(): v for k, v in (data.get("headers") or {}).items()}
        set_cookie = headers.get("set-cookie", "")
        m = re.search(rf"{re.escape(cookie_name)}=([^;,\s]+)", set_cookie)
        if m and m.group(1) != _FIXED:
            return ToolResult(
                f"No session fixation on {url}: the server issued a fresh {cookie_name} "
                f"({m.group(1)[:12]}…) instead of keeping the supplied value — good, it rotates.")
        if not set_cookie or (m is None):
            return ToolResult(
                f"POSSIBLE SESSION FIXATION on {url} (medium): the server accepted the attacker-"
                f"chosen {cookie_name}={_FIXED} and did not issue a new one. Confirm the session is "
                "still valid after login (not rotated on authentication), then record it.")
        return ToolResult(
            f"POSSIBLE SESSION FIXATION on {url} (medium): the server echoed back the supplied "
            f"{cookie_name} value rather than rotating it. Confirm it survives login, then record.")
