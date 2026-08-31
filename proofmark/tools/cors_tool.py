"""CORS misconfiguration testing. Sends a foreign Origin and inspects the CORS
response headers: reflecting an arbitrary origin — especially with credentials —
lets a malicious site read authenticated responses from the target."""
from __future__ import annotations

from proofmark.http_client import Request
from proofmark.tools.base import Tool, ToolResult

_EVIL = "https://evil.example"


class CorsTool(Tool):
    name = "cors_test"
    description = (
        "Test an endpoint for CORS misconfiguration. Sends Origin: https://evil.example and checks "
        "whether the response reflects that arbitrary origin, trusts 'null', or uses '*' with "
        "credentials — any of which lets a malicious site read the target's responses (authenticated "
        "ones, if credentials are allowed). Give the URL."
    )
    parameters = {"type": "object",
                  "properties": {"url": {"type": "string", "description": "The endpoint to test."}},
                  "required": ["url"]}
    returns_untrusted_data = True

    def __init__(self, client) -> None:
        self._client = client

    def run(self, url="", **_) -> ToolResult:
        data = self._client.send_full(Request("GET", url, {"Origin": _EVIL}))
        if data.get("error"):
            return ToolResult(f"request failed: {data['error']}", is_error=True)
        headers = {k.lower(): v for k, v in (data.get("headers") or {}).items()}
        acao = headers.get("access-control-allow-origin")
        acac = (headers.get("access-control-allow-credentials") or "").strip().lower() == "true"
        if acao is None:
            return ToolResult(f"No CORS headers on {url} — the endpoint does not send "
                              "Access-Control-Allow-Origin, so cross-origin reads are not enabled here.")
        issues = []
        if acao == _EVIL:
            issues.append(f"reflects an arbitrary Origin (ACAO = {acao})")
        elif acao.strip().lower() == "null":
            issues.append("trusts the 'null' origin (reachable from a sandboxed iframe / data: URL)")
        elif acao == "*" and acac:
            issues.append("uses wildcard '*' together with credentials")
        if issues:
            severity = "high" if acac else "medium"
            impact = ("With Allow-Credentials: true, a malicious origin can read authenticated responses."
                      if acac else "A malicious origin can read this response cross-site.")
            return ToolResult(f"CORS MISCONFIGURATION ({severity}) on {url}: " + "; ".join(issues) +
                              f". {impact} Record the finding with these headers as evidence.")
        return ToolResult(f"CORS looks safe on {url}: ACAO = {acao}, credentials = {acac}. An arbitrary "
                          "origin is not reflected.")
