"""Prototype pollution (Node/JS) testing.

If a backend deep-merges request JSON into an object without guarding __proto__ /
constructor.prototype, an attacker can add properties to Object.prototype — which
then appear on objects that never set them. This injects a uniquely-named property
via __proto__, then checks whether it surfaces in a response where it was never
set — the signature of a polluted prototype.
"""
from __future__ import annotations

from proofmark.http_client import Request
from proofmark.tools.base import Tool, ToolResult

_MARK = "pmProtoPolluted"
_VAL = "PM_PP_INJECTED"
_PAYLOADS = [
    f'{{"__proto__":{{"{_MARK}":"{_VAL}"}}}}',
    f'{{"constructor":{{"prototype":{{"{_MARK}":"{_VAL}"}}}}}}',
]


class PrototypePollutionTool(Tool):
    name = "prototype_pollution_test"
    description = (
        "Test a JSON endpoint for prototype pollution (Node/JS). Sends __proto__ and "
        "constructor.prototype payloads, then checks whether the injected property leaks into a "
        "response where it was never set — the signature of a vulnerable object merge. Give the "
        "url (and optionally probe_url — a GET endpoint returning an object to inspect afterwards)."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Endpoint that merges a JSON body."},
            "method": {"type": "string", "description": "HTTP method (default POST)."},
            "probe_url": {"type": "string", "description": "GET endpoint to inspect after polluting "
                          "(defaults to re-GETting url)."},
        },
        "required": ["url"],
    }
    returns_untrusted_data = True

    def __init__(self, client) -> None:
        self._client = client

    def _send(self, method, url, body):
        _o, _t, ex = self._client.send(
            Request(method, url, {"Content-Type": "application/json"}, body))
        return (ex.response_preview if ex else "") or ""

    def _get(self, url):
        _o, _t, ex = self._client.send(Request("GET", url, {}))
        return (ex.response_preview if ex else "") or ""

    def run(self, url="", method="POST", probe_url="", **_) -> ToolResult:
        method = (method or "POST").upper()
        check = probe_url or url
        for payload in _PAYLOADS:
            self._send(method, url, payload)
            body = self._get(check)
            if _VAL in body and _MARK in body:
                return ToolResult(
                    f"PROTOTYPE POLLUTION LIKELY on {url} (high). After sending "
                    f"{payload}, the injected property '{_MARK}' surfaced in a later response "
                    f"({check}) though it was never set there — Object.prototype is being polluted. "
                    "Record it; this can escalate to DoS, XSS, or RCE depending on downstream sinks.")
        return ToolResult(
            f"No prototype pollution detected on {url}. The __proto__ / constructor.prototype "
            "payloads did not surface in a later response — the merge appears guarded.")
