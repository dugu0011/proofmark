"""Cross-site scripting with real execution proof.

Reflection isn't proof — the payload has to actually run. This tool injects XSS
payloads that call alert() with a unique token, loads the page in the headless
browser, and confirms only when a dialog fires carrying that token. A fired dialog
is unambiguous: injected script executed. No dialog, no finding."""
from __future__ import annotations

import secrets

from proofmark.tools._paraminject import base_value, set_param
from proofmark.tools.base import Tool, ToolResult

# Break-out payloads across the common reflection contexts (HTML body, attribute,
# script string, tag). {t} is the unique token the dialog must echo back.
_PAYLOADS = [
    "<script>alert('{t}')</script>",
    "\"><script>alert('{t}')</script>",
    "'><script>alert('{t}')</script>",
    "\"><img src=x onerror=alert('{t}')>",
    "\"><svg onload=alert('{t}')>",
    "'-alert('{t}')-'",
    "javascript:alert('{t}')",
]


class XssTool(Tool):
    name = "xss_test"
    description = (
        "Test a parameter for XSS by proving execution, not reflection. Injects payloads that "
        "call alert() with a unique token, loads the page in the real headless browser, and "
        "confirms only when a dialog fires with that token — so a reflected-but-escaped value is "
        "never a false positive. Give the full url and the parameter. Needs the browser sandbox."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Full URL including the parameter's value."},
            "param": {"type": "string", "description": "Parameter to inject into."},
        },
        "required": ["url", "param"],
    }
    returns_untrusted_data = True

    def __init__(self, browser) -> None:
        self._browser = browser

    def run(self, url="", param="", **_) -> ToolResult:
        if base_value(url, param, "query", None) is None:
            return ToolResult(f"Parameter '{param}' was not found in the query string.",
                              is_error=True)
        token = "PX" + secrets.token_hex(4)
        for template in _PAYLOADS:
            payload = template.format(t=token)
            target, _b = set_param(url, param, "query", None, payload)
            data = self._browser.navigate(target)
            if isinstance(data, dict) and data.get("error"):
                return ToolResult(f"Browser unavailable for XSS confirmation: {data['error']}. "
                                  "Build it once with `proofmark build-sandbox`, then retry.",
                                  is_error=True)
            for d in (data or {}).get("dialogs", []):
                if token in str(d.get("message", "")):
                    return ToolResult(
                        f"XSS CONFIRMED on '{param}' (high). Payload {payload!r} fired a "
                        f"{d.get('type', 'dialog')} — injected script executed in the browser. "
                        "Record the finding; the run's screenshot is visual proof.")
        return ToolResult(f"No XSS confirmed on '{param}'. None of the payloads executed (the value "
                          "is likely escaped or filtered). Try a stored context or a different sink.")
