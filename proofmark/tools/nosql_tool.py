"""NoSQL (MongoDB) operator-injection testing.

If a backend passes request data straight into a Mongo query, an attacker can slip
in operators — {"$ne": null} to bypass a password check, {"$gt": ""} or
{"$regex": ".*"} to match every record. This proves it differentially: a value
that matches nothing vs the same field with a match-everything operator; if the
operator changes the result, operators are being interpreted.
"""
from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from proofmark.http_client import Request
from proofmark.tools.base import Tool, ToolResult

_MARK = "zqxNoSQLnomatchzqx"      # a value no real record should equal
_OPS = [("$ne", _MARK), ("$gt", ""), ("$regex", ".*")]


class NoSqlInjectionTool(Tool):
    name = "nosql_injection_test"
    description = (
        "Test a parameter for NoSQL (MongoDB) operator injection. Compares a value that matches "
        "nothing against the same field carrying a $ne/$gt/$regex operator that matches everything; "
        "if the operator broadens the result, the backend interprets query operators — enabling "
        "auth bypass and data exfiltration. Works on query params (field[$ne]=) and JSON bodies. "
        "Give the url, the parameter, and where=query or where=json (+ the JSON body)."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Full target URL."},
            "param": {"type": "string", "description": "Parameter / JSON field to inject into."},
            "method": {"type": "string", "description": "HTTP method (default GET; POST for json)."},
            "where": {"type": "string", "enum": ["query", "json"], "description": "query (default) or json."},
            "body": {"type": "string", "description": "JSON request body, required when where=json."},
        },
        "required": ["url", "param"],
    }
    returns_untrusted_data = True

    def __init__(self, client) -> None:
        self._client = client

    # --- request shaping ----------------------------------------------------

    def _query(self, url, drop, add_key, add_value):
        parts = urlsplit(url)
        pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != drop]
        pairs.append((add_key, add_value))
        return urlunsplit(parts._replace(query=urlencode(pairs)))

    def _json(self, body, param, value):
        try:
            data = json.loads(body or "{}")
        except ValueError:
            return None
        if not isinstance(data, dict) or param not in data:
            return None
        data = dict(data)
        data[param] = value
        return json.dumps(data)

    def _send_q(self, method, url):
        _o, _t, ex = self._client.send(Request(method, url, {}))
        return (ex.status if ex else None), len((ex.response_preview if ex else "") or "")

    def _send_j(self, method, url, body):
        _o, _t, ex = self._client.send(Request(method, url, {"Content-Type": "application/json"}, body))
        return (ex.status if ex else None), len((ex.response_preview if ex else "") or "")

    @staticmethod
    def _differs(base, inj) -> bool:
        (bs, bl), (is_, il) = base, inj
        if bs is not None and is_ is not None:
            if (bs >= 400 or bs is None) and 200 <= (is_ or 0) < 300:
                return True                       # operator turned failure into success
        return il - bl > 50                        # operator returned notably more data

    # --- run ----------------------------------------------------------------

    def run(self, url="", param="", method="GET", where="query", body=None, **_) -> ToolResult:
        where = "json" if where == "json" else "query"
        method = (method or ("POST" if where == "json" else "GET")).upper()

        if where == "query":
            parts = urlsplit(url)
            if not any(k == param for k, _ in parse_qsl(parts.query, keep_blank_values=True)):
                return ToolResult(f"Parameter '{param}' was not found in the query string.", is_error=True)
            base = self._send_q(method, self._query(url, param, param, _MARK))
            for op, val in _OPS:
                inj = self._send_q(method, self._query(url, param, f"{param}[{op}]", val))
                if self._differs(base, inj):
                    return self._hit(param, op, base, inj)
            return self._clean(param)

        # json
        if self._json(body, param, _MARK) is None:
            return ToolResult(f"Field '{param}' was not found in the JSON body (or body isn't JSON).",
                              is_error=True)
        base = self._send_j(method, url, self._json(body, param, _MARK))
        for op, val in _OPS:
            inj = self._send_j(method, url, self._json(body, param, {op: val}))
            if self._differs(base, inj):
                return self._hit(param, op, base, inj)
        return self._clean(param)

    def _hit(self, param, op, base, inj):
        return ToolResult(
            f"NOSQL INJECTION LIKELY on '{param}' (high). The {op} operator changed the result — "
            f"baseline (no-match value) → HTTP {base[0]} / {base[1]} bytes, injected ({op}) → "
            f"HTTP {inj[0]} / {inj[1]} bytes. The backend interprets query operators; this commonly "
            "enables authentication bypass and bulk data exfiltration. Record it.")

    def _clean(self, param):
        return ToolResult(f"No NoSQL injection detected on '{param}'. Operator payloads did not "
                          "change the result — operators appear to be treated as literal values.")
