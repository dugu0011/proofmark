"""Shared parameter-injection helpers for the exploit tools: read a parameter's
value, rewrite it (query or body), and send while timing the round-trip."""
from __future__ import annotations

import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from proofmark.http_client import Request


def base_value(url: str, param: str, where: str, body: str | None) -> str | None:
    src = parse_qsl(body or "", keep_blank_values=True) if where == "body" \
        else parse_qsl(urlsplit(url).query, keep_blank_values=True)
    for k, v in src:
        if k == param:
            return v
    return None


def set_param(url: str, param: str, where: str, body: str | None, value: str):
    """Return (url, body) with `param` set to value, or None if the param is absent."""
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


def send_timed(client, method: str, url: str, body: str | None):
    """Return (status, response_body, elapsed_seconds)."""
    start = time.perf_counter()
    _ok, _text, ex = client.send(Request(method, url, {}, body))
    return (ex.status if ex else None), (ex.response_preview if ex else "") or "", \
        time.perf_counter() - start
