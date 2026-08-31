"""Turn a username + password into a session Proofmark can scan with.

Proofmark authenticates with a session you provide. This does the login for you in
the two common shapes: POST the credentials, then capture either the Set-Cookie
session (cookie apps) or a token from the JSON response (SPA / API apps). Login
flows vary, so if no session is found it says so and you fall back to passing
--auth-header / --auth-cookie directly.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlencode

from proofmark.http_client import Request

_TOKEN_KEYS = ("token", "access_token", "accessToken", "jwt", "id_token", "idToken", "authToken")
_COOKIE_ATTRS = {"path", "domain", "expires", "max-age", "samesite", "secure", "httponly", "version"}
_COOKIE_RE = re.compile(r"\s*([^=;,\s]+)=([^;,]+)")


@dataclass
class LoginResult:
    ok: bool
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    detail: str = ""


def _find_token(body: str):
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    stack = [data]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for k in _TOKEN_KEYS:
                v = node.get(k)
                if isinstance(v, str) and len(v) > 8:
                    return v
            stack.extend(v for v in node.values() if isinstance(v, (dict, list)))
        elif isinstance(node, list):
            stack.extend(node)
    return None


def parse_set_cookie(set_cookie) -> dict:
    """Session cookies from a Set-Cookie header value (string or list)."""
    if not set_cookie:
        return {}
    values = set_cookie if isinstance(set_cookie, list) else [set_cookie]
    cookies: dict = {}
    for raw in values:
        for line in str(raw).split("\n"):
            m = _COOKIE_RE.match(line)
            if m and m.group(1).lower() not in _COOKIE_ATTRS:
                cookies[m.group(1)] = m.group(2).strip()
    return cookies


def perform_login(client, url, username, password, *, user_field="username",
                  pass_field="password", as_json=False) -> LoginResult:
    if as_json:
        body = json.dumps({user_field: username, pass_field: password})
        headers = {"Content-Type": "application/json"}
    else:
        body = urlencode({user_field: username, pass_field: password})
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

    data = client.send_full(Request("POST", url, headers, body))
    if data.get("error"):
        return LoginResult(False, detail=f"login request failed: {data['error']}")

    status = data.get("status")
    resp_headers = data.get("headers") or {}
    set_cookie = next((v for k, v in resp_headers.items() if k.lower() == "set-cookie"), None)
    cookies = parse_set_cookie(set_cookie)
    if cookies:
        return LoginResult(True, cookies=cookies,
                           detail=f"logged in (HTTP {status}); captured {len(cookies)} session cookie(s)")

    token = _find_token(data.get("body") or "")
    if token:
        return LoginResult(True, headers={"Authorization": f"Bearer {token}"},
                           detail=f"logged in (HTTP {status}); captured a bearer token")

    return LoginResult(False, detail=(
        f"login returned HTTP {status} but no session was found — no Set-Cookie and no token in the "
        "body. Check --login-user-field/--login-pass-field, try --login-json, or pass --auth-header "
        "directly."))
