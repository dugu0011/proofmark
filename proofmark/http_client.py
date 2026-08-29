"""One place that sends an HTTP request, and remembers it.

Both the plain probe and the replay tool go through here, so the scope check,
the sandboxing and the request log live in exactly one spot. The log is what
turns "send a request" into an intercept proxy: the agent can look back at what
it sent, then resend a modified copy — capture, mutate, replay, which is how a
real injection or authorization bug is actually confirmed.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from proofmark.authorization import Authorization
from proofmark.sandbox import Sandbox


@dataclass
class Request:
    method: str
    url: str
    headers: dict = field(default_factory=dict)
    body: str | None = None


@dataclass
class Exchange:
    """A sent request and what came back — one entry in the log."""

    index: int
    request: Request
    status: int | None
    response_preview: str
    error: str | None = None


class RequestLog:
    def __init__(self) -> None:
        self._items: list[Exchange] = []
        # How many replays reproduced a live response. A finding only earns "high"
        # confidence once the exploit was reproduced a second time (see the record
        # tool) — this is that corroboration counter.
        self.replays_ok = 0

    def add(self, request: Request, status, preview, error=None) -> Exchange:
        ex = Exchange(len(self._items), request, status, preview, error)
        self._items.append(ex)
        return ex

    def get(self, index: int) -> Exchange | None:
        return self._items[index] if 0 <= index < len(self._items) else None

    def __len__(self) -> int:
        return len(self._items)

    def records(self) -> list[dict]:
        """Every exchange as plain dicts, for the run record and for replay."""
        return [{
            "method": ex.request.method, "url": ex.request.url,
            "headers": ex.request.headers or {}, "body": ex.request.body,
            "status": ex.status, "error": ex.error,
        } for ex in self._items]

    def summary(self) -> str:
        if not self._items:
            return "(no requests yet)"
        lines = []
        for ex in self._items:
            tag = f"HTTP {ex.status}" if ex.status is not None else f"ERR {ex.error or ''}"
            lines.append(f"[{ex.index}] {ex.request.method} {ex.request.url} -> {tag}")
        return "\n".join(lines)


class HttpClient:
    """Sends requests from inside the sandbox, within scope, and logs them."""

    # State-changing methods a "safe mode" run refuses, so the agent can be pointed
    # at production without risk of deleting or overwriting data. Impact is proven
    # with reads instead (e.g. GET another user's record to show broken access).
    DESTRUCTIVE = {"DELETE", "PUT", "PATCH"}

    def __init__(self, sandbox: Sandbox, authorization: Authorization, log: RequestLog,
                 *, safe_mode: bool = True, auth_headers: dict | None = None,
                 auth_cookies: dict | None = None,
                 identities: dict[str, dict] | None = None) -> None:
        self._sb = sandbox
        self._auth = authorization
        self.log = log
        self.safe_mode = safe_mode
        # Credentials attached to every in-scope request, so the agent can test as
        # an authenticated user — where the interesting authorization bugs live.
        self._auth_headers = dict(auth_headers or {})
        self._auth_cookies = dict(auth_cookies or {})
        # Extra named identities (a second, lower-privileged user; an admin) the
        # agent can *replay a request as* to test access control — the primitive
        # behind BOLA/IDOR and BFLA. Each is {"headers": {...}, "cookies": {...},
        # optional "label"}. "anonymous" (no credentials) is always available.
        self._identities = {k: dict(v) for k, v in (identities or {}).items()}
        # In-run cache of idempotent responses, so re-fetching the same page does
        # not cost another sandbox round-trip or another wall of tokens.
        self._cache: dict[str, tuple] = {}

    def _creds_for(self, identity: str | None) -> tuple[dict, dict]:
        """(headers, cookies) for a named identity. None/'primary' = the run's own."""
        if identity in (None, "primary"):
            return self._auth_headers, self._auth_cookies
        if identity == "anonymous":
            return {}, {}
        ident = self._identities.get(identity)
        if ident is None:
            return self._auth_headers, self._auth_cookies  # unknown → primary
        return ident.get("headers") or {}, ident.get("cookies") or {}

    def _apply_auth(self, headers: dict | None, identity: str | None = None) -> dict:
        """Merge in an identity's credentials. The agent's own headers win, so it
        can deliberately drop or swap a token to test access control."""
        creds_headers, creds_cookies = self._creds_for(identity)
        merged = {**creds_headers, **(headers or {})}
        if creds_cookies and not any(k.lower() == "cookie" for k in merged):
            merged["Cookie"] = "; ".join(f"{k}={v}" for k, v in creds_cookies.items())
        return merged

    @property
    def authenticated(self) -> bool:
        return bool(self._auth_headers or self._auth_cookies)

    def alternate_identities(self) -> list[str]:
        """Identities the agent can replay a request as, to compare access.

        Always includes 'anonymous'; plus any configured second user / admin.
        These are what authz_probe compares against the primary identity.
        """
        names = list(self._identities.keys())
        if "anonymous" not in names:
            names.append("anonymous")
        return names

    def identity_label(self, identity: str | None) -> str:
        if identity in (None, "primary"):
            return "primary"
        if identity == "anonymous":
            return "anonymous (no credentials)"
        return (self._identities.get(identity) or {}).get("label") or identity

    @staticmethod
    def _cache_key(request: "Request", identity: str | None = None) -> str:
        h = json.dumps(request.headers or {}, sort_keys=True)
        return f"{identity or 'primary'}\n{request.method.upper()}\n{request.url}\n{h}\n{request.body or ''}"

    def raw(self, request: Request) -> dict | None:
        """Scope-checked, sandboxed fetch that returns the FULL parsed response.

        For internal tools (recon) that need the whole body to parse, not the
        short preview the agent sees. Still logs a compact exchange.
        """
        if not self._auth.permits_host(request.url):
            self.log.add(request, None, "", error="out of scope")
            return None
        spec = json.dumps({
            "method": request.method, "url": request.url,
            "headers": self._apply_auth(request.headers), "body": request.body, "timeout": 20,
        })
        code, out = self._sb.exec(["python", self._sb.runner_path, spec], timeout=30)
        try:
            data = json.loads(out.strip())
        except ValueError:
            self.log.add(request, None, out[:200], error=f"runner exit {code}")
            return None
        if "error" in data:
            self.log.add(request, None, "", error=data["error"])
            return None
        self.log.add(request, data.get("status"), (data.get("body") or "")[:1200])
        return data

    def send(self, request: Request, *, identity: str | None = None) -> tuple[bool, str, Exchange]:
        """Returns (ok, text_for_the_agent, logged_exchange).

        ``identity`` selects whose credentials to attach: None/'primary' the run's
        own, 'anonymous' none, or a configured second user / admin. That is how
        authz_probe re-sends one request as another principal to test access.
        """
        if not self._auth.permits_host(request.url):
            scope = ", ".join(sorted(self._auth.allowed_hosts)) or "no live host"
            msg = (f"Refused: {request.url} is outside the authorized scope ({scope}). "
                   "Stay on the target you were pointed at.")
            ex = self.log.add(request, None, "", error="out of scope")
            return False, msg, ex

        if self.safe_mode and request.method.upper() in self.DESTRUCTIVE:
            msg = (f"Refused in safe mode: {request.method.upper()} is a state-changing "
                   "method that could damage or delete data on a live target. Prove "
                   "impact with a non-destructive request instead — e.g. GET another "
                   "user's record to demonstrate broken access control. (Safe mode can "
                   "be turned off for this run if a destructive test is truly required.)")
            ex = self.log.add(request, None, "", error="blocked by safe mode")
            return False, msg, ex

        key = self._cache_key(request, identity) if request.method.upper() in ("GET", "HEAD") else None
        if key is not None and key in self._cache:
            status, preview, first_idx = self._cache[key]
            ex = self.log.add(request, status, preview)
            text = (f"[cached — identical to request #{first_idx}] HTTP {status}. Response "
                    "unchanged since then; body omitted to save time. Use "
                    f"replay_request #{first_idx} or list_requests if you need it again.")
            return True, text, ex

        spec = json.dumps({
            "method": request.method, "url": request.url,
            "headers": self._apply_auth(request.headers, identity), "body": request.body, "timeout": 20,
        })
        code, out = self._sb.exec(["python", self._sb.runner_path, spec], timeout=30)
        out = out.strip()
        try:
            data = json.loads(out)
        except ValueError:
            ex = self.log.add(request, None, out[:200], error=f"runner exit {code}")
            return False, f"request failed (exit {code}): {out[:200]}", ex

        if "error" in data:
            ex = self.log.add(request, None, "", error=data["error"])
            return False, f"request error: {data['error']}", ex

        status = data.get("status")
        preview = (data.get("body") or "")[:1200]
        ex = self.log.add(request, status, preview)
        if key is not None:
            self._cache[key] = (status, preview, ex.index)
        headers = data.get("headers", {})
        text = (f"HTTP {status}  ({data.get('elapsed_ms','?')} ms)\n"
                f"headers: {json.dumps(headers)[:400]}\n"
                f"body[:1200]:\n{preview}")
        return True, text, ex
