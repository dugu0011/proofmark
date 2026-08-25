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

    def __init__(self, sandbox: Sandbox, authorization: Authorization, log: RequestLog) -> None:
        self._sb = sandbox
        self._auth = authorization
        self.log = log

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
            "headers": request.headers or {}, "body": request.body, "timeout": 20,
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

    def send(self, request: Request) -> tuple[bool, str, Exchange]:
        """Returns (ok, text_for_the_agent, logged_exchange)."""
        if not self._auth.permits_host(request.url):
            scope = ", ".join(sorted(self._auth.allowed_hosts)) or "no live host"
            msg = (f"Refused: {request.url} is outside the authorized scope ({scope}). "
                   "Stay on the target you were pointed at.")
            ex = self.log.add(request, None, "", error="out of scope")
            return False, msg, ex

        spec = json.dumps({
            "method": request.method, "url": request.url,
            "headers": request.headers or {}, "body": request.body, "timeout": 20,
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
        headers = data.get("headers", {})
        text = (f"HTTP {status}  ({data.get('elapsed_ms','?')} ms)\n"
                f"headers: {json.dumps(headers)[:400]}\n"
                f"body[:1200]:\n{preview}")
        return True, text, ex
