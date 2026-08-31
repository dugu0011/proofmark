"""Out-of-band interaction listener — how Proofmark PROVES blind vulnerabilities.

The worst bugs are blind: a blind SSRF, a blind command injection, an XXE that
exfiltrates over HTTP, a blind SQL injection observable only out of band. You
cannot prove those from the response — you prove them by making the target reach
back to a server you control.

This is that server. It mints unique canary URLs, listens for any request whose
token appears in the path or the Host header, and records it. A tool hands the
agent a canary; the agent plants it in a payload; a recorded hit is the proof.

Self-contained: stdlib http.server on a background daemon thread, no external
collaborator service. For a target that can only resolve DNS, point a wildcard
record at this host and set the public base accordingly.
"""
from __future__ import annotations

import atexit
import os
import re
import secrets
import socket
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_TOKEN_RE = re.compile(r"^[0-9a-f]{16}$")


@dataclass
class Interaction:
    token: str
    at: str
    method: str
    path: str
    remote: str
    host: str
    user_agent: str
    body_preview: str

    def summary(self) -> str:
        extra = f' body="{self.body_preview}"' if self.body_preview else ""
        return (f"[{self.at}] {self.method} {self.path} from {self.remote} "
                f"(Host: {self.host or '-'}, UA: {self.user_agent or '-'}){extra}")


def _primary_ip() -> str:
    """Best-effort LAN IP the target is most likely able to reach."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return "127.0.0.1"


def _is_token(value: str) -> bool:
    return bool(_TOKEN_RE.match(value or ""))


class InteractionServer:
    """A live out-of-band listener. Thread-safe; auto-closed at process exit."""

    def __init__(self, *, bind_host: str = "0.0.0.0", bind_port: int = 0,
                 public_host: str = "", public_base: str = "") -> None:
        self._store: dict[str, list[Interaction]] = {}
        self._lock = threading.Lock()

        self._server = ThreadingHTTPServer((bind_host, bind_port), self._handler_factory())
        self.port = self._server.server_address[1]

        public_base = public_base or os.getenv("PROOFMARK_OOB_PUBLIC_BASE", "")
        public_host = public_host or os.getenv("PROOFMARK_OOB_PUBLIC_HOST", "")
        self._public_base = public_base.rstrip("/") or f"http://{public_host or _primary_ip()}:{self.port}"

        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self._closed = False
        atexit.register(self.close)

    # --- canary lifecycle ---------------------------------------------------

    def new_canary(self, hint: str = "") -> str:
        token = secrets.token_hex(8)  # 16 hex chars
        with self._lock:
            self._store.setdefault(token, [])
        return token

    def http_url(self, token: str) -> str:
        return f"{self._public_base}/{token}"

    def dns_host(self, token: str) -> str:
        host = self._public_base.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        # a bare IP can't carry a token as a subdomain — reuse the http path form
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
            return f"{host} (no DNS canary — use the http url)"
        return f"{token}.{host}"

    def interactions(self, token: str) -> list[Interaction]:
        with self._lock:
            return list(self._store.get(token, []))

    def close(self) -> None:
        if getattr(self, "_closed", True):
            return
        self._closed = True
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception:
            pass

    # --- request handling ---------------------------------------------------

    def _token_from(self, path: str, host: str) -> str | None:
        seg = path.lstrip("/").split("/", 1)[0].split("?", 1)[0]
        if _is_token(seg):
            return seg
        label = host.split(":", 1)[0].split(".", 1)[0]
        if _is_token(label):
            return label
        return None

    def _record(self, token: str, method: str, path: str, remote: str, host: str,
                ua: str, body: bytes) -> None:
        inter = Interaction(
            token=token, at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            method=method, path=path, remote=remote, host=host, user_agent=ua,
            body_preview=(body or b"")[:512].decode("utf-8", "replace").replace("\n", " "),
        )
        with self._lock:
            self._store.setdefault(token, []).append(inter)

    def _handler_factory(self):
        server = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # silence stderr access log
                pass

            def _handle(self):
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    length = 0
                body = self.rfile.read(length) if length > 0 else b""
                host = self.headers.get("Host", "")
                token = server._token_from(self.path, host)
                if token is not None:
                    server._record(token, self.command, self.path, self.client_address[0],
                                   host, self.headers.get("User-Agent", ""), body)
                payload = b"ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)

            do_GET = _handle
            do_POST = _handle
            do_PUT = _handle
            do_HEAD = _handle
            do_OPTIONS = _handle
            do_DELETE = _handle

        return _Handler
