"""Runs one HTTP request and prints the result as JSON.

This is copied into the sandbox container and executed there, so every request
the agent makes leaves from inside the jail rather than from the host. It uses
only the standard library, so the container needs nothing installed.

Usage: python http_runner.py '<json>'  where json is
  {"method","url","headers":{},"body":"","timeout":20}
"""
import json
import sys
import time
import urllib.error
import urllib.request

MAX_BODY = 20000  # never flood the model's context with a huge response


def main() -> None:
    try:
        spec = json.loads(sys.argv[1])
    except (IndexError, ValueError) as exc:
        print(json.dumps({"error": f"bad request spec: {exc}"}))
        return

    method = str(spec.get("method", "GET")).upper()
    url = spec.get("url", "")
    headers = spec.get("headers", {}) or {}
    body = spec.get("body")
    timeout = float(spec.get("timeout", 20))

    data = body.encode() if isinstance(body, str) and body else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)

    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(MAX_BODY + 1)
            _emit(resp.status, dict(resp.headers), raw, started)
    except urllib.error.HTTPError as exc:
        # A 4xx/5xx is a normal, interesting result — not an error to the agent.
        raw = exc.read(MAX_BODY + 1) if hasattr(exc, "read") else b""
        _emit(exc.code, dict(exc.headers or {}), raw, started)
    except Exception as exc:  # noqa: BLE001 - connection refused, DNS, timeout...
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}", "url": url}))


def _emit(status: int, headers: dict, raw: bytes, started: float) -> None:
    text = raw.decode("utf-8", "replace")
    truncated = len(text) > MAX_BODY
    print(json.dumps({
        "status": status,
        "headers": headers,
        "body": text[:MAX_BODY],
        "body_truncated": truncated,
        "elapsed_ms": round((time.time() - started) * 1000),
    }))


if __name__ == "__main__":
    main()
