"""The browser tool: load a page with JavaScript running, and prove client-side
bugs. A fired dialog is caught as proof that injected script executed.

The browser needs Chromium, which is heavy, so it runs in a dedicated image
(built once with `proofmark build-sandbox`) and is started lazily on first use.
If the image is not built, the tool says so clearly instead of failing the run.
Scope is enforced here before the browser navigates anywhere.
"""
from __future__ import annotations

import json
from pathlib import Path

from proofmark.authorization import Authorization
from proofmark.sandbox import Sandbox, SandboxError
from proofmark.tools.base import Tool, ToolResult

BROWSER_IMAGE = "proofmark-sandbox:latest"
_RUNNER = Path(__file__).parent.parent / "resources" / "browser_runner.py"


class BrowserTool(Tool):
    name = "browser"
    returns_untrusted_data = True
    description = (
        "Load a URL in a real headless browser (JavaScript runs) to test client-side "
        "issues — reflected/stored/DOM XSS, CSRF flows. You can fill a field, click a "
        "selector, and evaluate JS. If a dialog (alert/prompt) fires, that is proof "
        "injected script executed. Only in-scope URLs are allowed."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "js": {"type": "string", "description": "Optional JS to evaluate on the page."},
            "fill": {"type": "object", "description": "Optional {selector, value} to fill a field."},
            "click": {"type": "string", "description": "Optional CSS selector to click."},
            "wait_ms": {"type": "integer", "description": "How long to wait after actions."},
        },
        "required": ["url"],
    }

    def __init__(self, authorization: Authorization) -> None:
        self._auth = authorization
        self._sb: Sandbox | None = None
        self._runner_path: str | None = None
        self._unavailable: str | None = None

    def _ensure(self) -> bool:
        if self._sb is not None:
            return True
        if self._unavailable is not None:
            return False
        try:
            self._sb = Sandbox(image=BROWSER_IMAGE, mem_limit="1g", auto_pull=False,
                               name_prefix="proofmark-browser")
            self._sb.start()
            self._runner_path = self._sb.install_script(_RUNNER)
            return True
        except SandboxError as exc:
            self._sb = None
            self._unavailable = str(exc)
            return False

    def run(self, **kwargs) -> ToolResult:
        url = kwargs.get("url", "")
        if not self._auth.permits_host(url):
            scope = ", ".join(sorted(self._auth.allowed_hosts)) or "no live host"
            return ToolResult(f"Refused: {url} is outside the authorized scope ({scope}).",
                              is_error=True)
        if not self._ensure():
            return ToolResult(
                f"The browser is unavailable: {self._unavailable}. "
                "Build it once with `proofmark build-sandbox`, then retry.", is_error=True)

        spec = json.dumps({
            "url": url, "js": kwargs.get("js"), "fill": kwargs.get("fill"),
            "click": kwargs.get("click"), "wait_ms": kwargs.get("wait_ms", 800),
        })
        code, out = self._sb.exec(["python", self._runner_path, spec], timeout=45)
        try:
            data = json.loads(out.strip())
        except ValueError:
            return ToolResult(f"browser run failed (exit {code}): {out[:300]}", is_error=True)
        if "error" in data:
            return ToolResult(f"browser error: {data['error']}", is_error=True)

        dialogs = data.get("dialogs") or []
        proof = ""
        if dialogs:
            proof = ("\n*** DIALOG FIRED — injected script executed: "
                     + "; ".join(f"{d['type']}({d['message']!r})" for d in dialogs) + " ***")
        return ToolResult(
            f"final_url: {data.get('final_url')}\ntitle: {data.get('title')}\n"
            f"console: {data.get('console')}\ntext[:800]:\n{(data.get('text') or '')[:800]}{proof}")

    def close(self) -> None:
        if self._sb is not None:
            self._sb.stop()
            self._sb = None
