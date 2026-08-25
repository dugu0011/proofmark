"""Reading the source, inside the sandbox, for a code target.

Three tools the agent uses to work a codebase: list what is there, read a file,
and search across all of it. Everything is confined to the copied source root
(/src) — a path that escapes it is refused, so the agent cannot read the rest of
the container, let alone the host.
"""
from __future__ import annotations

import shlex

from proofmark.sandbox import Sandbox
from proofmark.tools.base import Tool, ToolResult


def _safe_rel(path: str) -> str | None:
    """A relative path with no escape. Returns the cleaned path or None."""
    path = (path or "").strip().lstrip("/")
    parts = [p for p in path.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None
    return "/".join(parts)


class ListFilesTool(Tool):
    name = "list_files"
    description = ("List files in the source tree (optionally under a subdirectory). "
                   "Use this to map the codebase before reading specific files.")
    parameters = {
        "type": "object",
        "properties": {"path": {"type": "string", "description": "Subdirectory, relative to the source root. Optional."}},
    }

    def __init__(self, sandbox: Sandbox) -> None:
        self._sb = sandbox

    def run(self, **kwargs) -> ToolResult:
        rel = _safe_rel(kwargs.get("path", ""))
        if rel is None:
            return ToolResult("Refused: path escapes the source root.", is_error=True)
        base = f"{self._sb.source_root}/{rel}".rstrip("/")
        code, out = self._sb.exec(
            f"find {shlex.quote(base)} -type f -not -path '*/.git/*' | head -400", timeout=20)
        listing = out.replace(self._sb.source_root + "/", "")
        return ToolResult(listing.strip() or "(no files)")


class ReadFileTool(Tool):
    name = "read_file"
    description = "Read a file from the source tree. Returns it with line numbers."
    parameters = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "File path relative to the source root."},
            "start_line": {"type": "integer", "description": "Optional first line (1-based)."},
            "end_line": {"type": "integer", "description": "Optional last line."},
        },
        "required": ["path"],
    }

    def __init__(self, sandbox: Sandbox) -> None:
        self._sb = sandbox

    def run(self, **kwargs) -> ToolResult:
        rel = _safe_rel(kwargs.get("path", ""))
        if rel is None:
            return ToolResult("Refused: path escapes the source root.", is_error=True)
        target = f"{self._sb.source_root}/{rel}"
        start = int(kwargs.get("start_line") or 1)
        end = int(kwargs.get("end_line") or start + 400)
        end = min(end, start + 400)  # never dump an unbounded file into the context
        code, out = self._sb.exec(
            f"nl -ba {shlex.quote(target)} 2>/dev/null | sed -n '{start},{end}p'", timeout=15)
        if code != 0 or not out.strip():
            return ToolResult(f"Could not read {rel} (does it exist?).", is_error=True)
        return ToolResult(out.rstrip())


class SearchCodeTool(Tool):
    name = "search_code"
    description = ("Search the whole source tree for a pattern (grep). Use this to find "
                   "where user input is handled, where queries are built, where secrets live.")
    parameters = {
        "type": "object",
        "properties": {"pattern": {"type": "string", "description": "A grep pattern (extended regex)."}},
        "required": ["pattern"],
    }

    def __init__(self, sandbox: Sandbox) -> None:
        self._sb = sandbox

    def run(self, **kwargs) -> ToolResult:
        pattern = kwargs.get("pattern", "")
        if not pattern.strip():
            return ToolResult("No pattern given.", is_error=True)
        code, out = self._sb.exec(
            f"grep -rnE --binary-files=without-match {shlex.quote(pattern)} "
            f"{shlex.quote(self._sb.source_root)} 2>/dev/null | head -80", timeout=25)
        listing = out.replace(self._sb.source_root + "/", "")
        return ToolResult(listing.strip() or "(no matches)")
