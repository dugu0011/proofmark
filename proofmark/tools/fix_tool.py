"""propose_fix: the agent writes a patch, Proofmark verifies it applies.

The agent has read the code and proven the bug, so it is well placed to write
the fix. This tool's job is the check: it reads the current file from the
sandbox, applies the proposed unified diff in memory, and only accepts it if it
applies cleanly. A patch that does not apply is refused — a broken fix never
reaches the report.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from proofmark.patcher import PatchError, apply_unified_diff
from proofmark.sandbox import Sandbox
from proofmark.tools.base import Tool, ToolResult
from proofmark.tools.code_tools import _safe_rel


@dataclass
class FixLog:
    fixes: list[dict] = field(default_factory=list)  # {file, diff, explanation}


class ProposeFixTool(Tool):
    name = "propose_fix"
    description = (
        "Propose a fix for a finding as a unified diff against a source file. The "
        "patch is verified to apply cleanly before it is accepted — if it does not "
        "apply, fix your diff and try again. Use this after you have proven a bug in "
        "a code target."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file": {"type": "string", "description": "Path relative to the source root."},
            "unified_diff": {"type": "string", "description": "A unified diff (with @@ hunks)."},
            "explanation": {"type": "string", "description": "What the fix does and why."},
        },
        "required": ["file", "unified_diff"],
    }

    def __init__(self, sandbox: Sandbox, log: FixLog) -> None:
        self._sb = sandbox
        self._log = log

    def run(self, **kwargs) -> ToolResult:
        rel = _safe_rel(kwargs.get("file", ""))
        if rel is None:
            return ToolResult("Refused: file path escapes the source root.", is_error=True)
        diff = kwargs.get("unified_diff", "")
        if not diff.strip():
            return ToolResult("No diff given.", is_error=True)

        code, content = self._sb.exec(f"cat {self._sb.source_root}/{rel} 2>/dev/null", timeout=15)
        if code != 0:
            return ToolResult(f"Could not read {rel} to check the patch.", is_error=True)
        try:
            apply_unified_diff(content, diff)
        except PatchError as exc:
            return ToolResult(f"Patch does not apply: {exc}. Re-read the file and fix your diff.",
                              is_error=True)

        self._log.fixes.append({
            "file": rel, "diff": diff.strip(),
            "explanation": kwargs.get("explanation", ""),
        })
        return ToolResult(f"Fix for {rel} verified — it applies cleanly and was recorded.")
