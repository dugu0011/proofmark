"""The coverage tool — record and review which checks you've run per endpoint."""
from __future__ import annotations

from proofmark.coverage import CHECKS, CoverageBoard
from proofmark.tools.base import Tool, ToolResult


class CoverageTool(Tool):
    name = "coverage"
    description = (
        "Track which security checks you've run against which endpoints so you cover the OWASP "
        "Top 10 methodically and never leave a class untested. action='note' records that you "
        "tested an endpoint for a check (endpoint, check, result); action='gaps' shows what's "
        "still untested per endpoint (do these next); action='matrix' shows the full picture. "
        f"Checks: {', '.join(CHECKS)}."
    )
    parameters = {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["note", "gaps", "matrix"],
                       "description": "note a result, list gaps (default), or show the matrix."},
            "endpoint": {"type": "string", "description": "The endpoint, e.g. GET /api/orders/{id}."},
            "check": {"type": "string", "description": "The check, e.g. 'sqli' or 'bola-idor'."},
            "result": {"type": "string", "description": "Outcome: 'tested', 'vulnerable', 'safe'."},
        },
    }

    def __init__(self, board: CoverageBoard) -> None:
        self._board = board

    def run(self, action="gaps", endpoint="", check="", result="tested", **_) -> ToolResult:
        if action == "note":
            if not endpoint or not check:
                return ToolResult("note needs both 'endpoint' and 'check'.", is_error=True)
            self._board.note(endpoint, check, result or "tested")
            return ToolResult(f"noted: {endpoint} × {check} = {result or 'tested'}")

        if action == "matrix":
            matrix = self._board.matrix()
            if not matrix:
                return ToolResult("Nothing tracked yet — note your results as you test.")
            lines = [f"{e}: " + ", ".join(f"{c}={s}" for c, s in sorted(cs.items()))
                     for e, cs in sorted(matrix.items())]
            return ToolResult("Coverage matrix:\n" + "\n".join(lines))

        gaps = self._board.gaps()
        if not gaps:
            return ToolResult("No endpoints tracked yet. As you discover endpoints, note what you "
                              "test so this can tell you what's left.")
        lines = [f"{e}: still to test — {', '.join(cs) if cs else 'complete ✓'}"
                 for e, cs in sorted(gaps.items())]
        return ToolResult("Coverage gaps (untested checks per endpoint — work these next):\n"
                          + "\n".join(lines))
