"""Recall what has already been proven, so the agent can chain findings.

Real impact usually comes from combining bugs — a leaked key used against another
endpoint, an IDOR that reaches an admin object, an SSRF that reads cloud metadata
which unlocks the next step. This tool lets the agent look back at everything it
has proven so far and deliberately build a chain, then record the combined,
higher-impact result.
"""
from __future__ import annotations

from proofmark.tools.base import Tool, ToolResult


class ListFindingsTool(Tool):
    name = "list_findings"
    description = (
        "List the vulnerabilities you have already proven this run. Use it to CHAIN "
        "them into higher impact — e.g. feed a leaked credential or an IDOR into "
        "another endpoint to reach admin data or account takeover — then record the "
        "combined result as its own, higher-severity finding with the full steps."
    )
    parameters = {"type": "object", "properties": {}}

    def __init__(self, record_tool) -> None:
        self._record = record_tool

    def run(self, **kwargs) -> ToolResult:
        recorded = getattr(self._record, "recorded", []) or []
        if not recorded:
            return ToolResult("No findings recorded yet — prove one first, then look for a chain.")
        lines = ["Proven so far (look for a chain that raises impact):"]
        for i, f in enumerate(recorded, 1):
            where = f" @ {f['location']}" if f.get("location") else ""
            lines.append(f"  {i}. [{f['severity']}] {f['title']}{where}")
        return ToolResult("\n".join(lines))
