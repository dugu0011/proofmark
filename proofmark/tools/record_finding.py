"""Record a vulnerability the agent has already reproduced.

This is the tool that justifies the whole run, and the system prompt is strict
about it: the agent may only call it once it has a concrete proof-of-concept that
reproduces the issue. A finding without a PoC is exactly the false positive this
tool exists to avoid, so the description says so and the loop keeps the PoC.
"""
from __future__ import annotations

from proofmark.findings import Finding
from proofmark.tools.base import Tool, ToolResult


class RecordFindingTool(Tool):
    name = "record_finding"
    description = (
        "Record a vulnerability you have PROVEN. Only call this after you have a "
        "concrete proof-of-concept that reproduces the issue — the request you sent "
        "and the response that demonstrates the impact. Do not record anything you "
        "have not actually reproduced."
    )
    parameters = {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
            "location": {"type": "string", "description": "Endpoint, parameter, or file:line."},
            "description": {"type": "string", "description": "What the issue is and its impact."},
            "proof_of_concept": {
                "type": "string",
                "description": "The exact reproduction: request(s) sent and response(s) proving it.",
            },
            "remediation": {"type": "string", "description": "How to fix it."},
        },
        "required": ["title", "severity", "description", "proof_of_concept"],
    }

    def run(self, **kwargs) -> ToolResult:
        if not str(kwargs.get("proof_of_concept", "")).strip():
            return ToolResult(
                "Refused: a finding needs a proof-of-concept. Reproduce it first, "
                "then record it with the request and response that prove it.",
                is_error=True,
            )
        finding = Finding.from_tool(**kwargs)
        return ToolResult(
            f"Recorded [{finding.severity.value}] {finding.title}.",
            data=finding,
        )
