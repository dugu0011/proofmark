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
            "confidence": {"type": "string", "enum": ["high", "medium", "low"],
                           "description": "How sure you are you PROVED a real exploit. Be honest."},
            "location": {"type": "string", "description": "Endpoint, parameter, or file:line."},
            "owasp_category": {"type": "string", "description": "OWASP category, e.g. 'A01:2021 Broken Access Control'."},
            "cwe": {"type": "string", "description": "CWE id, e.g. 'CWE-89'."},
            "description": {"type": "string", "description": "What the issue is and its impact."},
            "proof_of_concept": {
                "type": "string",
                "description": "The exact reproduction: request(s) sent and response(s) proving it.",
            },
            "remediation": {"type": "string", "description": "How to fix it."},
        },
        "required": ["title", "severity", "description", "proof_of_concept"],
    }

    def __init__(self) -> None:
        # Track what has been recorded so the same bug is never reported twice.
        self._seen: set[str] = set()

    def run(self, **kwargs) -> ToolResult:
        if not str(kwargs.get("proof_of_concept", "")).strip():
            return ToolResult(
                "Refused: a finding needs a proof-of-concept. Reproduce it first, "
                "then record it with the request and response that prove it.",
                is_error=True,
            )
        finding = Finding.from_tool(**kwargs)
        fp = finding.fingerprint()
        if fp in self._seen:
            return ToolResult(
                f"Already recorded: {finding.title} at {finding.location or 'this location'}. "
                "Move on to something else.",
                is_error=True,
            )
        self._seen.add(fp)
        return ToolResult(
            f"Recorded [{finding.severity.value}/{finding.confidence}] {finding.title}.",
            data=finding,
        )
