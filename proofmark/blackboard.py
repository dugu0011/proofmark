"""Shared state a graph of agents reads and writes.

Specialized agents are only worth more than one generalist if they actually hand
work to each other. The blackboard is how: the recon agent writes down what it
mapped, the exploit agent reads that as its starting brief and writes back the
vulnerabilities it proves. Everything the agents discover accumulates here, and
`briefing()` turns it into the opening context for the next agent in the graph.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from proofmark.findings import Finding


@dataclass
class Blackboard:
    notes: list[str] = field(default_factory=list)      # observations from recon etc.
    findings: list[Finding] = field(default_factory=list)

    def add_note(self, note: str) -> None:
        note = (note or "").strip()
        if note:
            self.notes.append(note)

    def briefing(self) -> str:
        """What the next agent should know before it starts."""
        if not self.notes and not self.findings:
            return ""
        lines = ["What earlier agents have already established about this target:"]
        for note in self.notes[-40:]:
            lines.append(f"  • {note}")
        for f in self.findings:
            lines.append(f"  ✓ PROVEN [{f.severity.value}] {f.title} at {f.location or '?'}")
        lines.append("Build on this. Do not repeat work that is already done.")
        return "\n".join(lines)
