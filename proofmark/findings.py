"""What the agent is trying to produce: a validated finding with a proof.

A finding here is deliberately expensive to create. The whole reason this tool
exists is to avoid the "this *looks* wrong" output of a static scanner, so a
finding must carry a proof-of-concept — the concrete steps that reproduced it.
The agent is instructed never to record one without that.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    # The reproduction: what was sent, what came back, why it proves the bug.
    proof_of_concept: str
    remediation: str = ""
    # Where it lives — an endpoint, a file:line, a parameter. Free text on purpose.
    location: str = ""
    found_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def from_tool(cls, **kw) -> "Finding":
        sev = kw.get("severity", "info")
        try:
            severity = Severity(str(sev).lower())
        except ValueError:
            severity = Severity.INFO
        return cls(
            title=str(kw.get("title", "Untitled finding"))[:200],
            severity=severity,
            description=str(kw.get("description", "")),
            proof_of_concept=str(kw.get("proof_of_concept", "")),
            remediation=str(kw.get("remediation", "")),
            location=str(kw.get("location", "")),
        )
