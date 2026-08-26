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
    # Structured classification, so a finding is machine-usable (compliance,
    # dashboards) and not just prose. All optional — the agent fills what it knows.
    owasp_category: str = ""   # e.g. "A01:2021 Broken Access Control"
    cwe: str = ""              # e.g. "CWE-89"
    # How sure the agent is it reproduced a *real* exploit. Honesty here is what
    # keeps the report trustworthy — a low-confidence finding is flagged as such.
    confidence: str = "medium"  # high | medium | low
    found_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def fingerprint(self) -> str:
        """Identity for de-duplication: the same bug in the same place is one bug."""
        return f"{self.title.strip().lower()}|{self.location.strip().lower()}"

    @classmethod
    def from_tool(cls, **kw) -> "Finding":
        sev = kw.get("severity", "info")
        try:
            severity = Severity(str(sev).lower())
        except ValueError:
            severity = Severity.INFO
        conf = str(kw.get("confidence", "medium")).lower()
        if conf not in ("high", "medium", "low"):
            conf = "medium"
        return cls(
            title=str(kw.get("title", "Untitled finding"))[:200],
            severity=severity,
            description=str(kw.get("description", "")),
            proof_of_concept=str(kw.get("proof_of_concept", "")),
            remediation=str(kw.get("remediation", "")),
            location=str(kw.get("location", "")),
            owasp_category=str(kw.get("owasp_category", "")),
            cwe=str(kw.get("cwe", "")),
            confidence=conf,
        )
