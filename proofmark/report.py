"""Turn a run into a report a developer can act on.

Markdown, because it reads fine in a terminal, renders in a PR comment, and
converts to anything else. Every finding leads with its proof — the report is
only as trustworthy as the reproduction behind each claim.
"""
from __future__ import annotations

from proofmark.agent import Outcome
from proofmark.authorization import Authorization
from proofmark.findings import Finding, Severity

_ICON = {
    Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵", Severity.INFO: "⚪",
}


def to_markdown(outcome: Outcome, auth: Authorization, *, target: str, model: str,
                product: str, fixes: list[dict] | None = None) -> str:
    findings = sorted(outcome.findings, key=lambda f: -f.severity.rank)
    lines: list[str] = []
    lines.append(f"# {product} — security assessment")
    lines.append("")
    lines.append(f"**Target:** {target}  ")
    lines.append(f"**Authorized by:** {auth.operator} at {auth.asserted_at.isoformat()}  ")
    lines.append(f"**Scope:** {', '.join(auth.as_header()['scope'])}  ")
    lines.append(f"**Engine:** {model}  ")
    lines.append(f"**Effort:** {outcome.steps_used} step(s); stopped because {outcome.stopped_reason}.")
    lines.append("")

    # Summary counts.
    counts = {s: sum(1 for f in findings if f.severity == s) for s in Severity}
    tally = ", ".join(f"{counts[s]} {s.value}" for s in Severity if counts[s]) or "none"
    lines.append(f"## Summary")
    lines.append("")
    lines.append(f"**{len(findings)} proven finding(s):** {tally}.")
    if outcome.summary:
        lines.append("")
        lines.append(f"> {outcome.summary}")
    lines.append("")

    if not findings:
        lines.append("No vulnerabilities were reproduced in this run. Note that a clean run "
                     "is evidence, not proof of absence — it means the agent could not prove "
                     "an exploit within its budget, not that none exists.")
        lines.extend(_fixes_section(fixes))
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")
    for i, f in enumerate(findings, 1):
        lines.extend(_finding_block(i, f))
    lines.extend(_fixes_section(fixes))
    return "\n".join(lines)


def _finding_block(i: int, f: Finding) -> list[str]:
    out = [
        f"### {i}. {_ICON[f.severity]} {f.title}",
        "",
        f"**Severity:** {f.severity.value}  &nbsp; **Confidence:** {f.confidence}  ",
    ]
    if f.location:
        out.append(f"**Location:** {f.location}  ")
    if f.owasp_category:
        out.append(f"**OWASP:** {f.owasp_category}  ")
    if f.cwe:
        out.append(f"**CWE:** {f.cwe}  ")
    # record_finding appends captured reproduction to the PoC for downstream
    # readers; in this report it gets its own Evidence section, so keep PoC prose.
    poc = f.proof_of_concept.split("--- captured reproduction ---", 1)[0].strip()
    out += ["", f.description, "", "**Proof of concept:**", "", "```", poc, "```", ""]
    for j, ev in enumerate(getattr(f, "evidence", None) or [], 1):
        out += [
            f"**Evidence {j} — {ev.get('method', '')} {ev.get('url', '')} → HTTP {ev.get('status')}**",
            "", "```bash", ev.get("curl", "").strip(), "```",
        ]
        if ev.get("response_preview"):
            out += ["Response:", "", "```", ev["response_preview"].strip(), "```", ""]
    if f.remediation:
        out += ["**Remediation:**", "", f.remediation, ""]
    out.append("---")
    out.append("")
    return out


def _fixes_section(fixes: list[dict] | None) -> list[str]:
    if not fixes:
        return []
    out = ["", "## Suggested fixes", "",
           "Each patch below was verified to apply cleanly to the source at scan time."]
    for i, fx in enumerate(fixes, 1):
        out += ["", f"### Fix {i}: {fx.get('file', '')}", ""]
        if fx.get("explanation"):
            out.append(fx["explanation"])
            out.append("")
        out += ["```diff", fx.get("diff", "").strip(), "```"]
    return out
