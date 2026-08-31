"""Export proven findings as SARIF 2.1.0 — the format enterprise CI consumes.

GitHub code scanning, Azure DevOps, and most security dashboards ingest SARIF, so
emitting it (`--sarif report.sarif`) drops Proofmark's results straight into an
organization's existing pipeline — no custom parsing of the Markdown report.
"""
from __future__ import annotations

import re

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/dugu0011/proofmark"

# severity -> SARIF level
_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
          "low": "note", "info": "note"}


def _rule_id(f: dict) -> str:
    """A stable rule id: prefer CWE, then OWASP code, then a title slug."""
    cwe = (f.get("cwe") or "").strip()
    if cwe:
        return cwe.upper()
    m = re.search(r"\b(A\d{2}|API\d{1,2})\b", f.get("owasp_category") or "", re.I)
    if m:
        return m.group(1).upper()
    slug = re.sub(r"[^a-z0-9]+", "-", (f.get("title") or "finding").lower()).strip("-")
    return slug or "finding"


def to_sarif(findings: list[dict], *, target: str, version: str,
             tool_name: str = "Proofmark") -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        rid = _rule_id(f)
        title = f.get("title") or rid
        severity = (f.get("severity") or "info").lower()
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": re.sub(r"[^A-Za-z0-9]+", "", title.title())[:80] or rid,
                "shortDescription": {"text": title},
                "fullDescription": {"text": f.get("description") or title},
                "defaultConfiguration": {"level": _LEVEL.get(severity, "note")},
                "properties": {"tags": [t for t in ["security", f.get("owasp_category"),
                                                    f.get("cwe")] if t]},
            }
        location = f.get("location") or target
        message = f.get("description") or title
        if f.get("proof_of_concept"):
            message += f"\n\nProof of concept:\n{f['proof_of_concept']}"
        if f.get("remediation"):
            message += f"\n\nRemediation: {f['remediation']}"
        results.append({
            "ruleId": rid,
            "level": _LEVEL.get(severity, "note"),
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": location}},
            }],
            "properties": {
                "severity": severity,
                "confidence": f.get("confidence"),
                "owasp": f.get("owasp_category"),
                "cwe": f.get("cwe"),
                "proven": True,
            },
        })

    return {
        "version": "2.1.0",
        "$schema": _SCHEMA,
        "runs": [{
            "tool": {"driver": {
                "name": tool_name,
                "version": version,
                "informationUri": _INFO_URI,
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {"target": target},
        }],
    }
