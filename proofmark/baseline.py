"""Baseline / diff — report only findings that are new since a saved run.

In CI you don't want to re-alert on issues you've already triaged. A baseline is a
set of finding fingerprints; on the next run, anything whose fingerprint is in the
baseline is "known" and only genuinely new findings are surfaced (and gate the
build). First run against a fresh baseline path just records it.
"""
from __future__ import annotations

import hashlib
import json
import os
import re


def fingerprint(finding: dict) -> str:
    """Stable id for 'the same finding' across runs: normalized title + location +
    vulnerability class (CWE or OWASP). Independent of wording drift in the PoC."""
    title = re.sub(r"\s+", " ", (finding.get("title") or "").lower()).strip()
    loc = (finding.get("location") or "").strip().lower()
    klass = (finding.get("cwe") or finding.get("owasp_category") or "").strip().lower()
    return hashlib.sha256(f"{title}|{loc}|{klass}".encode()).hexdigest()[:16]


def read(path: str) -> set[str] | None:
    """The baseline fingerprints, or None if the file does not exist yet."""
    if not os.path.exists(path):
        return None
    try:
        data = json.loads(open(path, encoding="utf-8").read())
    except (ValueError, OSError):
        return set()
    if isinstance(data, dict):
        return set(data.get("fingerprints", []))
    return set(data) if isinstance(data, list) else set()


def write(findings: list[dict], path: str) -> int:
    fps = sorted({fingerprint(f) for f in findings})
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"fingerprints": fps, "count": len(fps)}, fh, indent=2)
    return len(fps)


def new_findings(findings: list[dict], known: set[str]) -> list[dict]:
    return [f for f in findings if fingerprint(f) not in known]
