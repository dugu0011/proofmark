"""Score a Proofmark run against a labeled target — recall over known bug classes.

A pentest benchmark can't fully automate precision (only a human knows if a novel
finding is real), but it can measure RECALL: of the vulnerability classes a target
is known to contain, how many did the agent prove? That is the number that tells
you whether a model/tooling change made the agent better or worse.

Usage:
    python benchmarks/score.py proofmark_runs/<run-id>            # or .../run.json
    python benchmarks/score.py <run> --expected benchmarks/expected_juice_shop.json

Findings are matched to expected OWASP categories by their code (A03, API1, …),
read from each finding's owasp_category. Extra findings (categories not in the
label set) are listed for manual review rather than scored as false positives.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_CODE = re.compile(r"\b(A\d{2}|API\d{1,2})\b", re.IGNORECASE)


def _codes(text: str) -> set[str]:
    return {m.upper() for m in _CODE.findall(text or "")}


def _load_findings(run_path: Path) -> list[dict]:
    if run_path.is_dir():
        candidates = [run_path / "run.json", *run_path.glob("*/run.json")]
        run_path = next((c for c in candidates if c.exists()), run_path / "run.json")
    data = json.loads(run_path.read_text())
    return data.get("findings", [])


def score(findings: list[dict], expected: list[str]) -> dict:
    expected_codes = {e.upper() for e in expected}
    found_codes: set[str] = set()
    extras: list[str] = []
    for f in findings:
        codes = _codes(f.get("owasp_category", "")) | _codes(f.get("cwe", ""))
        hit = codes & expected_codes
        found_codes |= hit
        if not hit:
            extras.append(f"{f.get('title','?')}  [{f.get('owasp_category','') or 'uncategorized'}]")
    matched = sorted(found_codes)
    missed = sorted(expected_codes - found_codes)
    recall = len(found_codes) / len(expected_codes) if expected_codes else 1.0
    return {"matched": matched, "missed": missed, "extras": extras,
            "recall": recall, "total_findings": len(findings)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run", help="run directory or run.json")
    ap.add_argument("--expected", default=str(Path(__file__).parent / "expected_juice_shop.json"))
    args = ap.parse_args()

    findings = _load_findings(Path(args.run))
    label = json.loads(Path(args.expected).read_text())
    expected = label.get("owasp_categories", [])
    r = score(findings, expected)

    print(f"\nProofmark recall — {label.get('target', args.run)}\n" + "=" * 54)
    print(f"  findings in run:     {r['total_findings']}")
    print(f"  expected classes:    {', '.join(expected)}")
    print(f"  matched:             {', '.join(r['matched']) or '-'}")
    print(f"  missed:              {', '.join(r['missed']) or '-'}")
    print(f"  recall:              {r['recall']:.2f}  ({len(r['matched'])}/{len(expected)})")
    if r["extras"]:
        print("  extra findings (review by hand — may be true positives):")
        for e in r["extras"][:20]:
            print(f"    - {e}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
