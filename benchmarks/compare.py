"""Compare a Proofmark run against a Strix run on the same target — the number
that backs the word "better".

Two dimensions matter, and they are reported side by side:
  * recall over the target's known bug classes — who found more of what's there,
  * proven findings — how many were backed by a reproduced proof-of-concept.

Proofmark's edge is the second column: its findings are proven, not asserted, so
a fair comparison shows both, not just a raw count.

Usage:
    python benchmarks/compare.py --proofmark <run-dir|run.json> \
                                 --strix <strix-report.json> \
                                 --expected benchmarks/expected_juice_shop.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from benchmarks.score import _codes, _load_findings, score
except ImportError:  # run as `python benchmarks/compare.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from benchmarks.score import _codes, _load_findings, score


def _is_proven(f: dict) -> bool:
    """A finding backed by a reproduced PoC or captured evidence."""
    return bool((f.get("proof_of_concept") or "").strip() or f.get("evidence"))


def proven_count(findings: list[dict]) -> int:
    return sum(1 for f in findings if _is_proven(f))


def normalize_strix(data) -> list[dict]:
    """Best-effort adapter from a Strix report to the common finding shape.

    Accepts a list, or a dict with the findings under findings/vulnerabilities/
    results/issues, and pulls a title plus any OWASP/CWE codes out of each item's
    text — so scoring works even without knowing Strix's exact schema.
    """
    if isinstance(data, dict):
        for key in ("findings", "vulnerabilities", "results", "issues"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            data = []
    out: list[dict] = []
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        blob = " ".join(str(v) for v in item.values() if isinstance(v, (str, int)))
        title = item.get("title") or item.get("name") or item.get("type") or "finding"
        owasp = str(item.get("owasp_category") or item.get("owasp") or "")
        cwe = str(item.get("cwe") or item.get("cwe_id") or "")
        if not (_codes(owasp) or _codes(cwe)):
            owasp = blob  # let the codes fall out of the whole record
        out.append({
            "title": title, "owasp_category": owasp, "cwe": cwe,
            "proof_of_concept": item.get("proof_of_concept") or item.get("poc") or "",
            "evidence": item.get("evidence"),
        })
    return out


def compare(pm: list[dict], strix: list[dict], expected: list[str]) -> dict:
    ps, ss = score(pm, expected), score(strix, expected)
    return {
        "expected": [e.upper() for e in expected],
        "proofmark": {**ps, "proven": proven_count(pm)},
        "strix": {**ss, "proven": proven_count(strix)},
        "proofmark_only": sorted(set(ps["matched"]) - set(ss["matched"])),
        "strix_only": sorted(set(ss["matched"]) - set(ps["matched"])),
    }


def _load_strix(path: Path) -> list[dict]:
    return normalize_strix(json.loads(path.read_text()))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--proofmark", required=True, help="Proofmark run dir or run.json")
    ap.add_argument("--strix", required=True, help="Strix report JSON")
    ap.add_argument("--expected", default=str(Path(__file__).parent / "expected_juice_shop.json"))
    args = ap.parse_args()

    label = json.loads(Path(args.expected).read_text())
    expected = label.get("owasp_categories", [])
    pm = _load_findings(Path(args.proofmark))
    strix = _load_strix(Path(args.strix))
    r = compare(pm, strix, expected)

    def row(name, d):
        return (f"  {name:<12} findings {d['total_findings']:>3} | proven {d['proven']:>3} | "
                f"recall {d['recall']:.2f} ({len(d['matched'])}/{len(expected)}) | "
                f"matched {', '.join(d['matched']) or '-'}")

    print(f"\nProofmark vs Strix — {label.get('target', 'target')}\n" + "=" * 66)
    print(f"  expected classes: {', '.join(r['expected'])}\n")
    print(row("Proofmark", r["proofmark"]))
    print(row("Strix", r["strix"]))
    print()
    print(f"  only Proofmark found: {', '.join(r['proofmark_only']) or '-'}")
    print(f"  only Strix found:     {', '.join(r['strix_only']) or '-'}")
    pm_p, sx_p = r["proofmark"]["proven"], r["strix"]["proven"]
    print(f"\n  proven-finding edge: Proofmark {pm_p} vs Strix {sx_p} "
          f"({'Proofmark' if pm_p > sx_p else 'Strix' if sx_p > pm_p else 'tie'})")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
