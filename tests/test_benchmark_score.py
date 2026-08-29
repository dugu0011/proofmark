"""The pentest recall scorer."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from benchmarks.score import score, _codes  # noqa: E402


def test_codes_extracts_owasp_and_api_codes():
    assert _codes("A03:2021 Injection") == {"A03"}
    assert _codes("API1:2023 Broken Object Level Authorization") == {"API1"}
    assert _codes("no category here") == set()


def test_recall_counts_matched_expected_classes():
    findings = [
        {"title": "SQLi", "owasp_category": "A03:2021 Injection"},
        {"title": "BOLA", "owasp_category": "A01:2021 Broken Access Control"},
        {"title": "Weird thing", "owasp_category": "A10:2021 SSRF"},   # not expected -> extra
    ]
    r = score(findings, ["A01", "A02", "A03"])
    assert set(r["matched"]) == {"A01", "A03"}
    assert r["missed"] == ["A02"]
    assert abs(r["recall"] - 2 / 3) < 1e-6
    assert any("Weird thing" in e for e in r["extras"])


def test_perfect_recall_when_all_classes_found():
    findings = [{"title": "x", "owasp_category": c} for c in ("A01", "A02")]
    r = score(findings, ["A01", "A02"])
    assert r["recall"] == 1.0 and r["missed"] == []
