"""Proofmark-vs-Strix comparison harness."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from benchmarks.compare import compare, normalize_strix, proven_count  # noqa: E402


def test_normalize_strix_list_form_extracts_codes():
    data = [
        {"title": "SQLi", "owasp_category": "A03:2021 Injection"},
        {"name": "IDOR", "description": "Broken access control API1:2023 on /orders"},
        "junk-not-a-dict",
    ]
    out = normalize_strix(data)
    assert len(out) == 2
    assert out[0]["title"] == "SQLi"
    # the second finding's code falls out of its text blob
    assert "API1" in out[1]["owasp_category"] or "API1" in out[1]["cwe"] \
        or "API1" in out[1]["owasp_category"]


def test_normalize_strix_dict_wrapper():
    data = {"vulnerabilities": [{"type": "XSS", "owasp": "A03"}]}
    assert normalize_strix(data)[0]["owasp_category"] == "A03"
    assert normalize_strix({"nothing": 1}) == []


def test_proven_count():
    findings = [
        {"title": "a", "proof_of_concept": "curl ... -> 200 leaked"},
        {"title": "b", "evidence": {"request": "..."}},
        {"title": "c", "proof_of_concept": ""},        # not proven
        {"title": "d"},                                 # not proven
    ]
    assert proven_count(findings) == 2


def test_compare_reports_both_dimensions():
    expected = ["A01", "A02", "A03", "A05"]
    proofmark = [
        {"title": "SQLi", "owasp_category": "A03:2021 Injection",
         "proof_of_concept": "time-based 5.1s vs 0.1s"},
        {"title": "BOLA", "owasp_category": "A01:2021 Broken Access Control",
         "evidence": {"req": "as other user -> 200"}},
        {"title": "Weak crypto", "owasp_category": "A02:2021 Cryptographic Failures",
         "proof_of_concept": "forged HS256 token accepted"},
    ]
    strix = [
        {"title": "SQLi", "owasp_category": "A03"},              # overlaps, unproven here
        {"title": "Misconfig", "owasp_category": "A05"},         # strix-only class
    ]
    r = compare(proofmark, strix, expected)

    assert set(r["proofmark"]["matched"]) == {"A01", "A02", "A03"}
    assert set(r["strix"]["matched"]) == {"A03", "A05"}
    assert r["proofmark"]["proven"] == 3
    assert r["strix"]["proven"] == 0
    assert r["proofmark_only"] == ["A01", "A02"]
    assert r["strix_only"] == ["A05"]
    assert r["proofmark"]["recall"] == 0.75    # 3 of 4 expected classes
