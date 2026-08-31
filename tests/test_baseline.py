"""Baseline / diff fingerprinting."""
from __future__ import annotations

import proofmark.baseline as bl

F1 = {"title": "SQL injection", "location": "GET /search?q=", "cwe": "CWE-89"}
F2 = {"title": "Reflected XSS", "location": "GET /q?x=", "owasp_category": "A03:2021 Injection"}


def test_fingerprint_is_stable_and_ignores_poc_wording():
    a = bl.fingerprint({**F1, "proof_of_concept": "q=1'"})
    b = bl.fingerprint({**F1, "proof_of_concept": "totally different wording"})
    assert a == b
    assert bl.fingerprint(F1) != bl.fingerprint(F2)


def test_new_findings_filters_known():
    known = {bl.fingerprint(F1)}
    out = bl.new_findings([F1, F2], known)
    assert out == [F2]


def test_read_missing_is_none(tmp_path):
    assert bl.read(str(tmp_path / "nope.json")) is None


def test_write_then_read_roundtrip(tmp_path):
    path = str(tmp_path / "baseline.json")
    n = bl.write([F1, F2], path)
    assert n == 2
    fps = bl.read(path)
    assert bl.fingerprint(F1) in fps and bl.fingerprint(F2) in fps
    # after baselining both, nothing is new
    assert bl.new_findings([F1, F2], fps) == []
