"""SARIF 2.1.0 export."""
from __future__ import annotations

import json

from proofmark.sarif import to_sarif

FINDINGS = [
    {"title": "SQL injection in search", "severity": "critical", "location": "GET /search?q=",
     "description": "Request data reaches a SQL query.", "proof_of_concept": "q=1' -> DB error",
     "remediation": "Use bound parameters.", "confidence": "high",
     "owasp_category": "A03:2021 Injection", "cwe": "CWE-89"},
    {"title": "Missing security headers", "severity": "low", "location": "GET /",
     "description": "No CSP.", "owasp_category": "A05:2021 Security Misconfiguration"},
]


def test_sarif_shape_is_valid():
    doc = to_sarif(FINDINGS, target="https://app.test", version="0.11.0")
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Proofmark"
    assert run["tool"]["driver"]["version"] == "0.11.0"
    assert len(run["results"]) == 2
    assert run["properties"]["target"] == "https://app.test"
    # serializes cleanly
    json.dumps(doc)


def test_severity_maps_to_level():
    doc = to_sarif(FINDINGS, target="t", version="v")
    levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    assert levels["CWE-89"] == "error"          # critical -> error
    assert levels["A05"] == "note"              # low -> note


def test_rule_id_prefers_cwe_then_owasp():
    doc = to_sarif(FINDINGS, target="t", version="v")
    ids = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "CWE-89" in ids                      # had a CWE
    assert "A05" in ids                         # no CWE -> OWASP code


def test_message_includes_proof_and_remediation():
    doc = to_sarif(FINDINGS, target="t", version="v")
    sqli = next(r for r in doc["runs"][0]["results"] if r["ruleId"] == "CWE-89")
    assert "Proof of concept" in sqli["message"]["text"]
    assert "Remediation" in sqli["message"]["text"]


def test_rules_are_deduplicated():
    dup = FINDINGS + [dict(FINDINGS[0])]        # same CWE-89 twice
    doc = to_sarif(dup, target="t", version="v")
    rule_ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
    assert rule_ids.count("CWE-89") == 1        # one rule
    assert len(doc["runs"][0]["results"]) == 3  # but three results


def test_empty_findings_valid():
    doc = to_sarif([], target="t", version="v")
    assert doc["runs"][0]["results"] == []
    json.dumps(doc)
