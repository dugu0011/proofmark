"""The tamper-evident run record — the differentiator, so it needs real tests.

A record must be provably intact: any edit, any reordered step, any dropped step
must be caught, and a signed record must fail if the wrong key checks it.
"""
import json
import os

import pytest

from proofmark import audit


def _record(run_id="test-run"):
    return audit.RunRecord(
        run_id=run_id, product="Proofmark", version="0.1.0",
        target="https://app.test", kind="url", operator="me@team.com",
        model="anthropic/claude-sonnet-4-6",
        authorization={"scope": ["app.test"], "operator": "me@team.com"},
        started_at="2026-01-01T00:00:00+00:00", finished_at="2026-01-01T00:05:00+00:00",
        stopped_reason="agent finished",
        steps=[{"kind": "action", "text": "http_request", "detail": "GET /api/users/1"},
               {"kind": "finding", "text": "[high] IDOR", "detail": "/api/users/{id}"}],
        requests=[{"method": "GET", "url": "https://app.test/api/users/2", "status": 200, "error": None}],
        findings=[{"title": "IDOR", "severity": "high", "location": "/api/users/{id}",
                   "description": "cross-user read", "proof_of_concept": "GET /api/users/2 -> 200",
                   "remediation": "enforce authz"}],
    )


def test_a_saved_record_verifies(tmp_path):
    audit.save(_record(), str(tmp_path))
    ok, reason = audit.verify(str(tmp_path / "test-run"))
    assert ok and "intact" in reason


def test_editing_a_step_breaks_the_chain(tmp_path):
    audit.save(_record(), str(tmp_path))
    run = tmp_path / "test-run" / "run.json"
    data = json.loads(run.read_text())
    data["steps"][0]["detail"] = "GET /api/users/999 — tampered"
    run.write_text(json.dumps(data))
    ok, reason = audit.verify(str(tmp_path / "test-run"))
    assert not ok and "altered" in reason


def test_dropping_a_step_is_caught(tmp_path):
    audit.save(_record(), str(tmp_path))
    run = tmp_path / "test-run" / "run.json"
    data = json.loads(run.read_text())
    data["steps"] = data["steps"][:1]           # drop the finding step, keep the tip
    run.write_text(json.dumps(data))
    ok, reason = audit.verify(str(tmp_path / "test-run"))
    assert not ok


def test_a_signed_record_verifies_with_the_key(tmp_path, monkeypatch):
    monkeypatch.setenv(audit.SIGNING_KEY_ENV, "s3cr3t-run-key")
    audit.save(_record(), str(tmp_path))
    ok, reason = audit.verify(str(tmp_path / "test-run"))
    assert ok and "signature valid" in reason


def test_a_signed_record_fails_with_the_wrong_key(tmp_path, monkeypatch):
    monkeypatch.setenv(audit.SIGNING_KEY_ENV, "right-key")
    audit.save(_record(), str(tmp_path))
    monkeypatch.setenv(audit.SIGNING_KEY_ENV, "wrong-key")
    ok, reason = audit.verify(str(tmp_path / "test-run"))
    assert not ok and "signature does not match" in reason


def test_a_signed_record_needs_the_key_present(tmp_path, monkeypatch):
    monkeypatch.setenv(audit.SIGNING_KEY_ENV, "the-key")
    audit.save(_record(), str(tmp_path))
    monkeypatch.delenv(audit.SIGNING_KEY_ENV)
    ok, reason = audit.verify(str(tmp_path / "test-run"))
    assert not ok and "not set" in reason


def test_tampering_after_signing_is_caught(tmp_path, monkeypatch):
    monkeypatch.setenv(audit.SIGNING_KEY_ENV, "the-key")
    audit.save(_record(), str(tmp_path))
    run = tmp_path / "test-run" / "run.json"
    data = json.loads(run.read_text())
    data["findings"][0]["severity"] = "low"     # downgrade a finding, keep the signature
    run.write_text(json.dumps(data))
    ok, reason = audit.verify(str(tmp_path / "test-run"))
    assert not ok
