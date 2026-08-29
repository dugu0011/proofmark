"""Proof-of-exploit evidence: curl rendering and record_finding capture."""
from __future__ import annotations

from proofmark.findings import Finding, render_curl
from proofmark.http_client import Request, RequestLog
from proofmark.tools.record_finding import RecordFindingTool


def test_render_curl_includes_method_headers_and_body():
    curl = render_curl("POST", "https://app.test/api/x",
                       {"Content-Type": "application/json"}, '{"a":1}')
    assert curl.startswith("curl -i -X POST https://app.test/api/x")
    assert "-H 'Content-Type: application/json'" in curl
    assert "--data '{\"a\":1}'" in curl


def test_render_curl_quotes_dangerous_urls():
    curl = render_curl("GET", "https://app.test/a;rm -rf /")
    assert "'https://app.test/a;rm -rf /'" in curl  # shell-quoted, not executable


def _log_with_request():
    log = RequestLog()
    req = Request("GET", "https://app.test/api/orders/123", {"Accept": "application/json"})
    log.add(req, 200, "order 123: alice's data")
    return log


def test_record_finding_attaches_structured_evidence():
    log = _log_with_request()
    result = RecordFindingTool(log).run(
        title="IDOR on orders", severity="high",
        description="Another user can read this order.",
        proof_of_concept="Fetched order 123 as a different user.",
        evidence_requests=[0],
    )
    finding: Finding = result.data
    assert len(finding.evidence) == 1
    ev = finding.evidence[0]
    assert ev["method"] == "GET" and ev["status"] == 200
    assert ev["url"].endswith("/api/orders/123")
    assert ev["curl"].startswith("curl -i -X GET")
    assert "alice's data" in ev["response_preview"]


def test_evidence_is_appended_to_the_proof_so_it_surfaces_everywhere():
    log = _log_with_request()
    result = RecordFindingTool(log).run(
        title="IDOR", severity="high", description="d",
        proof_of_concept="the prose proof", evidence_requests=[0],
    )
    poc = result.data.proof_of_concept
    assert "the prose proof" in poc
    assert "--- captured reproduction ---" in poc
    assert "curl -i -X GET" in poc
    assert "HTTP 200" in poc


def test_unknown_request_numbers_are_ignored():
    log = _log_with_request()
    result = RecordFindingTool(log).run(
        title="x", severity="low", description="d",
        proof_of_concept="p", evidence_requests=[0, 99, "bad"],
    )
    assert len(result.data.evidence) == 1  # only #0 existed


def test_a_finding_without_evidence_requests_still_records():
    result = RecordFindingTool(RequestLog()).run(
        title="x", severity="low", description="d", proof_of_concept="p",
    )
    assert not result.is_error
    assert result.data.evidence == []
