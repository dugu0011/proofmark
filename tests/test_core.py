"""Offline tests: everything that does not need Docker or a live model.

These cover the parts that must be right for the tool to be trustworthy — the
scope gate, the refusal to record a finding without a proof, and the report.
"""
from proofmark.agent import Outcome
from proofmark.authorization import Authorization
from proofmark.config import RunConfig
from proofmark.findings import Finding, Severity
from proofmark.report import to_markdown
from proofmark.tools.base import ToolRegistry
from proofmark.tools.record_finding import RecordFindingTool


# --------------------------------------------------------------- scope gate
def test_in_scope_host_is_allowed():
    auth = Authorization.grant("https://app.test/login", "me", ["cdn.app.test"])
    assert auth.permits_host("https://app.test/api/users")
    assert auth.permits_host("https://cdn.app.test/asset.js")


def test_out_of_scope_and_metadata_ip_are_denied():
    auth = Authorization.grant("https://app.test", "me")
    assert not auth.permits_host("https://evil.test/steal")
    # The classic SSRF target must never be reachable by default.
    assert not auth.permits_host("http://169.254.169.254/latest/meta-data/")


def test_a_code_target_denies_all_network():
    # No live host means network probing has nothing legitimate to reach.
    auth = Authorization.grant("./my-service", "me", [])
    assert not auth.permits_host("https://anything.test")


def test_credentials_are_stripped_from_the_scope_host():
    auth = Authorization.grant("https://user:pass@app.test/x", "me")
    assert auth.permits_host("https://app.test/y")


# --------------------------------------------------- proof-of-concept is required
def test_recording_without_a_poc_is_refused():
    reg = ToolRegistry([RecordFindingTool()])
    result = reg.dispatch("record_finding", {
        "title": "x", "severity": "high", "description": "d", "proof_of_concept": ""})
    assert result.is_error and "proof-of-concept" in result.output


def test_a_finding_with_a_poc_is_accepted():
    reg = ToolRegistry([RecordFindingTool()])
    result = reg.dispatch("record_finding", {
        "title": "IDOR", "severity": "high", "description": "d",
        "proof_of_concept": "GET /api/users/2 as user 1 -> 200"})
    assert isinstance(result.data, Finding)
    assert result.data.severity is Severity.HIGH


# ------------------------------------------------------------- registry safety
def test_unknown_tool_and_bad_json_do_not_crash():
    reg = ToolRegistry([RecordFindingTool()])
    assert reg.dispatch("nope", {}).is_error
    assert reg.dispatch("record_finding", "{not valid json").is_error


# ---------------------------------------------------------------------- report
def test_report_leads_with_the_proof_and_records_authorization():
    auth = Authorization.grant("https://app.test/login", "me@team.com", ["cdn.app.test"])
    f = Finding.from_tool(title="IDOR on /api/users", severity="high",
                          location="/api/users/{id}", description="Cross-user read.",
                          proof_of_concept="GET /api/users/2 -> 200 with another user's data",
                          remediation="Enforce object-level authz.")
    md = to_markdown(Outcome(findings=[f], summary="one issue", steps_used=7,
                             stopped_reason="agent finished"),
                     auth, target="https://app.test/login", model="m", product="Proofmark")
    assert "IDOR on /api/users" in md
    assert "Proof of concept" in md
    assert "**Authorized by:** me@team.com" in md
    assert "1 proven finding" in md


def test_a_clean_run_is_reported_honestly():
    auth = Authorization.grant("https://app.test", "me")
    md = to_markdown(Outcome(steps_used=40, stopped_reason="step budget exhausted"),
                     auth, target="https://app.test", model="m", product="Proofmark")
    assert "clean run is evidence, not proof of absence" in md


# ---------------------------------------------------------------------- config
def test_model_prefix_picks_the_right_key():
    assert RunConfig("t", "url", model="anthropic/claude-sonnet-4-6").key_env_var() == "ANTHROPIC_API_KEY"
    assert RunConfig("t", "url", model="openai/gpt-4o").key_env_var() == "OPENAI_API_KEY"
    assert RunConfig("t", "url", model="azure/gpt-4.1").key_env_var() == "AZURE_API_KEY"


# ------------------------------------------------------ code-target scope
def test_code_scope_allows_loopback_denies_internet():
    auth = Authorization.for_code("./my-service", "me")
    assert auth.permits_host("http://localhost:8000/user")
    assert auth.permits_host("http://127.0.0.1:5000/")
    assert auth.permits_host("http://[::1]:3000/x")
    assert not auth.permits_host("https://evil.test")
    # SSRF classic still denied even in code mode.
    assert not auth.permits_host("http://169.254.169.254/latest/meta-data/")


def test_scope_is_per_host_ignoring_port():
    auth = Authorization.grant("https://app.test:8443/login", "me")
    assert auth.permits_host("https://app.test/other")
    assert auth.permits_host("https://app.test:9000/x")


def test_repo_shorthand_is_normalized():
    from proofmark.source import _normalize_repo_url
    assert _normalize_repo_url("owner/repo") == "https://github.com/owner/repo.git"
    assert _normalize_repo_url("https://github.com/o/r.git") == "https://github.com/o/r.git"
    assert _normalize_repo_url("git@github.com:o/r.git") == "git@github.com:o/r.git"
