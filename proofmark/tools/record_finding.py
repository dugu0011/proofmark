"""Record a vulnerability the agent has already reproduced.

This is the tool that justifies the whole run, and the system prompt is strict
about it: the agent may only call it once it has a concrete proof-of-concept that
reproduces the issue. A finding without a PoC is exactly the false positive this
tool exists to avoid, so the description says so and the loop keeps the PoC.
"""
from __future__ import annotations

from proofmark.findings import Finding, render_curl
from proofmark.tools.base import Tool, ToolResult


class RecordFindingTool(Tool):
    name = "record_finding"
    description = (
        "Record a vulnerability you have PROVEN. Only call this after you have a "
        "concrete proof-of-concept that reproduces the issue — the request you sent "
        "and the response that demonstrates the impact. Do not record anything you "
        "have not actually reproduced. Pass evidence_requests with the request "
        "numbers (from list_requests) that prove it — each is captured verbatim, "
        "rendered as a curl and attached as evidence. To rate a live finding 'high' "
        "confidence, you must first reproduce the exploit a second time with "
        "replay_request — proof, not a single lucky response."
    )
    parameters = {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
            "confidence": {"type": "string", "enum": ["high", "medium", "low"],
                           "description": "How sure you are you PROVED a real exploit. Be honest."},
            "location": {"type": "string", "description": "Endpoint, parameter, or file:line."},
            "owasp_category": {"type": "string", "description": "OWASP category, e.g. 'A01:2021 Broken Access Control'."},
            "cwe": {"type": "string", "description": "CWE id, e.g. 'CWE-89'."},
            "description": {"type": "string", "description": "What the issue is and its impact."},
            "proof_of_concept": {
                "type": "string",
                "description": "The exact reproduction: request(s) sent and response(s) proving it.",
            },
            "evidence_requests": {
                "type": "array",
                "items": {"type": "integer"},
                "description": "Request numbers (from list_requests) that prove this finding. "
                               "Each is captured as a curl + its response and attached as evidence.",
            },
            "remediation": {"type": "string", "description": "How to fix it."},
        },
        "required": ["title", "severity", "description", "proof_of_concept"],
    }

    def __init__(self, log=None, *, require_replay: bool = False,
                 suppress_titles: set | None = None) -> None:
        # Track what has been recorded so the same bug is never reported twice.
        self._seen: set[str] = set()
        # Compact list of what has been proven, so the agent can recall it (via
        # list_findings) and chain findings into higher-impact attacks.
        self.recorded: list[dict] = []
        # For live targets, "high" confidence is earned, not asserted: it requires
        # the exploit to have been reproduced a second time via replay_request.
        self._log = log
        self._require_replay = require_replay
        # Titles the operator already judged false positives — the platform's
        # learning fed back in, so the agent does not re-report a known non-issue.
        self._suppress = {t.strip().lower() for t in (suppress_titles or set())}

    def _attach_evidence(self, finding: Finding, indices) -> None:
        """Capture the named requests verbatim as structured evidence + curl.

        The proof is taken from the request log, not the model's prose, so it is
        exactly what hit the wire — and it is appended to the PoC so it shows up
        everywhere the finding is read."""
        if not indices or self._log is None:
            return
        evidence: list[dict] = []
        blocks: list[str] = []
        for raw in indices:
            try:
                i = int(raw)
            except (TypeError, ValueError):
                continue
            ex = self._log.get(i)
            if ex is None:
                continue
            req = ex.request
            curl = render_curl(req.method, req.url, req.headers, req.body)
            preview = (ex.response_preview or "")[:800]
            evidence.append({
                "request_index": i, "method": req.method, "url": req.url,
                "status": ex.status, "curl": curl, "response_preview": preview,
            })
            blocks.append(
                f"# request #{i}: {req.method} {req.url}  ->  HTTP {ex.status}\n"
                f"{curl}\n\n# response:\n{preview}"
            )
        if evidence:
            finding.evidence = evidence
            finding.proof_of_concept = (
                finding.proof_of_concept.rstrip()
                + "\n\n--- captured reproduction ---\n" + "\n\n".join(blocks)
            )

    def run(self, **kwargs) -> ToolResult:
        title = str(kwargs.get("title", "")).strip().lower()
        if title and title in self._suppress:
            return ToolResult(
                f"Skipped: '{kwargs.get('title')}' was previously judged a false positive "
                "for this target. Do not report it again; look for something else.",
                is_error=True,
            )
        if not str(kwargs.get("proof_of_concept", "")).strip():
            return ToolResult(
                "Refused: a finding needs a proof-of-concept. Reproduce it first, "
                "then record it with the request and response that prove it.",
                is_error=True,
            )
        downgraded = False
        if self._require_replay and str(kwargs.get("confidence", "")).lower() == "high":
            reproduced = self._log is not None and self._log.replays_ok > 0
            if not reproduced:
                kwargs = {**kwargs, "confidence": "medium"}
                downgraded = True

        finding = Finding.from_tool(**kwargs)
        fp = finding.fingerprint()
        if fp in self._seen:
            return ToolResult(
                f"Already recorded: {finding.title} at {finding.location or 'this location'}. "
                "Move on to something else.",
                is_error=True,
            )
        self._seen.add(fp)
        self._attach_evidence(finding, kwargs.get("evidence_requests"))
        self.recorded.append({"title": finding.title, "severity": finding.severity.value,
                              "location": finding.location})
        note = ""
        if downgraded:
            note = (" Confidence lowered to medium: I have no record of this exploit "
                    "being reproduced. Reproduce it with replay_request, then re-recording "
                    "it can be rated high.")
        return ToolResult(
            f"Recorded [{finding.severity.value}/{finding.confidence}] {finding.title}.{note}",
            data=finding,
        )
