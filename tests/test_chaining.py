"""Exploit chaining: recalling proven findings via list_findings."""
from __future__ import annotations

from proofmark.tools.record_finding import RecordFindingTool
from proofmark.tools.list_findings_tool import ListFindingsTool


def test_list_findings_is_empty_before_anything_is_proven():
    out = ListFindingsTool(RecordFindingTool()).run()
    assert not out.is_error and "No findings recorded yet" in out.output


def test_recorded_findings_are_listed_for_chaining():
    rec = RecordFindingTool()
    rec.run(title="Leaked API key", severity="high", description="d",
            proof_of_concept="p", location="/config")
    rec.run(title="IDOR on /orders", severity="high", description="d",
            proof_of_concept="p", location="/api/orders/1")
    out = ListFindingsTool(rec).run().output
    assert "Leaked API key" in out and "IDOR on /orders" in out
    assert "chain" in out.lower()
    assert len(rec.recorded) == 2


def test_a_duplicate_finding_is_not_double_listed():
    rec = RecordFindingTool()
    rec.run(title="Same bug", severity="high", description="d", proof_of_concept="p", location="/x")
    rec.run(title="Same bug", severity="high", description="d", proof_of_concept="p", location="/x")
    assert len(rec.recorded) == 1
