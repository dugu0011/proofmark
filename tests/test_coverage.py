"""Coverage tracker — the systematic-testing bookkeeping."""
from __future__ import annotations

from proofmark.coverage import CHECKS, CoverageBoard
from proofmark.tools.coverage_tool import CoverageTool


def test_board_records_and_reports_gaps():
    b = CoverageBoard()
    b.note("GET /api/orders/{id}", "bola-idor", "vulnerable")
    b.note("GET /api/orders/{id}", "sqli", "safe")
    gaps = b.gaps()
    assert "GET /api/orders/{id}" in gaps
    remaining = gaps["GET /api/orders/{id}"]
    assert "bola-idor" not in remaining and "sqli" not in remaining
    assert "ssrf" in remaining
    assert len(remaining) == len(CHECKS) - 2


def test_matrix_reflects_status():
    b = CoverageBoard()
    b.note("/fetch", "ssrf", "vulnerable")
    assert b.matrix() == {"/fetch": {"ssrf": "vulnerable"}}


def test_tool_note_then_gaps():
    board = CoverageBoard()
    tool = CoverageTool(board)
    assert tool.run(action="note", endpoint="/login", check="sqli", result="safe").output.startswith("noted")
    out = tool.run(action="gaps")
    assert "/login" in out.output and "sqli" not in out.output.split("/login", 1)[1].split("\n", 1)[0]


def test_tool_note_requires_endpoint_and_check():
    assert CoverageTool(CoverageBoard()).run(action="note", endpoint="/x").is_error


def test_tool_gaps_empty_when_nothing_tracked():
    assert "No endpoints tracked" in CoverageTool(CoverageBoard()).run(action="gaps").output


def test_tool_matrix():
    board = CoverageBoard()
    board.note("/a", "xss", "vulnerable")
    assert "xss=vulnerable" in CoverageTool(board).run(action="matrix").output
