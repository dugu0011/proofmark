"""Multi-target collection + argv passthrough (pure helpers)."""
from __future__ import annotations

from click.testing import CliRunner

from proofmark.cli import _collect_targets, _passthrough_argv, main


def test_collect_from_repeated_flags():
    assert _collect_targets(("https://a", "https://b"), "") == ["https://a", "https://b"]


def test_collect_dedupes_and_keeps_order():
    assert _collect_targets(("https://a", "https://a", "https://b"), "") == ["https://a", "https://b"]


def test_collect_from_file(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("https://a\n# a comment\n\nhttps://c\n")
    assert _collect_targets(("https://a",), str(f)) == ["https://a", "https://c"]


def test_passthrough_strips_target_flags():
    argv = ["proofmark", "scan", "-t", "https://a", "-t", "https://b",
            "--authorized", "--scan-mode", "quick", "--target-list", "f.txt"]
    assert _passthrough_argv(argv) == ["--authorized", "--scan-mode", "quick"]


def test_passthrough_strips_equals_form():
    argv = ["proofmark", "scan", "--target=https://a", "-t=https://b", "--operator", "me"]
    assert _passthrough_argv(argv) == ["--operator", "me"]


def test_single_target_still_reaches_auth_gate():
    # one -t: the normal path runs (reaches the authorization refusal without --authorized)
    r = CliRunner().invoke(main, ["scan", "-t", "https://app.test"])
    assert "refused" in r.output.lower() or "authorized" in r.output.lower()


def test_no_target_errors():
    r = CliRunner().invoke(main, ["scan"])
    assert "no target" in r.output.lower()
