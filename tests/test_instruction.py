"""--instruction / --instruction-file steering flags."""
from __future__ import annotations

from click.testing import CliRunner

from proofmark.cli import main


def test_instruction_option_is_accepted():
    # no --authorized: it should reach the authorization refusal, proving the
    # option parsed (not "no such option").
    r = CliRunner().invoke(main, ["scan", "-t", "https://app.test", "--instruction", "focus on IDOR"])
    assert "no such option" not in r.output.lower()
    assert "refused" in r.output.lower() or "authorized" in r.output.lower()


def test_instruction_file_missing_errors(tmp_path):
    r = CliRunner().invoke(main, ["scan", "-t", "https://app.test",
                                  "--instruction-file", str(tmp_path / "nope.md")])
    assert "could not read" in r.output.lower()


def test_instruction_file_is_read(tmp_path):
    f = tmp_path / "roe.md"
    f.write_text("Only test /api/*. Do not touch /admin.")
    r = CliRunner().invoke(main, ["scan", "-t", "https://app.test", "--instruction-file", str(f)])
    assert "could not read" not in r.output.lower()
    assert "refused" in r.output.lower() or "authorized" in r.output.lower()


def test_scan_mode_accepted():
    from click.testing import CliRunner
    from proofmark.cli import main
    r = CliRunner().invoke(main, ["scan", "-t", "https://app.test", "--scan-mode", "quick"])
    assert "no such option" not in r.output.lower()
    assert "refused" in r.output.lower() or "authorized" in r.output.lower()
