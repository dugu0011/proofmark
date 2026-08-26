"""CLI smoke tests: catch missing options and broken wiring without a live run.

The kind of bug these exist for: an option's function parameter added without
its @click.option decorator — the command then rejects the flag (or fails to
start). A unit test of the agent won't catch that; invoking the CLI does.
"""
from click.testing import CliRunner

from proofmark.cli import main

# Every option APIShield (and CI) passes to `proofmark scan`. If any is missing
# a decorator, --help won't mention it and this fails.
EXPECTED_OPTIONS = [
    "--target", "--authorized", "--operator", "--model", "--strategy",
    "--max-steps", "--time-budget", "--run-dir", "--output",
    "--events-file", "--control-file", "--base-url", "--allow-host",
    "--safe-mode", "--recon-model", "--exploit-model",
]


def test_scan_declares_every_option():
    result = CliRunner().invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
    for opt in EXPECTED_OPTIONS:
        assert opt in result.output, f"scan is missing the {opt} option"


def test_scan_refuses_without_authorization():
    # A real invocation path: it must reach the authorization gate, not crash on
    # argument wiring. (No LLM key / no run needed — the gate fires first.)
    result = CliRunner().invoke(main, ["scan", "-t", "https://example.test"])
    assert result.exit_code != 0
    assert "authorized" in result.output.lower()


def test_top_level_commands_exist():
    result = CliRunner().invoke(main, ["--help"])
    for cmd in ("scan", "verify", "replay", "doctor", "mcp", "build-sandbox", "keygen"):
        assert cmd in result.output
