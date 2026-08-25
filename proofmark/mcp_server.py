"""A Model Context Protocol server, so an AI coding assistant can run Proofmark.

Exposes two tools over MCP — scan a target, and verify a run record — by driving
the same tested CLI underneath. This is how Proofmark plugs into Claude Code,
Cursor, Codex and anything else that speaks MCP: `proofmark mcp` starts the
server on stdio, and the assistant calls the tools.

The `mcp` package is an optional dependency (`pip install 'proofmark[mcp]'`), so
importing it is guarded and the CLI gives a clear message if it is missing.
"""
from __future__ import annotations

import subprocess
import sys

from proofmark.config import DEFAULT_MODEL


def _run_cli(args: list[str], timeout: int = 900) -> str:
    try:
        proc = subprocess.run(["proofmark", *args], capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return "proofmark is not on PATH inside this environment."
    except subprocess.TimeoutExpired:
        return "the scan exceeded the time budget."
    return (proc.stdout or "") + (("\n[stderr]\n" + proc.stderr) if proc.stderr.strip() else "")


def build_server():
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("proofmark")

    @server.tool()
    def proofmark_scan(target: str, authorized: bool = False,
                       model: str = DEFAULT_MODEL, strategy: str = "single") -> str:
        """Run the Proofmark security agent against a target you are authorized to test.

        target: a live URL, a git repo, or a local path.
        authorized: must be true — you assert you may test this target.
        strategy: 'single' or 'graph' (recon -> exploit).
        Returns the Markdown report of what was proven.
        """
        if not authorized:
            return ("Refused. Proofmark actively exploits its target. Set authorized=true "
                    "only for a system you own or are permitted to test.")
        return _run_cli(["scan", "-t", target, "--authorized", "--operator", "mcp",
                         "--model", model, "--strategy", strategy])

    @server.tool()
    def proofmark_verify(run_dir: str) -> str:
        """Check that a Proofmark run record is intact and, if signed, unaltered."""
        return _run_cli(["verify", run_dir], timeout=30)

    return server


def main() -> None:
    try:
        import mcp  # noqa: F401
    except ImportError:
        print("The MCP server needs the 'mcp' package. Install it with:\n"
              "  pip install 'proofmark[mcp]'", file=sys.stderr)
        sys.exit(1)
    build_server().run()
