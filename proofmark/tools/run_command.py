"""Run a shell command inside the sandbox.

The agent uses this for everything HTTP cannot express: decoding a token,
running a quick Python snippet, inspecting a payload, chaining a small script.
It runs in the same jailed container as everything else — no host access, capped
resources, killed if it hangs.
"""
from __future__ import annotations

from proofmark.sandbox import Sandbox
from proofmark.tools.base import Tool, ToolResult


class RunCommandTool(Tool):
    name = "run_command"
    description = (
        "Run a shell command inside the sandbox and get its output. Use for "
        "decoding, quick scripts (python3 is available), or inspecting data. "
        "Runs jailed with no host access."
    )
    parameters = {
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "The shell command to run."},
        },
        "required": ["command"],
    }

    def __init__(self, sandbox: Sandbox) -> None:
        self._sandbox = sandbox

    def run(self, **kwargs) -> ToolResult:
        command = kwargs.get("command", "").strip()
        if not command:
            return ToolResult("No command given.", is_error=True)
        code, out = self._sandbox.exec(command, timeout=30)
        tail = out if len(out) <= 6000 else out[:6000] + "\n...[truncated]"
        return ToolResult(f"exit={code}\n{tail}")
