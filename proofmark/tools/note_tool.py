"""note: the agent writes an observation to the shared blackboard.

Used mainly by the recon agent, whose job is to map and hand off, not to exploit.
A note is how it passes what it found to the exploit agent that follows.
"""
from __future__ import annotations

from proofmark.blackboard import Blackboard
from proofmark.tools.base import Tool, ToolResult


class NoteTool(Tool):
    name = "note"
    description = (
        "Record an observation for the agents that follow you — an endpoint worth "
        "attacking, a parameter that looks unsanitized, the tech stack, an auth "
        "scheme. Use this to hand off what you mapped."
    )
    parameters = {
        "type": "object",
        "properties": {"observation": {"type": "string"}},
        "required": ["observation"],
    }

    def __init__(self, blackboard: Blackboard) -> None:
        self._bb = blackboard

    def run(self, **kwargs) -> ToolResult:
        obs = kwargs.get("observation", "")
        if not obs.strip():
            return ToolResult("Nothing to note.", is_error=True)
        self._bb.add_note(obs)
        return ToolResult("Noted.")
