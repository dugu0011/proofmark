"""The contract every tool implements, and the registry the agent calls through.

A tool is the only way the agent affects the world. Each declares a JSON schema
(so the model knows how to call it) and a run() that does the work inside the
sandbox. The registry turns the set of tools into the `tools=[...]` list the LLM
tool-calling API expects, and dispatches a call back to the right object.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class ToolResult:
    """What a tool hands back to the agent. `output` is fed to the model."""

    output: str
    # Optional structured payload for the loop itself (e.g. a recorded finding).
    data: Any = None
    is_error: bool = False


class Tool:
    name: str = ""
    description: str = ""
    # JSON-schema of the arguments, OpenAI function-call style.
    parameters: dict = {"type": "object", "properties": {}}
    # True when the tool's output is content controlled by the TARGET (an HTTP
    # body, a rendered page, a DNS answer). Such output is data to analyze, never
    # instructions — the loop fences it so a hostile target cannot inject prompts.
    returns_untrusted_data: bool = False

    def run(self, **kwargs) -> ToolResult:  # pragma: no cover - overridden
        raise NotImplementedError

    def spec(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


class ToolRegistry:
    def __init__(self, tools: list[Tool]) -> None:
        self._tools = {t.name: t for t in tools}

    def specs(self) -> list[dict]:
        return [t.spec() for t in self._tools.values()]

    def untrusted(self, name: str) -> bool:
        """Does this tool return target-controlled data that must be fenced?"""
        tool = self._tools.get(name)
        return bool(tool and getattr(tool, "returns_untrusted_data", False))

    def dispatch(self, name: str, arguments: str | dict) -> ToolResult:
        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(f"No such tool: {name}", is_error=True)
        try:
            args = json.loads(arguments) if isinstance(arguments, str) else (arguments or {})
        except ValueError as exc:
            return ToolResult(f"Could not parse arguments as JSON: {exc}", is_error=True)
        if not isinstance(args, dict):
            return ToolResult("Arguments must be a JSON object.", is_error=True)
        try:
            return tool.run(**args)
        except TypeError as exc:
            return ToolResult(f"Bad arguments for {name}: {exc}", is_error=True)
        except Exception as exc:  # noqa: BLE001 - a tool must never crash the loop
            return ToolResult(f"{type(exc).__name__}: {exc}", is_error=True)
