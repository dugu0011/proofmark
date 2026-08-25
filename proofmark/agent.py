"""The loop: plan, act, observe, repeat, until proven or out of budget.

This is the brain. It hands the model the mission and the tools, lets it choose
an action, runs that action in the sandbox, feeds the result back, and goes
again. It stops when the agent calls `finish`, when it has nothing left to do,
or when it hits the step or time budget — an autonomous agent needs a hard stop
it cannot argue its way out of.

Every step is reported to a callback so the CLI can show the agent working, the
way a pentester narrates a session.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from proofmark.authorization import Authorization
from proofmark.findings import Finding
from proofmark.llm import LLM, LLMError
from proofmark.prompts import first_message, system_prompt
from proofmark.tools.base import Tool, ToolRegistry

# The agent's own end-the-session tool. Defined here because it acts on the loop,
# not on the world.
_FINISH_SPEC = {
    "type": "function",
    "function": {
        "name": "finish",
        "description": "End the assessment. Call this when you have tested the surface and "
                       "recorded everything you could prove.",
        "parameters": {
            "type": "object",
            "properties": {"summary": {"type": "string", "description": "A short wrap-up."}},
            "required": ["summary"],
        },
    },
}


@dataclass
class Event:
    """One thing that happened, for the CLI to render."""

    kind: str   # "think" | "action" | "observation" | "finding" | "done" | "error"
    text: str
    detail: str = ""


@dataclass
class Outcome:
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    steps_used: int = 0
    stopped_reason: str = ""


class Agent:
    def __init__(
        self,
        llm: LLM,
        registry: ToolRegistry,
        authorization: Authorization,
        *,
        name: str,
        system_suffix: str = "",
        max_steps: int = 40,
        time_budget_seconds: int = 600,
        on_event: Callable[[Event], None] | None = None,
        steer_fn: Callable[[], list[str]] | None = None,
    ) -> None:
        self._llm = llm
        self._registry = registry
        self._auth = authorization
        self._name = name
        self._system_suffix = system_suffix
        self._max_steps = max_steps
        self._deadline = time.time() + time_budget_seconds
        self._emit = on_event or (lambda e: None)
        self._steer = steer_fn or (lambda: [])

    def run(self, target: str, kind: str) -> Outcome:
        system = system_prompt(self._name, self._auth)
        if self._system_suffix:
            system += "\n\n" + self._system_suffix
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": first_message(target, kind)},
        ]
        tools = [*self._registry.specs(), _FINISH_SPEC]
        outcome = Outcome()

        for step in range(1, self._max_steps + 1):
            outcome.steps_used = step
            if time.time() > self._deadline:
                outcome.stopped_reason = "time budget exhausted"
                self._emit(Event("done", "Stopping: time budget reached."))
                break

            # Operator steering: instructions pushed in mid-run are injected as
            # user turns the agent must act on next. This is what lets a human
            # redirect a live run instead of only watching it.
            for instruction in (self._steer() or []):
                instruction = str(instruction).strip()
                if not instruction:
                    continue
                messages.append({
                    "role": "user",
                    "content": f"OPERATOR INSTRUCTION (act on this now): {instruction}",
                })
                self._emit(Event("steer", instruction))

            try:
                reply = self._llm.complete(messages, tools)
            except LLMError as exc:
                outcome.stopped_reason = f"model error: {exc}"
                self._emit(Event("error", f"Model error: {exc}"))
                break

            if reply.text.strip():
                self._emit(Event("think", reply.text.strip()))
            messages.append(reply.raw_message)

            if not reply.tool_calls:
                # The model reasoned but did not act. Nudge it once, then move on.
                messages.append({
                    "role": "user",
                    "content": "Take an action with a tool, or call finish if you are done.",
                })
                continue

            stop = self._handle_calls(reply.tool_calls, messages, outcome)
            if stop:
                break
        else:
            outcome.stopped_reason = "step budget exhausted"
            self._emit(Event("done", "Stopping: step budget reached."))

        return outcome

    def _handle_calls(self, calls: list[dict], messages: list[dict], outcome: Outcome) -> bool:
        """Execute each tool call, append results, return True to stop the loop."""
        for call in calls:
            name, args = call["name"], call["arguments"]

            if name == "finish":
                summary = _arg(args, "summary")
                outcome.summary = summary
                outcome.stopped_reason = "agent finished"
                self._emit(Event("done", summary or "Assessment complete."))
                return True

            self._emit(Event("action", f"{name}", _short(args)))
            result = self._registry.dispatch(name, args)

            if result.data is not None and isinstance(result.data, Finding):
                outcome.findings.append(result.data)
                f = result.data
                self._emit(Event("finding", f"[{f.severity.value}] {f.title}", f.location))
            elif result.is_error:
                self._emit(Event("observation", result.output[:400], "refused/error"))
            else:
                self._emit(Event("observation", _preview(result.output)))

            messages.append({
                "role": "tool",
                "tool_call_id": call["id"],
                "content": result.output[:8000],
            })
        return False


def build_registry(tools: list[Tool]) -> ToolRegistry:
    return ToolRegistry(tools)


# -- small helpers --------------------------------------------------------
def _arg(arguments, key: str) -> str:
    import json
    try:
        data = json.loads(arguments) if isinstance(arguments, str) else (arguments or {})
        return str(data.get(key, ""))
    except ValueError:
        return ""


def _short(arguments) -> str:
    text = arguments if isinstance(arguments, str) else str(arguments)
    return text[:160] + ("..." if len(text) > 160 else "")


def _preview(output: str) -> str:
    line = output.strip().splitlines()[0] if output.strip() else "(no output)"
    return line[:200] + ("..." if len(line) > 200 else "")
